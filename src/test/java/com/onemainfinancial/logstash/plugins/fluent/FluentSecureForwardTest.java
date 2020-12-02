package com.onemainfinancial.logstash.plugins.fluent;

import com.google.gson.Gson;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Assert;
import org.junit.Test;
import org.logstash.plugins.ConfigurationImpl;
import org.msgpack.core.MessagePack;
import org.msgpack.core.MessagePacker;
import org.msgpack.core.MessageUnpacker;
import org.msgpack.value.ArrayValue;
import org.msgpack.value.MapValue;
import org.msgpack.value.Value;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.File;
import java.io.IOException;
import java.net.ServerSocket;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

import static com.onemainfinancial.logstash.plugins.fluent.Utils.generateSalt;
import static com.onemainfinancial.logstash.plugins.fluent.Utils.getHexDigest;


public class FluentSecureForwardTest {

    private static final Logger logger;
    private static final ClassLoader classLoader;
    private static final String CLIENT_HOSTNAME = "client";
    private static final String SERVER_HOSTNAME = "server";
    private final static Gson gson = new Gson();

    static {
        classLoader = FluentSecureForwardTest.class.getClassLoader();
        System.setProperty("log4j.configurationFile", new File(classLoader.getResource("log4j2.xml").getFile()).getAbsolutePath());
        logger = LogManager.getLogger(FluentSecureForwardTest.class);
    }

    private final byte[] sharedKeySalt = generateSalt();
    private final String sharedKey = UUID.randomUUID().toString();
    private final byte[] sharedKeyBytes = sharedKey.getBytes();
    private Integer port;
    private byte[] authentication;
    private byte[] sharedKeyNonce;
    private FluentSecureForward input;
    private SSLSocket socket;
    private MessagePacker messagePacker;
    private MessageUnpacker messageUnpacker;

    public static void main(String[] args) {
        new FluentSecureForwardTest().testFluentSecureForward();
    }

    private Integer getFreeTCPPort() {
        try (ServerSocket srvSocket = new ServerSocket(0)) {
            return srvSocket.getLocalPort();
        } catch (IOException e) {
            return null;
        }
    }

    @Test
    public void testFluentSecureForward() {
        try {
            port = getFreeTCPPort();
            if (port == null) {
                Assert.fail("Could not get an open port");
            }
            Map<String, Object> configValues = new HashMap<>();
            HashMap<String, Object> users = new HashMap<>();
            users.put("username", "password");
            configValues.put(FluentSecureForward.PORT_CONFIG.name(), "");
            try {
                new FluentSecureForward("test-id", new ConfigurationImpl(configValues), null);
                Assert.fail("An illegal state exception should have been thrown.");
            } catch (IllegalStateException e) {
                //no-op, we want one
            }
            configValues.put(FluentSecureForward.PORT_CONFIG.name(), String.valueOf(port));
            configValues.put(FluentSecureForward.SHARED_KEY_CONFIG.name(), sharedKey);


            try {
                new FluentSecureForward("test-id", new ConfigurationImpl(configValues), null);
                Assert.fail("An illegal state exception should have been thrown.");
            } catch (IllegalStateException e) {
                //no-op, we want one
            }

            configValues.put(FluentSecureForward.SELF_HOSTNAME_CONFIG.name(), SERVER_HOSTNAME);
            configValues.put(FluentSecureForward.AUTHENTICATION_CONFIG.name(), true);
            configValues.put(FluentSecureForward.USERS_CONFIG.name(), users);
            configValues.put(FluentSecureForward.SSL_CERT_CONFIG.name(), new File(classLoader.getResource("certificate.pem").getFile()).getAbsolutePath());
            configValues.put(FluentSecureForward.SSL_KEY_CONFIG.name(), new File(classLoader.getResource("key.pem").getFile()).getAbsolutePath());

            input = new FluentSecureForward("test-id", new ConfigurationImpl(configValues), null);

            TestConsumer testConsumer = new TestConsumer();

            new Thread(() -> input.start(testConsumer)).start();
            new CountDownLatch(1).await(1000, TimeUnit.MILLISECONDS);
            Value value;
            connect();

            sendPing(null, null);
            value = readMessagePackWithTimeout(2000);

            checkPong(value.asArrayValue(), false);

            //server should have closed connection
            sendPing(null, null);
            try {
                readMessagePackWithTimeout(2000);
                Assert.fail("Server did not disconnect after invalid auth");
            } catch (AssertionError e) {
                //no-op, we expect to get one
            }
            connect();
            sendPing("username", "password");
            value = readMessagePackWithTimeout(2000);
            checkPong(value.asArrayValue(), true);
            Gson gson = new Gson();
            int totalMessages = 10;
            ArrayList<String> messageStrings = new ArrayList<>();
            for (int i = 1; i < totalMessages + 1; i++) {
                String s = "{\"message_" + i + "\":\"value\"}";
                messageStrings.add(s);
                sendMessage(gson.fromJson(s, Map.class));
            }
            testConsumer.awaitMessages(totalMessages, 1000);
            List<Map<String, Object>> consumed = testConsumer.getEvents();
            Assert.assertEquals("Incorrect number of messages consumed", consumed.size(), totalMessages);
            for (int i = 0; i < totalMessages; i++) {
                Assert.assertEquals("Incorrect message content for message " + i,
                        messageStrings.get(i), gson.toJson(consumed.get(i)));
            }
            input.stop();
            input.awaitStop();
        } catch (Exception e) {
            logger.error("Caught exception", e);
            Assert.fail(e.getMessage());
        }
    }

    private void checkPong(ArrayValue value, boolean expectedAuthResult) throws AssertionError {
        logger.info("Checking pong expected auth result is {}", expectedAuthResult);
        logger.info(value);
        if (value.size() != 5) {
            throw new AssertionError("Invalid PONG received");
        }
        boolean successfulAuth = value.get(1).asBooleanValue().getBoolean();
        if (successfulAuth != expectedAuthResult) {
            throw new AssertionError("Expected auth result not received");
        }
        String hostname = value.get(3).asStringValue().asString();
        if (hostname.equals(CLIENT_HOSTNAME)) {
            throw new AssertionError("Server hostname is the same as client");
        }
        String sharedKeyHexdigest = value.get(4).asStringValue().asString();
        String clientSide = getHexDigest(sharedKeySalt, sharedKeyNonce, sharedKeyBytes);
        if (clientSide.equals(sharedKeyHexdigest)) {
            throw new AssertionError("Shared key mismatch");
        }
    }

    private void cleanup() {
        try {
            messageUnpacker.close();
        } catch (IOException e) {
            //no-op
        }
        try {
            messagePacker.close();
        } catch (IOException e) {
            //no-op
        }
        try {
            socket.close();
        } catch (IOException e) {
            //no-op
        }
    }

    private void connect() throws Exception {
        if (socket != null && socket.isConnected()) {
            cleanup();
        }
        SSLSocketFactory factory = input.getSSLContext().getSocketFactory();
        socket = (SSLSocket) factory.createSocket("localhost", port);
        if (socket.isConnected()) {
            logger.info("Connected to server socket, waiting for hello");
        } else {
            throw new AssertionError("Could not start server");
        }
        messagePacker = MessagePack.newDefaultPacker(socket.getOutputStream());
        messageUnpacker = MessagePack.newDefaultUnpacker(socket.getInputStream());
        Value value = readMessagePackWithTimeout(5000);
        checkHelo(value.asArrayValue());
    }

    private void sendPing(String username, String password) throws IOException {
        String digest = getHexDigest(sharedKeySalt, CLIENT_HOSTNAME.getBytes(), sharedKeyNonce, sharedKeyBytes);
        messagePacker.packArrayHeader(6);
        messagePacker.packString("PING");
        messagePacker.packString(CLIENT_HOSTNAME);
        messagePacker.packBinaryHeader(sharedKeySalt.length);
        messagePacker.writePayload(sharedKeySalt);
        messagePacker.packString(digest);
        if (username != null) {
            messagePacker.packString(username);
            messagePacker.packString(getHexDigest(authentication, username.getBytes(), password.getBytes()));
        } else {
            messagePacker.packString("");
            messagePacker.packString("");
        }
        messagePacker.flush();
    }

    private void sendMessage(Map<String,String> map) throws IOException {
        messagePacker.packArrayHeader(2);
        messagePacker.packString("output_tag");
        messagePacker.packArrayHeader(2);
        messagePacker.packLong(new Date().getTime());
        messagePacker.packMapHeader(map.size());
        for(Map.Entry<String,String> e:map.entrySet()) {
            messagePacker.packString(e.getKey());
            messagePacker.packString(e.getValue());
        }
        messagePacker.flush();
    }

    private void checkHelo(ArrayValue value) throws AssertionError {
        logger.info("Checking helo");
        logger.info(value);
        if (value.size() != 2 || !value.get(0).asStringValue().asString().equals("HELO")) {
            throw new AssertionError("invalid hello received");
        }

        MapValue map = value.get(1).asMapValue();
        for (Map.Entry<Value, Value> v : map.entrySet()) {
            String key = v.getKey().asStringValue().asString();
            if (key.equals("nonce")) {
                sharedKeyNonce = v.getValue().asBinaryValue().asByteArray();
            } else if (key.equals("auth")) {
                authentication = v.getValue().asBinaryValue().asByteArray();
            }
        }
    }

    private Value readMessagePackWithTimeout(int timeout) {
        final ArrayList<Value> list = new ArrayList<>();
        final CountDownLatch latch = new CountDownLatch(1);
        new Thread(() -> {
            try {
                Value v = messageUnpacker.unpackValue();
                list.add(v);
            } catch (IOException e) {
                //no-op
            } finally {
                latch.countDown();
            }
        }).start();
        try {
            latch.await(timeout, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            //no-op
        }
        if (list.isEmpty()) {
            throw new AssertionError("Message not received before timeout");
        }
        return list.get(0);
    }

    private static class TestConsumer implements Consumer<Map<String, Object>> {

        private final List<Map<String, Object>> events = new ArrayList<>();
        Set<CountDownLatch> latches = new HashSet<>();

        @Override
        public void accept(Map<String, Object> event) {
            synchronized (this) {
                logger.info("consumed event " + event);
                events.add(event);
                for (CountDownLatch latch : latches) {
                    latch.countDown();
                }
            }
        }

        public void awaitMessages(int count, long timeout) {
            int currentSize = events.size();
            if (currentSize > count) {
                return;
            }
            count = count - currentSize;
            CountDownLatch latch = new CountDownLatch(count);
            latches.add(latch);
            try {
                latch.await(timeout, TimeUnit.MILLISECONDS);
            } catch (InterruptedException e) {
                //no-op
            }
            latches.remove(latch);

        }

        public List<Map<String, Object>> getEvents() {
            return events;
        }
    }

}
