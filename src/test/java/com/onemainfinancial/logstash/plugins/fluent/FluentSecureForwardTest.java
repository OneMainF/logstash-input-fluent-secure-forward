package com.onemainfinancial.logstash.plugins.fluent;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
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

import static com.onemainfinancial.logstash.plugins.fluent.FluentSecureForward.*;
import static com.onemainfinancial.logstash.plugins.fluent.Utils.generateSalt;
import static com.onemainfinancial.logstash.plugins.fluent.Utils.getHexDigest;

public class FluentSecureForwardTest {

    private static final Logger logger;
    private static final ClassLoader classLoader;
    private static final String CLIENT_HOSTNAME = "client";
    private static final String SERVER_HOSTNAME = "server";
    private static final String ID = "test-id";

    static {
        classLoader = FluentSecureForwardTest.class.getClassLoader();
        System.setProperty("log4j.configurationFile", new File(classLoader.getResource("log4j2.xml").getFile()).getAbsolutePath());
        logger = LogManager.getLogger(FluentSecureForwardTest.class);
    }

    private final Gson gson = new Gson();
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
    private final Gson prettyPrinter=new GsonBuilder().setPrettyPrinting().create();
    public static void main(String[] args) {
        new FluentSecureForwardTest().testFluentSecureForward();
    }

    private Integer getFreeTCPPort() {
        try (ServerSocket srvSocket = new ServerSocket(0)) {
            return srvSocket.getLocalPort();
        } catch (IOException e) {
            Assert.fail("Could not get an open port");
            return null;
        }
    }

    public Map<String, Object> map(Object... args) {
        Map<String, Object> m = new HashMap<>();
        for (int i = 0; i < args.length; i = i + 2) {
            m.put(String.valueOf(args[i]), args[i + 1]);
        }
        return m;
    }

    @Test
    public void testPathParsing() {
        String path = "[host][name]";
        Assert.assertEquals(Utils.getParsedPathFromCache(path), Arrays.asList("host", "name"));
        Map<String, Object> serverA = map("host", map("name", "Server A"));
        Assert.assertEquals(Utils.get(serverA, path), "Server A");

    }

    @Test
    public void testExpansion() {
        Map<String, Object> serverA = map("pod", "pod", "host", map("name", "Server A"));
        Assert.assertEquals(ExpansionPattern.expand("Test-%{[host][name]}-%{pod}", serverA), "Test-Server A-pod");
    }

    @Test
    public void testMultiline() {
        try {
            port = getFreeTCPPort();
            Map<String, Object> configValues = new HashMap<>();
            configValues.put(PORT_CONFIG.name(), String.valueOf(port));
            configValues.put(SHARED_KEY_CONFIG.name(), sharedKey);
            configValues.put(SELF_HOSTNAME_CONFIG.name(), SERVER_HOSTNAME);
            configValues.put(AUTHENTICATION_CONFIG.name(), true);
            configValues.put(SSL_CERT_CONFIG.name(), new File(classLoader.getResource("certificate.pem").getFile()).getAbsolutePath());
            configValues.put(SSL_KEY_CONFIG.name(), new File(classLoader.getResource("key.pem").getFile()).getAbsolutePath());
            configValues.put(MULTILINE_CONFIG.name(), Collections.singletonList(
                    map(
                            "timeout", 2000,
                            "group_key", "%{[host][name]}:%{pod}",
                            "match", map(
                                    "host", ".*"
                            ),
                            "discard_pattern", "DEBUG .*",
                            "pattern", "\\[.*",
                            "field", "message",
                            "multiline", Collections.singletonList(map(
                                    "timeout", 2000,
                                    "match", map(
                                            "messageTwo", ".*"
                                    ),
                                    "pattern", "\\[.*",
                                    "field", "messageTwo"
                            ))
                    )
            ));

            input = new FluentSecureForward(ID, new ConfigurationImpl(configValues), null);
            TestConsumer testConsumer = new TestConsumer();
            new Thread(() -> input.start(testConsumer)).start();
            connect();
            Map<String, Object> serverA = map("name", "Server A");
            Map<String, Object> serverB = map("name", "Server B");
            Map<String, Object> serverC = map("name", "Server C");
            List<Map<String, Object>> list = Arrays.asList(
                    map("key", "1", "host", serverC, "pod", "Pod A", "message", "hello"),
                    map("key", "2", "host", serverA, "pod", "Pod A", "message", "[ Start of first stack for server a", "messageTwo", "one"),
                    map("key", "3", "host", serverA, "pod", "Pod A", "message", "  second line of stack"),
                    map("key", "4", "host", serverA, "pod", "Pod A", "message", "DEBUG some debug info to discard"),
                    map("key", "5", "message", "single message two"),
                    map("key", "6", "host", serverB, "pod", "Pod A", "message", "[ Start of first stack for server b"),
                    map("key", "7", "host", serverB, "pod", "Pod A", "message", "[ Start of second stack for server b"),
                    map("key", "8", "host", serverA, "pod", "Pod A", "message", "  third line of stack"),
                    map("key", "9", "host", serverA, "pod", "Pod A", "message", "[ Start of second stack for server a", "messageTwo", "two"),
                    map("key", "10", "host", serverA, "pod", "Pod A", "message", "[ Start of third stack for server a"),
                    map("key", "12", "host", serverC, "pod", "Pod A", "message", " world")
            );
            Map<String, Object> expectedOrder = map(
                    "1", map("message", "hello\\n world"),
                    "5", map("message", "single message two"),
                    "6", map("message", "[ Start of first stack for server b"),
                    "2", map("message", "[ Start of first stack for server a\\n  second line of stack\\n  third line of stack",
                            "messageTwo","one\\ntwo"),
                    "6", map("message", "[ Start of first stack for server b"),
                    "7", map("message", "[ Start of second stack for server b"),
                    "10", map("message", "[ Start of third stack for server a")
            );
            for (Map<String, Object> map : list) {
                sendMessage(map);
            }

            testConsumer.awaitMessages(expectedOrder.size(), 12000);
            List<Map<String, Object>> consumed = testConsumer.getEvents();
            logger.info("consumed events are \n" + prettyPrinter.toJson(consumed));
            Assert.assertEquals("Incorrect number of messages consumed", expectedOrder.size(), consumed.size());
            for (Map<String, Object> m : consumed) {
                String key = (String) m.get("key");
                Map<String,Object> expected= (Map<String, Object>) expectedOrder.get(key);
                for(Map.Entry<String,Object> e: expected.entrySet()){

                    Assert.assertEquals("Field "+e.getKey()+" did not have the correct value in message "+key,  e.getValue(),m.get(e.getKey()));
                }


            }
            input.stop();
            input.awaitStop();

        } catch (Exception e) {
            logger.error("Caught exception", e);
            Assert.fail("Unexpected exception: " + e.getMessage());
        }
    }

    @Test
    public void testFluentSecureForward() {
        try {
            port = getFreeTCPPort();

            Map<String, Object> configValues = new HashMap<>();
            Map<String, Object> users = new HashMap<>();
            users.put("username", "password");
            configValues.put(PORT_CONFIG.name(), "");
            try {
                new FluentSecureForward(ID, new ConfigurationImpl(configValues), null);
                Assert.fail("An illegal state exception should have been thrown.");
            } catch (IllegalStateException e) {
                //no-op, we want one
            }
            configValues.put(PORT_CONFIG.name(), String.valueOf(port));
            configValues.put(SHARED_KEY_CONFIG.name(), sharedKey);


            try {
                new FluentSecureForward(ID, new ConfigurationImpl(configValues), null);
                Assert.fail("An illegal state exception should have been thrown.");
            } catch (IllegalStateException e) {
                //no-op, we want one
            }

            configValues.put(SELF_HOSTNAME_CONFIG.name(), SERVER_HOSTNAME);
            configValues.put(AUTHENTICATION_CONFIG.name(), true);
            configValues.put(USERS_CONFIG.name(), users);
            configValues.put(SSL_CERT_CONFIG.name(), new File(classLoader.getResource("certificate.pem").getFile()).getAbsolutePath());
            configValues.put(SSL_KEY_CONFIG.name(), new File(classLoader.getResource("key.pem").getFile()).getAbsolutePath());

            input = new FluentSecureForward(ID, new ConfigurationImpl(configValues), null);

            TestConsumer testConsumer = new TestConsumer();

            new Thread(() -> input.start(testConsumer)).start();
            connect();
            sendPing(null, null);
            checkPong(false);

            //server should have closed connection
            sendPing(null, null);
            boolean failedToReadMessage = true;
            try {
                readMessagePackWithTimeout(2000);
            } catch (AssertionError e) {
                failedToReadMessage = false;
            }
            if (failedToReadMessage) {
                Assert.fail("Server did not disconnect after invalid auth");
            }


            connect();
            sendPing("username", "password");
            checkPong(true);

            int totalMessages = 10;
            List<String> messageStrings = new ArrayList<>();
            for (int i = 1; i < totalMessages + 1; i++) {
                messageStrings.add("{\"message_" + i + "\":\"value\"}");
                sendMessage(gson.fromJson(messageStrings.get(messageStrings.size() - 1), Map.class));
            }
            testConsumer.awaitMessages(totalMessages, 1000);
            List<Map<String, Object>> consumed = testConsumer.getEvents();
            Assert.assertEquals("Incorrect number of messages consumed", totalMessages, consumed.size());
            for (int i = 0; i < totalMessages; i++) {
                Assert.assertEquals("Incorrect message content for message " + i,
                        messageStrings.get(i), gson.toJson(consumed.get(i)));
            }

            input.stop();
            input.awaitStop();
        } catch (Exception e) {
            logger.error("Caught exception", e);
            Assert.fail("Unexpected exception: " + e.getMessage());
        }
    }

    private void checkPong(boolean expectedAuthResult) {
        checkPong(readMessagePackWithTimeout(2000).asArrayValue(), expectedAuthResult);
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
        TimeUnit.SECONDS.sleep(1);
        SSLSocketFactory factory = input.getSSLContext().getSocketFactory();
        socket = (SSLSocket) factory.createSocket("localhost", port);
        if (socket.isConnected()) {
            logger.info("Connected to server socket, waiting for hello");
        } else {
            throw new AssertionError("Could not start server");
        }
        messagePacker = MessagePack.newDefaultPacker(socket.getOutputStream());
        messageUnpacker = MessagePack.newDefaultUnpacker(socket.getInputStream());
        checkHelo();
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

    private void sendMessage(Map<String, Object> map) throws IOException {
        if (map == null) {
            try {
                Thread.sleep(100);

            } catch (InterruptedException e) {
                //no-op
            }
            return;
        }
        messagePacker.packArrayHeader(2);
        messagePacker.packString("output_tag");
        messagePacker.packArrayHeader(2);
        messagePacker.packLong(new Date().getTime());
        packMap(map);
        messagePacker.flush();
    }

    private void packMap(Map<String, Object> map) throws IOException {
        messagePacker.packMapHeader(map.size());
        for (Map.Entry<String, Object> e : map.entrySet()) {
            messagePacker.packString(e.getKey());
            if (e.getValue() instanceof Map) {
                packMap((Map<String, Object>) e.getValue());
            } else {
                messagePacker.packString(e.getValue().toString());
            }
        }
    }


    private void checkHelo() throws AssertionError {
        checkHelo(readMessagePackWithTimeout(5000).asArrayValue());
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
                Assert.fail(count + " messages not received within " + timeout + " ms");
            }
            latches.remove(latch);

        }

        public List<Map<String, Object>> getEvents() {
            return events;
        }
    }

}
