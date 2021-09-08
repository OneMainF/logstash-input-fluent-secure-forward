package com.onemainfinancial.logstash.plugins.fluent;

import com.google.gson.Gson;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.msgpack.core.MessageInsufficientBufferException;
import org.msgpack.core.MessagePack;
import org.msgpack.core.MessagePacker;
import org.msgpack.core.MessageUnpacker;
import org.msgpack.value.ArrayValue;
import org.msgpack.value.Value;
import org.msgpack.value.ValueType;

import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSocket;
import javax.security.sasl.AuthenticationException;
import java.io.EOFException;
import java.io.IOException;
import java.net.Socket;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static com.onemainfinancial.logstash.plugins.fluent.Utils.generateSalt;
import static com.onemainfinancial.logstash.plugins.fluent.Utils.getHexDigest;

public class FluentSession extends Thread {

    private static final String REMOVE_HOST_CLOSED_MESSAGE = "Remote host closed connection during handshake";
    private static final Logger logger = LogManager.getLogger(FluentSession.class);
    private final Gson gson = new Gson();
    private final byte[] sharedKeyNonce = generateSalt();
    private final byte[] authKeySalt = generateSalt();
    private final Socket session;
    private final FluentSecureForward parent;
    private final String fromAddress;
    private MessageUnpacker messageUnpacker;
    private MessagePacker messagePacker;

    FluentSession(FluentSecureForward parent, Socket socket) {
        this.parent = parent;
        this.session = socket;
        this.fromAddress = session.getRemoteSocketAddress().toString();
        logger.debug("Received connection from {}", fromAddress);
    }

    private void sendPong(PingResult pingResult) throws IOException {
        messagePacker.packArrayHeader(5);
        messagePacker.packString("PONG");
        messagePacker.packBoolean(pingResult.successful);
        if (pingResult.successful) {
            messagePacker.packString("");
            messagePacker.packString(parent.selfHostname);
            messagePacker.packString(getHexDigest((byte[]) pingResult.object, parent.selfHostnameBytes, sharedKeyNonce, parent.sharedKeyBytes));
        } else {
            messagePacker.packString((String) pingResult.object);
            messagePacker.packString("");
            messagePacker.packString("");
        }
        messagePacker.flush();
    }

    private void sendHello() throws IOException {
        messagePacker.packArrayHeader(2);
        messagePacker.packString("HELO");
        messagePacker.packMapHeader(3);
        messagePacker.packString("nonce");
        messagePacker.packBinaryHeader(sharedKeyNonce.length);
        messagePacker.writePayload(sharedKeyNonce);
        messagePacker.packString("auth");
        if (parent.requireAuthentication) {
            messagePacker.packBinaryHeader(authKeySalt.length);
            messagePacker.writePayload(authKeySalt);
        } else {
            messagePacker.packString("");
        }
        messagePacker.packString("keepalive");
        messagePacker.packBoolean(parent.enableKeepalive);
        messagePacker.flush();
    }

    private PingResult checkPing(ArrayValue value) {
        if (value.size() != 6) {
            return new PingResult(false, "invalid ping message");
        }
        byte[] hostname = value.get(1).asRawValue().asByteArray();
        byte[] sharedKeySalt = value.get(2).asRawValue().asByteArray();
        String sharedKeyHexDigest = value.get(3).asStringValue().asString();
        String username = value.get(4).asStringValue().asString().toLowerCase();
        byte[] usernameBytes = value.get(4).asRawValue().asByteArray();
        if (!getHexDigest(sharedKeySalt, hostname, sharedKeyNonce, parent.sharedKeyBytes).equals(sharedKeyHexDigest)) {
            new PingResult(false, "shared key mismatch");
        } else if (parent.requireAuthentication && !(parent.users.containsKey(username) &&
                getHexDigest(authKeySalt, usernameBytes, parent.users.get(username).getBytes())
                        .equals(value.get(5).asStringValue().asString()))) {
            return new PingResult(false, "username/password mismatch");
        }
        return new PingResult(true, sharedKeySalt);
    }

    private void unpackBytes(byte[] bytes) throws IOException {
        try (MessageUnpacker unpacker = MessagePack.newDefaultUnpacker(bytes)) {
            while (unpacker.hasNext()) {
                decodeEvent(unpacker.unpackValue());
            }
        }
    }

    @SuppressWarnings("unchecked")
    private void decodeEvent(Value value) {
        try {
            ValueType valueType = value.getValueType();
            logger.trace("Checking value type {} from {}", valueType, fromAddress);
            switch (valueType) {
                case BINARY:
                    unpackBytes(value.asBinaryValue().asByteArray());
                    break;
                case STRING:
                    unpackBytes(value.asStringValue().asByteArray());
                    break;
                case ARRAY:
                    for (Value v : value.asArrayValue()) {
                        this.decodeEvent(v);
                    }
                    break;
                case MAP:
                    parent.accept(gson.fromJson(value.asMapValue().toString(), Map.class));
                    break;
                default:
                    logger.trace("Cannot handle value {} of type {} from {}", value, valueType, fromAddress);
                    break;
            }
        } catch (Exception e) {
            logger.error("Could not decode event from {}", fromAddress, e);
        }
    }

    private boolean unpackValues() throws IOException {
        try {
            logger.debug("Attempting to unpack values from {}", fromAddress);
            boolean messageRead = false;
            while (messageUnpacker.hasNext()) {
                ArrayValue arrayValue = messageUnpacker.unpackValue().asArrayValue();
                messageRead = true;
                logger.trace("Received message from {} {}", fromAddress, arrayValue);
                String messageType = arrayValue.get(0).asStringValue().asString();
                if (messageType.equals("PING")) {
                    PingResult result = checkPing(arrayValue);
                    sendPong(result);
                    if (!result.successful) {
                        throw new AuthenticationException("Client failed authentication");
                    }
                } else {
                    logger.trace("Received event of type {} from {}", messageType, fromAddress);
                    decodeEvent(arrayValue.get(1));
                }
            }
            return messageRead;
        } catch (MessageInsufficientBufferException e) {
            logger.debug("Caught insufficient buffer exception from {}", fromAddress);
            logger.trace("Stack trace is", e);
            return true;
        }
    }

    @Override
    @SuppressWarnings("java:S2142")
    public void run() {
        try {
            if (session instanceof SSLSocket) {
                ((SSLSocket) session).startHandshake();
            }
            messageUnpacker = MessagePack.newDefaultUnpacker(session.getInputStream());
            messagePacker = MessagePack.newDefaultPacker(session.getOutputStream());
            sendHello();
            logger.debug("Waiting for messages from {}", fromAddress);
            while (unpackValues()) {
                TimeUnit.SECONDS.sleep(1);
            }
        } catch (AuthenticationException e) {
            logger.error("Socket {} failed authentication", fromAddress);
        } catch (EOFException e) {
            logger.info("Socket closed with reason {}", e.getMessage());
        } catch (SSLHandshakeException e) {
            if (e.getMessage().equalsIgnoreCase(REMOVE_HOST_CLOSED_MESSAGE)) {
                logger.info("Remote host {} closed", fromAddress, e);
            } else {
                logger.error("Caught SSLHandshakeException from socket {}", fromAddress, e);
            }
        } catch (Exception e) {
            logger.error("Caught exception from socket {}", fromAddress, e);
        } finally {
            closeAll(messagePacker, messageUnpacker, session);
        }
    }

    private void closeAll(AutoCloseable... closeables) {
        logger.info("Closing connection to {}", fromAddress);
        for (AutoCloseable closeable : closeables) {
            if (closeable != null) {
                try {
                    closeable.close();
                } catch (Exception e) {
                    logger.trace("Could not close {}", closeable, e);
                }
            }
        }
    }

    private static class PingResult {
        public final boolean successful;
        public final Object object;

        public PingResult(boolean successful, Object object) {
            this.successful = successful;
            this.object = object;
        }
    }
}