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
import java.io.EOFException;
import java.io.IOException;
import java.net.Socket;
import java.util.Map;

import static com.onemainfinancial.logstash.plugins.fluent.Utils.generateSalt;
import static com.onemainfinancial.logstash.plugins.fluent.Utils.getHexDigest;

public class FluentSession extends Thread {
    private static final String REMOVE_HOST_CLOSED_MESSAGE = "Remote host closed connection during handshake";
    private static final Logger logger = LogManager.getLogger(FluentSession.class);
    private final static Gson gson = new Gson();
    private final byte[] sharedKeyNonce = generateSalt();
    private final byte[] authKeySalt = generateSalt();
    private final Socket session;
    private final FluentSecureForward parent;
    private final String id;
    private MessageUnpacker messageUnpacker;
    private MessagePacker messagePacker;

    FluentSession(FluentSecureForward parent, Socket socket) {
        this.parent = parent;
        this.session = socket;
        this.id = session.getRemoteSocketAddress().toString();
        logger.info("Received connection {}", id);
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


    @SuppressWarnings("unchecked")
    private void decodeEvent(Value value) {
        try {
            ValueType valueType = value.getValueType();
            logger.trace("Checking value type {} from {}",valueType,id);
            switch (valueType) {
                case BINARY:
                    decodeEvent(MessagePack.newDefaultUnpacker(value.asBinaryValue().asByteArray()).unpackValue());
                    break;
                case STRING:
                    decodeEvent(MessagePack.newDefaultUnpacker(value.asStringValue().asByteArray()).unpackValue());
                    break;
                case ARRAY:
                    for(Value v:value.asArrayValue()){
                        this.decodeEvent(v);
                    }
                    break;
                case MAP:
                    parent.consumer.accept(gson.fromJson(value.asMapValue().toString(), Map.class));
                    break;
                default:
                    logger.trace("Cannot handle value {} of type {} from {}",value, valueType, id);
                    break;
            }
        } catch (Exception e) {
            logger.error("Could not decode event from {}", id, e);
        }
    }

    private void readFromSession() throws IOException {
        logger.info("Waiting for messages from {}",id);
        while (!session.isClosed()) {
            try {
                ArrayValue arrayValue = messageUnpacker.unpackValue().asArrayValue();
                logger.trace("Received message from {} {}",id,arrayValue);
                String messageType = arrayValue.get(0).asStringValue().asString();
                if (messageType.equals("PING")) {
                    PingResult result = checkPing(arrayValue);
                    sendPong(result);
                    if (!result.successful) {
                        return;
                    }
                } else {
                    logger.trace("Received event of type {} from {}", messageType,id);
                    decodeEvent(arrayValue.get(1));
                }
            } catch (MessageInsufficientBufferException e) {
                logger.error("Caught insufficient buffer exception", e);
            }
        }
    }

    public void run() {
        try {
            if (session instanceof SSLSocket) {
                ((SSLSocket) session).startHandshake();
            }
            messageUnpacker = MessagePack.newDefaultUnpacker(session.getInputStream());
            messagePacker = MessagePack.newDefaultPacker(session.getOutputStream());
            sendHello();
            readFromSession();
        } catch (EOFException e) {
            logger.info("Socket closed with reason " + e.getMessage());
        } catch (SSLHandshakeException e) {
            if (e.getMessage().equalsIgnoreCase(REMOVE_HOST_CLOSED_MESSAGE)) {
                logger.info("Suppressed exception from socket {}", id, e);
            } else {
                logger.error("Caught SSLHandshakeException from socket {}", id, e);
            }
        } catch (Exception e) {
            logger.error("Caught exception from socket {}", id, e);
        }
        cleanup();
    }

    private void cleanup() {
        try {
            messageUnpacker.close();
        } catch (IOException e) {
            logger.trace("Could not close message unpacker for {}", id, e);
        }
        try {
            messagePacker.close();
        } catch (IOException e) {
            logger.trace("Could not close message packer for {}", id, e);
        }
        try {
            session.close();
        } catch (IOException e) {
            logger.trace("Could not close session {}", id, e);
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