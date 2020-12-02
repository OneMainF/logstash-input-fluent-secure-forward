package com.onemainfinancial.logstash.plugins.fluent;


import org.msgpack.core.MessagePack;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

public class Utils {
    private static final String MD_ALGORITHM = "SHA-512";

    private Utils() {
        //no-op
    }


    public static String getHexDigest(byte[]... updates) {
        try {
            MessageDigest md = MessageDigest.getInstance(MD_ALGORITHM);
            StringBuilder hexString = new StringBuilder();
            for (byte[] b : updates) {
                md.update(b);
            }
            for (byte b : md.digest()) {
                String hex = Integer.toHexString(0xFF & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            return "";
        }
    }


    public static byte[] generateSalt() {
        byte[] b = new byte[16];
        new Random().nextBytes(b);
        return b;
    }
}
