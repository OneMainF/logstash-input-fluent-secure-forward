package com.onemainfinancial.logstash.plugins.fluent;

import co.elastic.logstash.api.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.net.ServerSocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.TrustManagerFactory;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.*;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.function.Consumer;

import static co.elastic.logstash.api.PluginConfigSpec.*;

// class name must match plugin name
@LogstashPlugin(name = "fluent_secure_forward")
public class FluentSecureForward implements Input {
    static final PluginConfigSpec<String> SELF_HOSTNAME_CONFIG = stringSetting("self_hostname");
    static final PluginConfigSpec<String> SHARED_KEY_CONFIG = requiredStringSetting("shared_key");
    static final PluginConfigSpec<String> HOST_CONFIG = stringSetting("host", "0.0.0.0");
    static final PluginConfigSpec<String> PORT_CONFIG = stringSetting("port", "24284");
    static final PluginConfigSpec<String> SSL_VERSION_CONFIG = stringSetting("ssl_version", "TLSv1.2");
    static final PluginConfigSpec<String> SSL_CIPHERS_CONFIG = stringSetting("ssl_ciphers", "");
    static final PluginConfigSpec<Boolean> SSL_ENABLE_CONFIG = booleanSetting("ssl_enable", true);
    static final PluginConfigSpec<String> SSL_CERT_CONFIG = requiredStringSetting("ssl_cert");
    static final PluginConfigSpec<String> SSL_KEY_CONFIG = requiredStringSetting("ssl_key");
    static final PluginConfigSpec<Boolean> AUTHENTICATION_CONFIG = booleanSetting("authentication", false);
    static final PluginConfigSpec<Map<String, Object>> USERS_CONFIG = hashSetting("users");
    static final String PLUGIN_NAME = FluentSecureForward.class.getAnnotation(LogstashPlugin.class).name();
    static final Logger logger = LogManager.getLogger(FluentSecureForward.class);
    final String selfHostname;
    final boolean requireAuthentication;
    final HashMap<String, String> users = new HashMap<>();
    private final CountDownLatch done = new CountDownLatch(1);
    private final String host;
    private final Integer port;
    private final String sslVersion;
    private final String[] sslCiphers;
    private final String sslCert;
    private final String sslKey;
    private final boolean sslEnable;
    private final String id;
    byte[] sharedKeyBytes;
    byte[] selfHostnameBytes;
    boolean enableKeepalive = false; //TODO Implement keep alive
    InetAddress inetAddress;
    Consumer<Map<String, Object>> consumer;
    private ServerSocket socket = null;
    private volatile boolean stopped;
    private SSLContext sslContext;


    /**
     * Required constructor.
     *
     * @param id            Plugin id
     * @param configuration Logstash Configuration
     * @param context       Logstash Context
     */
    public FluentSecureForward(final String id, final Configuration config, final Context context) {
        this.id = id;
        // constructors should validate configuration options
        if (config.contains(SELF_HOSTNAME_CONFIG)) {
            selfHostname = config.get(SELF_HOSTNAME_CONFIG);
        } else {
            logger.warn("self_hostname will be auto determined, it is recommended to set this property");
            try {
                selfHostname = InetAddress.getLocalHost().getHostName();
            } catch (UnknownHostException e) {
                throw new IllegalStateException("Could not determine local host name, please set self_hostname");
            }
            logger.info("self_hostname set to {}", selfHostname);
        }
        if (!config.contains(SHARED_KEY_CONFIG)) {
            throw new IllegalStateException("A value must be specified for 'shared_key'");
        }
        sharedKeyBytes = config.get(SHARED_KEY_CONFIG).getBytes();
        selfHostnameBytes = selfHostname.getBytes();
        host = config.get(HOST_CONFIG);
        sslVersion = config.get(SSL_VERSION_CONFIG);
        sslCiphers = config.get(SSL_CIPHERS_CONFIG).split("  +");
        sslCert = config.get(SSL_CERT_CONFIG);
        sslKey = config.get(SSL_KEY_CONFIG);
        sslEnable = config.get(SSL_ENABLE_CONFIG);
        try {
            inetAddress = InetAddress.getByName(host);
        } catch (UnknownHostException e) {
            throw new IllegalStateException("Value '" + host + "' for setting 'host' is not valid. " + e.getMessage());
        }
        try {
            port = Integer.parseInt(config.get(PORT_CONFIG));
        } catch (NumberFormatException e) {
            throw new IllegalStateException("Value '" + config.get(PORT_CONFIG) + "' for setting 'port' is not valid");
        }

        if (sslEnable) {
            if (sslCert == null || sslKey == null) {
                throw new IllegalStateException("A value must be specified for both 'ssl_cert' and 'ssl_key' when 'ssl_enable' is true");
            }
            if (!new File(sslCert).isFile()) {
                throw new IllegalStateException("File '" + sslCert + "' for setting 'ssl_cert' does not exist or cannot be accessed");
            }
            if (!new File(sslKey).isFile()) {
                throw new IllegalStateException("File '" + sslKey + "' for setting 'ssl_key' does not exist or cannot be accessed");
            }
        }
        requireAuthentication = config.get(AUTHENTICATION_CONFIG);
        if (config.contains(USERS_CONFIG)) {
            for (Map.Entry<String, Object> e : config.get(USERS_CONFIG).entrySet()) {
                String username = e.getKey().toLowerCase();
                if (!(e.getValue() instanceof String)) {
                    throw new IllegalStateException("Value for key '" + username + "' for setting 'users' must be a string");
                }
                if (this.users.containsKey(username)) {
                    throw new IllegalStateException("Value for key '" + username + "' for setting 'users' already provided.  User names are case insensitive");
                }
                this.users.put(e.getKey().toLowerCase(), e.getValue().toString());
            }
        }

    }

    private ServerSocket getSSLServerSocket() throws GeneralSecurityException, IOException {
        SSLContext sslContext = getSSLContext();
        SSLServerSocket sslServerSocket = (SSLServerSocket) sslContext
                .getServerSocketFactory()
                .createServerSocket(port, 0, inetAddress);
        if (!sslCiphers[0].equals("")) {
            sslServerSocket.setEnabledCipherSuites(sslCiphers);
        }
        return sslServerSocket;
    }

    public SSLContext getSSLContext() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, KeyException, InvalidKeySpecException, UnrecoverableKeyException {
        if (sslContext != null) {
            return sslContext;
        }
        char[] emptyPassword = "".toCharArray();
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, emptyPassword);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        FileInputStream is = new FileInputStream(sslCert);
        X509Certificate cer = (X509Certificate) certificateFactory.generateCertificate(is);
        boolean keyFound = false;
        StringBuilder privateKeyContent = new StringBuilder();
        for (String line : Files.readAllLines(new File(sslKey).toPath())) {
            if (line.equals("-----BEGIN PRIVATE KEY-----")) {
                keyFound = true;
            } else if (line.equals("-----END PRIVATE KEY-----")) {

                break;
            } else if (keyFound) {
                privateKeyContent.append(line);
            }
        }
        if (privateKeyContent.length() == 0) {
            throw new KeyException("No private keys found in file");
        }
        PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyContent.toString()));
        ks.setKeyEntry("default", keyFactory.generatePrivate(keySpecPKCS8), emptyPassword, new Certificate[]{cer});
        final KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        final TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());

        kmf.init(ks, emptyPassword);
        tmf.init(ks);
        sslContext = SSLContext.getInstance(sslVersion);
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        return sslContext;
    }

    private ServerSocket getServerSocket() throws IOException {
        return ServerSocketFactory.getDefault().createServerSocket(port, 0, inetAddress);
    }

    private void acceptNewConnection() throws IOException {
        try {
            Socket client = socket.accept();
            new FluentSession(this, client).start();
        } catch (SocketException e) {
            if (!stopped) {
                logger.error("Caught socket exception", e);
            }
        }
    }

    @Override
    public void start(Consumer<Map<String, Object>> consumer) {
        this.consumer = consumer;
        // The start method should push Map<String, Object> instances to the supplied QueueWriter
        // instance. Those will be converted to Event instances later in the Logstash event
        // processing pipeline.
        //
        // Inputs that operate on unbounded streams of data or that poll indefinitely for new
        // events should loop indefinitely until they receive a stop request. Inputs that produce
        // a finite sequence of events should loop until that sequence is exhausted or until they
        // receive a stop request, whichever comes first.

        try {
            logger.info("Starting {} input listener {}:{}", PLUGIN_NAME, host, port);
            socket = sslEnable ? getSSLServerSocket() : getServerSocket();
            logger.debug("{} {} started on {}:{}", PLUGIN_NAME, id, host, port);
            while (!stopped) {
                acceptNewConnection();
            }
        } catch (Exception e) {
            logger.error("Could not start server ", e);
        } finally {
            stopped = true;
            done.countDown();
        }
    }

    @Override
    public void stop() {
        stopped = true; // set flag to request cooperative stop of input
        if (socket != null) {
            try {
                socket.close();
            } catch (IOException e) {
                //no-op
            }
        }
        logger.info("{} {} stopped", PLUGIN_NAME, this.id);
    }

    @Override
    public void awaitStop() throws InterruptedException {
        //this method is called at the begging of the input stopping
        //should block until finished
        done.await();
    }

    @Override
    public Collection<PluginConfigSpec<?>> configSchema() {
        // should return a list of all configuration options for this plugin
        return PluginHelper.commonInputSettings(
                Arrays.asList(
                        AUTHENTICATION_CONFIG,
                        USERS_CONFIG,
                        SELF_HOSTNAME_CONFIG,
                        SHARED_KEY_CONFIG,
                        HOST_CONFIG,
                        PORT_CONFIG,
                        SSL_VERSION_CONFIG,
                        SSL_CIPHERS_CONFIG,
                        SSL_CERT_CONFIG,
                        SSL_KEY_CONFIG
                ));
    }

    @Override
    public String getId() {
        return this.id;
    }
}
