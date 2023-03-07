package yagura.model;

import burp.BurpExtension;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.InvocationType;
import com.burgstaller.okhttp.AuthenticationCacheInterceptor;
import com.burgstaller.okhttp.CachingAuthenticatorDecorator;
import com.burgstaller.okhttp.basic.BasicAuthenticator;
import com.burgstaller.okhttp.digest.CachingAuthenticator;
import com.burgstaller.okhttp.digest.DigestAuthenticator;
import extension.burp.HttpTarget;
import extension.helpers.HttpUtil;
import extension.helpers.HttpUtil.DummyOutputStream;
import extension.helpers.StringUtil;
import java.awt.event.ActionEvent;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Authenticator;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.PasswordAuthentication;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpClient.Redirect;
import java.net.http.HttpClient.Version;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import okhttp3.MediaType;
import okhttp3.MultipartBody;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

/**
 *
 * @author isayan
 */
public class SendToServer extends SendToMenuItem {

    private final static Logger logger = Logger.getLogger(SendToServer.class.getName());

    public SendToServer(SendToItem item) {
        super(item);
    }

    public SendToServer(SendToItem item, ContextMenuEvent contextMenu) {
        super(item, contextMenu);
    }

    public void sendToEvent(List<HttpRequestResponse> messageInfo) {
        if (this.isReverseOrder()) {
            for (int i = messageInfo.size() - 1; i >= 0; i--) {
                sendToServer(messageInfo.get(i));
            }
        } else {
            for (int i = 0; i < messageInfo.size(); i++) {
                sendToServer(messageInfo.get(i));
            }
        }
    }

    /*
     * https://alvinalexander.com/java/jwarehouse/openjdk-8/jdk/src/share/classes/sun/net/www/protocol/http/HttpURLConnection.java.shtml
     */
    private final ExecutorService threadExecutor = Executors.newSingleThreadExecutor();

    protected void sendToServer(HttpRequestResponse messageInfo) {
        BurpExtension.helpers().outPrintln("sendToServer:");

        // 拡張オプションを取得
        HttpExtendProperty extendProp = new HttpExtendProperty();
        extendProp.setProperties(getExtendProperties());
        if (HttpExtendProperty.HttpClientType.CUSTOM.equals(extendProp.getHttpClientType())) {
            sendToServerUseOkHttpClient(messageInfo, extendProp);
        } else {
            sendToServerUseBurpClient(messageInfo);
            //sendToServerUseHttpClient(messageInfo, extendProp);
        }
    }

    protected void sendToServerUseBurpClient(HttpRequestResponse messageInfo) {
        Runnable sendTo = new Runnable() {
            @Override
            public void run() {
              try (ByteArrayOutputStream ostm = new ByteArrayOutputStream()) {
                    URL tagetURL = new URL(getTarget());
                    outPostHeader(ostm, tagetURL);
                    String boundary = HttpUtil.generateBoundary();
                    ostm.write(StringUtil.getBytesRaw(String.format("Content-Type: %s", "multipart/form-data;boundary=" + boundary) + StringUtil.NEW_LINE));
                    try (ByteArrayOutputStream bodyStream = new ByteArrayOutputStream()) {
                        outMultipart(boundary, bodyStream, messageInfo);
                        ostm.write(StringUtil.getBytesRaw(String.format("Content-Length: %d", bodyStream.size()) + StringUtil.NEW_LINE));
                        ostm.write(StringUtil.getBytesRaw("Connection: close" + StringUtil.NEW_LINE));
                        ostm.write(StringUtil.getBytesRaw(StringUtil.NEW_LINE));
                        ostm.write(bodyStream.toByteArray());
                    }
                    burp.api.montoya.http.message.requests.HttpRequest request = burp.api.montoya.http.message.requests.HttpRequest.httpRequest(HttpTarget.getHttpTarget(getTarget()), ByteArray.byteArray(ostm.toByteArray()));
                    HttpRequestResponse http = BurpExtension.api().http().sendRequest(request);
                    burp.api.montoya.http.message.responses.HttpResponse resnponse = http.response();
                    int statusCode = http.response().statusCode();
                    if (statusCode == HttpURLConnection.HTTP_OK) {
                        if (resnponse.body().length() == 0) {
                            fireSendToCompleteEvent(new SendToEvent(this, "Success[" + statusCode + "]"));
                        } else {
                            fireSendToWarningEvent(new SendToEvent(this, "Warning[" + statusCode + "]:" + resnponse.bodyToString()));
                            logger.log(Level.WARNING, "[" + statusCode + "]", resnponse.body());
                        }
                    } else {
                        // 200以外
                        fireSendToWarningEvent(new SendToEvent(this, "Error[" + statusCode + "]:" + resnponse.bodyToString()));
                        logger.log(Level.WARNING, "[" + statusCode + "]", resnponse.body());
                    }
                } catch (IOException ex) {
                    fireSendToErrorEvent(new SendToEvent(this, "Error[" + ex.getClass().getName() + "]:" + ex.getMessage()));
                    logger.log(Level.SEVERE, ex.getMessage(), ex);
                } catch (Exception ex) {
                    fireSendToErrorEvent(new SendToEvent(this, "Error[" + ex.getClass().getName() + "]:" + ex.getMessage()));
                    logger.log(Level.SEVERE, ex.getMessage(), ex);
                }
            }
        };
        this.threadExecutor.submit(sendTo);
    }

    protected void sendToServerUseJDKClient(HttpRequestResponse messageInfo, HttpExtendProperty extendProp) {
        Runnable sendTo = new Runnable() {
            @Override
            public void run() {
                String boundary = HttpUtil.generateBoundary();
                HttpURLConnection conn = null;
                try {
                    DummyOutputStream dummy = new DummyOutputStream();
                    outMultipart(boundary, dummy, messageInfo);
                    int contentLength = dummy.getSize();

                    URL url = new URL(getTarget()); // 送信先
                    // 拡張オプションを取得
                    Proxy.Type proxyProtocol = extendProp.getProxyProtocol();
                    Proxy proxy = Proxy.NO_PROXY;
                    if (!Proxy.Type.DIRECT.equals(proxyProtocol)) {
                        String proxyHost = extendProp.getProxyHost();
                        if (Proxy.Type.HTTP.equals(proxyProtocol)) {
                            int proxyPort = extendProp.getProxyPort();
                            SocketAddress addr = new InetSocketAddress(proxyHost, proxyPort);
                            proxy = new Proxy(Proxy.Type.HTTP, addr);
                        } else if (Proxy.Type.SOCKS.equals(proxyProtocol)) {
                            int proxyPort = extendProp.getProxyPort();
                            SocketAddress addr = new InetSocketAddress(proxyHost, proxyPort);
                            proxy = new Proxy(Proxy.Type.SOCKS, addr);
                        }
                    }
                    String proxyUser = extendProp.getProxyUser();
                    String proxyPasswd = extendProp.getProxyPasswd();
                    Authenticator authenticator = null;
                    if (!proxyUser.isEmpty()) {
                        authenticator = new Authenticator() {
                            @Override
                            protected PasswordAuthentication getPasswordAuthentication() {
                                return new PasswordAuthentication(proxyUser, proxyPasswd.toCharArray());
                            }
                        };
                    }

                    if (extendProp.isIgnoreValidateCertification()) {
                        HttpUtil.ignoreSocketFactory();
                    }

//                    if (!proxyUser.isEmpty()) {
//                    Authenticator.setDefault(authenticator);
//                    }
//                    else {
//                        Authenticator.setDefault(null);
//                    }

                    conn = (HttpURLConnection) url.openConnection(proxy);
                    conn.setFixedLengthStreamingMode(contentLength);
                    conn.setRequestMethod("POST");
                    conn.setDoOutput(true);
                    if (!proxyUser.isEmpty() && Proxy.Type.HTTP.equals(proxyProtocol)) {
                        byte[] basicAuth = Base64.getEncoder().encode(StringUtil.getBytesRaw(String.format("%s:%s", new Object[]{proxyUser, proxyPasswd})));
                        conn.setRequestProperty("Authorization", "Basic " + StringUtil.getStringRaw(basicAuth));
                    }
                    conn.setRequestProperty("Content-Type", "multipart/form-data; boundary=" + boundary);
                    conn.connect();
                    try (OutputStream ostm = conn.getOutputStream()) {
                        outMultipart(boundary, ostm, messageInfo);
                    } catch (IOException e) {
                        fireSendToErrorEvent(new SendToEvent(this, e.getMessage()));
                    } catch (Exception e) {
                        fireSendToErrorEvent(new SendToEvent(this, e.getMessage()));
                    }

                    InputStream istm = conn.getInputStream();
                    try (ByteArrayOutputStream bostm = new ByteArrayOutputStream()) {
                        BufferedInputStream bistm = new BufferedInputStream(istm);
                        String decodeMessage;
                        byte buf[] = new byte[4096];
                        int len;
                        while ((len = bistm.read(buf)) != -1) {
                            bostm.write(buf, 0, len);
                        }
                        int statusCode = conn.getResponseCode();
                        decodeMessage = StringUtil.getBytesRawString(bostm.toByteArray());
                        if (statusCode == HttpURLConnection.HTTP_OK) {
                            if (decodeMessage.length() == 0) {
                                fireSendToCompleteEvent(new SendToEvent(this, "Success[" + statusCode + "]"));
                            } else {
                                fireSendToWarningEvent(new SendToEvent(this, "Warning[" + statusCode + "]:" + decodeMessage));
                            }
                        } else {
                            // 200以外
                            fireSendToErrorEvent(new SendToEvent(this, "Error[" + statusCode + "]:" + decodeMessage));
                        }

                    } catch (IOException e) {
                        fireSendToErrorEvent(new SendToEvent(this, "Error[" + e.getClass().getName() + "]:" + e.getMessage()));
                    } finally {
                        if (istm != null) {
                            istm.close();
                        }
                    }
                } catch (IOException ex) {
                    fireSendToErrorEvent(new SendToEvent(this, "Error[" + ex.getClass().getName() + "]:" + ex.getMessage()));
                } catch (Exception ex) {
                    fireSendToErrorEvent(new SendToEvent(this, "Error[" + ex.getClass().getName() + "]:" + ex.getMessage()));
                } finally {
                    if (conn != null) {
                        conn.disconnect();
                    }
                }
            }
        };
        this.threadExecutor.submit(sendTo);
    }

    protected void sendToServerUseHttpClient(HttpRequestResponse messageInfo, HttpExtendProperty extendProp) {
        Runnable sendTo = new Runnable() {
            @Override
            public void run() {
                try {
                    // 拡張オプションを取得
                    // Authorization
                    HttpExtendProperty.AuthorizationType authorizationType = extendProp.getAuthorizationType();
                    Authenticator authenticator = null;
                    if (!HttpExtendProperty.AuthorizationType.NONE.equals(authorizationType)) {
                        String authorizationUser = extendProp.getAuthorizationUser();
                        String authorizationPasswd = extendProp.getAuthorizationPasswd();
                        authenticator = new Authenticator() {
                            @Override
                            protected PasswordAuthentication getPasswordAuthentication() {
                                return new PasswordAuthentication(authorizationUser, authorizationPasswd.toCharArray());
                            }
                        };
                    }

                    // Proxy
                    Proxy.Type proxyProtocol = extendProp.getProxyProtocol();
                    Proxy proxy = Proxy.NO_PROXY;
                    if (!Proxy.Type.DIRECT.equals(proxyProtocol)) {
                        String proxyHost = extendProp.getProxyHost();
                        if (Proxy.Type.HTTP.equals(proxyProtocol)) {
                            int proxyPort = extendProp.getProxyPort();
                            SocketAddress addr = new InetSocketAddress(proxyHost, proxyPort);
                            proxy = new Proxy(Proxy.Type.HTTP, addr);
                        } else if (Proxy.Type.SOCKS.equals(proxyProtocol)) {
                            // https://bugs.openjdk.java.net/browse/JDK-8214516
                            int proxyPort = extendProp.getProxyPort();
                            SocketAddress addr = new InetSocketAddress(proxyHost, proxyPort);
                            proxy = new Proxy(Proxy.Type.SOCKS, addr);
                        }
                    }
                    Authenticator proxyAuthenticator = null;
                    if (!Proxy.Type.DIRECT.equals(proxyProtocol)) {
                        String proxyUser = extendProp.getProxyUser();
                        String proxyPasswd = extendProp.getProxyPasswd();
                        if (!proxyUser.isEmpty()) {
                            proxyAuthenticator = new Authenticator() {
                                @Override
                                protected PasswordAuthentication getPasswordAuthentication() {
                                    return new PasswordAuthentication(proxyUser, proxyPasswd.toCharArray());
                                }
                            };
                        }
                    }
                    boolean ignoreValidateCertification = extendProp.isIgnoreValidateCertification();
                    HttpClient.Builder builder = HttpClient.newBuilder()
                            .version(Version.HTTP_1_1)
                            .followRedirects(Redirect.NORMAL)
                            .connectTimeout(Duration.ofSeconds(10));

                    if (ignoreValidateCertification) {
                        builder = builder.sslContext(HttpUtil.ignoreSSLContext());
                    }
                    final Properties props = System.getProperties();
                    props.setProperty("jdk.internal.httpclient.disableHostnameVerification", Boolean.toString(ignoreValidateCertification));

                    if (authenticator != null) {
                        builder = builder.authenticator(authenticator);
                    }
                    if (!Proxy.Type.DIRECT.equals(proxyProtocol)) {
                        ProxySelector staticProxy = new HttpUtil.StaticProxySelector(proxy) {
                            @Override
                            public void connectFailed(URI uri, SocketAddress sa, IOException ex) {
                                fireSendToErrorEvent(new SendToEvent(this, "Error[" + ex.getClass().getName() + "]:" + ex.getMessage()));
                                logger.log(Level.SEVERE, ex.getMessage(), ex);
                            }
                        };
                        builder = builder.proxy(staticProxy);
                    }
                    try (ByteArrayOutputStream ostm = new ByteArrayOutputStream()) {
                        String boundary = HttpUtil.generateBoundary();
                        outMultipart(boundary, ostm, messageInfo);
                        synchronized (Authenticator.class) {
                            Authenticator saveProxyAuth = Authenticator.getDefault();
                            try {
                                if (proxy != Proxy.NO_PROXY) {
                                    if (proxyAuthenticator != null) {
                                        saveProxyAuth = HttpUtil.putAuthenticator(proxyAuthenticator);
                                    }
                                }
                                HttpRequest request = HttpRequest.newBuilder()
                                        .uri(URI.create(getTarget())) // 送信先
                                        .header("Content-Type", "multipart/form-data;boundary=" + boundary)
                                        .POST(BodyPublishers.ofByteArray(ostm.toByteArray()))
                                        .build();

                                HttpClient client = builder.build();
                                HttpResponse<String> response = client.send(request, BodyHandlers.ofString());
                                int statusCode = response.statusCode();
                                String bodyMessage = response.body();
                                if (statusCode == HttpURLConnection.HTTP_OK) {
                                    if (bodyMessage.length() == 0) {
                                        fireSendToCompleteEvent(new SendToEvent(this, "Success[" + statusCode + "]"));
                                    } else {
                                        fireSendToWarningEvent(new SendToEvent(this, "Warning[" + statusCode + "]:" + bodyMessage));
                                        logger.log(Level.WARNING, "[" + statusCode + "]", bodyMessage);
                                    }
                                } else {
                                    // 200以外
                                    fireSendToWarningEvent(new SendToEvent(this, "Error[" + statusCode + "]:" + bodyMessage));
                                    logger.log(Level.WARNING, "[" + statusCode + "]", bodyMessage);
                                }
                            } finally {
                                if (proxyAuthenticator != null) {
                                    HttpUtil.putAuthenticator(saveProxyAuth);
                                }
                            }
                        }
                    }
                } catch (IOException ex) {
                    fireSendToErrorEvent(new SendToEvent(this, "Error[" + ex.getClass().getName() + "]:" + ex.getMessage()));
                    logger.log(Level.SEVERE, ex.getMessage(), ex);
                } catch (Exception ex) {
                    fireSendToErrorEvent(new SendToEvent(this, "Error[" + ex.getClass().getName() + "]:" + ex.getMessage()));
                    logger.log(Level.SEVERE, ex.getMessage(), ex);
                }
            }
        };
        this.threadExecutor.submit(sendTo);
    }

    protected void sendToServerUseOkHttpClient(HttpRequestResponse messageInfo, HttpExtendProperty extendProp) {
        Runnable sendTo;
        sendTo = new Runnable() {

            @Override
            public void run() {
                try {
                    burp.api.montoya.http.message.requests.HttpRequest httpRequest = messageInfo.request();
                    burp.api.montoya.http.message.responses.HttpResponse httpResponse = messageInfo.response();
                    HttpService httpService = httpRequest.httpService();

                    MultipartBody.Builder multipartBuilder = new MultipartBody.Builder()
                            .setType(MultipartBody.FORM) //multipart/form-data
                            .addFormDataPart("host", httpService.host())
                            .addFormDataPart("port", StringUtil.toString(httpService.port()))
                            .addFormDataPart("protocol", HttpTarget.getProtocol(httpService.secure()))
                            .addFormDataPart("url", httpRequest.url());
                    String notes = messageInfo.annotations().notes();
                    if (notes != null) {
                        multipartBuilder.addFormDataPart("comment", notes);
                    }
                    HighlightColor color = messageInfo.annotations().highlightColor();
                    if (color != null) {
                        multipartBuilder.addFormDataPart("highlight", color.name());
                    }
                    if (httpRequest != null) {
                        multipartBuilder.addFormDataPart("request", null, RequestBody.create(httpRequest.toByteArray().getBytes(), MediaType.parse("application/json")));
                    }
                    if (httpResponse != null) {
                        multipartBuilder.addFormDataPart("response", null, RequestBody.create(httpResponse.toByteArray().getBytes(), MediaType.parse("application/json")));
                    }
                    MultipartBody multipartBody = multipartBuilder.build();

                    // 拡張オプションを取得
                    //
                    // Authorization
                    HttpExtendProperty.AuthorizationType authorizationType = extendProp.getAuthorizationType();
                    String authorizationUser = extendProp.getAuthorizationUser();
                    String authorizationPasswd = extendProp.getAuthorizationPasswd();
                    okhttp3.Authenticator authenticator = null;
                    switch (authorizationType) {
                        case BASIC:
                            authenticator = new BasicAuthenticator(new com.burgstaller.okhttp.digest.Credentials(authorizationUser, authorizationPasswd));
                            break;
                        case DIGEST:
                            authenticator = new DigestAuthenticator(new com.burgstaller.okhttp.digest.Credentials(authorizationUser, authorizationPasswd));
                            break;
                    }

                    // Proxy
                    Proxy proxy = Proxy.NO_PROXY;
                    Proxy.Type proxyProtocol = extendProp.getProxyProtocol();
                    if (!Proxy.Type.DIRECT.equals(proxyProtocol)) {
                        String proxyHost = extendProp.getProxyHost();
                        if (Proxy.Type.HTTP.equals(proxyProtocol)) {
                            int proxyPort = extendProp.getProxyPort();
                            SocketAddress addr = new InetSocketAddress(proxyHost, proxyPort);
                            proxy = new Proxy(Proxy.Type.HTTP, addr);
                        } else if (Proxy.Type.SOCKS.equals(proxyProtocol)) {
                            int proxyPort = extendProp.getProxyPort();
                            SocketAddress addr = new InetSocketAddress(proxyHost, proxyPort);
                            proxy = new Proxy(Proxy.Type.SOCKS, addr);
                        }
                    }
                    String proxyUser = extendProp.getProxyUser();
                    String proxyPasswd = extendProp.getProxyPasswd();
                    Authenticator proxyAuthenticator = null;
                    if (!proxyUser.isEmpty()) {
                        proxyAuthenticator = new Authenticator() {
                            @Override
                            protected PasswordAuthentication getPasswordAuthentication() {
                                return new PasswordAuthentication(proxyUser, proxyPasswd.toCharArray());
                            }
                        };
                    }

                    KeyManager[] keyManagers = null;
                    X509TrustManager trustKeyManager = null;
                    // クライアント証明書
                    if (extendProp.isUseClientCertificate()) {
                        KeyStore keyStore = KeyStore.getInstance(extendProp.getClientCertificateStoreType().name());
                        keyStore.load(new ByteArrayInputStream(extendProp.getClientCertificate()), extendProp.getClientCertificatePasswd().toCharArray());
                        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                        trustManagerFactory.init(keyStore);
                        TrustManager[] trustKeyManagers = trustManagerFactory.getTrustManagers();
                        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("X509");
                        keyManagerFactory.init(keyStore, extendProp.getClientCertificatePasswd().toCharArray());
                        keyManagers = keyManagerFactory.getKeyManagers();
                        trustKeyManager = (X509TrustManager) trustKeyManagers[0];
                    }
                    else {
                        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
                        keyStore.load(null, null);
                        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                        trustManagerFactory.init(keyStore);
                        TrustManager[] trustKeyManagers = trustManagerFactory.getTrustManagers();
                        trustKeyManager = (X509TrustManager) trustKeyManagers[0];
                    }

                    TrustManager[] trustManagers = null;
                    if (extendProp.isIgnoreValidateCertification()) {
                        trustManagers = HttpUtil.trustAllCerts();
                    }
                    SSLContext sslContext = SSLContext.getInstance("TLS");
                    sslContext.init(keyManagers, trustManagers, null);

                    OkHttpClient.Builder clientBuilder = new OkHttpClient.Builder();
                    clientBuilder = clientBuilder.sslSocketFactory(sslContext.getSocketFactory(), trustKeyManager);

                    if (extendProp.isIgnoreValidateCertification()) {
                        clientBuilder = clientBuilder.hostnameVerifier((hostname, session) -> true);
                    }

                    // Authorization
                    if (authenticator != null) {
                        final Map<String, CachingAuthenticator> authCache = new ConcurrentHashMap<>();
                        clientBuilder = clientBuilder.authenticator(new CachingAuthenticatorDecorator(authenticator, authCache));
                        clientBuilder = clientBuilder.addInterceptor(new AuthenticationCacheInterceptor(authCache));
                    }

                    synchronized (Authenticator.class) {
                        Authenticator saveProxyAuth = Authenticator.getDefault();
                        try {
                            if (proxy != Proxy.NO_PROXY) {
                                clientBuilder = clientBuilder.proxy(proxy);
                                if (proxyAuthenticator != null) {
                                    saveProxyAuth = HttpUtil.putAuthenticator(proxyAuthenticator);
                                }
                            }

                            Request.Builder requestBuilder = new Request.Builder().url(getTarget()).post(multipartBody);
                            try (Response response = clientBuilder.build().newCall(requestBuilder.build()).execute()) {
                                int statusCode = response.code();
                                String bodyMessage = response.body().string();
                                if (statusCode == HttpURLConnection.HTTP_OK) {
                                    if (bodyMessage.length() == 0) {
                                        fireSendToCompleteEvent(new SendToEvent(this, "Success[" + statusCode + "]"));
                                    } else {
                                        fireSendToWarningEvent(new SendToEvent(this, "Warning[" + statusCode + "]:" + bodyMessage));
                                        logger.log(Level.WARNING, "[" + statusCode + "]", bodyMessage);
                                    }
                                } else {
                                    // 200以外
                                    fireSendToWarningEvent(new SendToEvent(this, "Error[" + statusCode + "]:" + bodyMessage));
                                    logger.log(Level.WARNING, "[" + statusCode + "]", bodyMessage);
                                }

                            } catch (IOException ex) {
                                fireSendToErrorEvent(new SendToEvent(this, "Error[" + ex.getClass().getName() + "]:" + ex.getMessage()));
                                logger.log(Level.SEVERE, ex.getMessage(), ex);
                            }
                        } finally {
                            if (proxyAuthenticator != null) {
                                HttpUtil.putAuthenticator(saveProxyAuth);
                            }
                        }
                    }

                } catch (NoSuchAlgorithmException | KeyStoreException | IOException | CertificateException | UnrecoverableKeyException | KeyManagementException ex) {
                    fireSendToErrorEvent(new SendToEvent(this, "Error[" + ex.getClass().getName() + "]:" + ex.getMessage()));
                    logger.log(Level.SEVERE, ex.getMessage(), ex);
                }
            }
        };
        this.threadExecutor.submit(sendTo);
    }

    protected void outPostHeader(OutputStream out, URL tagetURL) throws IOException, Exception {
        HttpTarget httpService = new HttpTarget(tagetURL);
        String target = tagetURL.getFile().isEmpty() ? "/" : tagetURL.getFile();
        out.write(StringUtil.getBytesRaw(String.format("POST %s HTTP/1.1", target) + HttpUtil.LINE_TERMINATE));
        out.write(StringUtil.getBytesRaw(String.format("Host: %s", HttpUtil.buildHost(httpService.getHost(), httpService.getPort(), httpService.secure())) + HttpUtil.LINE_TERMINATE));
        out.write(StringUtil.getBytesRaw(String.format("User-Agent: %s", "Java-http-client/BurpSuite") + HttpUtil.LINE_TERMINATE));
    }

    protected void outMultipart(String boundary, OutputStream out, HttpRequestResponse messageInfo) throws IOException, Exception {
        burp.api.montoya.http.message.requests.HttpRequest httpRequest = messageInfo.request();
        burp.api.montoya.http.message.responses.HttpResponse httpResponse = messageInfo.response();

        HttpService httpService = httpRequest.httpService();
        HttpUtil.outMultipartText(boundary, out, "host", httpService.host());
        HttpUtil.outMultipartText(boundary, out, "port", StringUtil.toString(httpService.port()));
        HttpUtil.outMultipartText(boundary, out, "protocol", HttpTarget.getProtocol(httpService.secure()));
        HttpUtil.outMultipartText(boundary, out, "url", httpRequest.url());
        String notes = messageInfo.annotations().notes();
        if (notes != null) {
            HttpUtil.outMultipartText(boundary, out, "comment", notes, StandardCharsets.UTF_8);
        }
        HighlightColor color = messageInfo.annotations().highlightColor();
        if (color != null) {
            HttpUtil.outMultipartText(boundary, out, "highlight", color.name());
        }
        if (messageInfo.request() != null && this.isRequest()) {
            HttpUtil.outMultipartBinary(boundary, out, "request", httpRequest.toByteArray().getBytes());
        }
        if (messageInfo.response() != null && this.isResponse()) {
            HttpUtil.outMultipartBinary(boundary, out, "response", httpResponse.toByteArray().getBytes());
        }
        HttpUtil.outMultipartFinish(boundary, out);
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        List<HttpRequestResponse> messageInfo = this.contextMenu.selectedRequestResponses();
        sendToEvent(messageInfo);
    }

    @Override
    public void menuItemClicked(String menuItemCaption, List<HttpRequestResponse> messageInfo) {
        sendToEvent(messageInfo);
    }

    @Override
    public boolean isEnabled() {
        boolean enabled = (this.contextMenu.invocationType() != InvocationType.INTRUDER_PAYLOAD_POSITIONS)
                || (this.contextMenu.invocationType() != InvocationType.SITE_MAP_TREE);
        return enabled;
    }

}
