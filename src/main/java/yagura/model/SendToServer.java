package yagura.model;

import extension.burp.IssueAlertEvent;
import burp.BurpExtension;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.InvocationType;
import com.burgstaller.okhttp.AuthenticationCacheInterceptor;
import com.burgstaller.okhttp.CachingAuthenticatorDecorator;
import com.burgstaller.okhttp.DispatchingAuthenticator;
import com.burgstaller.okhttp.basic.BasicAuthenticator;
import com.burgstaller.okhttp.digest.CachingAuthenticator;
import com.burgstaller.okhttp.digest.DigestAuthenticator;
import extension.burp.HttpTarget;
import extension.helpers.DateUtil;
import extension.helpers.HttpRequestWapper;
import extension.helpers.HttpResponseWapper;
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
import java.time.LocalDateTime;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import okhttp.socks.SocksProxyAuthInterceptor;
import okhttp3.MediaType;
import okhttp3.MultipartBody;
import okhttp3.OkHttpClient;
import okhttp3.Protocol;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import yagura.model.HttpExtendProperty.HttpProtocol;

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

    /*
     * https://alvinalexander.com/java/jwarehouse/openjdk-8/jdk/src/share/classes/sun/net/www/protocol/http/HttpURLConnection.java.shtml
     */
    private final ExecutorService threadExecutor = Executors.newSingleThreadExecutor();

    protected void sendToServer(HttpRequestResponse messageInfo) {
        // 拡張オプションを取得
        SendToExtendProperty extendProp = new SendToExtendProperty();
        extendProp.setProperties(getExtendProperties());
        if (HttpExtendProperty.HttpClientType.CUSTOM.equals(extendProp.getHttpExtendProperty().getHttpClientType())) {
            sendToServerUseOkHttpClient(messageInfo, extendProp);
        } else {
            sendToServerUseBurpClient(messageInfo, extendProp);
        }
    }

    protected void sendToServerUseBurpClient(HttpRequestResponse messageInfo, SendToExtendProperty extendProp) {
        final Runnable sendTo = new Runnable() {
            @Override
            public void run() {
                try (ByteArrayOutputStream ostm = new ByteArrayOutputStream()) {
                    URL tagetURL = new URL(getTarget());
                    outPostHeader(ostm, tagetURL, extendProp.getHttpExtendProperty().getHttpProtocol());
                    String boundary = HttpUtil.generateBoundary();
                    ostm.write(StringUtil.getBytesRaw(String.format("Content-Type: %s", "multipart/form-data;boundary=" + boundary) + StringUtil.NEW_LINE));
                    try (ByteArrayOutputStream bodyStream = new ByteArrayOutputStream()) {
                        outMultipart(boundary, bodyStream, messageInfo, extendProp);
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
                            fireIssueAlertInfoEvent(new IssueAlertEvent(this, "Success[" + statusCode + "]"));
                        } else {
                            fireIssueAlertErrorEvent(new IssueAlertEvent(this, "Information[" + statusCode + "]:" + resnponse.bodyToString()));
                            logger.log(Level.INFO, "[" + statusCode + "]", resnponse.body());
                        }
                    } else {
                        // 200以外
                        fireIssueAlertErrorEvent(new IssueAlertEvent(this, "Error[" + statusCode + "]:" + resnponse.bodyToString()));
                        logger.log(Level.WARNING, "[" + statusCode + "]", resnponse.body());
                    }
                } catch (IOException ex) {
                    fireIssueAlertCriticalEvent(new IssueAlertEvent(this, "Error[" + ex.getClass().getName() + "]:" + ex.getMessage()));
                    logger.log(Level.SEVERE, ex.getMessage(), ex);
                } catch (Exception ex) {
                    fireIssueAlertCriticalEvent(new IssueAlertEvent(this, "Error[" + ex.getClass().getName() + "]:" + ex.getMessage()));
                    logger.log(Level.SEVERE, ex.getMessage(), ex);
                }
            }
        };
        this.threadExecutor.submit(sendTo);
    }

    protected void sendToServerUseJDKClient(HttpRequestResponse messageInfo, SendToExtendProperty extendProp) {
        final HttpExtendProperty extendConnectionProp = extendProp.getHttpExtendProperty();
        final Runnable sendTo = new Runnable() {
            @Override
            public void run() {
                String boundary = HttpUtil.generateBoundary();
                HttpURLConnection conn = null;
                try {
                    DummyOutputStream dummy = new DummyOutputStream();
                    outMultipart(boundary, dummy, messageInfo, extendProp);
                    int contentLength = dummy.getSize();

                    URL url = new URL(getTarget()); // 送信先

                    // 拡張オプションを取得
                    // Authorization
                    HttpExtendProperty.AuthorizationType authorizationType = extendConnectionProp.getAuthorizationType();
                    Authenticator authenticator = null;
                    String authorizationUser = extendConnectionProp.getAuthorizationUser();
                    String authorizationPasswd = extendConnectionProp.getAuthorizationPasswd();
                    if (!HttpExtendProperty.AuthorizationType.NONE.equals(authorizationType)) {
                        authenticator = new Authenticator() {
                            @Override
                            protected PasswordAuthentication getPasswordAuthentication() {
                                return new PasswordAuthentication(authorizationUser, authorizationPasswd.toCharArray());
                            }
                        };
                    }

                    // Proxy
                    Proxy.Type proxyProtocol = extendConnectionProp.getProxyProtocol();
                    Proxy proxy = Proxy.NO_PROXY;
                    if (!Proxy.Type.DIRECT.equals(proxyProtocol)) {
                        String proxyHost = extendConnectionProp.getProxyHost();
                        if (Proxy.Type.HTTP.equals(proxyProtocol)) {
                            int proxyPort = extendConnectionProp.getProxyPort();
                            SocketAddress addr = new InetSocketAddress(proxyHost, proxyPort);
                            proxy = new Proxy(Proxy.Type.HTTP, addr);
                        } else if (Proxy.Type.SOCKS.equals(proxyProtocol)) {
                            int proxyPort = extendConnectionProp.getProxyPort();
                            SocketAddress addr = new InetSocketAddress(proxyHost, proxyPort);
                            proxy = new Proxy(Proxy.Type.SOCKS, addr);
                        }
                    }
                    String proxyUser = extendConnectionProp.getProxyUser();
                    String proxyPasswd = extendConnectionProp.getProxyPasswd();
                    Authenticator proxyAuthenticator = null;
                    if (!proxyUser.isEmpty()) {
                        proxyAuthenticator = new Authenticator() {
                            @Override
                            protected PasswordAuthentication getPasswordAuthentication() {
                                return new PasswordAuthentication(proxyUser, proxyPasswd.toCharArray());
                            }
                        };
                    }

                    if (extendConnectionProp.isIgnoreValidateCertification()) {
                        HttpUtil.ignoreSocketFactory();
                    }

                    conn = (HttpURLConnection) url.openConnection(proxy);
                    conn.setFixedLengthStreamingMode(contentLength);
                    conn.setRequestMethod("POST");
                    conn.setDoOutput(true);
                    if (!proxyUser.isEmpty() && Proxy.Type.HTTP.equals(proxyProtocol)) {
                        byte[] basicAuth = Base64.getEncoder().encode(StringUtil.getBytesRaw(String.format("%s:%s", new Object[]{authorizationUser, authorizationPasswd})));
                        conn.setRequestProperty("Authorization", "Basic " + StringUtil.getStringRaw(basicAuth));
                    }
                    conn.setRequestProperty("Content-Type", "multipart/form-data; boundary=" + boundary);
                    conn.connect();
                    try (OutputStream ostm = conn.getOutputStream()) {
                        outMultipart(boundary, ostm, messageInfo, extendProp);
                    } catch (IOException e) {
                        fireIssueAlertCriticalEvent(new IssueAlertEvent(this, e.getMessage()));
                    } catch (Exception e) {
                        fireIssueAlertCriticalEvent(new IssueAlertEvent(this, e.getMessage()));
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
                                fireIssueAlertInfoEvent(new IssueAlertEvent(this, "Success[" + statusCode + "]"));
                            } else {
                                fireIssueAlertErrorEvent(new IssueAlertEvent(this, "Warning[" + statusCode + "]:" + decodeMessage));
                            }
                        } else {
                            // 200以外
                            fireIssueAlertCriticalEvent(new IssueAlertEvent(this, "Error[" + statusCode + "]:" + decodeMessage));
                        }

                    } catch (IOException e) {
                        fireIssueAlertCriticalEvent(new IssueAlertEvent(this, "Error[" + e.getClass().getName() + "]:" + e.getMessage()));
                    } finally {
                        if (istm != null) {
                            istm.close();
                        }
                    }
                } catch (IOException ex) {
                    fireIssueAlertCriticalEvent(new IssueAlertEvent(this, "Error[" + ex.getClass().getName() + "]:" + ex.getMessage()));
                } catch (Exception ex) {
                    fireIssueAlertCriticalEvent(new IssueAlertEvent(this, "Error[" + ex.getClass().getName() + "]:" + ex.getMessage()));
                } finally {
                    if (conn != null) {
                        conn.disconnect();
                    }
                }
            }
        };
        this.threadExecutor.submit(sendTo);
    }

    protected void sendToServerUseHttpClient(HttpRequestResponse messageInfo, SendToExtendProperty extendProp) {
        final HttpExtendProperty extendConnectionProp = extendProp.getHttpExtendProperty();
        final Runnable sendTo = new Runnable() {
            @Override
            public void run() {
                try {
                    // 拡張オプションを取得
                    // Authorization
                    HttpExtendProperty.AuthorizationType authorizationType = extendConnectionProp.getAuthorizationType();
                    Authenticator authenticator = null;
                    if (!HttpExtendProperty.AuthorizationType.NONE.equals(authorizationType)) {
                        String authorizationUser = extendConnectionProp.getAuthorizationUser();
                        String authorizationPasswd = extendConnectionProp.getAuthorizationPasswd();
                        authenticator = new Authenticator() {
                            @Override
                            protected PasswordAuthentication getPasswordAuthentication() {
                                return new PasswordAuthentication(authorizationUser, authorizationPasswd.toCharArray());
                            }
                        };
                    }

                    // Proxy
                    Proxy.Type proxyProtocol = extendConnectionProp.getProxyProtocol();
                    Proxy proxy = Proxy.NO_PROXY;
                    if (!Proxy.Type.DIRECT.equals(proxyProtocol)) {
                        String proxyHost = extendConnectionProp.getProxyHost();
                        if (Proxy.Type.HTTP.equals(proxyProtocol)) {
                            int proxyPort = extendConnectionProp.getProxyPort();
                            SocketAddress addr = new InetSocketAddress(proxyHost, proxyPort);
                            proxy = new Proxy(Proxy.Type.HTTP, addr);
                        } else if (Proxy.Type.SOCKS.equals(proxyProtocol)) {
                            // https://bugs.openjdk.java.net/browse/JDK-8214516
                            int proxyPort = extendConnectionProp.getProxyPort();
                            SocketAddress addr = new InetSocketAddress(proxyHost, proxyPort);
                            proxy = new Proxy(Proxy.Type.SOCKS, addr);
                        }
                    }
                    Authenticator socksAuthenticator = null;
                    if (Proxy.Type.SOCKS.equals(proxyProtocol)) {
                        String proxyUser = extendConnectionProp.getProxyUser();
                        String proxyPasswd = extendConnectionProp.getProxyPasswd();
                        if (!proxyUser.isEmpty()) {
                            socksAuthenticator = new Authenticator() {
                                @Override
                                protected PasswordAuthentication getPasswordAuthentication() {
                                    return new PasswordAuthentication(proxyUser, proxyPasswd.toCharArray());
                                }
                            };
                        }
                    }
                    boolean ignoreValidateCertification = extendConnectionProp.isIgnoreValidateCertification();
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
                                fireIssueAlertCriticalEvent(new IssueAlertEvent(this, "Error[" + ex.getClass().getName() + "]:" + ex.getMessage()));
                                logger.log(Level.SEVERE, ex.getMessage(), ex);
                            }
                        };
                        builder = builder.proxy(staticProxy);
                    }
                    try (ByteArrayOutputStream ostm = new ByteArrayOutputStream()) {
                        String boundary = HttpUtil.generateBoundary();
                        outMultipart(boundary, ostm, messageInfo, extendProp);
                        synchronized (Authenticator.class) {
                            Authenticator saveProxyAuth = Authenticator.getDefault();
                            try {
                                if (Proxy.Type.SOCKS.equals(proxyProtocol)) {
                                    if (socksAuthenticator != null) {
                                        saveProxyAuth = HttpUtil.putAuthenticator(socksAuthenticator);
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
                                        fireIssueAlertInfoEvent(new IssueAlertEvent(this, "Success[" + statusCode + "]"));
                                    } else {
                                        fireIssueAlertErrorEvent(new IssueAlertEvent(this, "Warning[" + statusCode + "]:" + bodyMessage));
                                        logger.log(Level.WARNING, "[" + statusCode + "]", bodyMessage);
                                    }
                                } else {
                                    // 200以外
                                    fireIssueAlertErrorEvent(new IssueAlertEvent(this, "Error[" + statusCode + "]:" + bodyMessage));
                                    logger.log(Level.WARNING, "[" + statusCode + "]", bodyMessage);
                                }
                            } finally {
                                if (socksAuthenticator != null) {
                                    HttpUtil.putAuthenticator(saveProxyAuth);
                                }
                            }
                        }
                    }
                } catch (IOException ex) {
                    fireIssueAlertCriticalEvent(new IssueAlertEvent(this, "Error[" + ex.getClass().getName() + "]:" + ex.getMessage()));
                    logger.log(Level.SEVERE, ex.getMessage(), ex);
                } catch (Exception ex) {
                    fireIssueAlertCriticalEvent(new IssueAlertEvent(this, "Error[" + ex.getClass().getName() + "]:" + ex.getMessage()));
                    logger.log(Level.SEVERE, ex.getMessage(), ex);
                }
            }
        };
        this.threadExecutor.submit(sendTo);
    }

    protected String newDummyRespose() {
        final String DUMMY_RESPOSE = "HTTP/1.1 202 Accepted" + HttpUtil.LINE_TERMINATE
                + "Date: " + DateUtil.valueOfHttpDate(ZonedDateTime.of(LocalDateTime.now(), DateUtil.ZONE_OFFSET_GMT)) + HttpUtil.LINE_TERMINATE
                + "Server: Yagura-Dummy-Response" + HttpUtil.LINE_TERMINATE
                + "Content-Length: 0" + HttpUtil.LINE_TERMINATE + HttpUtil.LINE_TERMINATE;
        return DUMMY_RESPOSE;
    }

    protected void sendToServerUseOkHttpClient(HttpRequestResponse messageInfo, SendToExtendProperty extendProp) {
        SendToParameterProperty extendSendToParameterProp = extendProp.getSendToParameterProperty();
        final HttpExtendProperty extendConnectionProp = extendProp.getHttpExtendProperty();
        final Runnable sendTo = new Runnable() {

            @Override
            public void run() {
                try {
                    burp.api.montoya.http.message.requests.HttpRequest httpRequest = messageInfo.request();
                    burp.api.montoya.http.message.responses.HttpResponse httpResponse = messageInfo.response();
                    HttpService httpService = messageInfo.httpService();

                    MultipartBody.Builder multipartBuilder = new MultipartBody.Builder()
                            .setType(MultipartBody.FORM) //multipart/form-data
                            .addFormDataPart("host", httpService.host())
                            .addFormDataPart("port", StringUtil.toString(httpService.port()))
                            .addFormDataPart("protocol", HttpTarget.getProtocol(httpService.secure()))
                            .addFormDataPart("url", httpRequest.url());

                    if (extendSendToParameterProp.isUseOverride()) {
                        if (extendSendToParameterProp.isUseReqName()) {
                            SendToParameterProperty.LinePartType lineType = extendSendToParameterProp.getReqNameLineType();
                            String value = SendToParameterProperty.getParameter(extendSendToParameterProp.getReqName(), messageInfo);
                            if (value != null) {
                                multipartBuilder.addFormDataPart("reqName", SendToParameterProperty.extractLinePart(lineType, value));
                            }
                        }
                        if (extendSendToParameterProp.isUseReqComment()) {
                            SendToParameterProperty.LinePartType lineType = extendSendToParameterProp.getReqCommentLineType();
                            String value = SendToParameterProperty.getParameter(extendSendToParameterProp.getReqComment(), messageInfo);
                            if (value != null) {
                                multipartBuilder.addFormDataPart("reqComment", SendToParameterProperty.extractLinePart(lineType, value));
                            }
                        }
                        if (extendSendToParameterProp.isUseReqNum()) {
                            String value = SendToParameterProperty.getParameter(extendSendToParameterProp.getReqName(), messageInfo);
                            if (value != null) {
                                multipartBuilder.addFormDataPart("reqNum", value);
                            }
                        }
                    } else {
                        String notes = messageInfo.annotations().notes();
                        if (notes != null) {
                            multipartBuilder.addFormDataPart("comment", notes);
                        }
                    }

                    HighlightColor color = messageInfo.annotations().highlightColor();
                    if (color != null) {
                        multipartBuilder.addFormDataPart("highlight", color.name());
                    }
                    if (httpRequest != null) {
                        HttpRequestWapper wrapRequest = new HttpRequestWapper(httpRequest);
                        multipartBuilder.addFormDataPart("request", "request", RequestBody.create(wrapRequest.getMessageByte(), MediaType.parse("application/json")));
                    }
                    if (httpResponse != null) {
                        HttpResponseWapper wrapResponse = new HttpResponseWapper(httpResponse);
                        multipartBuilder.addFormDataPart("response", "response", RequestBody.create(wrapResponse.getMessageByte(), MediaType.parse("application/json")));
                        String guessCharset = wrapResponse.getGuessCharset();
                        if (guessCharset != null) {
                            multipartBuilder.addFormDataPart("encoding", guessCharset);
                        }
                    } else {
                        if (extendSendToParameterProp.isUseOverride() && extendSendToParameterProp.isUseDummyResponse()) {
                            burp.api.montoya.http.message.responses.HttpResponse dummyResponse = burp.api.montoya.http.message.responses.HttpResponse.httpResponse(newDummyRespose());
                            multipartBuilder.addFormDataPart("response", "response", RequestBody.create(dummyResponse.toByteArray().getBytes(), MediaType.parse("application/json")));
                        }
                    }

                    MultipartBody multipartBody = multipartBuilder.build();

                    // 拡張オプションを取得
                    //
                    // Authorization
                    HttpExtendProperty.AuthorizationType authorizationType = extendConnectionProp.getAuthorizationType();
                    String authorizationUser = extendConnectionProp.getAuthorizationUser();
                    String authorizationPasswd = extendConnectionProp.getAuthorizationPasswd();
                    okhttp3.Authenticator authenticator = null;
                    switch (authorizationType) {
                        case BASIC: {
                            authenticator = new BasicAuthenticator(new com.burgstaller.okhttp.digest.Credentials(authorizationUser, authorizationPasswd));
                            break;
                        }
                        case DIGEST: {
                            authenticator = new DigestAuthenticator(new com.burgstaller.okhttp.digest.Credentials(authorizationUser, authorizationPasswd));
                            break;
                        }
                    }

                    // Proxy
                    Proxy proxy = Proxy.NO_PROXY;
                    Proxy.Type proxyProtocol = extendConnectionProp.getProxyProtocol();
                    if (!Proxy.Type.DIRECT.equals(proxyProtocol)) {
                        String proxyHost = extendConnectionProp.getProxyHost();
                        if (Proxy.Type.HTTP.equals(proxyProtocol)) {
                            int proxyPort = extendConnectionProp.getProxyPort();
                            SocketAddress addr = new InetSocketAddress(proxyHost, proxyPort);
                            proxy = new Proxy(Proxy.Type.HTTP, addr);
                        } else if (Proxy.Type.SOCKS.equals(proxyProtocol)) {
                            int proxyPort = extendConnectionProp.getProxyPort();
                            SocketAddress addr = new InetSocketAddress(proxyHost, proxyPort);
                            proxy = new Proxy(Proxy.Type.SOCKS, addr);
                        }
                    }
                    DispatchingAuthenticator proxyAuthenticator = null;
                    PasswordAuthentication socksAuthentication = null;
                    String proxyUser = extendConnectionProp.getProxyUser();
                    String proxyPasswd = extendConnectionProp.getProxyPasswd();
                    if (Proxy.Type.HTTP.equals(proxyProtocol)) {
                        if (!proxyUser.isEmpty()) {
                            com.burgstaller.okhttp.digest.Credentials credentials = new com.burgstaller.okhttp.digest.Credentials(proxyUser, proxyPasswd);
                            final BasicAuthenticator basicProxyAuthenticator = new BasicAuthenticator(credentials);
                            final DigestAuthenticator digestProxyAuthenticator = new DigestAuthenticator(credentials);
                            digestProxyAuthenticator.setProxy(true);
                            proxyAuthenticator = new DispatchingAuthenticator.Builder()
                                    .with("digest", digestProxyAuthenticator)
                                    .with("basic", basicProxyAuthenticator)
                                    .build();
                        }
                    } else if (Proxy.Type.SOCKS.equals(proxyProtocol)) {
                        if (!proxyUser.isEmpty()) {
                            socksAuthentication = new PasswordAuthentication(proxyUser, proxyPasswd.toCharArray());
                        }
                    }

                    KeyManager[] keyManagers = null;
                    X509TrustManager trustKeyManager = null;
                    // クライアント証明書
                    if (extendConnectionProp.isUseClientCertificate()) {
                        KeyStore keyStore = KeyStore.getInstance(extendConnectionProp.getClientCertificateStoreType().name());
                        keyStore.load(new ByteArrayInputStream(extendConnectionProp.getClientCertificate()), extendConnectionProp.getClientCertificatePasswd().toCharArray());
                        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                        trustManagerFactory.init(keyStore);
                        TrustManager[] trustKeyManagers = trustManagerFactory.getTrustManagers();
                        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("X509");
                        keyManagerFactory.init(keyStore, extendConnectionProp.getClientCertificatePasswd().toCharArray());
                        keyManagers = keyManagerFactory.getKeyManagers();
                        trustKeyManager = (X509TrustManager) trustKeyManagers[0];
                    } else {
                        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
                        keyStore.load(null, null);
                        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                        trustManagerFactory.init(keyStore);
                        TrustManager[] trustKeyManagers = trustManagerFactory.getTrustManagers();
                        trustKeyManager = (X509TrustManager) trustKeyManagers[0];
                    }

                    TrustManager[] trustManagers = null;
                    if (extendConnectionProp.isIgnoreValidateCertification()) {
                        trustManagers = HttpUtil.trustAllCerts();
                    }
                    SSLContext sslContext = SSLContext.getInstance("TLS");
                    sslContext.init(keyManagers, trustManagers, null);

                    OkHttpClient.Builder clientBuilder = new OkHttpClient.Builder();
                    // protocol
                    if (extendConnectionProp.getHttpProtocol().equals(HttpProtocol.HTTP_1_1)) {
                        clientBuilder = clientBuilder.protocols(Arrays.asList(Protocol.HTTP_1_1));
                    } else if (extendConnectionProp.getHttpProtocol().equals(HttpProtocol.HTTP_2)) {
                        clientBuilder = clientBuilder.protocols(Arrays.asList(Protocol.HTTP_2));
                    }
                    // timeout
                    int timeout = extendConnectionProp.getTimeout();
                    clientBuilder = clientBuilder.connectTimeout(timeout, TimeUnit.SECONDS).readTimeout(timeout, TimeUnit.SECONDS).writeTimeout(timeout, TimeUnit.SECONDS);

                    clientBuilder = clientBuilder.sslSocketFactory(sslContext.getSocketFactory(), trustKeyManager);

                    // IgnoreValidateCertification
                    if (extendConnectionProp.isIgnoreValidateCertification()) {
                        clientBuilder = clientBuilder.hostnameVerifier((hostname, session) -> true);
                    }

                    // Authorization
                    if (authenticator != null) {
                        final Map<String, CachingAuthenticator> authCache = new ConcurrentHashMap<>();
                        clientBuilder = clientBuilder.authenticator(new CachingAuthenticatorDecorator(authenticator, authCache));
                        clientBuilder = clientBuilder.addInterceptor(new AuthenticationCacheInterceptor(authCache));
                    }

                    if (proxy != Proxy.NO_PROXY) {
                        clientBuilder = clientBuilder.proxy(proxy);
                        if (proxyAuthenticator != null) {
                            clientBuilder = clientBuilder.proxyAuthenticator(proxyAuthenticator);
                        }

                        if (socksAuthentication != null) {
                            clientBuilder = clientBuilder.addInterceptor(new SocksProxyAuthInterceptor(socksAuthentication));
                        }
                    }

                    Request.Builder requestBuilder = new Request.Builder().url(getTarget()).post(multipartBody);
                    Response response = clientBuilder.build().newCall(requestBuilder.build()).execute();
                    int statusCode = response.code();
                    String bodyMessage = response.body().string();
                    if (statusCode == HttpURLConnection.HTTP_OK) {
                        if (bodyMessage.length() == 0) {
                            fireIssueAlertInfoEvent(new IssueAlertEvent(this, "Success[" + statusCode + "]"));
                        } else {
                            fireIssueAlertErrorEvent(new IssueAlertEvent(this, "Information[" + statusCode + "]:" + bodyMessage));
                            logger.log(Level.INFO, "[" + statusCode + "]", bodyMessage);
                        }
                    } else {
                        // 200以外
                        fireIssueAlertErrorEvent(new IssueAlertEvent(this, "Error[" + statusCode + "]:" + bodyMessage));
                        logger.log(Level.WARNING, "[" + statusCode + "]", bodyMessage);
                    }
                } catch (IOException | NoSuchAlgorithmException | KeyStoreException | CertificateException | UnrecoverableKeyException | KeyManagementException ex) {
                    fireIssueAlertCriticalEvent(new IssueAlertEvent(this, "Error[" + ex.getClass().getName() + "]:" + ex.getMessage()));
                    logger.log(Level.SEVERE, ex.getMessage(), ex);
                } catch (Exception ex) {
                    fireIssueAlertCriticalEvent(new IssueAlertEvent(this, "Error[" + ex.getClass().getName() + "]:" + ex.getMessage()));
                    logger.log(Level.SEVERE, ex.getMessage(), ex);
                }
            }
        };
        this.threadExecutor.submit(sendTo);
    }

    protected void outPostHeader(OutputStream out, URL tagetURL, HttpExtendProperty.HttpProtocol httpProtocol) throws IOException, Exception {
        HttpTarget httpService = new HttpTarget(tagetURL);
        String target = tagetURL.getFile().isEmpty() ? "/" : tagetURL.getFile();
        // protocol
        String httpMode = "HTTP/1.1";
        if (httpProtocol.equals(HttpProtocol.HTTP_1_1)) {
            httpMode = "HTTP/1.1";
        } else if (httpProtocol.equals(HttpProtocol.HTTP_2)) {
            httpMode = "HTTP/2";
        }
        out.write(StringUtil.getBytesRaw(String.format("POST %s %s", target, httpMode) + HttpUtil.LINE_TERMINATE));
        out.write(StringUtil.getBytesRaw(String.format("Host: %s", HttpUtil.buildHost(httpService.getHost(), httpService.getPort(), httpService.secure())) + HttpUtil.LINE_TERMINATE));
        out.write(StringUtil.getBytesRaw(String.format("User-Agent: %s", "Java-http-client/BurpSuite") + HttpUtil.LINE_TERMINATE));
    }

    protected void outMultipart(String boundary, OutputStream out, HttpRequestResponse messageInfo, SendToExtendProperty extendProp) throws IOException, Exception {
        burp.api.montoya.http.message.requests.HttpRequest httpRequest = messageInfo.request();
        HttpService httpService = httpRequest.httpService();
        HttpUtil.outMultipartText(boundary, out, "host", httpService.host());
        HttpUtil.outMultipartText(boundary, out, "port", StringUtil.toString(httpService.port()));
        HttpUtil.outMultipartText(boundary, out, "protocol", HttpTarget.getProtocol(httpService.secure()));
        HttpUtil.outMultipartText(boundary, out, "url", httpRequest.url());

        SendToParameterProperty extendSendToParameterProp = extendProp.getSendToParameterProperty();
        if (extendSendToParameterProp.isUseOverride()) {
            if (extendSendToParameterProp.isUseReqName()) {
                SendToParameterProperty.LinePartType lineType = extendSendToParameterProp.getReqNameLineType();
                String value = SendToParameterProperty.getParameter(extendSendToParameterProp.getReqName(), messageInfo);
                if (value != null) {
                    HttpUtil.outMultipartText(boundary, out, "reqName", SendToParameterProperty.extractLinePart(lineType, value), StandardCharsets.UTF_8);
                }
            }
            if (extendSendToParameterProp.isUseReqComment()) {
                SendToParameterProperty.LinePartType lineType = extendSendToParameterProp.getReqCommentLineType();
                if (extendSendToParameterProp.getReqName() == SendToParameterProperty.SendToParameterType.HISTORY_COMMENT) {
                    String value = SendToParameterProperty.getParameter(extendSendToParameterProp.getReqComment(), messageInfo);
                    if (value != null) {
                        HttpUtil.outMultipartText(boundary, out, "reqComment", SendToParameterProperty.extractLinePart(lineType, value), StandardCharsets.UTF_8);
                    }
                }
            }
            if (extendSendToParameterProp.isUseReqNum()) {
                if (extendSendToParameterProp.getReqName() == SendToParameterProperty.SendToParameterType.HISTORY_NUMBER) {
                    String value = SendToParameterProperty.getParameter(extendSendToParameterProp.getReqName(), messageInfo);
                    if (value != null) {
                        HttpUtil.outMultipartText(boundary, out, "reqNum", value, StandardCharsets.UTF_8);
                    }
                }
            }
        } else {
            String notes = messageInfo.annotations().notes();
            if (notes != null) {
                HttpUtil.outMultipartText(boundary, out, "comment", notes, StandardCharsets.UTF_8);
            }
        }

        HighlightColor color = messageInfo.annotations().highlightColor();
        if (color != null) {
            HttpUtil.outMultipartText(boundary, out, "highlight", color.name());
        }

        if (messageInfo.request() != null && this.isRequest()) {
            HttpRequestWapper wrapRequest = new HttpRequestWapper(messageInfo.request());
            HttpUtil.outMultipartBinary(boundary, out, "request", wrapRequest.getMessageByte());
        }
        if (this.isResponse()) {
            if (messageInfo.response() != null) {
                HttpResponseWapper wrapResponse = new HttpResponseWapper(messageInfo.response());
                HttpUtil.outMultipartBinary(boundary, out, "response", wrapResponse.getMessageByte());
                String guessCharset = wrapResponse.getGuessCharset();
                if (guessCharset != null) {
                    HttpUtil.outMultipartText(boundary, out, "encoding", guessCharset);
                }
            } else {
                if (extendSendToParameterProp.isUseOverride() && extendSendToParameterProp.isUseDummyResponse()) {
                    burp.api.montoya.http.message.responses.HttpResponse dummyResponse = burp.api.montoya.http.message.responses.HttpResponse.httpResponse(newDummyRespose());
                    HttpUtil.outMultipartBinary(boundary, out, "response", dummyResponse.toByteArray().getBytes());
                }
            }
        }
        HttpUtil.outMultipartFinish(boundary, out);
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        if (contextMenu.messageEditorRequestResponse().isPresent()) {
            List<HttpRequestResponse> messageInfo = List.of(contextMenu.messageEditorRequestResponse().get().requestResponse());
            sendToEvent(messageInfo);
        } else {
            List<HttpRequestResponse> messageInfo = this.contextMenu.selectedRequestResponses();
            sendToEvent(messageInfo);
        }
    }

    public void sendToEvent(SendToMessage sendToMessage) {
        List<HttpRequestResponse> messageInfo = sendToMessage.getSelectedMessages();
        sendToEvent(messageInfo);
    }

    public void sendToEvent(List<HttpRequestResponse> messageInfo) {
        menuItemClicked(getCaption(), SendToMessage.newSendToMessage(messageInfo, this.isEnabled()));
    }

    @Override
    public void menuItemClicked(String menuItemCaption, SendToMessage sendToMessage) {
        List<HttpRequestResponse> messageInfo = sendToMessage.getSelectedMessages();
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

    @Override
    public boolean isEnabled() {
        return (this.contextMenu.invocationType() == InvocationType.PROXY_HISTORY)
                || (this.contextMenu.invocationType() == InvocationType.SEARCH_RESULTS)
                || (this.contextMenu.invocationType() == InvocationType.MESSAGE_VIEWER_REQUEST)
                || (this.contextMenu.invocationType() == InvocationType.MESSAGE_VIEWER_RESPONSE)
                || (this.contextMenu.invocationType() == InvocationType.MESSAGE_EDITOR_REQUEST)
                || (this.contextMenu.invocationType() == InvocationType.MESSAGE_EDITOR_RESPONSE)
                || (this.contextMenu.invocationType() == null); // Orgnaizerではnull
    }

}
