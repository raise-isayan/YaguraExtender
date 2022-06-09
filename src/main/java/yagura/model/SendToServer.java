package yagura.model;

import burp.BurpExtender;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import extension.burp.HttpService;
import extension.helpers.ConvertUtil;
import extension.helpers.HttpUtil;
import extension.helpers.HttpUtil.DummyOutputStream;
import extension.helpers.StringUtil;
import java.lang.UnsupportedOperationException;
import java.awt.event.ActionEvent;
import java.io.BufferedInputStream;
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
import java.time.Duration;
import java.util.Base64;
import java.util.Properties;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author isayan
 */
public class SendToServer extends SendToMenuItem {
    private final static Logger logger = Logger.getLogger(SendToServer.class.getName());

    public SendToServer(SendToItem item, IContextMenuInvocation contextMenu) {
        super(item, contextMenu);
    }

    @Override
    public void menuItemClicked(String menuItemCaption, IHttpRequestResponse[] messageInfo) {
        sendToEvent(messageInfo);
    }

    public void sendToEvent(IHttpRequestResponse[] messageInfo) {
        if (this.isReverseOrder()) {
            for (int i = messageInfo.length - 1; i >= 0; i--) {
                sendToServer(messageInfo[i]);
            }
        } else {
            for (int i = 0; i < messageInfo.length; i++) {
                sendToServer(messageInfo[i]);
            }
        }
    }

    /*
     * https://alvinalexander.com/java/jwarehouse/openjdk-8/jdk/src/share/classes/sun/net/www/protocol/http/HttpURLConnection.java.shtml
     */
    private final ExecutorService threadExecutor = Executors.newSingleThreadExecutor();

    protected void sendToServer(IHttpRequestResponse messageInfo) {
        // 拡張オプションを取得
        Properties prop = getExtendProperty();
        String useProxy = prop.getProperty("useProxy", SendToExtend.USE_CUSTOM_PROXY);
        if (SendToExtend.USE_CUSTOM_PROXY.equals(useProxy)) {
            sendToServerUseHttpClient(messageInfo);
        } else {
            sendToServerUseBurpClient(messageInfo);
        }
    }

    protected void sendToServerUseBurpClient(IHttpRequestResponse messageInfo) {
        Runnable sendTo = new Runnable() {
            @Override
            public void run() {
                try {
                    try ( ByteArrayOutputStream ostm = new ByteArrayOutputStream()) {
                        URL tagetURL = new URL(getTarget());
                        outPostHeader(ostm, tagetURL);
                        String boundary = HttpUtil.generateBoundary();
                        ostm.write(StringUtil.getBytesRaw(String.format("Content-Type: %s", "multipart/form-data;boundary=" + boundary) + StringUtil.NEW_LINE));
                        try ( ByteArrayOutputStream bodyStream = new ByteArrayOutputStream()) {
                            outMultipart(boundary, bodyStream, messageInfo);
                            ostm.write(StringUtil.getBytesRaw(String.format("Content-Length: %d", bodyStream.size()) + StringUtil.NEW_LINE));
                            ostm.write(StringUtil.getBytesRaw("Connection: close" + StringUtil.NEW_LINE));
                            ostm.write(StringUtil.getBytesRaw(StringUtil.NEW_LINE));
                            ostm.write(bodyStream.toByteArray());
                        }
                        HttpService httpService = new HttpService(tagetURL);
                        IHttpRequestResponse httpRequestResponse = BurpExtender.getCallbacks().makeHttpRequest(httpService, ostm.toByteArray());
                        extension.helpers.HttpResponse response = extension.helpers.HttpResponse.parseHttpResponse(httpRequestResponse.getResponse());
                        int statusCode = response.getStatusCode();
                        if (statusCode == HttpURLConnection.HTTP_OK) {
                            if (response.getBody().length() == 0) {
                                fireSendToCompleteEvent(new SendToEvent(this, "Success[" + statusCode + "]"));
                            } else {
                                fireSendToWarningEvent(new SendToEvent(this, "Warning[" + statusCode + "]:" + response.getBody()));
                                logger.log(Level.WARNING, "[" + statusCode + "]", response.getBody());
                            }
                        } else {
                            // 200以外
                            fireSendToWarningEvent(new SendToEvent(this, "Error[" + statusCode + "]:" + response.getBody()));
                            logger.log(Level.WARNING, "[" + statusCode + "]", response.getBody());
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

    protected void sendToServerUseJDKClient(IHttpRequestResponse messageInfo) {
        throw new UnsupportedOperationException();
//        Runnable sendTo = new Runnable() {
//            @Override
//            public void run() {
//                String boundary = HttpUtil.generateBoundary();
//                HttpURLConnection conn = null;
//                try {
//                    DummyOutputStream dummy = new DummyOutputStream();
//                    outMultipart(boundary, dummy, messageInfo);
//                    int contentLength = dummy.getSize();
//                    
//                    URL url = new URL(getTarget()); // 送信先
//                    // 拡張オプションを取得
//                    Properties prop = getExtendProperty();
//                    String proxyProtocol =  prop.getProperty("proxyProtocol", Proxy.Type.DIRECT.name());
//                    Proxy proxy = Proxy.NO_PROXY;
//                    if (!Proxy.Type.DIRECT.name().equals(proxyProtocol)) {
//                        String proxyHost =  prop.getProperty("proxyHost", "");
//                        if (Proxy.Type.HTTP.name().equals(proxyProtocol)) {
//                            int proxyPort = ConvertUtil.parseIntDefault(prop.getProperty("proxyPort", "8080"), 8080);
//                            SocketAddress addr = new InetSocketAddress(proxyHost, proxyPort);
//                            proxy = new Proxy(Proxy.Type.HTTP, addr);                                                                
//                        }
//                        else if (Proxy.Type.SOCKS.name().equals(proxyProtocol)) {
//                            int proxyPort = ConvertUtil.parseIntDefault(prop.getProperty("proxyPort", "1080"), 1080);
//                            SocketAddress addr = new InetSocketAddress(proxyHost, proxyPort);
//                            proxy = new Proxy(Proxy.Type.SOCKS, addr);                                                                                        
//                        }
//                    } 
//                    String proxyUser = prop.getProperty("proxyUser", "");
//                    String proxyPasswd = prop.getProperty("proxyPasswd", "");                    
//                    Authenticator authenticator = new Authenticator() {
//                        @Override
//                        protected PasswordAuthentication getPasswordAuthentication() {
//                            return new PasswordAuthentication(proxyUser, proxyPasswd.toCharArray());
//                        }               
//                    };
////                    if (!proxyUser.isEmpty()) {
//                        Authenticator.setDefault(authenticator);
////                    }
////                    else {
////                        Authenticator.setDefault(null);                    
////                    }
//
////                    boolean ignoreValidateCertification = ConvertUtil.parseBooleanDefault(prop.getProperty("ignoreValidateCertification", Boolean.TRUE.toString()), false);
////                    if (ignoreValidateCertification) {
//                        HttpUtil.ignoreSocketFactory();
////                    }
//
//                    conn = (HttpURLConnection) url.openConnection(proxy);
//                    conn.setFixedLengthStreamingMode(contentLength);
//                    conn.setRequestMethod("POST");
//                    conn.setDoOutput(true);
//                    if (!proxyUser.isEmpty() && Proxy.Type.HTTP.name().equals(proxyProtocol)) {
//                        byte [] basicAuth = Base64.getEncoder().encode(StringUtil.getBytesRaw(String.format("%s:%s", new Object [] {proxyUser, proxyPasswd})));
//                        conn.setRequestProperty("Authorization", "Basic " + StringUtil.getStringRaw(basicAuth));
//                    }
//                    conn.setRequestProperty("Content-Type", "multipart/form-data; boundary=" + boundary);
//                    conn.connect();
//                    OutputStream ostm = null;
//                    try {
//                        ostm = conn.getOutputStream();
//                        outMultipart(boundary, ostm, messageInfo);
//                    } catch (IOException e) {
//                        fireSendToErrorEvent(new SendToEvent(this, e.getMessage()));
//                    } catch (Exception e) {
//                        fireSendToErrorEvent(new SendToEvent(this, e.getMessage()));
//                    } finally {
//                        if (ostm != null) {
//                            ostm.close();
//                        }
//                    }
//
//                    InputStream istm = conn.getInputStream();
//                    ByteArrayOutputStream bostm = new ByteArrayOutputStream();
//                    try {
//                        BufferedInputStream bistm = new BufferedInputStream(istm);
//                        String decodeMessage;
//                        byte buf[] = new byte[4096];
//                        int len;
//                        while ((len = bistm.read(buf)) != -1) {
//                            bostm.write(buf, 0, len);
//                        }
//                        int statusCode = conn.getResponseCode();
//                        decodeMessage = StringUtil.getBytesRawString(bostm.toByteArray());
//                        if (statusCode == HttpURLConnection.HTTP_OK) {
//                            if (decodeMessage.length() == 0) {
//                                fireSendToCompleteEvent(new SendToEvent(this, "Success[" + statusCode + "]"));
//                            } else {
//                                fireSendToWarningEvent(new SendToEvent(this, "Warning[" + statusCode + "]:" + decodeMessage));
//                            }
//                        } else {
//                            // 200以外
//                            fireSendToErrorEvent(new SendToEvent(this, "Error[" + statusCode + "]:" + decodeMessage));
//                        }
//
//                    } catch (IOException e) {
//                        fireSendToErrorEvent(new SendToEvent(this, "Error[" + e.getClass().getName() + "]:" + e.getMessage()));
//                    } finally {
//                        if (istm != null) {
//                            istm.close();
//                        }
//                        if (bostm != null) {
//                            bostm.close();
//                        }
//                    }
//                } catch (IOException ex) {
//                    fireSendToErrorEvent(new SendToEvent(this, "Error[" + ex.getClass().getName() + "]:" + ex.getMessage()));
//                } catch (Exception ex) {
//                    fireSendToErrorEvent(new SendToEvent(this, "Error[" + ex.getClass().getName() + "]:" + ex.getMessage()));
//                } finally {
//                    if (conn != null) {
//                        conn.disconnect();
//                    }
//                }
//            }
//
//        };
//        this.threadExecutor.submit(sendTo);
    }
    
    protected void sendToServerUseHttpClient(IHttpRequestResponse messageInfo) {
        Runnable sendTo = new Runnable() {
            @Override
            public void run() {
                HttpURLConnection conn = null;
                try {
                    // 拡張オプションを取得
                    Properties prop = getExtendProperty();
                    String proxyProtocol = prop.getProperty("proxyProtocol", Proxy.Type.DIRECT.name());
                    Proxy proxy = Proxy.NO_PROXY;
                    if (!Proxy.Type.DIRECT.name().equals(proxyProtocol)) {
                        String proxyHost = prop.getProperty("proxyHost", "");
                        if (Proxy.Type.HTTP.name().equals(proxyProtocol)) {
                            int proxyPort = ConvertUtil.parseIntDefault(prop.getProperty("proxyPort", "8080"), 8080);
                            SocketAddress addr = new InetSocketAddress(proxyHost, proxyPort);
                            proxy = new Proxy(Proxy.Type.HTTP, addr);
                        } else if (Proxy.Type.SOCKS.name().equals(proxyProtocol)) {
                            // https://bugs.openjdk.java.net/browse/JDK-8214516
                            int proxyPort = ConvertUtil.parseIntDefault(prop.getProperty("proxyPort", "1080"), 1080);
                            SocketAddress addr = new InetSocketAddress(proxyHost, proxyPort);
                            proxy = new Proxy(Proxy.Type.SOCKS, addr);
                        }
                    }
                    Authenticator authenticator = null;
                    if (!Proxy.Type.DIRECT.name().equals(proxyProtocol)) {
                        String proxyUser = prop.getProperty("proxyUser", "");
                        String proxyPasswd = prop.getProperty("proxyPasswd", "");
                        authenticator = new Authenticator() {
                            @Override
                            protected PasswordAuthentication getPasswordAuthentication() {
                                return new PasswordAuthentication(proxyUser, proxyPasswd.toCharArray());
                            }
                        };
                    }
                    boolean ignoreValidateCertification = ConvertUtil.parseBooleanDefault(prop.getProperty("ignoreValidateCertification", Boolean.TRUE.toString()), false);
                    HttpClient.Builder builder = HttpClient.newBuilder()
                            .version(Version.HTTP_1_1)
                            .followRedirects(Redirect.NORMAL)
                            .connectTimeout(Duration.ofSeconds(10));

                    if (ignoreValidateCertification) {
                        builder = builder.sslContext(HttpUtil.ignoreSSLContext());
                    }

                    final Properties props = System.getProperties(); 
                    props.setProperty("jdk.internal.httpclient.disableHostnameVerification", Boolean.valueOf(ignoreValidateCertification).toString());
                    
                    if (!Proxy.Type.DIRECT.name().equals(proxyProtocol)) {
                        ProxySelector staticProxy = new HttpUtil.StaticProxySelector(proxy) {
                            @Override
                            public void connectFailed(URI uri, SocketAddress sa, IOException ex) {
                                fireSendToErrorEvent(new SendToEvent(this, "Error[" + ex.getClass().getName() + "]:" + ex.getMessage()));
                                logger.log(Level.SEVERE, ex.getMessage(), ex);
                            }
                        };
                        builder = builder.proxy(staticProxy);
                    }
                    if (authenticator != null) {
                        builder = builder.authenticator(authenticator);
                    }
                    try ( ByteArrayOutputStream ostm = new ByteArrayOutputStream()) {
                        String boundary = HttpUtil.generateBoundary();
                        outMultipart(boundary, ostm, messageInfo);

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

    protected void outPostHeader(OutputStream out, URL tagetURL) throws IOException, Exception {
        HttpService httpService = new HttpService(tagetURL);
        String target = tagetURL.getFile().isEmpty() ? "/" : tagetURL.getFile();
        out.write(StringUtil.getBytesRaw(String.format("POST %s HTTP/1.1", target) + HttpUtil.LINE_TERMINATE));
        out.write(StringUtil.getBytesRaw(String.format("Host: %s", HttpUtil.buildHost(httpService.getHost(), httpService.getPort(), httpService.isHttps())) + HttpUtil.LINE_TERMINATE));
        out.write(StringUtil.getBytesRaw(String.format("User-Agent: %s", "Java-http-client/BurpSuite") + HttpUtil.LINE_TERMINATE));
    }

    protected void outMultipart(String boundary, OutputStream out, IHttpRequestResponse messageInfo) throws IOException, Exception {
        IHttpService httpService = messageInfo.getHttpService();
        HttpUtil.outMultipartText(boundary, out, "host", httpService.getHost());
        HttpUtil.outMultipartText(boundary, out, "port", StringUtil.toString(httpService.getPort()));
        HttpUtil.outMultipartText(boundary, out, "protocol", httpService.getProtocol());
        HttpUtil.outMultipartText(boundary, out, "url", StringUtil.toString(BurpExtender.getHelpers().getURL(messageInfo)));
        String comment = messageInfo.getComment();
        if (comment != null) {
            HttpUtil.outMultipartText(boundary, out, "comment", comment, StandardCharsets.UTF_8);
        }
        String color = messageInfo.getHighlight();
        if (color != null) {
            HttpUtil.outMultipartText(boundary, out, "highlight", color);
        }
        if (messageInfo.getRequest() != null && this.isRequest()) {
            HttpUtil.outMultipartBinary(boundary, out, "request", messageInfo.getRequest());
        }
        if (messageInfo.getResponse() != null && this.isResponse()) {
            HttpUtil.outMultipartBinary(boundary, out, "response", messageInfo.getResponse());
        }
        HttpUtil.outMultipartFinish(boundary, out);
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        IHttpRequestResponse[] messageInfo = this.contextMenu.getSelectedMessages();
        sendToEvent(messageInfo);
    }

    @Override
    public boolean isEnabled() {
        boolean enabled = (this.contextMenu.getInvocationContext() != IContextMenuInvocation.CONTEXT_INTRUDER_PAYLOAD_POSITIONS)
                || (this.contextMenu.getInvocationContext() != IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TREE);
        return enabled;
    }
    
}
