package yagura.model;

import burp.IContextMenuInvocation;
import extend.util.HttpUtil;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import extend.util.BurpWrap;
import extend.util.Util;

import java.awt.event.ActionEvent;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.Authenticator;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.PasswordAuthentication;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpClient.Redirect;
import java.net.http.HttpClient.Version;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
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

    static {
        // SSL 証明書検証をしない。
        HttpUtil.ignoreValidateCertification();
    }

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
                            int proxyPort = Util.parseIntDefault(prop.getProperty("proxyPort", "8080"), 8080);
                            SocketAddress addr = new InetSocketAddress(proxyHost, proxyPort);
                            proxy = new Proxy(Proxy.Type.HTTP, addr);
                        } else if (Proxy.Type.SOCKS.name().equals(proxyProtocol)) {
                            int proxyPort = Util.parseIntDefault(prop.getProperty("proxyPort", "1080"), 1080);
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
                    boolean ignoreValidateCertification = Util.parseBooleanDefault(prop.getProperty("ignoreValidateCertification", Boolean.TRUE.toString()), false);
                    String boundary = HttpUtil.generateBoundary();
                    HttpClient.Builder builder = HttpClient.newBuilder()
                        .version(Version.HTTP_1_1)
                        .followRedirects(Redirect.NORMAL)
                        .connectTimeout(Duration.ofSeconds(10));

                    if (ignoreValidateCertification) {
                        builder.sslContext(HttpUtil.ignoreSSLContext());
                    }

                    if (!Proxy.Type.DIRECT.name().equals(proxyProtocol)) {
                        ProxySelector staticProxy = new HttpUtil.StaticProxySelector(proxy) {
                            @Override
                            public void connectFailed(URI uri, SocketAddress sa, IOException ex) {
                                fireSendToErrorEvent(new SendToEvent(this, "Error[" + ex.getClass().getName() + "]:" + ex.getMessage()));
                                logger.log(Level.SEVERE, ex.getMessage(), ex);
                            }                            
                        };
                        builder.proxy(staticProxy);
                    }
                    if (authenticator != null) {
                        builder.authenticator(authenticator);
                    }
                    try ( ByteArrayOutputStream ostm = new ByteArrayOutputStream()) {
                        outMultipart(boundary, ostm, messageInfo);

                        HttpRequest request = HttpRequest.newBuilder()
                            .uri(URI.create(getTarget())) // 送信先
                            .timeout(Duration.ofSeconds(10))
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

    protected void outMultipart(String boundary, OutputStream out, IHttpRequestResponse messageInfo) throws IOException, Exception {
        IHttpService httpService = messageInfo.getHttpService();
        HttpUtil.outMultipartText(boundary, out, "host", httpService.getHost());
        HttpUtil.outMultipartText(boundary, out, "port", Util.toString(httpService.getPort()));
        HttpUtil.outMultipartText(boundary, out, "protocol", httpService.getProtocol());
        HttpUtil.outMultipartText(boundary, out, "url", Util.toString(BurpWrap.getURL(messageInfo)));
        String comment = messageInfo.getComment();
        if (comment != null) {
            HttpUtil.outMultipartText(boundary, out, "comment", comment, StandardCharsets.UTF_8);
        }
        String color = BurpWrap.getHighlightColor(messageInfo);
        if (color != null) {
            HttpUtil.outMultipartText(boundary, out, "highlight", BurpWrap.getHighlightColor(messageInfo));
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
