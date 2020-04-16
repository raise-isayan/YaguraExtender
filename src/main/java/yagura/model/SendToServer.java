package yagura.model;

import burp.IContextMenuInvocation;
import extend.util.HttpUtil;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import extend.util.BurpWrap;
import extend.util.Util;
import java.awt.event.ActionEvent;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.SocketAddress;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Properties;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 *
 * @author isayan
 */
public class SendToServer extends SendToMenuItem {

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

    private final ExecutorService threadExecutor = Executors.newSingleThreadExecutor();

    protected void sendToServer(IHttpRequestResponse messageInfo) {
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
                    Properties prop = getExtendProperty();
                    String proxyProtocol =  prop.getProperty("proxyProtocol", Proxy.Type.DIRECT.name());
                    Proxy proxy = Proxy.NO_PROXY;
                    if (!Proxy.Type.DIRECT.name().equals(proxyProtocol)) {
                        String proxyHost =  prop.getProperty("proxyHost", "");
                        if (Proxy.Type.HTTP.name().equals(proxyProtocol)) {
                            int proxyPort = Util.parseIntDefault(prop.getProperty("proxyPort", "8080"), 8080);
                            SocketAddress addr = new InetSocketAddress(proxyHost, proxyPort);
                            proxy = new Proxy(Proxy.Type.HTTP, addr);                                                                
                        }
                        else if (Proxy.Type.SOCKS.name().equals(proxyProtocol)) {
                            int proxyPort = Util.parseIntDefault(prop.getProperty("proxyPort", "1080"), 1080);
                            SocketAddress addr = new InetSocketAddress(proxyHost, proxyPort);
                            proxy = new Proxy(Proxy.Type.SOCKS, addr);                                                                                        
                        }
                    }                    
                    conn = (HttpURLConnection) url.openConnection(proxy);
                    conn.setFixedLengthStreamingMode(contentLength);
                    conn.setRequestMethod("POST");
                    conn.setDoOutput(true);
                    conn.setRequestProperty("Content-Type", "multipart/form-data; boundary=" + boundary);
                    conn.connect();

                    OutputStream ostm = null;
                    try {
                        ostm = conn.getOutputStream();
                        outMultipart(boundary, ostm, messageInfo);
                    } catch (IOException e) {
                        fireSendToErrorEvent(new SendToEvent(this, e.getMessage()));
                    } catch (Exception e) {
                        fireSendToErrorEvent(new SendToEvent(this, e.getMessage()));
                    } finally {
                        if (ostm != null) {
                            ostm.close();
                        }
                    }

                    InputStream istm = conn.getInputStream();
                    ByteArrayOutputStream bostm = new ByteArrayOutputStream();
                    try {
                        BufferedInputStream bistm = new BufferedInputStream(istm);
                        String decodeMessage;
                        byte buf[] = new byte[4096];
                        int len;
                        while ((len = bistm.read(buf)) != -1) {
                            bostm.write(buf, 0, len);
                        }
                        int statusCode = conn.getResponseCode();
                        decodeMessage = Util.decodeMessage(bostm.toByteArray());
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
                        if (bostm != null) {
                            bostm.close();
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

    class DummyOutputStream extends OutputStream {

        private int size = 0;

        @Override
        public void write(int b) throws IOException {
            size += 1;
        }

        @Override
        public void write(byte[] bytes) throws IOException {
            size += bytes.length;
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            size += len;
        }

        public int getSize() {
            return this.size;
        }
    }

    @Override
    public boolean isEnabled() {
        boolean enabled = (this.contextMenu.getInvocationContext() != IContextMenuInvocation.CONTEXT_INTRUDER_PAYLOAD_POSITIONS)
                || (this.contextMenu.getInvocationContext() != IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TREE);
        return enabled;
    }

}
