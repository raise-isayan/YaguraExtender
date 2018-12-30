package yagura.model;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IMessageEditorController;
import burp.IRequestInfo;
import burp.IResponseInfo;
import extend.util.BurpWrap;
import extend.view.base.HttpMessage;
import extend.view.base.HttpResponse;
import java.net.URL;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.RowFilter;

/**
 *
 * @author isayan
 */
public class HttpMessageItem implements IHttpRequestResponse {
    private IHttpRequestResponse httpItem = null;
    private int ordinal = -1;
    
    private String host = "";
    private int port;
    private String protocol;
    private byte[] request = new byte[0];
    private byte[] response = new byte[0];
    private URL url;
    private short statuscode = 0;
    private String comment = "";
    private String color = "";
    private String memo = "";

    public HttpMessageItem() {
    }

    public HttpMessageItem(IHttpRequestResponse httpItem) {
        this.httpItem = httpItem;
    }

    public HttpMessageItem(IHttpRequestResponse httpItem, int ordinal) {
        this.httpItem = httpItem;
        this.ordinal = ordinal;
    }

    /**
     * @return the ordinal
     */
    public int getOrdinal() {
        return this.ordinal;
    }

    public String getHost() {
        if (this.httpItem != null) {
            return this.httpItem.getHttpService().getHost();
        } else {
            return this.host;
        }
    }

    public int getPort() {
        if (this.httpItem != null) {
            return this.httpItem.getHttpService().getPort();
        } else {
            return this.port;
        }
    }

    public String getProtocol() {
        if (this.httpItem != null) {
            return this.httpItem.getHttpService().getProtocol();
        } else {
            return this.protocol;
        }
    }

    public void setHost(String host) throws Exception {
        if (this.httpItem != null) {
            this.httpItem.setHttpService(BurpWrap.getHttpService(host, this.httpItem.getHttpService().getPort(), this.httpItem.getHttpService().getProtocol()));
        } else {
            this.host = host;
        }
    }

    public void setPort(int port) throws Exception {
        if (this.httpItem != null) {
            this.httpItem.setHttpService(BurpWrap.getHttpService(this.httpItem.getHttpService().getHost(), port, this.httpItem.getHttpService().getProtocol()));
        } else {
            this.port = port;
        }
    }

    public void setProtocol(String protocol) throws Exception {
        if (this.httpItem != null) {
            this.httpItem.setHttpService(BurpWrap.getHttpService(this.httpItem.getHttpService().getHost(), this.httpItem.getHttpService().getPort(), protocol));
        } else {
            this.protocol = protocol;
        }
    }

    @Override
    public byte[] getRequest()  {
        if (this.httpItem != null) {
            return this.httpItem.getRequest();
        } else {
            return this.request;
        }
    }

    public URL getUrl() throws Exception {
        if (this.httpItem != null) {
            IRequestInfo reqInfo = BurpExtender.getHelpers().analyzeRequest(this.httpItem.getHttpService(), this.httpItem.getRequest());
            return reqInfo.getUrl();
        } else {
            return this.url;
        }
    }

    @Override
    public void setRequest(byte[] request)  {
        if (this.httpItem != null) {
            this.httpItem.setRequest(request);
        } else {
            this.request = new byte[request.length];
            System.arraycopy(request, 0, this.request, 0, request.length);
        }
    }

    @Override
    public byte[] getResponse()  {
        if (this.httpItem != null) {
            return this.httpItem.getResponse();
        } else {
            return this.response;
        }
    }

    @Override
    public void setResponse(byte[] response)  {
        if (this.httpItem != null) {
            this.httpItem.setResponse(response);
        } else {
            this.response = new byte[request.length];
            System.arraycopy(response, 0, this.response, 0, response.length);
        }
    }

    public short getStatusCode() throws Exception {
    if (this.httpItem != null) {
            if (this.httpItem.getResponse() != null) {
                IResponseInfo resInfo = BurpExtender.getHelpers().analyzeResponse(this.httpItem.getResponse());
                return resInfo.getStatusCode();
            }
            else {
                return 0;
            }
        } else {
            return this.statuscode;
        }
    }

    @Override
    public String getComment() {
        if (this.httpItem != null) {
            return this.httpItem.getComment();
        } else {
            return this.comment;
        }
    }

    @Override
    public void setComment(String comment)  {
        if (this.httpItem != null) {
            this.httpItem.setComment(comment);
        } else {
            this.comment = comment;
        }
    }
    
    @Override
    public String getHighlight() {
        if (this.httpItem != null) {
            return BurpWrap.getHighlightColor(this.httpItem);
        } else {
            return this.color;
        }
    }

    @Override
    public void setHighlight(String color) {
        if (this.httpItem != null) {
            BurpWrap.setHighlightColor(this.httpItem, color);
        } else {
            this.color = color;
        }
    }

    public String getMemo() {
        return this.memo;
    }

    public void setMemo(String memo)  {
        this.memo = memo;
    }
    
    public static HttpMessageItem toHttpMessageItem(RowFilter.Entry<? extends Object, ? extends Object> entry) {
        final RowFilter.Entry<? extends Object, ? extends Object> row = entry;
        IHttpRequestResponse item = (IHttpRequestResponse) row.getValue(0);
        return new HttpMessageItem(item);
    }

    public String getGuessCharset() {
        String charset = "8859_1";
        try {
            if (this.getResponse() != null) {
                HttpResponse res = new HttpResponse(HttpMessage.parseHttpMessage(this.getResponse()));
                charset = res.getGuessCharset();
                if (charset == null) {
                    charset = "8859_1";
                }
            }
        } catch (Exception ex) {
            Logger.getLogger(HttpMessageItem.class.getName()).log(Level.SEVERE, null, ex);
        }
        return charset;
    }

    public boolean isSSL() {
        return "https".equals(this.getProtocol());
    }
    
    public void dump() {
        try {
            System.out.println(String.format("[%d].getUrl=%s", ordinal, this.getUrl()));
            System.out.println(String.format("[%d].getRequest=%s", ordinal, this.getRequest()));
            System.out.println(String.format("[%d].getResponse=%s", ordinal, this.getResponse()));
            System.out.println(String.format("[%d].getHighlight=%s", ordinal, this.getHighlight()));
            System.out.println(String.format("[%d].getStatusCode=%d", ordinal, this.getStatusCode()));
        } catch (Exception ex) {
            Logger.getLogger(HttpMessageItem.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public String getContentMimeType() {
        String mimeType = null;
        try {
            if (this.getResponse() != null) {
                HttpResponse res = new HttpResponse(HttpMessage.parseHttpMessage(this.getResponse()));
                mimeType = res.getContentMimeType();
            }
        } catch (Exception ex) {
            Logger.getLogger(HttpMessageItem.class.getName()).log(Level.SEVERE, null, ex);
        }
        return mimeType;
    }

    @Override
    public IHttpService getHttpService() {
        return BurpWrap.getHttpService(getHost(), getPort(), getProtocol());
    }

    @Override
    public void setHttpService(IHttpService httpService) {
        try {
            this.setHost(httpService.getHost());
            this.setPort(httpService.getPort());
            this.setProtocol(httpService.getProtocol());
        } catch (Exception ex) {
            Logger.getLogger(HttpMessageItem.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public IMessageEditorController getController() {
        return new IMessageEditorController() {
            @Override
            public IHttpService getHttpService() {
                return HttpMessageItem.this.getHttpService();
            }

            @Override
            public byte[] getRequest() {
                return HttpMessageItem.this.getRequest();
            }

            @Override
            public byte[] getResponse() {
                return HttpMessageItem.this.getResponse();
            }
        
        };
    }

    
}
