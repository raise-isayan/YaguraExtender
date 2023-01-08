package yagura.model;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.MarkedHttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import extension.burp.HttpTarget;
import extension.burp.MessageHighlightColor;
import extension.helpers.HttpMesageHelper;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.RowFilter;

/**
 *
 * @author isayan
 */
public class HttpMessageItem implements HttpRequestResponse {
    private final static Logger logger = Logger.getLogger(HttpMessageItem.class.getName());

    private final HttpRequestResponse httpRequestResponse;
    private int ordinal = -1;

    private String host = "";
    private int port;
    private boolean secure;
    private byte[] request = new byte[0];
    private byte[] response = new byte[0];
    private String url;
    private short statuscode = 0;
    private String comment = "";
    MessageHighlightColor color = MessageHighlightColor.WHITE;
    private String memo = "";

    public HttpMessageItem() {
        this.httpRequestResponse = null;
    }

    public HttpMessageItem(HttpRequestResponse httpRequestResponse) {
        this.httpRequestResponse = httpRequestResponse;
    }

    public HttpMessageItem(HttpRequestResponse httpRequestResponse, int ordinal) {
        this.httpRequestResponse = httpRequestResponse;
        this.ordinal = ordinal;
    }

    /**
     * @return the ordinal
     */
    public int getOrdinal() {
        return this.ordinal;
    }

    public String getHost() {
        if (this.httpRequestResponse != null) {
            return this.httpRequestResponse.httpRequest().httpService().host();
        } else {
            return this.host;
        }
    }

    public int getPort() {
        if (this.httpRequestResponse != null) {
            return this.httpRequestResponse.httpRequest().httpService().port();
        } else {
            return this.port;
        }
    }

    public boolean isSecure() {
        if (this.httpRequestResponse != null) {
            return this.httpRequestResponse.httpRequest().httpService().secure();
        } else {
            return this.secure;
        }
    }

    public void setHost(String host) throws Exception {
        if (this.httpRequestResponse != null) {
            HttpService service = this.httpRequestResponse.httpRequest().httpService();
            this.httpRequestResponse.httpRequest().withService(HttpService.httpService(host, service.port(), service.secure()));
        } else {
            this.host = host;
        }
    }

    public void setPort(int port) throws Exception {
        if (this.httpRequestResponse != null) {
            HttpService service = this.httpRequestResponse.httpRequest().httpService();
            this.httpRequestResponse.httpRequest().withService(HttpService.httpService(service.host(), port, service.secure()));
        } else {
            this.port = port;
        }
    }

    public void setSecure(boolean secure) throws Exception {
        if (this.httpRequestResponse != null) {
            HttpService service = this.httpRequestResponse.httpRequest().httpService();
            this.httpRequestResponse.httpRequest().withService(HttpService.httpService(service.host(), service.port(), secure));
        } else {
            this.secure = secure;
        }
    }

    public byte[] getRequest() {
        if (this.httpRequestResponse != null) {
            return this.httpRequestResponse.httpRequest().asBytes().getBytes();
        } else {
            return this.request;
        }
    }

    public String getUrl() throws Exception {
        if (this.httpRequestResponse != null) {
            return this.httpRequestResponse.httpRequest().url();
        } else {
            return this.url;
        }
    }

    public void setRequest(byte[] request) {
        if (this.httpRequestResponse != null) {
            this.httpRequestResponse.httpRequest().withBody(ByteArray.byteArray(request));
        } else {
            this.request = new byte[request.length];
            System.arraycopy(request, 0, this.request, 0, request.length);
        }
    }

    public byte[] getResponse() {
        if (this.httpRequestResponse != null) {
            return this.httpRequestResponse.httpResponse().asBytes().getBytes();
        } else {
            return this.response;
        }
    }

    public void setResponse(byte[] response) {
        if (this.httpRequestResponse != null) {
            this.httpRequestResponse.httpResponse().withBody(ByteArray.byteArray(response));
        } else {
            this.response = new byte[request.length];
            System.arraycopy(response, 0, this.response, 0, response.length);
        }
    }

    public short getStatusCode() throws Exception {
        if (this.httpRequestResponse != null) {
            if (this.httpRequestResponse.httpResponse() != null) {
                return this.httpRequestResponse.httpResponse().statusCode();
            } else {
                return 0;
            }
        } else {
            return this.statuscode;
        }
    }

    public String getComment() {
        if (this.httpRequestResponse != null) {
            return this.httpRequestResponse.messageAnnotations().comment();
        } else {
            return this.comment;
        }
    }

    public void setComment(String comment) {
        if (this.httpRequestResponse != null) {
            this.httpRequestResponse.messageAnnotations().withComment(comment);
        } else {
            this.comment = comment;
        }
    }

    public String getHighlight() {
        if (this.httpRequestResponse != null) {
            return this.httpRequestResponse.messageAnnotations().highlightColor().name();
        } else {
            return this.color.name();
        }
    }

    public void setHighlight(String color) {
        if (this.httpRequestResponse != null) {
            this.httpRequestResponse.messageAnnotations().withHighlightColor(MessageHighlightColor.parseEnum(color).toHighlightColor());
        } else {
            this.color = MessageHighlightColor.parseEnum(color);
        }
    }

    public void setHighlightColor(HighlightColor color) {
        if (this.httpRequestResponse != null) {
            this.httpRequestResponse.withMessageAnnotations(this.httpRequestResponse.messageAnnotations().withHighlightColor(color));
        } else {
            this.color = MessageHighlightColor.valueOf(color);
        }
    }

    public MessageHighlightColor getHighlightColor() {
        if (this.httpRequestResponse != null) {
            return MessageHighlightColor.valueOf(this.httpRequestResponse.messageAnnotations().highlightColor());
        } else {
            return this.color;
        }
    }

    public String getMemo() {
        return this.memo;
    }

    public void setMemo(String memo) {
        this.memo = memo;
    }

    public URL toURL() throws MalformedURLException {
        return new URL(this.httpRequestResponse.httpRequest().url());
    }

    public static HttpMessageItem toHttpMessageItem(RowFilter.Entry<? extends Object, ? extends Object> entry) {
        final RowFilter.Entry<? extends Object, ? extends Object> row = entry;
        HttpRequestResponse item = (HttpRequestResponse) row.getValue(0);
        return new HttpMessageItem(item);
    }

    public String getGuessCharset() {
        String charset = StandardCharsets.ISO_8859_1.name();
        try {
            if (this.httpResponse() != null) {
                charset = HttpMesageHelper.getGuessCharset(this.httpResponse());
                if (charset == null) {
                    charset = StandardCharsets.ISO_8859_1.name();
                }
            }
        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return charset;
    }

    public void dump() {
        try {
            System.out.println(String.format("[%d].getUrl=%s", ordinal, this.getUrl()));
            System.out.println(String.format("[%d].getRequest=%s", ordinal, this.getRequest()));
            System.out.println(String.format("[%d].getResponse=%s", ordinal, this.getResponse()));
            System.out.println(String.format("[%d].getHighlight=%s", ordinal, this.getHighlight()));
            System.out.println(String.format("[%d].getStatusCode=%d", ordinal, this.getStatusCode()));
        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }

    public String getContentMimeType() {
        String mimeType = null;
        try {
            if (this.httpResponse() != null) {
                mimeType = HttpMesageHelper.getContentMimeType(this.httpResponse());
            }
        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return mimeType;
    }

    public HttpTarget getHttpTarget() {
        return HttpTarget.getHttpTarget(getHost(), getPort(), isSecure());
    }

    public void setHttpTarget(HttpTarget httpService) {
        try {
            this.setHost(httpService.getHost());
            this.setPort(httpService.getPort());
            this.setSecure(httpService.isSecure());
        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }

    @Override
    public HttpRequest httpRequest() {
        return this.httpRequestResponse.httpRequest();
    }

    @Override
    public HttpResponse httpResponse() {
        return this.httpRequestResponse.httpResponse();
    }

    @Override
    public Annotations messageAnnotations() {
        return this.httpRequestResponse.messageAnnotations();
    }

    @Override
    public HttpRequestResponse withMessageAnnotations(Annotations antns) {
        return this.httpRequestResponse.withMessageAnnotations(antns);
    }

    @Override
    public MarkedHttpRequestResponse withMarkers(List<Range> list, List<Range> list1) {
        return this.httpRequestResponse.withMarkers(list, list1);
    }

    @Override
    public MarkedHttpRequestResponse withRequestMarkers(List<Range> list) {
        return this.httpRequestResponse.withRequestMarkers(list);
    }

    @Override
    public MarkedHttpRequestResponse withRequestMarkers(Range... ranges) {
        return this.httpRequestResponse.withRequestMarkers(ranges);
    }

    @Override
    public MarkedHttpRequestResponse withResponseMarkers(List<Range> list) {
        return this.httpRequestResponse.withResponseMarkers(list);
    }

    @Override
    public MarkedHttpRequestResponse withResponseMarkers(Range... ranges) {
        return this.httpRequestResponse.withResponseMarkers(ranges);
    }

    @Override
    public MarkedHttpRequestResponse withNoMarkers() {
        return this.httpRequestResponse.withNoMarkers();
    }

}
