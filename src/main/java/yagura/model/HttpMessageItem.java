package yagura.model;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import extension.burp.HttpTarget;
import extension.burp.MessageHighlightColor;
import extension.helpers.HttpResponseWapper;
import extension.helpers.StringUtil;
import java.net.MalformedURLException;
import java.net.URL;
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
    private short statusCode = 0;
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
            return this.httpRequestResponse.request().httpService().host();
        } else {
            return this.host;
        }
    }

    public int getPort() {
        if (this.httpRequestResponse != null) {
            return this.httpRequestResponse.request().httpService().port();
        } else {
            return this.port;
        }
    }

    public boolean isSecure() {
        if (this.httpRequestResponse != null) {
            return this.httpRequestResponse.request().httpService().secure();
        } else {
            return this.secure;
        }
    }

    public void setHost(String host) throws Exception {
        if (this.httpRequestResponse != null) {
            HttpService service = this.httpRequestResponse.request().httpService();
            this.httpRequestResponse.request().withService(HttpService.httpService(host, service.port(), service.secure()));
        } else {
            this.host = host;
        }
    }

    public void setPort(int port) throws Exception {
        if (this.httpRequestResponse != null) {
            HttpService service = this.httpRequestResponse.request().httpService();
            this.httpRequestResponse.request().withService(HttpService.httpService(service.host(), port, service.secure()));
        } else {
            this.port = port;
        }
    }

    public void setSecure(boolean secure) throws Exception {
        if (this.httpRequestResponse != null) {
            HttpService service = this.httpRequestResponse.request().httpService();
            this.httpRequestResponse.request().withService(HttpService.httpService(service.host(), service.port(), secure));
        } else {
            this.secure = secure;
        }
    }

    public byte[] getRequest() {
        if (this.httpRequestResponse != null) {
            return this.httpRequestResponse.request().toByteArray().getBytes();
        } else {
            return this.request;
        }
    }

    public String getUrl() throws Exception {
        if (this.httpRequestResponse != null) {
            return this.httpRequestResponse.request().url();
        } else {
            return this.url;
        }
    }

    public void setRequest(byte[] request) {
        if (this.httpRequestResponse != null) {
            this.httpRequestResponse.request().withBody(ByteArray.byteArray(request));
        } else {
            this.request = new byte[request.length];
            System.arraycopy(request, 0, this.request, 0, request.length);
        }
    }

    public byte[] getResponse() {
        if (this.httpRequestResponse != null) {
            return this.httpRequestResponse.response().toByteArray().getBytes();
        } else {
            return this.response;
        }
    }

    public void setResponse(byte[] response) {
        if (this.httpRequestResponse != null) {
            this.httpRequestResponse.response().withBody(ByteArray.byteArray(response));
        } else {
            this.response = new byte[request.length];
            System.arraycopy(response, 0, this.response, 0, response.length);
        }
    }

    public short getStatusCode() throws Exception {
        if (this.httpRequestResponse != null) {
            if (this.httpRequestResponse.response() != null) {
                return this.httpRequestResponse.response().statusCode();
            } else {
                return 0;
            }
        } else {
            return this.statusCode;
        }
    }

    public void setStatusCode(short statusCode) throws Exception {
        if (this.httpRequestResponse != null) {
            if (this.httpRequestResponse.response() != null) {
                this.httpRequestResponse.response().withStatusCode(statusCode);
            }
        } else {
            this.statusCode = statusCode;
        }
    }

    public String getComment() {
        if (this.httpRequestResponse != null) {
            return this.httpRequestResponse.annotations().notes();
        } else {
            return this.comment;
        }
    }

    public void setComment(String comment) {
        if (this.httpRequestResponse != null) {
            this.httpRequestResponse.annotations().withNotes(comment);
        } else {
            this.comment = comment;
        }
    }

    public String getHighlight() {
        if (this.httpRequestResponse != null) {
            return this.httpRequestResponse.annotations().highlightColor().name();
        } else {
            return this.color.name();
        }
    }

    public void setHighlight(String color) {
        if (this.httpRequestResponse != null) {
            this.httpRequestResponse.annotations().withHighlightColor(MessageHighlightColor.parseEnum(color).toHighlightColor());
        } else {
            this.color = MessageHighlightColor.parseEnum(color);
        }
    }

    public void setHighlightColor(HighlightColor color) {
        if (this.httpRequestResponse != null) {
            this.httpRequestResponse.withAnnotations(this.httpRequestResponse.annotations().withHighlightColor(color));
        } else {
            this.color = MessageHighlightColor.valueOf(color);
        }
    }

    public MessageHighlightColor getHighlightColor() {
        if (this.httpRequestResponse != null) {
            return MessageHighlightColor.valueOf(this.httpRequestResponse.annotations().highlightColor());
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
        return new URL(this.httpRequestResponse.request().url());
    }

    public static HttpMessageItem toHttpMessageItem(RowFilter.Entry<? extends Object, ? extends Object> entry) {
        final RowFilter.Entry<? extends Object, ? extends Object> row = entry;
        HttpRequestResponse item = (HttpRequestResponse) row.getValue(0);
        return new HttpMessageItem(item);
    }

    public String getGuessCharset(String defaultCharset) {
        String charset = defaultCharset;
            if (this.response() != null) {
                HttpResponseWapper wrap = new HttpResponseWapper(this.response());
                charset = wrap.getGuessCharset(defaultCharset);
            }
        return charset;
    }

    public void dump() {
        try {
            System.out.println(String.format("[%d].getUrl=%s", ordinal, this.getUrl()));
            System.out.println(String.format("[%d].getRequest=%s", ordinal, StringUtil.getStringRaw(this.getRequest())));
            System.out.println(String.format("[%d].getResponse=%s", ordinal, StringUtil.getStringRaw(this.getResponse())));
            System.out.println(String.format("[%d].getHighlight=%s", ordinal, this.getHighlight()));
            System.out.println(String.format("[%d].getStatusCode=%d", ordinal, this.getStatusCode()));
        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }

    public String getContentMimeType() {
        String mimeType = null;
        try {
            if (this.response() != null) {
                HttpResponseWapper wrap = new HttpResponseWapper(this.response());
                mimeType = wrap.getContentMimeType();
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
    public HttpRequest request() {
        return this.httpRequestResponse.request();
    }

    @Override
    public HttpResponse response() {
        return this.httpRequestResponse.response();
    }

    @Override
    public Annotations annotations() {
        return this.httpRequestResponse.annotations();
    }

    @Override
    public String url() {
        return this.httpRequestResponse.url();
    }

    @Override
    public HttpService httpService() {
        return this.httpRequestResponse.httpService();
    }

    @Override
    public ContentType contentType() {
        return this.httpRequestResponse.contentType();
    }

    @Override
    public short statusCode() {
        return this.httpRequestResponse.statusCode();
    }

    @Override
    public List<Marker> requestMarkers() {
        return this.httpRequestResponse.requestMarkers();
    }

    @Override
    public List<Marker> responseMarkers() {
        return this.httpRequestResponse.responseMarkers();
    }

    @Override
    public HttpRequestResponse copyToTempFile() {
        return this.httpRequestResponse.copyToTempFile();
    }

    @Override
    public HttpRequestResponse withAnnotations(Annotations antns) {
        return this.httpRequestResponse.withAnnotations(antns);
    }

    @Override
    public HttpRequestResponse withRequestMarkers(Marker... markers) {
        return this.httpRequestResponse.withResponseMarkers(markers);
    }

    @Override
    public HttpRequestResponse withResponseMarkers(Marker... markers) {
        return this.httpRequestResponse.withResponseMarkers(markers);
    }

    @Override
    public HttpRequestResponse withRequestMarkers(List<Marker> list) {
        return this.httpRequestResponse.withRequestMarkers(list);
    }

    @Override
    public HttpRequestResponse withResponseMarkers(List<Marker> list) {
        return this.httpRequestResponse.withResponseMarkers(list);
    }

}
