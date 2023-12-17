package yagura.model;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.TimingData;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import extension.burp.HttpTarget;
import extension.burp.MessageHighlightColor;
import extension.helpers.HttpResponseWapper;
import extension.helpers.StringUtil;
import java.net.URL;
import java.net.MalformedURLException;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import javax.swing.RowFilter;

/**
 *
 * @author isayan
 */
public class HttpMessageItem implements ProxyHttpRequestResponse {

    private final static Logger logger = Logger.getLogger(HttpMessageItem.class.getName());

    private final ProxyHttpRequestResponse httpRequestResponse;
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

    public HttpMessageItem(ProxyHttpRequestResponse httpRequestResponse) {
        this.httpRequestResponse = httpRequestResponse;
    }

    public HttpMessageItem(ProxyHttpRequestResponse httpRequestResponse, int ordinal) {
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
            return this.httpRequestResponse.finalRequest().httpService().host();
        } else {
            return this.host;
        }
    }

    public int getPort() {
        if (this.httpRequestResponse != null) {
            return this.httpRequestResponse.finalRequest().httpService().port();
        } else {
            return this.port;
        }
    }

    public boolean isSecure() {
        if (this.httpRequestResponse != null) {
            return this.httpRequestResponse.finalRequest().httpService().secure();
        } else {
            return this.secure;
        }
    }

    public void setHost(String host) throws Exception {
        if (this.httpRequestResponse != null) {
            HttpService service = this.httpRequestResponse.finalRequest().httpService();
            this.httpRequestResponse.finalRequest().withService(HttpService.httpService(host, service.port(), service.secure()));
        } else {
            this.host = host;
        }
    }

    public void setPort(int port) throws Exception {
        if (this.httpRequestResponse != null) {
            HttpService service = this.httpRequestResponse.finalRequest().httpService();
            this.httpRequestResponse.finalRequest().withService(HttpService.httpService(service.host(), port, service.secure()));
        } else {
            this.port = port;
        }
    }

    public void setSecure(boolean secure) throws Exception {
        if (this.httpRequestResponse != null) {
            HttpService service = this.httpRequestResponse.finalRequest().httpService();
            this.httpRequestResponse.finalRequest().withService(HttpService.httpService(service.host(), service.port(), secure));
        } else {
            this.secure = secure;
        }
    }

    public byte[] getRequest() {
        if (this.httpRequestResponse != null) {
            return this.httpRequestResponse.finalRequest().toByteArray().getBytes();
        } else {
            return this.request;
        }
    }

    public String getUrl() throws Exception {
        if (this.httpRequestResponse != null) {
            return this.httpRequestResponse.finalRequest().url();
        } else {
            return this.url;
        }
    }

    public void setRequest(byte[] request) {
        if (this.httpRequestResponse != null) {
            this.httpRequestResponse.finalRequest().withBody(ByteArray.byteArray(request));
        } else {
            this.request = new byte[request.length];
            System.arraycopy(request, 0, this.request, 0, request.length);
        }
    }

    public byte[] getResponse() {
        if (this.httpRequestResponse != null) {
            return this.httpRequestResponse.originalResponse().toByteArray().getBytes();
        } else {
            return this.response;
        }
    }

    public void setResponse(byte[] response) {
        if (this.httpRequestResponse != null) {
            this.httpRequestResponse.originalResponse().withBody(ByteArray.byteArray(response));
        } else {
            this.response = new byte[request.length];
            System.arraycopy(response, 0, this.response, 0, response.length);
        }
    }

    public short getStatusCode() throws Exception {
        if (this.httpRequestResponse != null) {
            if (this.httpRequestResponse.originalResponse() != null) {
                return this.httpRequestResponse.originalResponse().statusCode();
            } else {
                return 0;
            }
        } else {
            return this.statusCode;
        }
    }

    public void setStatusCode(short statusCode) throws Exception {
        if (this.httpRequestResponse != null) {
            if (this.httpRequestResponse.originalResponse() != null) {
                this.httpRequestResponse.originalResponse().withStatusCode(statusCode);
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
            this.httpRequestResponse.annotations().withHighlightColor(color);
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
        return new URL(this.httpRequestResponse.finalRequest().url());
    }

    public static HttpMessageItem toHttpMessageItem(RowFilter.Entry<? extends Object, ? extends Object> entry) {
        final RowFilter.Entry<? extends Object, ? extends Object> row = entry;
        ProxyHttpRequestResponse item = (ProxyHttpRequestResponse) row.getValue(0);
        return new HttpMessageItem(item);
    }

    public String getGuessCharset(String defaultCharset) {
        String charset = defaultCharset;
        if (this.originalResponse() != null) {
            HttpResponseWapper wrap = new HttpResponseWapper(this.originalResponse());
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
            if (this.originalResponse() != null) {
                HttpResponseWapper wrap = new HttpResponseWapper(this.originalResponse());
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
    public Annotations annotations() {
        return this.httpRequestResponse.annotations();
    }

    @Override
    @SuppressWarnings("removal")
    public String url() {
        return this.httpRequestResponse.finalRequest().url();
    }

    @Override
    public boolean contains(String searchTerm, boolean caseSensitive) {
        return this.httpRequestResponse.contains(searchTerm, caseSensitive);
    }

    @Override
    public boolean contains(Pattern pattern) {
        return this.httpRequestResponse.contains(pattern);
    }

    @Override
    public HttpRequest finalRequest() {
        return this.httpRequestResponse.finalRequest();
    }

    @Override
    public HttpResponse originalResponse() {
        return this.httpRequestResponse.originalResponse();
    }

    @Override
    @SuppressWarnings("removal")
    public String method() {
        return this.httpRequestResponse.method();
    }

    @Override
    @SuppressWarnings("removal")
    public String path() {
        return this.httpRequestResponse.path();
    }

    @Override
    @SuppressWarnings("removal")
    public String host() {
        return this.httpRequestResponse.host();
    }

    @Override
    @SuppressWarnings("removal")
    public int port() {
        return this.httpRequestResponse.port();
    }

    @Override
    @SuppressWarnings("removal")
    public boolean secure() {
        return this.httpRequestResponse.secure();
    }

    @Override
    @SuppressWarnings("removal")
    public String httpServiceString() {
        return this.httpRequestResponse.httpServiceString();
    }

    @Override
    @SuppressWarnings("removal")
    public String requestHttpVersion() {
        return this.httpRequestResponse.requestHttpVersion();
    }

    @Override
    @SuppressWarnings("removal")
    public String requestBody() {
        return this.httpRequestResponse.requestBody();
    }

    @Override
    public boolean edited() {
        return this.httpRequestResponse.edited();
    }

    public HttpRequestResponse toHttpRequestResponse() {
        return new HttpRequestResponse() {
            @Override
            public HttpRequest request() {
                return httpRequestResponse.finalRequest();
            }

            @Override
            public HttpResponse response() {
                return httpRequestResponse.originalResponse();
            }

            @Override
            public boolean hasResponse() {
                return httpRequestResponse.originalResponse() != null;
            }

            @Override
            public Annotations annotations() {
                return httpRequestResponse.annotations();
            }

            @Override
            public Optional<TimingData> timingData() {
                return Optional.empty();
            }

            @Override
            @SuppressWarnings("removal")
            public String url() {
                return httpRequestResponse.finalRequest().url();
            }

            @Override
            public HttpService httpService() {
                return httpRequestResponse.finalRequest().httpService();
            }

            @Override
            @SuppressWarnings("removal")
            public ContentType contentType() {
                return httpRequestResponse.finalRequest().contentType();
            }

            @Override
            @SuppressWarnings("removal")
            public short statusCode() {
                return httpRequestResponse.originalResponse().statusCode();
            }

            @Override
            public List<Marker> requestMarkers() {
                return httpRequestResponse.finalRequest().markers();
            }

            @Override
            public List<Marker> responseMarkers() {
                return httpRequestResponse.originalResponse().markers();
            }

            @Override
            public boolean contains(String string, boolean bln) {
                return httpRequestResponse.contains(string, bln);
            }

            @Override
            public boolean contains(Pattern ptrn) {
                return httpRequestResponse.contains(ptrn);
            }

            @Override
            public HttpRequestResponse copyToTempFile() {
                throw new UnsupportedOperationException("Not supported yet.");
            }

            @Override
            public HttpRequestResponse withAnnotations(Annotations antns) {
                throw new UnsupportedOperationException("Not supported yet.");
            }

            @Override
            public HttpRequestResponse withRequestMarkers(List<Marker> list) {
                throw new UnsupportedOperationException("Not supported yet.");
            }

            @Override
            public HttpRequestResponse withRequestMarkers(Marker... markers) {
                throw new UnsupportedOperationException("Not supported yet.");
            }

            @Override
            public HttpRequestResponse withResponseMarkers(List<Marker> list) {
                throw new UnsupportedOperationException("Not supported yet.");
            }

            @Override
            public HttpRequestResponse withResponseMarkers(Marker... markers) {
                throw new UnsupportedOperationException("Not supported yet.");
            }

        };
    }

    @Override
    public HttpRequest request() {
        return httpRequestResponse.request();
    }

    @Override
    public HttpResponse response() {
        return httpRequestResponse.response();
    }

    @Override
    public HttpService httpService() {
        return httpRequestResponse.httpService();
    }

    @Override
    public ZonedDateTime time() {
        return httpRequestResponse.time();
    }

    @Override
    public int listenerPort() {
        return httpRequestResponse.listenerPort();
    }

    @Override
    public MimeType mimeType() {
        return httpRequestResponse.mimeType();
    }

    @Override
    public boolean hasResponse() {
        return httpRequestResponse.hasResponse();
    }

    @Override
    public TimingData timingData() {
        return httpRequestResponse.timingData();
    }
}
