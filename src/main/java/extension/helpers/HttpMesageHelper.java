package extension.helpers;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 * @author isayan
 */
public class HttpMesageHelper {

    public final static String LINE_TERMINATE = "\r\n";
    public final static Pattern HTTP_LINESEP = Pattern.compile("\\r\\n\\r\\n");
    private final static Pattern CONTENT_TYPE_MIME = Pattern.compile("\\s*([^\\s;]+);?", Pattern.MULTILINE);
    private final static Pattern CONTENT_CHARSET = Pattern.compile("(\\s*charset=[\"\']?([\\w_-]+)[\"\']?)", Pattern.MULTILINE);

    /**
     * httpBase
     */
    /**
     * @param headers
     * @param name
     * @return
     */
    public static HttpHeader findHeader(List<HttpHeader> headers, String name) {
        Optional<HttpHeader> header = headers.stream().filter(h -> h.name().equalsIgnoreCase(name)).findFirst();
        if (header.isPresent()) {
            return header.get();
        } else {
            return null;
        }
    }

    /**
     * httpRequest
     */
    /**
     *
     * @param parameters
     * @return
     */
    public static boolean hasQueryParameter(List<ParsedHttpParameter> parameters) {
        return parameters.stream().anyMatch(p -> p.type() == HttpParameterType.URL);
    }

    public static String getEncodeType(HttpRequest httpRequest) {
        HttpHeader contentType = getContentTypeHeader(httpRequest);
        Matcher m = CONTENT_TYPE_MIME.matcher(contentType.value());
        String encodeType = null;
        if (m.find()) {
            encodeType = m.group(1);
        }
        return encodeType;
    }

    public static String getGuessCharset(HttpRequest httpRequest) {
        String charset = null;
        HttpHeader contentType = getContentTypeHeader(httpRequest);
        if (contentType != null) {
            Matcher m = CONTENT_CHARSET.matcher(contentType.value());
            if (m.find()) {
                charset = m.group(2);
            }
        }
        if (charset == null) {
            charset = HttpUtil.getGuessCode(httpRequest.body().getBytes());
        }
        return HttpUtil.normalizeCharset(charset);
    }

    public static HttpHeader getContentTypeHeader(HttpRequest httpRequest) {
        return findHeader(httpRequest.headers(), "Content-Type");
    }

    public static boolean isHttps(HttpRequest httpRequest) {
        HttpHeader header = findHeader(httpRequest.headers(), "Referer");
        if (header != null) {
            return header.value().startsWith("https://");
        } else {
            return false;
        }
    }

    /**
     * httpResponse
     */
    private final static Pattern RESPONSE_META_SET = Pattern.compile("<meta (?:.*?)charset=[\"\']?([\\w_-]+)[\"\']?\\W+", Pattern.CASE_INSENSITIVE);

    public static HttpHeader getContentTypeHeader(HttpResponse httpResponse) {
        return findHeader(httpResponse.headers(), "Content-Type");
    }

    public static String getContentMimeType(HttpResponse httpResponse) {
        String mimeType = null;
        HttpHeader contentType = getContentTypeHeader(httpResponse);
        if (contentType != null) {
            Matcher m = CONTENT_TYPE_MIME.matcher(contentType.value());
            if (m.find()) {
                mimeType = m.group(2);
            }
        }
        return mimeType;
    }

    public static String getGuessCharset(HttpResponse httpResponse) {
        String charset = null;
        HttpHeader contentType = getContentTypeHeader(httpResponse);
        if (contentType != null) {
            Matcher m = CONTENT_CHARSET.matcher(contentType.value());
            if (m.find()) {
                charset = m.group(2);
            }
        }
        if (charset == null) {
            Matcher m2 = RESPONSE_META_SET.matcher(StringUtil.getStringRaw(httpResponse.body().getBytes()));
            if (m2.find()) {
                charset = m2.group(1);
            }
        }
        if (charset == null) {
            charset = HttpUtil.getGuessCode(httpResponse.body().getBytes());
        }
        return HttpUtil.normalizeCharset(charset);
    }

}
