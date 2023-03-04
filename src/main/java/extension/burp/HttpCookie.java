package extension.burp;

import burp.api.montoya.http.message.Cookie;
import extension.helpers.DateUtil;
import java.text.ParseException;
import java.time.ZonedDateTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.Scanner;

/**
 * RFC 6255 https://tools.ietf.org/html/rfc6265
 *
 * @author isayan
 */
public class HttpCookie implements Cookie {

    private String domain;
    private String path;
    private Optional<ZonedDateTime> expiration = Optional.empty();
    private String name;
    private String value;
    private long maxage = -1;
    private boolean secure = false;
    private boolean httpOnly = false;
    private String sameSite;

    public HttpCookie(Cookie cookie) {
        this.name = cookie.name();
        this.value = cookie.value();
        this.domain = cookie.domain();
        this.path = cookie.path();
        this.expiration = cookie.expiration();
    }

    public HttpCookie(String name, String value) {
        this.name = name;
        this.value = value;
    }

    public String getName() {
        return this.name;
    }

    public String getValue() {
        return this.value;
    }

    public long getMaxage() {
        return this.maxage;
    }

    public String getDomain() {
        return this.domain;
    }

    public String getPath() {
        return this.path;
    }

    public boolean isSecure() {
        return this.secure;
    }

    public boolean isHttpOnly() {
        return this.httpOnly;
    }

    public String getSameSite() {
        return this.sameSite;
    }

    public ZonedDateTime getExpiration() {
        if (this.expiration.isPresent()) {
            return this.expiration.get();
        } else {
            return null;
        }
    }

    public Date getExpirationAsDate() {
        return (this.expiration.isPresent()) ? Date.from(this.expiration.get().toInstant()) : null;
    }

    /**
     * Set-HttpCookie
     *
     * @param cookieString
     * @return
     * @throws ParseException
     */
    public static HttpCookie parseResponse(String cookieString) throws ParseException {
        HttpCookie cookie = null;
        Scanner s = new Scanner(cookieString).useDelimiter(";");
        if (s.hasNext()) {
            String target = s.next();
            String[] nameValue = target.split("=");
            String cookieName = nameValue[0].trim();
            if (!cookieName.isEmpty() && target.indexOf('=') > 0) {
                String cookieValue = nameValue.length >= 2 ? nameValue[1].trim() : "";
                cookie = new HttpCookie(cookieName, cookieValue);
            }
        }
        while (s.hasNext() && cookie != null) {
            String target = s.next();
            String[] attributeNameValue = target.split("=");
            String attributeName = attributeNameValue[0].trim();
            if (attributeNameValue.length < 2) {
                if ("secure".equalsIgnoreCase(attributeName)) {
                    cookie.secure = true;
                } else if ("HttpOnly".equalsIgnoreCase(attributeName)) {
                    cookie.httpOnly = true;
                }
            } else {
                String attributeValue = attributeNameValue[1].trim();
                if ("Expires".equalsIgnoreCase(attributeName)) {
                    try {
                        cookie.expiration = Optional.of(DateUtil.parseHttpDate(attributeValue));
                    } catch (DateTimeParseException e) {
                        //
                    }
                } else if ("Max-Age".equalsIgnoreCase(attributeName)) {
                    long maxAge = Long.parseLong(attributeValue);
                    cookie.maxage = maxAge;
                } else if ("Domain".equalsIgnoreCase(attributeName)) {
                    cookie.domain = attributeValue;
                } else if ("Path".equalsIgnoreCase(attributeName)) {
                    cookie.path = attributeValue;
                } else if ("SameSite".equalsIgnoreCase(attributeName)) {
                    cookie.sameSite = attributeValue;
                }

            }

        }
        if (cookie == null) {
            throw new ParseException("missing Cookie:" + cookieString, 0);
        }
        return cookie;
    }

    /**
     * HttpCookie
     *
     * @param cookieString
     * @return
     * @throws ParseException
     */
    public static HttpCookie[] parseResuest(String cookieString) throws ParseException {
        List<HttpCookie> cookieList = new ArrayList<>();
        Scanner s = new Scanner(cookieString).useDelimiter(";");
        while (s.hasNext()) {
            String target = s.next();
            String[] nameValue = target.split("=");
            String cookieName = nameValue[0].trim();
            if (!cookieName.isEmpty() && target.indexOf('=') > 0) {
                String cookieValue = nameValue.length >= 2 ? nameValue[1].trim() : "";
                HttpCookie cookie = new HttpCookie(cookieName, cookieValue);
                cookieList.add(cookie);
            }
        }
        return cookieList.toArray(HttpCookie[]::new);
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append(name);
        builder.append("=");
        builder.append(value);
        builder.append(";");
        if (this.path != null) {
            builder.append(" ");
            builder.append("Path=");
            builder.append(this.path);
            builder.append(";");
        }
        if (this.domain != null) {
            builder.append(" ");
            builder.append("Domain=");
            builder.append(this.domain);
        }
        if (this.expiration.isPresent()) {
            builder.append(" ");
            builder.append("Expires=");
            builder.append(DateUtil.valueOfHttpDate(this.expiration.get()));
            builder.append(";");
        }
        if (this.maxage >= 0) {
            builder.append(" ");
            builder.append("Max-Age=");
            builder.append(this.maxage);
            builder.append(";");
        }
        if (this.secure) {
            builder.append(" ");
            builder.append("Secure");
            builder.append(";");
        }
        if (this.httpOnly) {
            builder.append(" ");
            builder.append("HttpOnly");
            builder.append(";");
        }
        if (this.sameSite != null) {
            builder.append(" ");
            builder.append("SameSite=");
            builder.append(this.sameSite);
        }

        return builder.toString();
    }

    @Override
    public String name() {
        return this.name;
    }

    @Override
    public String value() {
        return this.value;
    }

    @Override
    public String domain() {
        return this.domain;
    }

    @Override
    public String path() {
        return this.path;
    }

    @Override
    public Optional<ZonedDateTime> expiration() {
        return this.expiration;
    }

}
