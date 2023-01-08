package extension.helpers;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.charset.IllegalCharsetNameException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.net.ssl.*;
import org.mozilla.universalchardet.UniversalDetector;

/**
 *
 * @author isayan
 */
public final class HttpUtil {
    private final static Logger logger = Logger.getLogger(HttpUtil.class.getName());

    public static String LINE_TERMINATE = "\r\n";

    private HttpUtil() {
    }

    private final static Pattern HEADER_VALUE = Pattern.compile("^([^:]+)\\s*:\\s*(.*)");

    public static String getHeader(String key, String[] headers) {
        String value = null;
        for (String header : headers) {
            Matcher m = HEADER_VALUE.matcher(header);
            if (m.matches()) {
                String k = m.group(1);
                String v = m.group(2);
                if (key.equalsIgnoreCase(k)) {
                    value = v;
                    break;
                }
            }
        }
        return value;
    }

    public static String getEnctype(String[] headers) {
        String contentType = HttpUtil.getHeader("Content-Type", headers);
        if (contentType != null && contentType.indexOf(';') > 0) {
            contentType = contentType.substring(0, contentType.indexOf(';'));
        }
        return contentType;
    }

    public static boolean isUrlEencoded(String header) {
        return (header == null || header.equals("application/x-www-form-urlencoded"));
    }

    public static boolean isMaltiPart(String header) {
        return (header.contains("multipart"));
    }

    public static boolean isPlain(String header) {
        return (header.contains("xml") || header.contains("json"));
    }

    public static boolean isValidUrl(String url) {
        try {
            new URL(url);
            return true;
        }
        catch (MalformedURLException ex) {
            return false;
        }
    }

    public static boolean startsWithHttp(String url) {
        return url.startsWith("http://") || url.startsWith("https://");
    }

    public static boolean isSSL(String protocol) {
        return "https".equals(protocol);
    }

    public static String buildHost(String host, int port, String protocol) {
        return buildHost(host, port, isSSL(protocol));
    }

    public static String buildHost(String host, int port, boolean useHttps) {
        if (HttpUtil.getDefaultPort(useHttps) == port || port == -1) {
            return host;
        }
        else {
            return host + ":" + port;
        }
    }

    /**
     * Boundaryの作成
     *
     * @return ランダムなBoundary
     */
    public static String generateBoundary() {
        StringBuilder buffer = new StringBuilder();
        buffer.append(StringUtil.randomIdent(40));
        return buffer.toString();
    }

    public static void outMultipartFinish(String boundary, OutputStream out) throws IOException {
        out.write(StringUtil.getBytesRaw("--" + boundary + "--" + LINE_TERMINATE));
    }

    public static void outMultipartText(String boundary, OutputStream out, String name, String text) throws IOException {
        // Text出力
        outMultipartText(boundary, out, name, text, null);
    }

    public static void outMultipartText(String boundary, OutputStream out, String name, String text, Charset charset) throws IOException {
        // Text出力
        out.write(StringUtil.getBytesRaw("--" + boundary + LINE_TERMINATE));
        out.write(StringUtil.getBytesRaw("Content-Disposition: form-data; name=\"" + name + "\"" + LINE_TERMINATE));
        if (charset == null) {
            out.write(StringUtil.getBytesRaw("Content-Type: text/plain;" + LINE_TERMINATE + LINE_TERMINATE));
            out.write(StringUtil.getBytesRaw(text));
        }
        else {
            out.write(StringUtil.getBytesRaw("Content-Type: text/plain; charset=" + charset.displayName() + LINE_TERMINATE + LINE_TERMINATE));
            out.write(StringUtil.getBytesCharset(text, charset));
        }
        out.write(StringUtil.getBytesRaw(LINE_TERMINATE));
    }

    public static void outMultipartBinary(String boundary, OutputStream out, String name, byte[] message) throws IOException {
        // バイナリー出力
        out.write(StringUtil.getBytesRaw("--" + boundary + LINE_TERMINATE));
        out.write(StringUtil.getBytesRaw("Content-Disposition: form-data; name=\"" + name + "\"; filename=\"" + name + "\"" + LINE_TERMINATE));
        out.write(StringUtil.getBytesRaw("Content-Type: application/octet-stream" + LINE_TERMINATE + LINE_TERMINATE));
        out.write(message, 0, message.length);
        out.write(StringUtil.getBytesRaw(LINE_TERMINATE));
    }

    public static HostnameVerifier ignoreHostnameVerifier() {
        return new HostnameVerifier() {
            @Override
            public boolean verify(String host, SSLSession ses) {
                return true;
            }
        };
    }

    protected static TrustManager[] trustAllCerts() {
        TrustManager[] tm = {
            new X509TrustManager() {
                @Override
                public void checkClientTrusted(X509Certificate[] arg0, String arg1)
                        throws CertificateException {
                }

                @Override
                public void checkServerTrusted(X509Certificate[] arg0, String arg1)
                        throws CertificateException {
                }

                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }
            }};
        return tm;
    }

    public static SSLContext ignoreSSLContext()
            throws NoSuchAlgorithmException, KeyManagementException {
        KeyManager[] km = null;
        SSLContext sslcontext = SSLContext.getInstance("SSL");
        sslcontext.init(km, trustAllCerts(), new SecureRandom());
        return sslcontext;
    }

    public static SSLSocketFactory ignoreSocketFactory()
            throws NoSuchAlgorithmException, KeyManagementException {
        return ignoreSSLContext().getSocketFactory();
    }

    public static void ignoreValidateCertification() {
        try {
            HttpsURLConnection.setDefaultSSLSocketFactory(ignoreSocketFactory());
            HttpsURLConnection.setDefaultHostnameVerifier(ignoreHostnameVerifier());
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        } catch (KeyManagementException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }

    public static void ignoreValidateCertification(
            SSLContext sslcontext) {
        try {
            ignoreValidateCertification(sslcontext, null, null);
        } catch (FileNotFoundException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        } catch (IOException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        } catch (CertificateException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        } catch (UnrecoverableKeyException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }

    public static void ignoreValidateCertification(
            SSLContext sslcontext, File clientCertFile, String passwd) throws IOException, CertificateException, UnrecoverableKeyException {
        KeyManager[] km = null;
        if (clientCertFile != null) {
            try {
                //クライアント証明書対応
                char[] passphrase = passwd.toCharArray();
                KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
                KeyStore ks = KeyStore.getInstance("PKCS12");
                ks.load(new FileInputStream(clientCertFile), passphrase);
                kmf.init(ks, passphrase);
                sslcontext.init(kmf.getKeyManagers(), trustAllCerts(), new SecureRandom());
            } catch (NoSuchAlgorithmException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            } catch (KeyManagementException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            } catch (KeyStoreException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        } else {
            try {
                sslcontext.init(km, trustAllCerts(), new SecureRandom());
            } catch (KeyManagementException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
    }

    public static String[] extractHTMLComments(String message) {
        return extractHTMLComments(message, false);
    }

    private static final Pattern HTML_COMMENT = Pattern.compile("<!--\n{0,}.+?\n{0,}-->", Pattern.DOTALL);

    public static boolean existsHTMLComments(String message) {
        Matcher matcher = HTML_COMMENT.matcher(message);
        return matcher.find();
    }

    public static String[] extractHTMLComments(String message, boolean uniqe) {
        ArrayList<String> list = new ArrayList<>();
        // Create matcher
        Matcher matcher = HTML_COMMENT.matcher(message);
        while (matcher.find()) {
            String comment = matcher.group();
            list.add(comment);
        }
        if (uniqe) {
            List<String> uniqList = ConvertUtil.toUniqList(list);
            return uniqList.toArray(new String[uniqList.size()]);
        } else {
            return list.toArray(new String[list.size()]);
        }
    }

    public static byte[] buildGetRequestByte(URL url) {
        StringBuilder buff = new StringBuilder();
        String protocol = url.getProtocol();
        String host = buildHost(url.getHost(), url.getPort(), url.getProtocol());
        String file = url.getFile();
        buff.append("GET ");
        buff.append(file);
        buff.append(" HTTP/1.1");
        buff.append("\r\n");
        buff.append("Host: ");
        buff.append(host);
        buff.append("\r\n");
        return StringUtil.getBytesRaw(buff.toString());
    }

    public static byte[] buildGetRequestByte(String urlString) throws MalformedURLException {
        return buildGetRequestByte(new URL(urlString));
    }

    public static String getBaseName(URL url) {
        String path[] = url.getPath().split("/");
        String name = (path.length > 0) ? path[path.length - 1] : "";
        if (name.equals("")) {
            name = url.getHost();
        }
        return name;
    }

    public static String normalizeURL(String value) {
        Pattern pattern = Pattern.compile("^(https?)://(.*?)(:(?:80|443))/");
        StringBuffer buff = new StringBuffer();
        Matcher m = pattern.matcher(value);
        if (m.find()) {
            String protocol = m.group(1);
            String port = m.group(3);
            if ("http:".startsWith(protocol) && ":80".equals(port)) {
                m.appendReplacement(buff, "$1://$2/");
            } else if ("https:".startsWith(protocol) && ":443".equals(port)) {
                m.appendReplacement(buff, "$1://$2/");
            }
        }
        m.appendTail(buff);
        return buff.toString();
    }

    public static Map.Entry<String, String> getParameter(String plain) {
        String s[] = plain.split("=", 2);
        if (s.length == 1) {
            return new AbstractMap.SimpleEntry<>(s[0], "");
        } else {
            return new AbstractMap.SimpleEntry<>(s[0], s[1]);
        }
    }

    public static Map.Entry<String, String> getHeader(String plain) {
        String s[] = plain.split(":", 2);
        if (s.length == 1) {
            return new AbstractMap.SimpleEntry<>(s[0], "");
        } else {
            return new AbstractMap.SimpleEntry<>(s[0], s[1].trim());
        }
    }

    private static final Pattern BASE_URI_CHANGE = Pattern.compile("(<head>)|(<body>|(<html>))", Pattern.CASE_INSENSITIVE);

    public static String changeBaseURI(String content, String topURL) {
        // かなり安易なBaseURIの設定
        // 差込位置
        int pos = 0;
        Matcher m = BASE_URI_CHANGE.matcher(content);
        if (m.find()) {
            pos = m.end();
        }
        StringBuilder buff = new StringBuilder(content);
        buff.insert(pos, String.format("<base href=\"%s\">", topURL));
        return buff.toString();
    }

    public static String toURL(String schema, String host, int port) {
        String url = String.format("%s://%s", schema, host);
        if (port != getDefaultPort(false) && port != getDefaultPort(true)) {
            url += ":" + port;
        }
        return url;
    }

    public static String toURL(String schema, String host, int port, String path) {
        return toURL(schema, host, port) + FileUtil.appendFirstSeparator(path, "/");
    }

    public static String getDefaultProtocol(boolean useHttps) {
        if (useHttps) {
            return "https";
        } else {
            return "http";
        }
    }

    public static int getDefaultPort(boolean useHttps) {
        if (useHttps) {
            return 443;
        } else {
            return 80;
        }
    }

    public static int getDefaultPort(String protocol) {
        if ("https".equals(protocol)) {
            return 443;
        } else if ("http".equals(protocol)) {
            return 80;
        } else {
            return -1;
        }
    }

    public static String getURLBasePath(String path) {
        int lastSep = path.lastIndexOf('/');
        if (lastSep > 0) {
            return path.substring(0, lastSep);
        } else if (lastSep == 0) {
            return "/";
        } else {
            return path;
        }
    }

    /**
     * 文字コードを判別する
     * 以下の移植 http://dobon.net/vb/dotnet/string/detectcode.html
     *
     * @param bytes 文字コードを調べるデータ
     * @return 適当と思われるEncoding、判断できなかった時はnull
     */
    public static String getGuessCode(byte[] bytes) {
        return getUniversalGuessCode(bytes, null);
    }

    public static int indexOfStartsWith(List<String> headers, String prefix) {
        for (int idx = 0; idx < headers.size(); idx++) {
            if (headers.get(idx).startsWith(prefix)) {
                return idx;
            }
        }
        return -1;
    }

    private final static Map<String, String> CHARSET_ALIAS = new HashMap<>();

    static {
        // universalchardet unknown support
        CHARSET_ALIAS.put("UTF-16BE", "UTF-16");
        CHARSET_ALIAS.put("HZ-GB-23121", "GB2312");
        CHARSET_ALIAS.put("X-ISO-10646-UCS-4-34121", "UTF-32");
        CHARSET_ALIAS.put("X-ISO-10646-UCS-4-21431", "UTF-32");
    }

    public static String normalizeCharset(String charsetName) {
        String aliasName = CHARSET_ALIAS.get(charsetName);
        if (aliasName == null) {
            try {
                Charset charst = Charset.forName(charsetName);
                return charst.name();
            } catch (IllegalCharsetNameException ex) {
                return null;
            } catch (IllegalArgumentException ex) {
                return null;
            }
        } else {
            return aliasName;
        }
    }

    public static String toHtmlEncode(String input) {
        StringBuilder buff = new StringBuilder();
        int length = input.length();
        for (int i = 0; i < length; i++) {
            char c = input.charAt(i);
            buff.append(toHtmlEncode(c));
        }
        return buff.toString();
    }

    public static String toHtmlEncode(char c) {
        StringBuilder buff = new StringBuilder();
        switch (c) {
            case '<':
                buff.append("&lt;");
                break;
            case '>':
                buff.append("&gt;");
                break;
            case '&':
                buff.append("&amp;");
                break;
            case '"':
                buff.append("&quot;");
                break;
            default:
                buff.append(c);
                break;
        }
        return buff.toString();
    }

    public static String getUniversalGuessCode(byte[] bytes) {
        return getUniversalGuessCode(bytes, null);
    }

    /**
     *
     * @param bytes 文字コードを調べるデータ
     * @return 適当と思われるEncoding、判断できなかった時はnull
     */
    public static String getUniversalGuessCode(byte[] bytes, String defaultCharset) {
        String guessCharset = null;
        ByteArrayInputStream fis = new ByteArrayInputStream(bytes);
        byte[] buf = new byte[4096];
        UniversalDetector detector = new UniversalDetector(null);
        int nread = -1;
        try {
            while ((nread = fis.read(buf)) >= 0 && !detector.isDone()) {
                detector.handleData(buf, 0, nread);
            }
        } catch (IOException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        detector.dataEnd();
        guessCharset = detector.getDetectedCharset();
        detector.reset();
        if (guessCharset == null) {
            guessCharset = defaultCharset;
        }
        return HttpUtil.normalizeCharset(guessCharset);
    }

    public static class StaticProxySelector extends ProxySelector {

        private static final List<Proxy> NO_PROXY_LIST = new ArrayList<>();

        static {
            NO_PROXY_LIST.add(Proxy.NO_PROXY);
        }

        private final List<Proxy> list = new ArrayList<>();

        public StaticProxySelector(Proxy proxy){
            Proxy p;
            if (proxy == null) {
                p = Proxy.NO_PROXY;
            } else {
                p = proxy;
            }
            list.add(p);
        }

        @Override
        public void connectFailed(URI uri, SocketAddress sa, IOException e) {
            /* ignore */
        }

        @Override
        public synchronized List<Proxy> select(URI uri) {
            String scheme = uri.getScheme().toLowerCase();
            if (scheme.equals("http") || scheme.equals("https")) {
                return list;
            } else {
                return NO_PROXY_LIST;
            }
        }

        public static ProxySelector of(Proxy proxy) {
            return new StaticProxySelector(proxy);
        }

    }

    public static class DummyOutputStream extends OutputStream {

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

}
