package extension.helpers;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.InetSocketAddress;
import java.net.URL;
import java.net.MalformedURLException;
import java.net.Proxy;
import java.net.Proxy.Type;
import java.net.ProxySelector;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;

/**
 *
 * @author isayan
 */
public class HttpUtilTest {

    private final static Logger logger = Logger.getLogger(HttpUtilTest.class.getName());

    public HttpUtilTest() {
    }

    @BeforeAll
    public static void setUpClass() throws Exception {
    }

    @AfterAll
    public static void tearDownClass() throws Exception {
    }

    @BeforeEach
    public void setUp() {
    }

    @AfterEach
    public void tearDown() {
    }

    /**
     * Test of buildHost method, of class HttpUtil.
     */
    @Test
    public void testBuildHost() {
        assertEquals("example.com", HttpUtil.buildHost("example.com", 80, false));
        assertEquals("example.com:443", HttpUtil.buildHost("example.com", 443, false));
        assertEquals("example.com", HttpUtil.buildHost("example.com", 443, true));
        assertEquals("example.com:80", HttpUtil.buildHost("example.com", 80, true));
        assertEquals("example.com:8080", HttpUtil.buildHost("example.com", 8080, false));
        assertEquals("example.com:8443", HttpUtil.buildHost("example.com", 8443, true));
        assertEquals("example.com", HttpUtil.buildHost("example.com", -1, true));
        assertEquals("example.com", HttpUtil.buildHost("example.com", -1, false));
    }

    /**
     * Test of isValidUrl method, of class HttpUtil.
     */
    @Test
    public void testIsValidUrl() {
        System.out.println("isValidUrl");
        assertEquals(true, HttpUtil.isValidUrl("http://example.com/dir/file/path.exe?1328319481"));
        assertEquals(true, HttpUtil.isValidUrl("http://example.com/dir/file/?<xss>"));
        assertEquals(false, HttpUtil.isValidUrl("http<xss>://example.com/dir/file/"));
    }

    /**
     * Test of startsWithHttp method, of class HttpUtil.
     */
    @Test
    public void testStartsWithHttp() {
        System.out.println("startsWithHttp");
        assertEquals(true, HttpUtil.startsWithHttp("http://"));
        assertEquals(true, HttpUtil.startsWithHttp("https://"));
        assertEquals(false, HttpUtil.startsWithHttp("shttp://"));
        assertEquals(false, HttpUtil.startsWithHttp("httpx://"));
    }

    /**
     * Test of isSSL method, of class HttpUtil.
     */
    @Test
    public void testIsSSL() {
        System.out.println("testIsSSL");
        assertEquals(false, HttpUtil.isSSL("http"));
        assertEquals(true, HttpUtil.isSSL("https"));
        assertEquals(false, HttpUtil.isSSL("shttp"));
        assertEquals(false, HttpUtil.isSSL("httpx"));
    }

    /**
     * Test of normalizeURL method, of class HttpUtil.
     */
    @Test
    public void testNormalizeURL() {
        System.out.println("normalizeURL");
        assertEquals("http://example.com/", HttpUtil.normalizeURL("http://example.com:80/"));
        assertEquals("http://example.com:8080/", HttpUtil.normalizeURL("http://example.com:8080/"));
        assertEquals("https://example.com:4438/", HttpUtil.normalizeURL("https://example.com:4438/"));
        assertEquals("https://example.com/", HttpUtil.normalizeURL("https://example.com:443/"));
        assertEquals("http://example.com/xxx", HttpUtil.normalizeURL("http://example.com:80/xxx"));
        assertEquals("https://example.com/xxx", HttpUtil.normalizeURL("https://example.com:443/xxx"));
        assertEquals("https://example.com:8443/xxx", HttpUtil.normalizeURL("https://example.com:8443/xxx"));
        assertEquals("https://example.com/xxx", HttpUtil.normalizeURL("https://example.com:443/xxx"));
    }

    /**
     * Test of testBaseName method, of class HttpUtil.
     */
    @Test
    public void testBaseName() {
        System.out.println("testBaseName");
        try {
            assertEquals("path.exe", HttpUtil.getBaseName(new URL("http://example.com/dir/file/path.exe?1328319481")));
            assertEquals("file", HttpUtil.getBaseName(new URL("http://example.com/dir/file/?1328319481")));
            assertEquals("dir", HttpUtil.getBaseName(new URL("http://example.com/dir?1328319481")));
            assertEquals("example.com", HttpUtil.getBaseName(new URL("http://example.com/?1328319481")));
        } catch (MalformedURLException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
            fail(ex.getMessage());
        }
    }

    /**
     * Test of buildGetRequestByte method, of class HttpUtil.
     */
    @Test
    public void testBuildGetRequestByte() {
        System.out.println("testBuildGetRequestByte");
        try {
            assertEquals("GET / HTTP/1.1\r\nHost: example.com\r\n", (StringUtil.getStringRaw(HttpUtil.buildGetRequestByte("http://example.com/"))));
            assertEquals("GET / HTTP/1.1\r\nHost: example.com:443\r\n", (StringUtil.getStringRaw(HttpUtil.buildGetRequestByte("http://example.com:443/"))));
            assertEquals("GET /?xxx=yyy&ccc=ddd HTTP/1.1\r\nHost: example.com\r\n", (StringUtil.getStringRaw(HttpUtil.buildGetRequestByte("https://example.com:443/?xxx=yyy&ccc=ddd"))));
            assertEquals("GET /?xxx=yyy&ccc=ddd HTTP/1.1\r\nHost: example.com:8443\r\n", (StringUtil.getStringRaw(HttpUtil.buildGetRequestByte("http://example.com:8443/?xxx=yyy&ccc=ddd"))));
            assertEquals("GET /?xxx=yyy&ccc=ddd HTTP/1.1\r\nHost: example.com\r\n", (StringUtil.getStringRaw(HttpUtil.buildGetRequestByte("https://example.com:443/?xxx=yyy&ccc=ddd#test123"))));
            assertEquals("GET /?xxx=yyy&ccc=ddd HTTP/1.1\r\nHost: example.com:8443\r\n", (StringUtil.getStringRaw(HttpUtil.buildGetRequestByte("http://example.com:8443/?xxx=yyy&ccc=ddd#test123"))));
            assertEquals("GET /?abc=123 HTTP/1.1\r\nHost: example.com\r\n", (StringUtil.getStringRaw(HttpUtil.buildGetRequestByte("http://example.com/?abc=123"))));
            assertEquals("GET /dir/file/?abc=123 HTTP/1.1\r\nHost: example.com\r\n", (StringUtil.getStringRaw(HttpUtil.buildGetRequestByte("http://example.com/dir/file/?abc=123"))));
            assertEquals("GET /dir/file?abc=123 HTTP/1.1\r\nHost: example.com\r\n", (StringUtil.getStringRaw(HttpUtil.buildGetRequestByte("http://example.com/dir/file?abc=123"))));
        } catch (MalformedURLException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
            fail(ex.getMessage());
        }
    }

    /**
     * Test of testGetParameter method, of class HttpUtil.
     */
    @Test
    public void testGetParameter() {
        System.out.println("testGetParameter");
        {
            Map.Entry keyval = HttpUtil.getParameter("abc");
            assertEquals("abc", keyval.getKey());
            assertEquals("", keyval.getValue());
        }
        {
            Map.Entry keyval = HttpUtil.getParameter("abc=edf");
            assertEquals("abc", keyval.getKey());
            assertEquals("edf", keyval.getValue());
        }
        {
            Map.Entry keyval = HttpUtil.getParameter("abc=edf=fgh");
            assertEquals("abc", keyval.getKey());
            assertEquals("edf=fgh", keyval.getValue());
        }
        {
            Map.Entry keyval = HttpUtil.getParameter("=");
            assertEquals("", keyval.getKey());
            assertEquals("", keyval.getValue());
        }
        {
            Map.Entry keyval = HttpUtil.getParameter("==");
            assertEquals("", keyval.getKey());
            assertEquals("=", keyval.getValue());
        }
    }

    /**
     * Test of testGetDefaultProtocol method, of class HttpUtil.
     */
    @Test
    public void testGetDefaultProtocol() {
        System.out.println("testGetDefaultProtocol");
        assertEquals("https", HttpUtil.getDefaultProtocol(true));
        assertEquals("http", HttpUtil.getDefaultProtocol(false));
    }

    /**
     * Test of testGetDefaultProtocol method, of class HttpUtil.
     */
    @Test
    public void testGetDefaultPort() {
        System.out.println("testGetDefaultPort");
        assertEquals(443, HttpUtil.getDefaultPort(true));
        assertEquals(80, HttpUtil.getDefaultPort(false));
    }

    /**
     * Test of testGetDefaultProtocol method, of class HttpUtil.
     */
    @Test
    public void testGetDefaultPort_String() {
        System.out.println("testGetDefaultPort_String");
        assertEquals(443, HttpUtil.getDefaultPort("https"));
        assertEquals(80, HttpUtil.getDefaultPort("http"));
        assertEquals(-1, HttpUtil.getDefaultPort("httpxxx"));
    }

    /**
     * Test of testMultipart method, of class HttpUtil.
     */
    @Test
    public void testMultipart() {
        try {
            String boundary = HttpUtil.generateBoundary();
            {
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                HttpUtil.outMultipartText(boundary, out, "host", "www.exmple.com");
                String result = StringUtil.getStringUTF8(out.toByteArray());
                assertTrue(result.contains("www.exmple.com"));
            }
            {
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                HttpUtil.outMultipartText(boundary, out, "port", StringUtil.toString(8080));
                String result = StringUtil.getStringUTF8(out.toByteArray());
                assertTrue(result.contains("8080"));
            }
            {
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                HttpUtil.outMultipartText(boundary, out, "protocol", "https");
                String result = StringUtil.getStringUTF8(out.toByteArray());
                assertTrue(result.contains("https"));
            }
            {
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                HttpUtil.outMultipartText(boundary, out, "url", "https://www.example.com/");
                String result = StringUtil.getStringUTF8(out.toByteArray());
                assertTrue(result.contains("https://www.example.com/"));
            }
            {
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                HttpUtil.outMultipartText(boundary, out, "comment", "コメント", StandardCharsets.UTF_8);
                String result = StringUtil.getStringUTF8(out.toByteArray());
                assertTrue(result.contains("コメント"));
            }
            {
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                HttpUtil.outMultipartText(boundary, out, "comment", "コメント");
                String result = StringUtil.getStringUTF8(out.toByteArray());
                assertFalse(result.contains("コメント"));
            }
        } catch (IOException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
            fail(ex.getMessage());
        }

    }

    /**
     */
    @Test
    public void testGetUniversalGuessCode() {
        System.out.println("testGetUniversalGuessCode");
        {
            try {
                assertEquals("US-ASCII", HttpUtil.getUniversalGuessCode("0123456ABCDEF".getBytes("UTF-8"), "US-ASCII"));
                assertEquals("Shift_JIS", HttpUtil.getUniversalGuessCode("入口入口入口入口".getBytes("Shift_JIS")));
                assertEquals("EUC-JP", HttpUtil.getUniversalGuessCode("入口入口入口入口".getBytes("EUC-JP")));
                assertEquals("UTF-8", HttpUtil.getUniversalGuessCode("入口入口入口入口".getBytes("UTF-8")));
//                assertEquals("UTF-16", HttpUtil.getUniversalGuessCode("ABCDEFGHIJKLMNOPQRSTUVWXYZあいうえおかきくけこ".getBytes("UTF-16BE")));
//                assertEquals("UTF-16", HttpUtil.getUniversalGuessCode("ABCDEFGHIJKLMNOPQRSTUVWXYZあいうえおかきくけこ".getBytes("UTF-16LE"))); // UTF-16LE になるのがベスト
                assertEquals("UTF-16", HttpUtil.getUniversalGuessCode("ABCDEFGHIJKLMNOPQRSTUVWXYZあいうえおかきくけこ".getBytes("UTF-16")));
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
                fail(ex.getMessage());
            }
        }

        {
            try {
                String expResult = "Shift_JIS";
                String expValue = "あいうえお";
                String guessCharset = HttpUtil.getUniversalGuessCode(expValue.getBytes("Shift_JIS"), "UTF-8");
                assertEquals(expResult, guessCharset);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
                fail(ex.getMessage());
            }
        }

        {
            try {
                String expResult = "Shift_JIS";
                String expValue = "①②③④⑤⑥⑦ⅩⅨあいうえおかきくけこ";
                String guessCharset = HttpUtil.getUniversalGuessCode(expValue.getBytes("MS932"), "UTF-8");
                assertEquals(expResult, guessCharset);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
                fail(ex.getMessage());
            }
        }

        {
            try {
                String expResult = "EUC-JP";
                String expValue = "あいうえお";
                String guessCharset = HttpUtil.getUniversalGuessCode(expValue.getBytes("EUC-JP"), "UTF-8");
                assertEquals(expResult, guessCharset);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
                fail(ex.getMessage());
            }
        }

        {
            try {
                String expResult = "ISO-2022-JP";
                String expValue = "あいうえお";
                String guessCharset = HttpUtil.getUniversalGuessCode(expValue.getBytes("ISO-2022-JP"), "UTF-8");
                assertEquals(expResult, guessCharset);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
                fail(ex.getMessage());
            }
        }

    }

    /**
     */
    @Test
    public void testUniversalCharCode() {
        System.out.println("testUniversalCharCode");
        // Chinese
        String[] list = {
            "ISO-2022-CN",
            "BIG5",
            "EUC-TW",
            "GB18030",
            "HZ-GB-23121",
            // Cyrillic
            "ISO-8859-5",
            "KOI8-R",
            "WINDOWS-1251",
            // MACCYRILLIC
            "IBM866",
            "IBM855",
            // Greek
            "ISO-8859-7",
            "WINDOWS-1253",
            // Hebrew
            "ISO-8859-8",
            "WINDOWS-1255",
            // Japanese
            "ISO-2022-JP",
            "SHIFT_JIS",
            "EUC-JP",
            // Korean
            "ISO-2022-KR",
            "EUC-KR",
            // Unicode
            "UTF-8",
            "UTF-16BE",
            "UTF-16LE",
            "UTF-32BE",
            "UTF-32LE",
            "X-ISO-10646-UCS-4-34121", // unk
            "X-ISO-10646-UCS-4-21431", // unk
            // Others
            "WINDOWS-1252",};
        for (String l : list) {
            String normChar = HttpUtil.normalizeCharset(l);
            if (normChar == null) {
                System.out.println("unk=" + l);

            } else {
                if (l.compareToIgnoreCase(normChar) != 0) {
                    System.out.println(l + "=" + normChar);
                }
            }

        }

    }

    @Test
    public void testLocale() {
        System.out.println(Locale.JAPANESE.toString());
        System.out.println(Locale.JAPANESE.getCountry());
        System.out.println(Locale.JAPANESE.getDisplayLanguage());
        System.out.println(Locale.JAPANESE.getDisplayName());
        System.out.println(Locale.JAPANESE.toLanguageTag());
        System.out.println(Locale.JAPANESE.getISO3Language());
        System.out.println(Locale.JAPANESE.getLanguage());
        System.out.println(Locale.JAPANESE.getDisplayScript());
        System.out.println(Locale.JAPANESE.getVariant());
        System.out.println(Locale.JAPANESE.toLanguageTag());
    }

    /**
     * Test of testNormalizeCharset method, of class HttpUtil.
     */
    @Test
    public void testNormalizeCharset() {
        System.out.println("testNormalizeCharset");
        assertEquals("Shift_JIS", HttpUtil.normalizeCharset("Shift_JIS"));
        assertEquals("Shift_JIS", HttpUtil.normalizeCharset("Shift-JIS"));
        assertEquals("Shift_JIS", HttpUtil.normalizeCharset("shift_jis"));
        assertEquals("windows-31j", HttpUtil.normalizeCharset("Windows-31J"));
        assertEquals("windows-31j", HttpUtil.normalizeCharset("MS932"));
        assertEquals(StringUtil.DEFAULT_ENCODING, HttpUtil.normalizeCharset(StringUtil.DEFAULT_ENCODING));
        assertEquals(null, HttpUtil.normalizeCharset(null));
    }

    /**
     * Test of StaticProxySelector class, of class HttpUtil.
     */
    @Test
    public void testStaticProxySelector() {
        System.out.println("staticProxySelector");
        Proxy localProxy = new Proxy(Type.HTTP, new InetSocketAddress("localhost", 8080));
        try {
            ProxySelector proxySelector = HttpUtil.StaticProxySelector.of(localProxy);
            List proxy = proxySelector.select(new URI("https://localhost"));
            assertEquals(1, proxy.size());
            assertEquals(localProxy, proxy.get(0));
        } catch (URISyntaxException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
            fail(ex.getMessage());
        }
        try {
            ProxySelector proxySelector = new HttpUtil.StaticProxySelector(localProxy);
            List proxy = proxySelector.select(new URI("https://localhost"));
            assertEquals(1, proxy.size());
            assertEquals(localProxy, proxy.get(0));
        } catch (URISyntaxException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
            fail(ex.getMessage());
        }
        try {
            ProxySelector proxySelector = new HttpUtil.StaticProxySelector(null);
            List proxy = proxySelector.select(new URI("https://localhost"));
            assertEquals(1, proxy.size());
            assertEquals(Proxy.NO_PROXY, proxy.get(0));
        } catch (URISyntaxException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
            fail(ex.getMessage());
        }
    }

}
