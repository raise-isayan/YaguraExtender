package extension.burp.montoya;

import extension.burp.HttpCookie;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
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
public class HttpCookieTest {

    public HttpCookieTest() {
    }

    @BeforeAll
    public static void setUpClass() {
    }

    @AfterAll
    public static void tearDownClass() {
    }

    @BeforeEach
    public void setUp() {
    }

    @AfterEach
    public void tearDown() {
    }

    private final String COOKIE_EMPTY = "";
    private final String COOKIE0 = "SID";
    private final String COOKIE1 = "SID=31d4d96e407aad42";
    private final String COOKIE2 = "SID=;";
    private final String COOKIE3 = "SID=31d4d96e407aad42; Path=/; Domain=example.com";
    private final String COOKIE4 = "SID=31d4d96e407aad42; Path=/; Secure; HttpOnly";
    private final String COOKIE5 = "SID=31d4d96e407aad42; Path=/; Max-Age=65535; HttpOnly";

    private final String COOKIE11 = "lang=en-US; Expires=Wed, 09 Jun 2021 10:18:14 GMT";
    private final String COOKIE12 = "lang=; Expires=Sun, 06 Nov 1994 08:49:37 GMT";

    private final String COOKIE21 = "PHPSESSID=4b26fe6442cfdef8bec4120b01c63007; SameSite=None; Expires=Wed, 21 Oct 2015 07:28:00 GMT";

    private final String COOKIE_REQ = "SID=31d4d96e407aad42; lang=en-US;";

    /**
     * Test of parseResponse method, of class HttpCookie.
     */
    @Test
    public void testParseResponse() throws Exception {
        System.out.println("parseResponse");
        {
            try {
                String cookieString = COOKIE_EMPTY;
                HttpCookie result = HttpCookie.parseResponse(cookieString);
                fail();
            } catch (ParseException ex) {
                assertTrue(true);
            }
        }
        {
            try {
                String cookieString = COOKIE0;
                HttpCookie result = HttpCookie.parseResponse(cookieString);
                fail();
            } catch (ParseException ex) {
                assertTrue(true);
            }
        }
        {
            String cookieString = COOKIE1;
            HttpCookie result = HttpCookie.parseResponse(cookieString);
            assertEquals("SID", result.getName());
            assertEquals("31d4d96e407aad42", result.getValue());
            assertNull(result.domain());
            assertNull(result.path());
            assertNull(result.getExpiration());
            assertNull(result.getExpirationAsDate());
            assertEquals(-1, result.getMaxage());
            assertFalse(result.isHttpOnly());
            assertFalse(result.isSecure());
        }
        {
            String cookieString = COOKIE2;
            HttpCookie result = HttpCookie.parseResponse(cookieString);
            assertEquals("SID", result.getName());
            assertEquals("", result.getValue());
            assertNull(result.getDomain());
            assertNull(result.getPath());
            assertNull(result.getExpiration());
            assertNull(result.getExpirationAsDate());
            assertEquals(-1, result.getMaxage());
            assertFalse(result.isHttpOnly());
            assertFalse(result.isSecure());
        }
        {
            String cookieString = COOKIE3;
            HttpCookie result = HttpCookie.parseResponse(cookieString);
            assertEquals("SID", result.getName());
            assertEquals("31d4d96e407aad42", result.getValue());
            assertEquals("/", result.getPath());
            assertEquals("example.com", result.getDomain());
            assertNull(result.getExpiration());
            assertEquals(-1, result.getMaxage());
            assertFalse(result.isHttpOnly());
            assertFalse(result.isSecure());
        }
        {
            String cookieString = COOKIE4;
            HttpCookie result = HttpCookie.parseResponse(cookieString);
            assertEquals("SID", result.getName());
            assertEquals("31d4d96e407aad42", result.getValue());
            assertEquals("/", result.getPath());
            assertNull(result.getDomain());
            assertNull(result.getExpiration());
            assertEquals(-1, result.getMaxage());
            assertTrue(result.isHttpOnly());
            assertTrue(result.isSecure());
        }
        {
            String cookieString = COOKIE5;
            HttpCookie result = HttpCookie.parseResponse(cookieString);
            assertEquals("SID", result.getName());
            assertEquals("31d4d96e407aad42", result.getValue());
            assertEquals("/", result.getPath());
            assertNull(result.getDomain());
            assertNull(result.getExpiration());
            assertEquals(65535, result.getMaxage());
            assertTrue(result.isHttpOnly());
            assertFalse(result.isSecure());
        }
    }

    /**
     * Test of parseRequest method, of class HttpCookie.
     */
    @Test
    public void testParseRequest() throws Exception {
        System.out.println("parseRequest");
        {
            String cookieString = COOKIE_EMPTY;
            HttpCookie[] result = HttpCookie.parseResuest(cookieString);
            assertEquals(0, result.length);
        }
        {
            String cookieString = COOKIE1;
            HttpCookie[] result = HttpCookie.parseResuest(cookieString);
            assertEquals(1, result.length);
            assertEquals("SID", result[0].getName());
            assertEquals("31d4d96e407aad42", result[0].getValue());
            assertNull(result[0].getDomain());
            assertNull(result[0].getPath());
            assertNull(result[0].getExpiration());
            assertEquals(-1, result[0].getMaxage());
            assertFalse(result[0].isHttpOnly());
            assertFalse(result[0].isSecure());
        }
        {
            String cookieString = COOKIE_REQ;
            HttpCookie[] result = HttpCookie.parseResuest(cookieString);
            assertEquals(2, result.length);
            assertEquals("SID", result[0].getName());
            assertEquals("31d4d96e407aad42", result[0].getValue());
            assertEquals("lang", result[1].getName());
            assertEquals("en-US", result[1].getValue());
        }
    }

    /**
     */
    @Test
    public void testExpiration() throws Exception {
        System.out.println("expiration");
        {
            SimpleDateFormat fmt = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss zzz", Locale.ENGLISH);
            Date expirationDate = fmt.parse("Wed, 09 Jun 2021 10:18:14 GMT");
            String cookieString = COOKIE11;
            HttpCookie result = HttpCookie.parseResponse(cookieString);
            assertEquals("lang", result.getName());
            assertEquals("en-US", result.getValue());
            assertNull(result.getPath());
            assertNull(result.getDomain());
            assertEquals(fmt.format(expirationDate), fmt.format(result.getExpirationAsDate()));
            assertEquals(-1, result.getMaxage());
            assertFalse(result.isHttpOnly());
            assertFalse(result.isSecure());
        }
    }

    /**
     */
    @Test
    public void testExpirationRemove() throws Exception {
        System.out.println("expirationRemove");
        {
            SimpleDateFormat fmt = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss zzz", Locale.ENGLISH);
            Date expirationDate = fmt.parse("Sun, 06 Nov 1994 08:49:37 GMT");
            String cookieString = COOKIE12;
            HttpCookie result = HttpCookie.parseResponse(cookieString);
            assertEquals("lang", result.getName());
            assertEquals("", result.getValue());
            assertNull(result.getPath());
            assertNull(result.getDomain());
            assertEquals(fmt.format(expirationDate), fmt.format(result.getExpirationAsDate()));
            assertEquals(-1, result.getMaxage());
            assertFalse(result.isHttpOnly());
            assertFalse(result.isSecure());
        }
    }

    /**
     * Test of toString method, of class HttpCookie.
     */
    @Test
    public void testCookie() {
        System.out.println("Cookie");
        {
            try {
                SimpleDateFormat fmt = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss zzz", Locale.ENGLISH);
                Date expirationDate = fmt.parse("Wed, 09 Jun 2021 10:18:14 GMT");
                String cookieString = COOKIE11;
                HttpCookie build = HttpCookie.parseResponse(cookieString);
                System.out.println(build.toString());
                HttpCookie result = HttpCookie.parseResponse(build.toString());
                assertEquals("lang", result.getName());
                assertEquals("en-US", result.getValue());
                assertNull(result.getPath());
                assertNull(result.getDomain());
                assertEquals(fmt.format(expirationDate), fmt.format(result.getExpirationAsDate()));
                assertEquals(-1, result.getMaxage());
                assertFalse(result.isHttpOnly());
                assertFalse(result.isSecure());
                assertNull(result.getSameSite());
            } catch (ParseException ex) {
                fail();
            }
        }
        {
            try {
                SimpleDateFormat fmt = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss zzz", Locale.ENGLISH);
                Date expirationDate = fmt.parse("Sun, 06 Nov 1994 08:49:37 GMT");
                String cookieString = COOKIE12;
                HttpCookie build = HttpCookie.parseResponse(cookieString);
                System.out.println(build.toString());
                HttpCookie result = HttpCookie.parseResponse(build.toString());
                assertEquals("lang", result.getName());
                assertEquals("", result.getValue());
                assertNull(result.getPath());
                assertNull(result.getDomain());
                assertEquals(fmt.format(expirationDate), fmt.format(result.getExpirationAsDate()));
                assertEquals(-1, result.getMaxage());
                assertFalse(result.isHttpOnly());
                assertFalse(result.isSecure());
                assertNull(result.getSameSite());
            } catch (ParseException ex) {
                fail();
            }
        }
    }

    /**
     * Test of toString method, of class HttpCookie.
     */
    @Test
    public void testCookie2() {
        System.out.println("Cookie2");
        {
            try {
                SimpleDateFormat fmt = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss zzz", Locale.ENGLISH);
                Date expirationDate = fmt.parse("Wed, 21 Oct 2015 07:28:00 GMT");
                String cookieString = COOKIE21;
                HttpCookie build = HttpCookie.parseResponse(cookieString);
                System.out.println(build.toString());
                HttpCookie result = HttpCookie.parseResponse(build.toString());
                assertEquals("PHPSESSID", result.getName());
                assertEquals("4b26fe6442cfdef8bec4120b01c63007", result.getValue());
                assertNull(result.getPath());
                assertNull(result.getDomain());
                assertEquals(fmt.format(expirationDate), fmt.format(result.getExpirationAsDate()));
                assertEquals(-1, result.getMaxage());
                assertFalse(result.isHttpOnly());
                assertFalse(result.isSecure());
                assertEquals(result.getSameSite(), "None");
            } catch (ParseException ex) {
                fail();
            }
        }
    }

}
