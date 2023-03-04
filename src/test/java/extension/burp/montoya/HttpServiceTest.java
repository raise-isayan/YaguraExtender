package extension.burp.montoya;

import extension.burp.HttpTarget;
import java.net.MalformedURLException;
import java.net.URL;
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
public class HttpServiceTest {

    public HttpServiceTest() {
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

    /**
     * Test of getURLString method, of class HttpTarget.
     */
    @Test
    public void testGetURL() {
        System.out.println("getURL");
        try {
            HttpTarget httpTarget = HttpTarget.getHttpTarget("www.example.jp", 80, "http");
            String expResult = "http://www.example.jp/";
            HttpTarget result = new HttpTarget(new URL(expResult));
            assertEquals(httpTarget.getHost(), result.getHost());
            assertEquals(httpTarget.host(), result.host());
            assertEquals(httpTarget.getPort(), result.getPort());
            assertEquals(httpTarget.port(), result.port());
            assertEquals(httpTarget.isSecure(), result.isSecure());
            assertEquals(httpTarget.secure(), result.secure());
            assertFalse(result.isSecure());
        } catch (MalformedURLException ex) {
            fail();
        }
    }

    /**
     * Test of getURLString method, of class HttpTarget.
     */
    @Test
    public void testGetURLString() {
        System.out.println("getURLString");
        {
            HttpTarget httpService = HttpTarget.getHttpTarget("www.example.jp", 80, "http");
            String expResult = "http://www.example.jp/";
            String result = HttpTarget.toURLString(httpService);
            assertEquals(expResult, result);
        }
        {
            HttpTarget httpService = HttpTarget.getHttpTarget("www.example.jp", 8080, "http");
            String expResult = "http://www.example.jp:8080/";
            String result = HttpTarget.toURLString(httpService);
            assertEquals(expResult, result);
        }
        {
            HttpTarget httpService = HttpTarget.getHttpTarget("www.example.jp", 443, "https");
            String expResult = "https://www.example.jp/";
            String result = HttpTarget.toURLString(httpService);
            assertEquals(expResult, result);
        }
        {
            HttpTarget httpService = HttpTarget.getHttpTarget("www.example.jp", 8443, "https");
            String expResult = "https://www.example.jp:8443/";
            String result = HttpTarget.toURLString(httpService);
            assertEquals(expResult, result);
        }
    }

    /**
     * Test of getHttpService method, of class HttpTarget.
     */
    @Test
    public void testGetHttpService_3args_1() {
        System.out.println("getHttpService");
        String host = "www.exampe.com";
        int port = 443;
        String protocol = "https";
        HttpTarget result = HttpTarget.getHttpTarget(host, port, protocol);
        assertEquals(host, result.getHost());
        assertEquals(443, result.getPort());
        assertTrue(result.isSecure());
    }

    /**
     * Test of getHttpService method, of class HttpTarget.
     */
    @Test
    public void testGetHttpService_3args_2() {
        System.out.println("getHttpService");
        String host = "www.exampe.com";
        int port = 8080;
        boolean useHttps = false;
        HttpTarget result = HttpTarget.getHttpTarget(host, port, useHttps);
        assertEquals(host, result.getHost());
        assertEquals(8080, result.getPort());
        assertFalse(result.isSecure());

    }

}
