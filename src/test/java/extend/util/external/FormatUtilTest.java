package extend.util.external;

import extension.helpers.json.JsonUtil;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
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
public class FormatUtilTest {

    private final static Logger logger = Logger.getLogger(FormatUtilTest.class.getName());

    public FormatUtilTest() {
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
     * Test of isURL method, of class FormatUtil.
     */
    @Test
    public void testURL() {
        try {
            System.out.println("URL");
            String plainURL = "http://example.com:333/aaa/test?aaa#xxxx";
            URL url = new URL(plainURL);
            System.out.println(url.getFile());
        } catch (MalformedURLException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
            fail();
        }
        try {
            System.out.println("URL");
            String plainURL = "http://example.com/aaa/test?aaa#xxxx";
            URL url = new URL(plainURL);
            System.out.println(url.getFile());
            System.out.println(url.getPort());
        } catch (MalformedURLException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
            fail();
        }

    }

    /**
     * Test of isURL method, of class FormatUtil.
     */
    @Test
    public void testIsURL_http() {
        System.out.println("isURL");
        String plainURL = "http://example.com/";
        boolean expResult = true;
        boolean result = FormatUtil.isUrl(plainURL);
        assertEquals(expResult, result);
    }

    @Test
    public void testIsURL_https() {
        System.out.println("isURL");
        String plainURL = "https://example.com/";
        boolean expResult = true;
        boolean result = FormatUtil.isUrl(plainURL);
        assertEquals(expResult, result);
    }

    @Test
    public void testIsURL_file() {
        System.out.println("isURL");
        {
            String plainURL = "file://example.com/";
            boolean expResult = false;
            boolean result = FormatUtil.isUrl(plainURL);
            assertEquals(expResult, result);
        }
        {
            String plainURL = "httpsfile://example.com/";
            boolean expResult = false;
            boolean result = FormatUtil.isUrl(plainURL);
            assertEquals(expResult, result);
        }
    }

    /**
     * Test of isXML method, of class FormatUtil.
     */
    @Test
    public void testIsXML() {
        System.out.println("isXML1");
        {
            String plainXML = "<root><a/><x>z</x></root>";
            boolean expResult = true;
            boolean result = FormatUtil.isXml(plainXML);
            assertEquals(expResult, result);
            try {
                FormatUtil.prettyXml(plainXML, false);
            } catch (IOException ex) {
                fail();
            }
        }

        System.out.println("isXML2");
        {
            String plainXML = "<root><a/>\r\n<x>z</x>\r\n</root>";
            boolean expResult = true;
            boolean result = FormatUtil.isXml(plainXML);
            assertEquals(expResult, result);
            try {
                FormatUtil.prettyXml(plainXML, false);
            } catch (IOException ex) {
                fail();
            }
        }

        System.out.println("isXML3");
        {
            String plainXML = "<root><a/>\r\n<x>z</x><z/><z/>\r\n</root>";
            boolean expResult = true;
            boolean result = FormatUtil.isXml(plainXML);
            assertEquals(expResult, result);
            try {
                FormatUtil.prettyXml(plainXML, false);
            } catch (IOException ex) {
                fail();
            }
        }

        System.out.println("isXML4");
        {
            String plainXML = "\r\n<root><a/>\r\n<x>z</x><z/><z/>\r\n</root>\r\n";
            boolean expResult = true;
            boolean result = FormatUtil.isXml(plainXML);
            assertEquals(expResult, result);
            try {
                FormatUtil.prettyXml(plainXML, false);
            } catch (IOException ex) {
                fail();
            }
        }

        System.out.println("isXML5");
        {
            String plainXML = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                    + "\r\n<root><a/>\r\n<x>z</x><z/><z/>\r\n</root>\r\n";
            boolean expResult = true;
            boolean result = FormatUtil.isXml(plainXML);
            assertEquals(expResult, result);
            try {
                FormatUtil.prettyXml(plainXML, false);
            } catch (IOException ex) {
                fail();
            }
        }

        System.out.println("isXML6");
        {
            String plainXML = "<root><a/>\r>>>>\n<x>z</x><z/><z/>\r\n</root>\r\n";
            boolean expResult = true;
            boolean result = FormatUtil.isXml(plainXML);
            assertEquals(expResult, result);
            try {
                FormatUtil.prettyXml(plainXML, false);
            } catch (IOException ex) {
                fail();
            }
        }

        System.out.println("isXML7");
        {
            String plainXML = "<root><a/>\r<<<<\n<x>z</x><z/><z/>\r\n</root>\r\n";
            boolean expResult = false;
            boolean result = FormatUtil.isXml(plainXML);
            assertEquals(expResult, result);
            try {
                FormatUtil.prettyXml(plainXML, false);
                fail();
            } catch (IOException ex) {
                assertTrue(true);
            }
        }

    }

    /**
     * Test of isJSON method, of class FormatUtil.
     */
    @Test
    public void testIsJSON() {
        System.out.println("isJSON1");
        {
            String plainJson = "[1,true,\"word\"]";
            boolean expResult = true;
            boolean result = FormatUtil.isJson(plainJson);
            assertEquals(expResult, result);
        }

        System.out.println("isJSON2");
        {
            String plainJson = "{\"key\":\"value\"}";
            boolean expResult = true;
            boolean result = FormatUtil.isJson(plainJson);
            assertEquals(expResult, result);
        }

        System.out.println("isJSON3");
        {
            String plainJson = "\r\n\t[1,true,\"word\"]\r\n\t";
            boolean expResult = true;
            boolean result = FormatUtil.isJson(plainJson);
            assertEquals(expResult, result);
        }

        System.out.println("isJSON4");
        {
            String plainJson = "\r\n\t[1,true,\r\n\"word\"]\r\n\t";
            boolean expResult = true;
            boolean result = FormatUtil.isJson(plainJson);
            assertEquals(expResult, result);
        }

        System.out.println("isJSON5");
        {
            String plainJson = "\r\n\t{\"key\":\"value\"}\t\r\n";
            boolean expResult = true;
            boolean result = FormatUtil.isJson(plainJson);
            assertEquals(expResult, result);
        }

        System.out.println("isJSON6");
        {
            String plainJson = "\r\n\t{\"key\":\r\n\"value\"}\t\r\n";
            boolean expResult = true;
            boolean result = FormatUtil.isJson(plainJson);
            assertEquals(expResult, result);
        }

        System.out.println("isJSON7");
        {
            String plainJson = "[\n    1,\n    true,\n    \"word\"\n]";
            boolean expResult = true;
            boolean result = FormatUtil.isJson(plainJson);
            assertEquals(expResult, result);
        }

        System.out.println("isJSON8");
        {
            // 本来はJSONとして有効だが falseを返す仕様
            String plainJson = "\"key\"";
            boolean expResult = false;
            boolean result = FormatUtil.isJson(plainJson);
            assertEquals(expResult, result);
        }

        System.out.println("isJSON9");
        {
            String plainJson = "\"key\"";
            boolean expResult = true;
            boolean result = JsonUtil.validJson(plainJson);
            assertEquals(expResult, result);
        }

    }

    /**
     * Test of prettyJSON method, of class FormatUtil.
     */
    @Test
    public void testPrettyJSON() throws Exception {
        System.out.println("prettyJSON");
        String plainJson = "[1,true,\"word\"]";
        String expResult = "[\n  1,\n  true,\n  \"word\"\n]";
        String result = FormatUtil.prettyJson(plainJson);
        assertEquals(expResult, result);
    }

}
