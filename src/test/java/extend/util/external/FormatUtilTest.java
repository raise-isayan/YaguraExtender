package extend.util.external;

import extend.util.external.FormatUtil;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author isayan
 */
public class FormatUtilTest {

    public FormatUtilTest() {
    }

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }

    @Before
    public void setUp() {
    }

    @After
    public void tearDown() {
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