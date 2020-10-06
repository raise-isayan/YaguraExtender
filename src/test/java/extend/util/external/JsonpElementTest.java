package extend.util.external;

import com.google.gson.JsonSyntaxException;
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
public class JsonpElementTest {
    
    public JsonpElementTest() {
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
     * Test of parseJsonp method, of class JsonpElement.
     */
    @Test
    public void testParseJsonp() {
        System.out.println("parseJsonp");
        {
            String json = "{\"abc\":123,\"def\":\"test\"}";
            try {
                JsonpElement jsonp = JsonpElement.parseJsonp(json);
                assertTrue(false);                    
            }
            catch (JsonSyntaxException ex) {
                assertTrue(true);                    
            }
        }

        {
            String json = "[\"abc\",\"def\",\"ghi\"]";
            try {
                JsonpElement jsonp = JsonpElement.parseJsonp(json);
                assertTrue(false);                    
            }
            catch (JsonSyntaxException ex) {
                assertTrue(true);                    
            }
        }

        {
            String json = "callback({ \"abc\": 123, \"def\": \"test\" });";
            try {
                JsonpElement jsonp = JsonpElement.parseJsonp(json);
                assertEquals("callback", jsonp.getCallbackName());                
                assertEquals(json, jsonp.getRaw());                
            }
            catch (JsonSyntaxException ex) {
                fail();
            }
        }        

        {
            String json = "_callback({ \"abc\": 123, \"def\": \"test\" });";
            try {
                JsonpElement jsonp = JsonpElement.parseJsonp(json);
                assertEquals("_callback", jsonp.getCallbackName());                
                assertEquals(json, jsonp.getRaw());                
            }
            catch (JsonSyntaxException ex) {
                fail();
            }
        }        

        {
            String json = " callback ({ \"abc\": 123, \"def\": \"test\" });";
            try {
                JsonpElement jsonp = JsonpElement.parseJsonp(json);
                assertEquals("callback", jsonp.getCallbackName());                
                assertEquals(json, jsonp.getRaw());                
            }
            catch (JsonSyntaxException ex) {
                fail();
            }
        }        
        
        {
            String json = "window.open({ \"abc\": 123, \"def\": \"test\" });";
            try {
                JsonpElement jsonp = JsonpElement.parseJsonp(json);
                assertEquals("window.open", jsonp.getCallbackName());                
                assertEquals(json, jsonp.getRaw());                
            }
            catch (JsonSyntaxException ex) {
                fail();
            }
        }        

        {
            String json = "$_({ \"abc\": 123, \"def\": \"test\" });";
            try {
                JsonpElement jsonp = JsonpElement.parseJsonp(json);
                assertEquals("$_", jsonp.getCallbackName());                
                assertEquals(json, jsonp.getRaw());                
            }
            catch (JsonSyntaxException ex) {
                fail();
            }
        }        
        {
            String json = "callback([\"abc\",\"def\",\"ghi\"])";
            try {
                JsonpElement jsonp = JsonpElement.parseJsonp(json);
                assertEquals("callback", jsonp.getCallbackName());                
                assertEquals(json, jsonp.getRaw());                
            }
            catch (JsonSyntaxException ex) {
                fail();
            }
        }
        {
            String json = "callback({\"inarray\":[\"abc\",\"def\",\"ghi\"]})";
            try {
                JsonpElement jsonp = JsonpElement.parseJsonp(json);
                assertEquals("callback", jsonp.getCallbackName());                
                assertEquals(json, jsonp.getRaw());                
            }
            catch (JsonSyntaxException ex) {
                fail();
            }
        }
        {
            String json = "callback([{\"abc\":\"def\"},\"ghi\"])";
            try {
                JsonpElement jsonp = JsonpElement.parseJsonp(json);
                assertEquals("callback", jsonp.getCallbackName());                
                assertEquals(json, jsonp.getRaw());                
            }
            catch (JsonSyntaxException ex) {
                fail();
            }
        }
    }
            
}
