package extend.util.external;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
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
public class JsonUtilTest {

    public JsonUtilTest() {
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
     * Test of stringify method, of class JsonUtil.
     */
    @Test
    public void testStringify() {
        System.out.println("stringify");
        JsonObject jsonObject = new JsonObject();
        jsonObject.addProperty("abc", 123);
        jsonObject.addProperty("def", "test");
        String expResult = "{\"abc\":123,\"def\":\"test\"}";
        String result = JsonUtil.stringify(jsonObject);
        assertEquals(expResult, result);
    }

    /**
     * Test of parse method, of class JsonUtil.
     */
    @Test
    public void testParse() {
        System.out.println("parse");
        String jsonElementString = "{ \n \"abc\": 123, \n \"def\": \"test\" }";
        JsonElement result = JsonUtil.parse(jsonElementString);
        assertEquals(true, result.isJsonObject());
        assertEquals(true, result.getAsJsonObject().has("abc"));
        assertEquals(false, result.getAsJsonObject().has("xyz"));
    }

    /**
     * Test of prettyJson method, of class JsonUtil.
     */
    @Test
    public void testPrettyJSON_String_boolean() {
        System.out.println("prettyJSON");
        {
            String jsonElementString = "{ \n \"abc\": 123, \n \"def\": \"test\" }";
            boolean pretty = false;
            String expResult = "{\"abc\":123,\"def\":\"test\"}";
            String result = JsonUtil.prettyJson(jsonElementString, pretty);
            assertEquals(expResult, result);
        }
        {
            try {
                String jsonElementString = "<html>test</test>";
                boolean pretty = false;
                String expResult = "{\"abc\":123,\"def\":\"test\"}";
                String result = JsonUtil.prettyJson(jsonElementString, pretty);
                fail();
            } catch (JsonSyntaxException ex) {
                assertTrue(true);
            }
        }
    }

    /**
     * Test of prettyJson method, of class JsonUtil.
     */
    @Test
    public void testPrettyJSON_JsonElement_boolean() {
        System.out.println("prettyJSON");
        JsonObject jsonObject = new JsonObject();
        jsonObject.addProperty("abc", 123);
        jsonObject.addProperty("def", "test");
        boolean pretty = false;
        String expResult = "{\"abc\":123,\"def\":\"test\"}";
        String result = JsonUtil.prettyJson(jsonObject, pretty);
        assertEquals(expResult, result);
    }

    @Test
    public void testisJson() {
        System.out.println("isJson");        
        {
            String json = "{\"abc\":123,\"def\":\"test\"}";
            boolean result = JsonUtil.isJson(json);
            assertEquals(true, result);        
        }
        {
            String json = "{ \n \"abc\": 123, \n \"def\": \"test\" }";
            boolean result = JsonUtil.isJson(json);
            assertEquals(true, result);                
        }        
        {
            String json = "[\"abc\",\"def\",\"ghi\"]";
            boolean result = JsonUtil.isJson(json);
            assertEquals(true, result);        
        }
        {
            String json = "[\n \"abc\",\"def\",\"ghi\" \n]";
            boolean result = JsonUtil.isJson(json);
            assertEquals(true, result);                
        }
    }
    
    @Test
    public void testisJsonp() {
        System.out.println("isJsonp");
        {
            String json = "{\"abc\":123,\"def\":\"test\"}";
            boolean result = JsonUtil.isJsonp(json);
            assertEquals(false, result);        
        }

        {
            String json = "[\"abc\",\"def\",\"ghi\"]";
            boolean result = JsonUtil.isJsonp(json);
            assertEquals(false, result);                
        }

        {
            String json = "callback({ \"abc\": 123, \"def\": \"test\" });";
            boolean result = JsonUtil.isJsonp(json);
            assertEquals(true, result);                
        }        

        {
            String json = "_callback({ \"abc\": 123, \"def\": \"test\" });";
            boolean result = JsonUtil.isJsonp(json);
            assertEquals(true, result);                
        }        

        {
            String json = " callback ({ \"abc\": 123, \"def\": \"test\" });";
            boolean result = JsonUtil.isJsonp(json);
            assertEquals(true, result);                
        }        
        
        {
            String json = "window.open({ \"abc\": 123, \"def\": \"test\" });";
            boolean result = JsonUtil.isJsonp(json);
            assertEquals(true, result);                
        }        

        {
            String json = "$_({ \"abc\": 123, \"def\": \"test\" });";
            boolean result = JsonUtil.isJsonp(json);
            assertEquals(true, result);                
        }        
        {
            String json = "callback([\"abc\",\"def\",\"ghi\"])";
            boolean result = JsonUtil.isJsonp(json);
            assertEquals(false, result);        
        }

    }

    @Test
    public void testJsonpElement() {
        System.out.println("isJsonp");
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
            }
            catch (JsonSyntaxException ex) {
                fail();
            }
        }        
        {
            String json = "callback([\"abc\",\"def\",\"ghi\"])";
            try {
                JsonpElement jsonp = JsonpElement.parseJsonp(json);
                assertTrue(false);                    
            }
            catch (JsonSyntaxException ex) {
                assertTrue(true);                    
            }
        }

    }
    
}
