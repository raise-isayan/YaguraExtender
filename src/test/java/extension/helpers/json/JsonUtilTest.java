package extension.helpers.json;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonSyntaxException;
import extension.helpers.json.JsonUtil;
import java.io.File;
import java.io.IOException;
import java.util.HashMap;
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
public class JsonUtilTest {

    public JsonUtilTest() {
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
     * Test of parse method, of class JsonUtil.
     */
    @Test
    public void testParseJsonObject() {
        System.out.println("parseJsonObject");
        String jsonElementString = "{ \n \"abc\": 123, \n \"def\": \"test\" }";
        JsonObject result = JsonUtil.parseJsonObject(jsonElementString);
        assertEquals(true, result.isJsonObject());
        assertEquals(true, result.has("abc"));
        assertEquals(true, result.has("abc"));
        assertEquals(false, result.has("xyz"));
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
        System.out.println("isJson0");
        {
            String json = "{\"abc\":123,\"def\":\"test\"}";
            boolean result = JsonUtil.isJson(json);
            assertEquals(true, result);
        }
        System.out.println("isJson1");
        {
            String json = "{ \n \"abc\": 123, \n \"def\": \"test\" \n }";
            boolean result = JsonUtil.isJson(json);
            assertEquals(true, result);
        }
        System.out.println("isJson2");
        {
            String json = "\n{\"abc\": 123, \"def\": \"test\"}\n";
            boolean result = JsonUtil.isJson(json);
            assertEquals(true, result);
        }
        System.out.println("isJson3");
        {
            String json = "[\"abc\",\"def\",\"ghi\"]";
            boolean result = JsonUtil.isJson(json);
            assertEquals(true, result);
        }
        System.out.println("isJson4");
        {
            String json = "[\n \"abc\",\"def\",\"ghi\" \n]";
            boolean result = JsonUtil.isJson(json);
            assertEquals(true, result);
        }
        System.out.println("isJson5");
        {
            String json = "\n[\"abc\",\"def\",\"ghi\"]\n";
            boolean result = JsonUtil.isJson(json);
            assertEquals(true, result);
        }
        System.out.println("isJson6");
        {
            String plainJson = "[1,true,\"word\"]";
            boolean expResult = true;
            boolean result = JsonUtil.isJson(plainJson);
            assertEquals(expResult, result);
        }
        System.out.println("isJson7");
        {
            String plainJson = "{\"key\":\"value\"}";
            boolean expResult = true;
            boolean result = JsonUtil.isJson(plainJson);
            assertEquals(expResult, result);
        }
        System.out.println("isJson8");
        {
            String plainJson = "\r\n\t[1,true,\"word\"]\r\n\t";
            boolean expResult = true;
            boolean result = JsonUtil.isJson(plainJson);
            assertEquals(expResult, result);
        }
        System.out.println("isJson9");
        {
            String plainJson = "\r\n\t[1,true,\r\n\"word\"]\r\n\t";
            boolean expResult = true;
            boolean result = JsonUtil.isJson(plainJson);
            assertEquals(expResult, result);
        }
        System.out.println("isJson10");
        {
            String plainJson = "\r\n\t{\"key\":\"value\"}\t\r\n";
            boolean expResult = true;
            boolean result = JsonUtil.isJson(plainJson);
            assertEquals(expResult, result);
        }
        System.out.println("isJson11");
        {
            String plainJson = "\r\n\t{\"key\":\r\n\"value\"}\t\r\n";
            boolean expResult = true;
            boolean result = JsonUtil.isJson(plainJson);
            assertEquals(expResult, result);
        }
        System.out.println("isJson12");
        {
            String plainJson = "[\n    1,\n    true,\n    \"word\"\n]";
            boolean expResult = true;
            boolean result = JsonUtil.isJson(plainJson);
            assertEquals(expResult, result);
        }
        System.out.println("isJson13");
        {
            // 本来はJSONとして有効だが falseを返す仕様
            String plainJson = "\"key\"";
            boolean expResult = false;
            boolean result = JsonUtil.isJson(plainJson);
            assertEquals(expResult, result);
        }

        System.out.println("isJson14");
        {
            String plainJson = "\"key\"";
            boolean expResult = true;
            boolean result = JsonUtil.validJson(plainJson);
            assertEquals(expResult, result);
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
            assertEquals(true, result);
        }

    }

    @Test
    public void testConfigJson() {
        try {
            System.out.println("configJson");
            File file = File.createTempFile("json", ".tmp");
            Map<String, String> config = new HashMap();
            config.put("abc", "test");
            config.put("def", "{\"abc\":123,\"def\":\"test\"}");
            JsonUtil.saveToJson(file, config);
            System.out.println(file.getAbsoluteFile());
        } catch (IOException ex) {
            Logger.getLogger(JsonUtilTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }


}