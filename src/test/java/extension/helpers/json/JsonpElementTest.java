package extension.helpers.json;

import com.google.gson.JsonSyntaxException;
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
public class JsonpElementTest {

    public JsonpElementTest() {
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
     * Test of parseJsonp method, of class JsonpElement.
     */
    @Test
    public void testParseJsonp() {
        System.out.println("parseJsonp");
        {
            String json = "{\"abc\":123,\"def\":\"test\"}";
            try {
                JsonpElement jsonp = JsonpElement.parseJsonp(json);
                fail();
            } catch (JsonSyntaxException ex) {
                assertTrue(true);
            }
        }

        {
            String json = "[\"abc\",\"def\",\"ghi\"]";
            try {
                JsonpElement jsonp = JsonpElement.parseJsonp(json);
                fail();
            } catch (JsonSyntaxException ex) {
                assertTrue(true);
            }
        }
        {
            String json = "callback({ \"abc\": 123, \"def\": \"test\" });";
            try {
                JsonpElement jsonp = JsonpElement.parseJsonp(json);
                assertEquals("callback", jsonp.getCallbackName());
                assertEquals(json, jsonp.getRaw());
            } catch (JsonSyntaxException ex) {
                fail(ex.getMessage());
            }
        }

        {
            String json = "_callback({ \"abc\": 123, \"def\": \"test\" });";
            try {
                JsonpElement jsonp = JsonpElement.parseJsonp(json);
                assertEquals("_callback", jsonp.getCallbackName());
                assertEquals(json, jsonp.getRaw());
            } catch (JsonSyntaxException ex) {
                fail(ex.getMessage());
            }
        }

        {
            String json = " callback ({ \"abc\": 123, \"def\": \"test\" });";
            try {
                JsonpElement jsonp = JsonpElement.parseJsonp(json);
                assertEquals("callback", jsonp.getCallbackName());
                assertEquals(json, jsonp.getRaw());
            } catch (JsonSyntaxException ex) {
                fail(ex.getMessage());
            }
        }

        {
            String json = "  callback  ({ \"abc\": 123, \"def\": \"test\" });";
            try {
                JsonpElement jsonp = JsonpElement.parseJsonp(json);
                assertEquals("callback", jsonp.getCallbackName());
                assertEquals(json, jsonp.getRaw());
            } catch (JsonSyntaxException ex) {
                fail(ex.getMessage());
            }
        }

        {
            String json = "window.open({ \"abc\": 123, \"def\": \"test\" });";
            try {
                JsonpElement jsonp = JsonpElement.parseJsonp(json);
                assertEquals("window.open", jsonp.getCallbackName());
                assertEquals(json, jsonp.getRaw());
            } catch (JsonSyntaxException ex) {
                fail(ex.getMessage());
            }
        }

        {
            String json = "$_({ \"abc\": 123, \"def\": \"test\" });";
            try {
                JsonpElement jsonp = JsonpElement.parseJsonp(json);
                assertEquals("$_", jsonp.getCallbackName());
                assertEquals(json, jsonp.getRaw());
            } catch (JsonSyntaxException ex) {
                fail(ex.getMessage());
            }
        }
        {
            String json = "callback([\"abc\",\"def\",\"ghi\"])";
            try {
                JsonpElement jsonp = JsonpElement.parseJsonp(json);
                assertEquals("callback", jsonp.getCallbackName());
                assertEquals(json, jsonp.getRaw());
            } catch (JsonSyntaxException ex) {
                fail(ex.getMessage());
            }
        }
        {
            String json = "callback({\"inarray\":[\"abc\",\"def\",\"ghi\"]})";
            try {
                JsonpElement jsonp = JsonpElement.parseJsonp(json);
                assertEquals("callback", jsonp.getCallbackName());
                assertEquals(json, jsonp.getRaw());
            } catch (JsonSyntaxException ex) {
                fail(ex.getMessage());
            }
        }
        {
            String json = "callback([{\"abc\":\"def\"},\"ghi\"])";
            try {
                JsonpElement jsonp = JsonpElement.parseJsonp(json);
                assertEquals("callback", jsonp.getCallbackName());
                assertEquals(json, jsonp.getRaw());
            } catch (JsonSyntaxException ex) {
                fail(ex.getMessage());
            }
        }
    }

}
