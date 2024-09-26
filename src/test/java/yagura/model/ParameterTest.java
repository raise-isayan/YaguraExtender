package yagura.model;

import extension.helpers.StringUtil;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 *
 * @author isayan
 */
public class ParameterTest {

    public ParameterTest() {
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

     @Test
    public void testMultipartContentType() {
        System.out.println("getMultipartContentType");

        String part = "------WebKitFormBoundaryWBgkjxY4kK7BfbBR\r\n"
                + "Content-Disposition: form-data; name=\"request\"; filename=\"\"\r\n"
                + "Content-Type: application/octet-stream\r\n"
                + "\r\n"
                + "test\r\n"
                + "------WebKitFormBoundaryWBgkjxY4kK7BfbBR\r\n";

        String expResult = "application/octet-stream";
        String result = Parameter.getMultipartContentType(StringUtil.getBytesRaw(part), 0, 200);
        assertEquals(expResult, result);

    }

}
