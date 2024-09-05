package yagura.view;

import extension.helpers.StringUtil;
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
public class GeneratePoCTabTest {

    public GeneratePoCTabTest() {
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
        String result = GeneratePoCTab.getMultipartContentType(StringUtil.getBytesRaw(part), 0, 200);
        assertEquals(expResult, result);

    }

    @Test
    public void testGenerateBinay() {
        System.out.println("generateBinay");
        String expResult = "0x00,0x0A,0x0F,0xAF,0xFF";
        String result = GeneratePoCTab.generateHexBinay(new byte[]{(byte) 0x00, (byte) 0x0a, (byte) 0x0f, (byte) 0xaf, (byte) 0xff});
        assertEquals(expResult, result);
    }

}
