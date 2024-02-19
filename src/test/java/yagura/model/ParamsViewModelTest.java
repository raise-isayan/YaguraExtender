package yagura.model;

import burp.api.montoya.http.message.ContentType;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import static org.junit.jupiter.api.Assertions.*;

/**
 *
 * @author isayan
 */
public class ParamsViewModelTest {

    public ParamsViewModelTest() {
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
     * Test of paramDecode method, of class ParamsViewModel.
     */
    @Test
    public void testParamDecode() throws Exception {
        System.out.println("paramDecode");
        {
            String value = new String("あいうえお".getBytes(StandardCharsets.UTF_8), StandardCharsets.ISO_8859_1);
            String expResult = "あいうえお";
            String result = ParamsViewModel.paramDecode(value, StandardCharsets.UTF_8.name(), ContentType.JSON);
            assertEquals(expResult, result);
        }
        {
            String value = "\\u3042\\u3044\\u3046\\u3048\\u304a";
            String expResult = "あいうえお";
            String result = ParamsViewModel.paramDecode(value, StandardCharsets.UTF_8.name(), ContentType.JSON);
            assertEquals(expResult, result);
        }
    }

    /**
     * Test of paramEncode method, of class ParamsViewModel.
     */
    @Test
    public void testParamEncode() throws Exception {
        System.out.println("paramEncode");
        {
            String value = "あいうえお";
            String expResult = "\\u3042\\u3044\\u3046\\u3048\\u304a";
            String result = ParamsViewModel.paramEncode(value, StandardCharsets.UTF_8.name(), ContentType.JSON);
            assertEquals(expResult, result);
        }
    }

}
