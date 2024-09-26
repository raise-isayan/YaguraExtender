package yagura.view;

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
    public void testGenerateBinay() {
        System.out.println("generateBinay");
        String expResult = "0x00,0x0a,0x0f,0xaf,0xff";
        String result = GeneratePoCTab.generateHexBinay(new byte[]{(byte) 0x00, (byte) 0x0a, (byte) 0x0f, (byte) 0xaf, (byte) 0xff});
        assertEquals(expResult, result);
    }

}
