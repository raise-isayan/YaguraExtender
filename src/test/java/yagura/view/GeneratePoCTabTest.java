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
    public void testGenerateFunction() {
        System.out.println("testGenerateFunction");
        {
            String gen = GeneratePoCTab.generateDataTransferFunction();
            System.out.println(gen);
            String delay = GeneratePoCTab.generateTimeDelayFunction();
            System.out.println(delay);
        }
    }

    @Test
    public void testGenerateBinay() {
        System.out.println("generateBinay");
        String expResult = "0x00,0x0a,0x0f,0xaf,0xff";
        String result = GeneratePoCTab.generateHexBinay(new byte[]{(byte) 0x00, (byte) 0x0a, (byte) 0x0f, (byte) 0xaf, (byte) 0xff});
        assertEquals(expResult, result);
    }

    @Test
    public void testGenerateWebSocketFunction() {
        System.out.println("testGenerateWebSocketFunction");
        {
            String gen = GenerateWebsocktPoCTab.generateWebSocketSendFunction();
            System.out.println(gen);
        }
        {
            String gen = GenerateWebsocktPoCTab.generateWebSocketReceiveFunction();
            System.out.println(gen);
        }
        {
            String gen = GenerateWebsocktPoCTab.generateWebSocketSendFunctionCall("https://www.example.com/", "test");
            System.out.println(gen);
            String genES = GenerateWebsocktPoCTab.generateWebSocketSendFunctionCall("https://www.example.com/\\\"", "test\\\"");
            System.out.println(genES);
        }
        {
            String gen = GenerateWebsocktPoCTab.generateWebSocketSendFunctionCall("https://www.example.com/", "test".getBytes());
            System.out.println(gen);
            String genES = GenerateWebsocktPoCTab.generateWebSocketSendFunctionCall("https://www.example.com/\\\"", "test\\\"".getBytes());
            System.out.println(genES);
        }
    }

}
