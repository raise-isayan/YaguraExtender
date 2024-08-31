package yagura.model;

import burp.api.montoya.http.message.HttpRequestResponse;
import java.util.Properties;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 *
 * @author isayan
 */
public class SendToParameterPropertyTest {

    public SendToParameterPropertyTest() {
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
     * Test of extractLinePart method, of class SendToParameterProperty.
     */
    @Test
    public void testExtractLinePart() {
        System.out.println("extractLinePart");
        // \r\n
        {
            SendToParameterProperty.LinePartType commentLineType = SendToParameterProperty.LinePartType.ALL_LINE;
            String value = "123\r\n456\r\n789";
            String expResult = "123\r\n456\r\n789";
            String result = SendToParameterProperty.extractLinePart(commentLineType, value);
            assertEquals(expResult, result);
        }
        {
            SendToParameterProperty.LinePartType commentLineType = SendToParameterProperty.LinePartType.FIRST_LINE;
            String value = "123\r\n456\r\n789";
            String expResult = "123";
            String result = SendToParameterProperty.extractLinePart(commentLineType, value);
            assertEquals(expResult, result);
        }
        {
            SendToParameterProperty.LinePartType commentLineType = SendToParameterProperty.LinePartType.SECOND_LINE;
            String value = "123\r\n456\r\n789";
            String expResult = "456\r\n789";
            String result = SendToParameterProperty.extractLinePart(commentLineType, value);
            assertEquals(expResult, result);
        }
        // \r
        {
            SendToParameterProperty.LinePartType commentLineType = SendToParameterProperty.LinePartType.ALL_LINE;
            String value = "123\r456\r789";
            String expResult = "123\r456\r789";
            String result = SendToParameterProperty.extractLinePart(commentLineType, value);
            assertEquals(expResult, result);
        }
        {
            SendToParameterProperty.LinePartType commentLineType = SendToParameterProperty.LinePartType.FIRST_LINE;
            String value = "123\r456\r789";
            String expResult = "123";
            String result = SendToParameterProperty.extractLinePart(commentLineType, value);
            assertEquals(expResult, result);
        }
        {
            SendToParameterProperty.LinePartType commentLineType = SendToParameterProperty.LinePartType.SECOND_LINE;
            String value = "123\r\n456\r\n789";
            String expResult = "456\r\n789";
            String result = SendToParameterProperty.extractLinePart(commentLineType, value);
            assertEquals(expResult, result);
        }
        // \n
        {
            SendToParameterProperty.LinePartType commentLineType = SendToParameterProperty.LinePartType.ALL_LINE;
            String value = "123\n456\n789";
            String expResult = "123\n456\n789";
            String result = SendToParameterProperty.extractLinePart(commentLineType, value);
            assertEquals(expResult, result);
        }
        {
            SendToParameterProperty.LinePartType commentLineType = SendToParameterProperty.LinePartType.FIRST_LINE;
            String value = "123\n456\n789";
            String expResult = "123";
            String result = SendToParameterProperty.extractLinePart(commentLineType, value);
            assertEquals(expResult, result);
        }
        {
            SendToParameterProperty.LinePartType commentLineType = SendToParameterProperty.LinePartType.SECOND_LINE;
            String value = "123\n456\n789";
            String expResult = "456\n789";
            String result = SendToParameterProperty.extractLinePart(commentLineType, value);
            assertEquals(expResult, result);
        }
    }

}
