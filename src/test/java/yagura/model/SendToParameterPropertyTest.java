package yagura.model;

import extend.util.external.TransUtil;
import extension.helpers.ConvertUtil;
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

    @Test
    public void testProperties() {
        System.out.println("testProperties");
        SendToParameterProperty sendoParam = new SendToParameterProperty();
        sendoParam.setUseOverride(true);
        sendoParam.setUseReqComment(true);
        sendoParam.setUseReqName(true);
        sendoParam.setUseReqNum(true);

        sendoParam.setReqName(SendToParameterProperty.SendToParameterType.REQUEST_REGEX);
        sendoParam.setReqNameMatchPattern("reqNamePattern");
        sendoParam.setReqNameMatchIgnoreCase(true);
        sendoParam.setReqNameMatchDecodeType(TransUtil.EncodePattern.HTML);

        sendoParam.setReqComment(SendToParameterProperty.SendToParameterType.REQUEST_REGEX);
        sendoParam.setReqCommentMatchPattern("reqNotePattern");
        sendoParam.setReqCommentMatchIgnoreCase(true);
        sendoParam.setReqCommentMatchDecodeType(TransUtil.EncodePattern.BASE64);

        Properties prop = sendoParam.getProperties();
        assertEquals(true, ConvertUtil.parseBooleanDefault(prop.getProperty("SendToPamareter.useOverride"), false));
        assertEquals(true, ConvertUtil.parseBooleanDefault(prop.getProperty("SendToPamareter.useReqComment"), false));
        assertEquals(true, ConvertUtil.parseBooleanDefault(prop.getProperty("SendToPamareter.useReqName"), false));
        assertEquals(true, ConvertUtil.parseBooleanDefault(prop.getProperty("SendToPamareter.useReqNum"), false));
        prop.list(System.out);
        {
            SendToParameterProperty resultArgs = new SendToParameterProperty();
            resultArgs.setProperties(prop);
            assertEquals(true, resultArgs.isUseOverride());
            assertEquals(true, resultArgs.isUseReqComment());
            assertEquals(true, resultArgs.isUseReqName());
            assertEquals(true, resultArgs.isUseReqNum());
        }

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
