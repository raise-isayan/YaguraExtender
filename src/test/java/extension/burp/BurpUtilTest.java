package extension.burp;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
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
public class BurpUtilTest {

    public BurpUtilTest() {
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
     * Test of parseFilterPattern method, of class BurpUtil.
     */
    @Test
    public void testParseFilterPattern() {
        System.out.println("parseFilterPattern");
        String pattern = "jpg,png,gif,js.map";
        {
            String expResult = "test.jpg";
            String result = BurpUtil.parseFilterPattern(pattern);
            Pattern p = Pattern.compile(result);
            Matcher m = p.matcher(expResult);
            assertTrue(m.find());
        }
        {
            String expResult = "test.jpg?xxx";
            String result = BurpUtil.parseFilterPattern(pattern);
            Pattern p = Pattern.compile(result);
            Matcher m = p.matcher(expResult);
            assertFalse(m.matches());
        }
        {
            String expResult = "test.gif";
            String result = BurpUtil.parseFilterPattern(pattern);
            Pattern p = Pattern.compile(result);
            Matcher m = p.matcher(expResult);
            assertTrue(m.find());
        }
        {
            String expResult = "test.js.map";
            String result = BurpUtil.parseFilterPattern(pattern);
            Pattern p = Pattern.compile(result);
            Matcher m = p.matcher(expResult);
            assertTrue(m.find());
        }
    }


}
