package extension.view.base;

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
public class RegexItemTest {

    public RegexItemTest() {
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
     * Test of isValidRegex method, of class RegexItem.
     */
    @Test
    public void testIsValidRegex() {
        System.out.println("isValidRegex");
        RegexItem instance = new RegexItem();
        {
            boolean expResult = false;
            instance.setRegexp(true);
            instance.setMatch("(");
            boolean result = instance.isValidRegex();
            assertEquals(expResult, result);
        }
        {
            boolean expResult = true;
            instance.setMatch("\\(");
            boolean result = instance.isValidRegex();
            assertEquals(expResult, result);
        }
        {
            boolean expResult = true;
            instance.setRegexp(false);
            instance.setMatch("(");
            boolean result = instance.isValidRegex();
            assertEquals(expResult, result);
        }
        {
            boolean expResult = false;
            instance.setRegexp(true);
            instance.setIgnoreCase(true);
            instance.setMatch("(");
            boolean result = instance.isValidRegex();
            assertEquals(expResult, result);
        }
    }

    /**
     * Test of compileRegex method, of class RegexItem.
     */
    @Test
    public void testCompileRegex_boolean() {
        System.out.println("compileRegex");
        RegexItem instance = new RegexItem();
        {
            Pattern expResult = null;
            instance.setMatch("(");
            Pattern result = instance.compileRegex(false);
            assertEquals(expResult, result);

        }
        {
            Pattern expResult = Pattern.compile(Pattern.quote("("));
            instance.setMatch("(");
            Pattern result = instance.compileRegex(true);
            assertEquals(expResult.pattern(), result.pattern());

        }
        {
            Pattern expResult = Pattern.compile("\\(");
            instance.setMatch("\\(");
            Pattern result = instance.compileRegex(false);
            assertEquals(expResult.pattern(), result.pattern());
        }
    }

    /**
     * Test of compileRegex method, of class RegexItem.
     */
    @Test
    public void testCompileRegex() {
        {
            Pattern result = RegexItem.compileRegex("a(.*)z", 0, false);
            assertTrue(result.matcher("aghjz").matches());
            assertFalse(result.matcher("AGHJZ").matches());
        }
        {
            Pattern result = RegexItem.compileRegex("a(.*)z", Pattern.CASE_INSENSITIVE, false);
            assertTrue(result.matcher("aghjz").matches());
            assertTrue(result.matcher("AGHJZ").matches());
        }
        {
            Pattern result = RegexItem.compileRegex("a(.*)z", 0, true);
            assertTrue(result.matcher("a(.*)z").matches());
            assertFalse(result.matcher("A(.*)Z").matches());
        }
        {
            Pattern result = RegexItem.compileRegex("a(.*)z", Pattern.CASE_INSENSITIVE, true);
            assertTrue(result.matcher("a(.*)z").matches());
            assertTrue(result.matcher("A(.*)Z").matches());
        }
        {
            Pattern result = RegexItem.compileRegex("a(z", 0, false);
            assertEquals(result, null);
        }
        {
            RegexItem regItem = new RegexItem();
            regItem.setMatch("a(.*)z");
            regItem.setRegexp(true);
            regItem.setIgnoreCase(false);
            regItem.recompileRegex();
            Pattern result = regItem.getRegexPattern();
            assertTrue(result.matcher("aghjz").matches());
            assertFalse(result.matcher("AGHJZ").matches());
        }
        {
            RegexItem regItem = new RegexItem();
            regItem.setMatch("a(.*)z");
            regItem.setRegexp(true);
            regItem.setIgnoreCase(true);
            regItem.recompileRegex();
            Pattern result = regItem.getRegexPattern();
            assertTrue(result.matcher("aghjz").matches());
            assertTrue(result.matcher("AGHJZ").matches());
        }
        {
            RegexItem regItem = new RegexItem();
            regItem.setMatch("a(.*)z");
            regItem.setRegexp(false);
            regItem.setIgnoreCase(false);
            regItem.recompileRegex();
            Pattern result = regItem.getRegexPattern();
            assertTrue(result.matcher("a(.*)z").matches());
            assertFalse(result.matcher("A(.*)Z").matches());
        }
        {
            RegexItem regItem = new RegexItem();
            regItem.setMatch("a(.*)z");
            regItem.setRegexp(false);
            regItem.setIgnoreCase(true);
            regItem.recompileRegex();
            Pattern result = regItem.getRegexPattern();
            assertTrue(result.matcher("a(.*)z").matches());
            assertTrue(result.matcher("A(.*)Z").matches());
        }

    }

}
