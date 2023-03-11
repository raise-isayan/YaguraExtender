package extension.burp;

import extension.burp.montoya.BurpVersionTest;
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

    @Test
    public void testSuiteVersion() {
        System.out.println("testSuiteVersion");
        {
            BurpVersion suite = new BurpVersion("Burp Suite Professional v2021.12.1 - ");
            assertEquals("Burp Suite Professional", suite.getProductName());
            assertEquals("2021", suite.getMajor());
            assertEquals(2021, suite.getMajorVersion());
            assertEquals("12.1", suite.getMinor());
            assertNull(suite.getBuild());
        }
        {
            BurpVersion suite = new BurpVersion("Burp Suite Professional v2022.12.6 - ");
            assertEquals("Burp Suite Professional", suite.getProductName());
            assertEquals("2022", suite.getMajor());
            assertEquals(2022, suite.getMajorVersion());
            assertEquals("12.6", suite.getMinor());
            assertNull(suite.getBuild());
        }
        {
            BurpVersion suite = new BurpVersion("Burp Suite Professional v2023.1.1-18663 ");
            assertEquals("Burp Suite Professional", suite.getProductName());
            assertEquals("2023", suite.getMajor());
            assertEquals(2023, suite.getMajorVersion());
            assertEquals("1.1", suite.getMinor());
            assertEquals("18663", suite.getBuild());
        }
        {
            BurpVersion suite = new BurpVersion("Burp Suite Community Edition v2020.7 ");
            assertEquals("Burp Suite Community Edition", suite.getProductName());
            assertEquals("2020", suite.getMajor());
            assertEquals(2020, suite.getMajorVersion());
            assertEquals("7", suite.getMinor());
            assertNull(suite.getBuild());
        }
        {
            BurpVersion suite = new BurpVersion("Burp Suite Community Edition v2023.2.1-19050 ");
            assertEquals("Burp Suite Community Edition", suite.getProductName());
            assertEquals("2023", suite.getMajor());
            assertEquals(2023, suite.getMajorVersion());
            assertEquals("2.1", suite.getMinor());
            assertEquals("19050", suite.getBuild());
        }
        {
            BurpVersion suite = new BurpVersion("Burp Suite Support v2023.1.2");
            assertEquals("Burp Suite Support", suite.getProductName());
            assertEquals("2023", suite.getMajor());
            assertEquals(2023, suite.getMajorVersion());
            assertEquals("1.2", suite.getMinor());
            assertNull(suite.getBuild());
        }

    }

    @Test
    public void testCompareSuiteVersion() {
        System.out.println("testCompareSuiteVersion");
        // https://portswigger.net/burp/releases/professional-community-2023-1
        // montoya Api 1.0.0
        final BurpVersion SUPPORT_MIN_VERSION = new BurpVersion("Burp Suite Support v2023.1.2");
        {
            BurpVersion suite = new BurpVersion("Burp Suite Community Edition v2023.1-18440 ");
            assertEquals(-1, suite.compareTo(SUPPORT_MIN_VERSION));
        }
        {
            BurpVersion suite = new BurpVersion("Burp Suite Community Edition v2023.2.1-19050 ");
            assertEquals(1, suite.compareTo(SUPPORT_MIN_VERSION));
        }
        {
            BurpVersion suite = new BurpVersion("Burp Suite Professional v2023.1.1- ");
            assertEquals(-1, suite.compareTo(SUPPORT_MIN_VERSION));
        }
        {
            BurpVersion suite = new BurpVersion("Burp Suite Professional v2023.1.2- ");
            assertEquals(0, suite.compareTo(SUPPORT_MIN_VERSION));
        }
        {
            BurpVersion suite = new BurpVersion("Burp Suite Professional v2023.1.3- ");
            assertEquals(1, suite.compareTo(SUPPORT_MIN_VERSION));
        }

    }

    @Test
    public void testCompareSuiteMontoyaVersion() {
        System.out.println("testCompareSuiteMontoyaVersion");
        final BurpVersion SUPPORT_MIN_VERSION = new BurpVersion("Burp Suite Support v2023.1.2");
        {
            BurpVersion suite = new BurpVersion(BurpVersionTest.BURP_2023_1_1_VERSION_COMMUNITY);
            assertEquals(-1, suite.compareTo(SUPPORT_MIN_VERSION));
        }
        {
            BurpVersion suite = new BurpVersion(BurpVersionTest.BURP_2023_1_2_VERSION_COMMUNITY);
            assertEquals(0, suite.compareTo(SUPPORT_MIN_VERSION));
        }
        {
            BurpVersion suite = new BurpVersion(BurpVersionTest.BURP_2023_1_3_VERSION_COMMUNITY);
            assertEquals(1, suite.compareTo(SUPPORT_MIN_VERSION));
        }
        {
            BurpVersion suite = new BurpVersion(BurpVersionTest.BURP_2023_2_1_VERSION_COMMUNITY);
            assertEquals(1, suite.compareTo(SUPPORT_MIN_VERSION));
        }
        {
            BurpVersion suite = new BurpVersion(BurpVersionTest.BURP_2023_1_1_VERSION_PRO);
            assertEquals(-1, suite.compareTo(SUPPORT_MIN_VERSION));
        }
        {
            BurpVersion suite = new BurpVersion(BurpVersionTest.BURP_2023_1_2_VERSION_PRO);
            assertEquals(0, suite.compareTo(SUPPORT_MIN_VERSION));
        }
        {
            BurpVersion suite = new BurpVersion(BurpVersionTest.BURP_2023_1_3_VERSION_PRO);
            assertEquals(1, suite.compareTo(SUPPORT_MIN_VERSION));
        }
    }

    @Test
    public void testCompareMinor() {
        System.out.println("testCompareMinor");
        assertEquals(-1, BurpVersion.compareMinor("1.7", "1.7.2"));
        assertEquals(0, BurpVersion.compareMinor("1.1", "1.1"));
        assertEquals(-1, BurpVersion.compareMinor("1", "1.2"));
        assertEquals(-1, BurpVersion.compareMinor("1.7.1", "1.7.2"));
        assertEquals(1, BurpVersion.compareMinor("1.7.2", "1.7.1"));
        assertEquals(-2, BurpVersion.compareMinor("1.7.1", "1.7.3"));
        assertEquals(2, BurpVersion.compareMinor("1.7.3", "1.7.1"));
        assertEquals(1, BurpVersion.compareMinor("1.7.1", "1.7"));
        assertEquals(1, BurpVersion.compareMinor("1.7.1", "1"));
        assertEquals(-1, BurpVersion.compareMinor("1", "1.7.1"));
    }

}
