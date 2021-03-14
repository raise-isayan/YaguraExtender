package yagura.model;

import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author isayan
 */
public class UniversalViewPropertyTest {

    public UniversalViewPropertyTest() {
    }

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }

    @Before
    public void setUp() {
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of getDefaultEncodingList method, of class UniversalViewProperty.
     */
    @Test
    public void testGetDefaultEncodingList_0args() {
        System.out.println("getDefaultEncodingList");
        List<String> result = UniversalViewProperty.getDefaultEncodingList();
        assertTrue(result.size() > 0);
    }

    /**
     * Test of getDefaultEncodingList method, of class UniversalViewProperty.
     */
    @Test
    public void testGetDefaultEncodingList_Locale() {
        System.out.println("getDefaultEncodingList");
        List<String> result = UniversalViewProperty.getDefaultEncodingList(Locale.JAPANESE);
        assertTrue(result.size() > 0);
    }

    /**
     * Test of getEncodingList method, of class UniversalViewProperty.
     */
    @Test
    public void testGetEncodingList() {
        System.out.println("getEncodingList");
        UniversalViewProperty instance = new UniversalViewProperty();
        List<String> result = instance.getEncodingList();
        assertTrue(result.size() > 0);
    }


    /**
     * Test of parseEnum method, of class NotifyType.
     */
    @Test
    public void testParseEnum() {
        System.out.println("parseEnum");
        String s = "GENERATE_POC";
        UniversalViewProperty.UniversalView expResult = UniversalViewProperty.UniversalView.GENERATE_POC;
        UniversalViewProperty.UniversalView result = UniversalViewProperty.UniversalView.parseEnum(s);
        assertEquals(expResult, result);
    }

    /**
     * Test of parseEnumSet method, of class NotifyType.
     */
    @Test
    public void testParseEnumSet() {
        System.out.println("parseEnumSet");
        String s = "[\"GENERATE_POC\",\"HTML_COMMENT\",\"JSON\"]";
        EnumSet<UniversalViewProperty.UniversalView> expResult = EnumSet.of(UniversalViewProperty.UniversalView.GENERATE_POC, UniversalViewProperty.UniversalView.HTML_COMMENT, UniversalViewProperty.UniversalView.JSON);
        EnumSet<UniversalViewProperty.UniversalView> result = UniversalViewProperty.UniversalView.parseEnumSet(s);
        assertEquals(expResult, result);
    }

}
