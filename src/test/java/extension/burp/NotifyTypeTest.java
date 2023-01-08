package extension.burp;

import java.util.EnumSet;
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
public class NotifyTypeTest {

    public NotifyTypeTest() {
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
     * Test of parseEnum method, of class NotifyType.
     */
    @Test
    public void testParseEnum() {
        System.out.println("parseEnum");
        String s = "ALERTS_TAB";
        NotifyType expResult = NotifyType.ALERTS_TAB;
        NotifyType result = NotifyType.parseEnum(s);
        assertEquals(expResult, result);
    }

    /**
     * Test of parseEnumSet method, of class NotifyType.
     */
    @Test
    public void testParseEnumSet() {
        System.out.println("parseEnumSet");
        String s = "[\"ALERTS_TAB\",\"ITEM_HIGHLIGHT\",\"COMMENT\"]";
        EnumSet<NotifyType> expResult = EnumSet.of(NotifyType.ALERTS_TAB, NotifyType.ITEM_HIGHLIGHT, NotifyType.COMMENT);
        EnumSet<NotifyType> result = NotifyType.parseEnumSet(s);
        assertEquals(expResult, result);
    }

    /**
     * Test of toString method, of class Severity.
     */
    @Test
    public void testToString() {
        System.out.println("toString");
        EnumSet<NotifyType> instance = EnumSet.allOf(NotifyType.class);
        for (NotifyType e : instance) {
            System.out.println("name:" + e.name());
            assertEquals(e, NotifyType.parseEnum(e.name()));
        }

        for (NotifyType e : NotifyType.values()) {
            System.out.println("value:" + e.toString());
            assertEquals(e, NotifyType.parseEnum(e.toString()));
        }
        System.out.println(instance.toString());
    }

}
