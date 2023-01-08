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
public class HighlightColorTest {

    public HighlightColorTest() {
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
        {
            String s = null;
            MessageHighlightColor expResult = MessageHighlightColor.WHITE;
            MessageHighlightColor result = MessageHighlightColor.parseEnum(s);
            assertEquals(expResult, result);
        }
        {
            String s = "RED";
            MessageHighlightColor expResult = MessageHighlightColor.RED;
            MessageHighlightColor result = MessageHighlightColor.parseEnum(s);
            assertEquals(expResult, result);
        }
    }

    /**
     * Test of parseEnumSet method, of class NotifyType.
     */
    @Test
    public void testParseEnumSet() {
        System.out.println("parseEnumSet");
        String s = "[\"WHITE\",\"BLUE\",\"YELLOW\"]";
        EnumSet<MessageHighlightColor> expResult = EnumSet.of(MessageHighlightColor.WHITE, MessageHighlightColor.BLUE, MessageHighlightColor.YELLOW);
        EnumSet<MessageHighlightColor> result = MessageHighlightColor.parseEnumSet(s);
        assertEquals(expResult, result);
    }

    /**
     * Test of toString method, of class Severity.
     */
    @Test
    public void testToString() {
        System.out.println("toString");
        EnumSet<MessageHighlightColor> instance = EnumSet.allOf(MessageHighlightColor.class);
        for (MessageHighlightColor e : instance) {
            System.out.println("name:" + e.name());
            assertEquals(e, MessageHighlightColor.parseEnum(e.name()));
        }

        for (MessageHighlightColor e : MessageHighlightColor.values()) {
            System.out.println("value:" + e.toString());
            assertEquals(e, MessageHighlightColor.parseEnum(e.toString()));
        }
        System.out.println(instance.toString());
    }

}
