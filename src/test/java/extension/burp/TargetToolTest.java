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
public class TargetToolTest {

    public TargetToolTest() {
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
     * Test of parseEnum method, of class TargetTool.
     */
    @Test
    public void testParseEnum() {
        System.out.println("parseEnum");
        String s = "PROXY";
        TargetTool expResult = TargetTool.PROXY;
        TargetTool result = TargetTool.parseEnum(s);
        assertEquals(expResult, result);
    }

    /**
     * Test of parseEnumSet method, of class Severity.
     */
    @Test
    public void testParseEnumSet() {
        System.out.println("parseEnumSet");
        {
            String s = "[\"PROXY\",\"REPEATER\",\"SCANNER\"]";
            EnumSet<TargetTool> expResult = EnumSet.of(TargetTool.PROXY, TargetTool.REPEATER, TargetTool.SCANNER);
            EnumSet<TargetTool> result = TargetTool.parseEnumSet(s);
            assertEquals(expResult, result);
        }
    }

    /**
     * Test of toString method, of class Severity.
     */
    @Test
    public void testToString() {
        System.out.println("toString");
        EnumSet<TargetTool> instance = EnumSet.allOf(TargetTool.class);
        for (TargetTool e : instance) {
            System.out.println("name:" + e.name());
            assertEquals(e, TargetTool.parseEnum(e.name()));
        }
        for (TargetTool e : TargetTool.values()) {
            System.out.println("value:" + e.toString());
            assertEquals(e, TargetTool.parseEnum(e.toString()));
        }
        System.out.println(instance.toString());
    }

}
