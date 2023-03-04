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
public class ConfidenceTest {

    public ConfidenceTest() {
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
     * Test of parseEnum method, of class Severity.
     */
    @Test
    public void testParseEnum() {
        System.out.println("parseEnum");
        String s = "CERTAIN";
        Confidence expResult = Confidence.CERTAIN;
        Confidence result = Confidence.parseEnum(s);
        assertEquals(expResult, result);
    }

    /**
     * Test of parseEnumSet method, of class Severity.
     */
    @Test
    public void testParseEnumSet() {
        System.out.println("parseEnumSet");
        {
            String s = "[\"CERTAIN\",\"FIRM\",\"TENTATIVE\"]";
            EnumSet<Confidence> expResult = EnumSet.of(Confidence.CERTAIN, Confidence.FIRM, Confidence.TENTATIVE);
            EnumSet<Confidence> result = Confidence.parseEnumSet(s);
            assertEquals(expResult, result);
        }
    }

    /**
     * Test of toString method, of class Severity.
     */
    @Test
    public void testToString() {
        System.out.println("toString");
        EnumSet<Severity> instance = EnumSet.allOf(Severity.class);
        for (Severity e : instance) {
            System.out.println("name:" + e.name());
            assertEquals(e, Severity.parseEnum(e.name()));
        }
        for (Severity e : Severity.values()) {
            System.out.println("value:" + e.toString());
            assertEquals(e, Severity.parseEnum(e.toString()));
        }
        System.out.println(instance.toString());
    }

}
