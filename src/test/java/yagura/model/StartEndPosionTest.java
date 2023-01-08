package yagura.model;

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
public class StartEndPosionTest {

    public StartEndPosionTest() {
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
     * Test of setPosision method, of class StartEndPosion.
     */
    @Test
    public void testStartEndPosision() {
        System.out.println("testStartEndPosision");
        int s = 0;
        int e = 1;
        {
            StartEndPosion instance = new StartEndPosion(s, e);
            assertEquals(s, instance.getStartPos());
            assertEquals(e, instance.getEndPos());
        }
        {
            try  {
                StartEndPosion instance = new StartEndPosion(e, s);
                fail();
            } catch (IllegalArgumentException ex) {
                assertTrue(true);
            }
        }
    }

    /**
     * Test of getLength method, of class StartEndPosion.
     */
    @Test
    public void testGetLength() {
        System.out.println("getLength");
        int s = 1;
        int e = 2;
        {
            StartEndPosion instance = new StartEndPosion(s, e);
            int result = instance.getLength();
            assertEquals(1, result);
        }
    }

}
