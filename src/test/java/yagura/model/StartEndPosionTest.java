package yagura.model;

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
public class StartEndPosionTest {

    public StartEndPosionTest() {
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
