package yagura.dynamic;

import java.io.File;
import java.io.FileNotFoundException;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 *
 * @author isayan
 */
public class BambdaFileTest {

    public BambdaFileTest() {
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

    @Test
    public void testTempleteSL() {
        System.out.println("testTempleteSL");
        try {
            String bambda_path = BambdaFileTest.class.getResource("/resources/HTTPHistoryViewFilter-SL.bambda").getPath();
            BambdaFile bamba = new BambdaFile();
            bamba.parse(new File(bambda_path));
            System.out.println("id:" + bamba.getID());
            System.out.println("name:" + bamba.getName());
            System.out.println("function:" + bamba.getFunction());
            System.out.println("location:" + bamba.getLocation());
            System.out.println("source:" + bamba.getSource());
            System.out.println("contents:" + bamba.getSourceContents());
            assertFalse(bamba.isMultiline());
        } catch (FileNotFoundException ex) {
            fail(ex.getMessage(), ex);
        }
    }

    @Test
    public void testTempleteML() {
        System.out.println("testTempleteML");
        try {
            String bambda_path = BambdaFileTest.class.getResource("/resources/HTTPHistoryViewFilter-ML.bambda").getPath();
            BambdaFile bamba = new BambdaFile();
            bamba.parse(new File(bambda_path));
            System.out.println("id:" + bamba.getID());
            System.out.println("name:" + bamba.getName());
            System.out.println("function:" + bamba.getFunction());
            System.out.println("location:" + bamba.getLocation());
            System.out.println("source:" + bamba.getSource());
            System.out.println("contents:" + bamba.getSourceContents());
            assertTrue(bamba.isMultiline());
        } catch (FileNotFoundException ex) {
            fail(ex.getMessage(), ex);
        }
    }

}
