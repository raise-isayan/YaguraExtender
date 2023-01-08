package extension.helpers;

import java.io.File;
import java.io.InputStream;
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
public class FileUtilTest {

    public FileUtilTest() {
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
     * Test of existsStartsDir method, of class FileUtil.
     */
    @Test
    public void testExistsStartsDir() {
        System.out.println("existsStartsDir");
        String resourcesPath = FileUtilTest.class.getResource("/resources/").getPath();
        File dir = new File(resourcesPath);
        String value = "burpextender";
        boolean expResult = true;
        boolean result = FileUtil.existsStartsDir(dir, value);
        assertEquals(expResult, result);
    }

    /**
     * Test of rotateFile method, of class FileUtil.
     */
    @Test
    public void testRotateFile() {
        System.out.println("rotateFile");
        String resourcesPath = FileUtilTest.class.getResource("/resources/").getPath();
        File dir = new File(resourcesPath);
        String value = "burpextender";
        File expResult = new File(resourcesPath, "burpextender.1");
        File result = FileUtil.rotateFile(dir, value);
        assertEquals(expResult, result);
    }

    /**
     * Test of bytesFromFile method, of class FileUtil.
     */
    @Test
    public void testBytesFromFile() throws Exception {
        System.out.println("bytesFromFile");
        String responseUTF8 = FileUtilTest.class.getResource("/resources/response.UTF-8").getPath();
        String result = StringUtil.getStringUTF8(FileUtil.bytesFromFile(new File(responseUTF8)));
        assertTrue(result.contains("あいうえお"));
    }

    /**
     * Test of readAllBytes method, of class FileUtil.
     */
    @Test
    public void testReadAllBytes() throws Exception {
        System.out.println("readAllBytes");
        InputStream streamUTF8 = FileUtilTest.class.getResourceAsStream("/resources/response.UTF-8");
        String result = StringUtil.getStringUTF8(FileUtil.readAllBytes(streamUTF8));
        assertTrue(result.contains("あいうえお"));
    }

    /**
     * Test of appendFirstSeparator method, of class FileUtil.
     */
    @Test
    public void testAppendFirstSeparator() {
        System.out.println("appendFirstSeparator");
        {
            String path = "test";
            String separator = "/";
            String expResult = "/test";
            String result = FileUtil.appendFirstSeparator(path, separator);
            assertEquals(expResult, result);
        }
        {
            String path = "/test";
            String separator = "/";
            String expResult = "/test";
            String result = FileUtil.appendFirstSeparator(path, separator);
            assertEquals(expResult, result);
        }
        {
            String path = "test/";
            String separator = "/";
            String expResult = "/test/";
            String result = FileUtil.appendFirstSeparator(path, separator);
            assertEquals(expResult, result);
        }
    }

    /**
     * Test of removeFirstSeparator method, of class FileUtil.
     */
    @Test
    public void testRemoveFirstSeparator() {
        System.out.println("removeFirstSeparator");
        {
            String path = "test";
            String separator = "/";
            String expResult = "test";
            String result = FileUtil.removeFirstSeparator(path, separator);
            assertEquals(expResult, result);
        }
        {
            String path = "/test";
            String separator = "/";
            String expResult = "test";
            String result = FileUtil.removeFirstSeparator(path, separator);
            assertEquals(expResult, result);
        }
        {
            String path = "/test/";
            String separator = "/";
            String expResult = "test/";
            String result = FileUtil.removeFirstSeparator(path, separator);
            assertEquals(expResult, result);
        }
    }

    /**
     * Test of appendLastSeparator method, of class FileUtil.
     */
    @Test
    public void testAppendLastSeparator() {
        System.out.println("appendLastSeparator");
        {
            String path = "test";
            String separator = "/";
            String expResult = "test/";
            String result = FileUtil.appendLastSeparator(path, separator);
            assertEquals(expResult, result);
        }
        {
            String path = "test/";
            String separator = "/";
            String expResult = "test/";
            String result = FileUtil.appendLastSeparator(path, separator);
            assertEquals(expResult, result);
        }
        {
            String path = "/test/";
            String separator = "/";
            String expResult = "/test/";
            String result = FileUtil.appendLastSeparator(path, separator);
            assertEquals(expResult, result);
        }
    }

    /**
     * Test of removeLastSeparator method, of class FileUtil.
     */
    @Test
    public void testRemoveLastSeparator() {
        System.out.println("removeLastSeparator");
        {
            String path = "test";
            String separator = "/";
            String expResult = "test";
            String result = FileUtil.removeLastSeparator(path, separator);
            assertEquals(expResult, result);
        }
        {
            String path = "test/";
            String separator = "/";
            String expResult = "test";
            String result = FileUtil.removeLastSeparator(path, separator);
            assertEquals(expResult, result);
        }
        {
            String path = "/test/";
            String separator = "/";
            String expResult = "/test";
            String result = FileUtil.removeLastSeparator(path, separator);
            assertEquals(expResult, result);
        }
    }

}
