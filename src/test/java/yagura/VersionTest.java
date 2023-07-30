package yagura;

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
public class VersionTest {

    public VersionTest() {
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
     * Test of getProjectName method, of class Version.
     */
    @Test
    public void testGetProjectName() {
        System.out.println("getProjectName");
        Version instance = Version.getInstance();
        String expResult = "YaguraExtension";
        String result = instance.getProjectName();
        assertEquals(expResult, result);
    }

    /**
     * Test of getTabCaption method, of class Version.
     */
    @Test
    public void testGetTabCaption() {
        System.out.println("getTabCaption");
        Version instance = Version.getInstance();
        String expResult = "Yagura";
        String result = instance.getTabCaption();
        assertEquals(expResult, result);
    }

    /**
     * Test of getVersionInfo method, of class Version.
     */
    @Test
    public void testGetVersionInfo() {
        System.out.println("getVersionInfo");
        Version instance = Version.getInstance();
        String expResult = "Product Version: ";
        String result = instance.getVersionInfo();
        assertTrue(result.startsWith(expResult));
    }

}
