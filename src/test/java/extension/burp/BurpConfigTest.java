package extension.burp;

import java.security.KeyStore;
import java.util.Enumeration;
import java.util.Properties;
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
public class BurpConfigTest {

    public BurpConfigTest() {
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
     * Test of loadCACeart method, of class BurpConfig.
     */
    @Test
    public void testLoadCACeart() throws Exception {
        System.out.println("loadCACeart");
        KeyStore result = BurpConfig.loadCACeart();
        Properties p = System.getProperties();
        Enumeration<String> e = result.aliases();
        while (e.hasMoreElements()) {
            // cacert
            String alias = e.nextElement();
            assertEquals("cacert", alias);
        }
    }

    @Test
    public void testSystemProperty() throws Exception {
        System.out.println("SystemProperty");
        Properties p = System.getProperties();
        p.list(System.out);
    }

}
