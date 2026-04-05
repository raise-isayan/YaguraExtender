package extend.util.external;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.file.Path;
import java.util.Map;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.AfterAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 *
 * @author isayan
 */
public class BurpBrowserTest {

    private final static Logger logger = Logger.getLogger(BurpBrowserTest.class.getName());

    public BurpBrowserTest() {
    }

    @BeforeAll
    public static void setUpClass() {
        try {
            Class browser = BurpBrowser.class;
            Field field = browser.getDeclaredField("chromium_prop");
            field.setAccessible(true);
            if (field.get(null) instanceof Properties prop) {
                prop.load(BurpBrowserTest.class.getResourceAsStream("/resources/chromium.properties"));
            }
        } catch (NoSuchFieldException | SecurityException | IOException | IllegalArgumentException | IllegalAccessException ex) {
            logger.log(Level.SEVERE, null, ex);
        }
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
    public void testOSTest() {
        System.out.println("testOSTest");
        String osver = BurpBrowser.getOSArc();
        assertNotNull(osver);
        System.out.println("osver:" + osver);
    }

    @Test
    public void testBrowserTest() {
        System.out.println("testBrowserTest");
        Path path = BurpBrowser.getBrowsePath();
        System.out.println("path:" + path);
        String version = BurpBrowser.getBrowserVersion();
        assertNotNull(version);
        System.out.println("version:" + version);
        assertEquals("131.0.6778.86", version);
    }

    @Test
    public void testBrowserProfiel() throws IOException {
        System.out.println("testBrowserProfiel");
        try {
            String state_path = BurpBrowserTest.class.getResource("/resources/Local_State").getPath();
            Map<String, BurpBrowser.BrowserProfile> profile_map = BurpBrowser.getBrowserProfile(new File(state_path).toPath());
            for (String key : profile_map.keySet()) {
                System.out.println("keys:" + key);
                System.out.println("value:" + profile_map.get(key).getName());
            }
        } catch (IOException ex) {
            fail(ex.getMessage(), ex);
        }
    }

}
