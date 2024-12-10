package extend.util.external;

import java.io.IOException;
import java.net.URL;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 *
 * @author isayan
 */
public class BurpBrowserTest {

    public BurpBrowserTest() {
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
    public void testBaseJar() throws IOException {
        System.out.println("testBaseJar");
        URL url = new URL("file:/resources/help.jar!/images/Extender_Yagura.png");
        System.out.println(url.toExternalForm());
        String result = BurpBrowser.getBaseJar(url);
        System.out.println("url =>" + result);
        assertTrue(result.contains("help.jar"));
    }

    @Test
    public void testBaseJar2() throws IOException {
        System.out.println("testBaseJar2");
        URL url = new URL("jar:file:/resources/help.jar!/images/Extender_Yagura.png");
        System.out.println("Protocol:" + url.getProtocol());
        System.out.println("Host:" + url.getHost());
        System.out.println("File:" + url.getFile());
        System.out.println("Path:" + url.getPath());
        System.out.println("UserInfo:" + url.getUserInfo());
        System.out.println("Exterm:" + url.toExternalForm());
        String result = BurpBrowser.getBaseJar(url);
        System.out.println("url =>" + result);
        assertTrue(result.contains("help.jar"));
    }

    @Test
    public void testBaseJar3() throws IOException {
        System.out.println("testBaseJar3");
        try {
            URL url = new URL("file:/C:\\Windows\\Temp\\help.jar!/images/Extender_Yagura.png");
            String result = BurpBrowser.getBaseJar(url);
            System.out.println("file =>" + result);
        } catch (Exception ex) {
            fail(ex);
        }
    }

    @Test
    public void testBaseJar4() throws IOException {
        System.out.println("testBaseJar4");
        try {
            URL url = new URL("jar:file:/resources/help.jar!/images/Extender_Yagura.png");
            String result = BurpBrowser.getBaseJar(url);
            System.out.println("file =>" + result);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

}
