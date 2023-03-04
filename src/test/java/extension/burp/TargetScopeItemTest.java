package extension.burp;

import extension.helpers.ConvertUtil;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.logging.Level;
import java.util.logging.Logger;
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
public class TargetScopeItemTest {

    private final static Logger logger = Logger.getLogger(TargetScopeItemTest.class.getName());

    public TargetScopeItemTest() {
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
     * Test of parseURL method, of class TargetScopeItem.
     */
    @Test
    public void testParseURL() {
        System.out.println("parseURL");
        try {
            URL url = new URL("https://www.google.com/aaa?test=bbb#xyz");
            TargetScopeItem result = TargetScopeItem.parseURL(url);
            {
                String expResult = "^\\Qwww.google.com\\E$";
                System.out.println(url.getHost());
                assertEquals(expResult, result.getHost());
            }
            {
                String expResult = "^\\Q/aaa?test=bbb\\E.*";
                System.out.println(result.getFile());
                assertEquals(expResult, result.getFile());
            }
            {
                int expResult = 443;
                System.out.println(result.getPort());
                assertEquals(expResult, ConvertUtil.parseIntDefault(result.getPort(), -1));
            }
        } catch (MalformedURLException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
            fail();
        }
        try {
            URL url = new URL("https://www.google.com");
            System.out.println(">" + url.getFile());
            URL url2 = new URL("https://www.google.com/");
            System.out.println(">" + url.getFile());
        } catch (MalformedURLException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
            fail();
        }
    }

}
