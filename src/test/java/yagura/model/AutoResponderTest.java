package yagura.model;

import extension.helpers.HttpUtil;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;

/**
 *
 * @author isayan
 */
public class AutoResponderTest {

    public AutoResponderTest() {
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
     */
    @Test
    public void testAutoResponderFindItem()  {
        AutoResponderProperty property = new AutoResponderProperty();
        List<AutoResponderItem> autoResponderItemList = new ArrayList<>();
        AutoResponderItem autoResponderItem = new AutoResponderItem();
        autoResponderItem.setMethod("GET");
        autoResponderItem.setMatch("http://www.example.com/");
        autoResponderItem.setSelected(true);
        autoResponderItem.setRegexp(false);
        autoResponderItem.setBodyOnly(true);
        autoResponderItem.setReplace("body");
        autoResponderItem.setContentType("text/html");
        autoResponderItemList.add(autoResponderItem);
        property.setAutoResponderItemList(autoResponderItemList);
        {
            AutoResponderItem item = property.findItem("http://www.example.com/");
            assertNotNull(item);
        }
        {
            AutoResponderItem item = property.findItem("http://www.example.com/test");
            assertNotNull(item);
        }
        {
            AutoResponderItem item = property.findItem("http://www.example.com/", "GET");
            assertNotNull(item);
        }
        {
            AutoResponderItem item = property.findItem("http://www.example.com/", "POST");
            assertNull(item);
        }
    }

    /**
     */
    @Test
    public void testAutoResponderMultiFindItem()  {
        AutoResponderProperty property = new AutoResponderProperty();
        List<AutoResponderItem> autoResponderItemList = new ArrayList<>();
        {
            AutoResponderItem autoResponderFirstItem = new AutoResponderItem();
            autoResponderFirstItem.setMatch("https://redirect/");
            autoResponderFirstItem.setSelected(true);
            autoResponderFirstItem.setRegexp(false);
            autoResponderFirstItem.setBodyOnly(true);
            autoResponderFirstItem.setReplace("reponse");
            autoResponderFirstItem.setContentType("text/html");
            autoResponderItemList.add(autoResponderFirstItem);
            AutoResponderItem autoResponderSecondtem = new AutoResponderItem();
            autoResponderSecondtem.setMatch("https://www.example.com/");
            autoResponderSecondtem.setSelected(true);
            autoResponderSecondtem.setRegexp(false);
            autoResponderSecondtem.setBodyOnly(false);
            autoResponderSecondtem.setReplace("body");
            autoResponderItemList.add(autoResponderSecondtem);
            property.setAutoResponderItemList(autoResponderItemList);
            {
                AutoResponderItem item = property.findItem("https://redirect/");
                assertNotNull(item);
            }
            {
                AutoResponderItem item = property.findItem("https://redirect/nnn");
                assertNotNull(item);
            }
        }
    }

    /**
     */
    @Test
    public void testAutoResponderItem()  {
        {
            AutoResponderItem autoResponderItem = new AutoResponderItem();
            autoResponderItem.setMatch("redirect");
            autoResponderItem.setSelected(true);
            autoResponderItem.setRegexp(false);
            autoResponderItem.setBodyOnly(true);
            autoResponderItem.setReplace("reponse");
            autoResponderItem.setContentType("text/html");
            assertFalse(autoResponderItem.isRegexp() && !autoResponderItem.isValidRegex());
            assertTrue(!autoResponderItem.isRegexp() && autoResponderItem.isValidRegex() && !HttpUtil.isValidUrl(autoResponderItem.getMatch()));
        }
        {
            AutoResponderItem autoResponderItem = new AutoResponderItem();
            autoResponderItem.setMatch("redirect");
            autoResponderItem.setSelected(true);
            autoResponderItem.setRegexp(true);
            autoResponderItem.setBodyOnly(true);
            autoResponderItem.setReplace("reponse");
            autoResponderItem.setContentType("text/html");
            assertFalse(autoResponderItem.isRegexp() && !autoResponderItem.isValidRegex());
            assertFalse(!autoResponderItem.isRegexp() && autoResponderItem.isValidRegex() && !HttpUtil.isValidUrl(autoResponderItem.getMatch()));
        }
        {
            AutoResponderItem autoResponderItem = new AutoResponderItem();
            autoResponderItem.setMatch("http://www.example.com");
            autoResponderItem.setSelected(true);
            autoResponderItem.setRegexp(false);
            autoResponderItem.setBodyOnly(true);
            autoResponderItem.setReplace("reponse");
            autoResponderItem.setContentType("text/html");
            assertFalse(autoResponderItem.isRegexp() && !autoResponderItem.isValidRegex());
            assertFalse(!autoResponderItem.isRegexp() && autoResponderItem.isValidRegex() && !HttpUtil.isValidUrl(autoResponderItem.getMatch()));
        }
        {
            AutoResponderItem autoResponderItem = new AutoResponderItem();
            autoResponderItem.setMatch("http\\://www\\.example\\.com");
            autoResponderItem.setSelected(true);
            autoResponderItem.setRegexp(true);
            autoResponderItem.setBodyOnly(true);
            autoResponderItem.setReplace("reponse");
            autoResponderItem.setContentType("text/html");
            assertFalse(autoResponderItem.isRegexp() && !autoResponderItem.isValidRegex());
            assertFalse(!autoResponderItem.isRegexp() && autoResponderItem.isValidRegex() && !HttpUtil.isValidUrl(autoResponderItem.getMatch()));
        }
    }


}
