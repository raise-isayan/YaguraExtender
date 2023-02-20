package extension.burp;

import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Properties;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import yagura.model.AutoResponderItem;
import yagura.model.AutoResponderProperty;

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
        List<AutoResponderItem> autoResponderItemList = new ArrayList<AutoResponderItem>();
        AutoResponderItem autoResponderItem = new AutoResponderItem();
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
            if (item != null) {
                System.out.println("find:" + item.toString());
            }
        }
        {
            AutoResponderItem item = property.findItem("http://www.example.com/test");
            if (item != null) {
                System.out.println("second:" + item.toString());
            }
        }
    }

}
