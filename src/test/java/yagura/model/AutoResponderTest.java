package yagura.model;

import extension.helpers.HttpUtil;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.EventQueue;
import java.awt.Toolkit;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.UIManager;
import javax.swing.UnsupportedLookAndFeelException;
import javax.swing.WindowConstants;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import yagura.view.SendToTab;

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
    public void testAutoResponderFindItem() {
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
    public void testAutoResponderMultiFindItem() {
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
    public void testAutoResponderItem() {
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

    public static void main(String[] args) {
        EventQueue.invokeLater(MainPanel::createAndShowGui);
    }

    final static class MainPanel extends JPanel {

        private MainPanel() {
            super(new BorderLayout());
            SendToTab sendTo = new SendToTab();
            java.util.List<SendToItem> list = new ArrayList<SendToItem>();
            SendToItem item1 = new SendToItem();
            item1.setCaption("caption1");
            item1.setTarget("target1");
            item1.setExtend(SendToItem.ExtendType.SEND_TO_JTRANSCODER);
            list.add(item1);
            SendToItem item2 = new SendToItem();
            item2.setCaption("caption2");
            item2.setTarget("target2");
            list.add(item2);
            SendToItem item3 = new SendToItem();
            item3.setCaption("caption3");
            item3.setTarget("target3");
            list.add(item3);
            sendTo.setSendToItemList(list);
            this.add(sendTo, BorderLayout.CENTER);
            setPreferredSize(new Dimension(320, 240));
        }

        private static void createAndShowGui() {
            try {
                UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            } catch (UnsupportedLookAndFeelException ignored) {
                Toolkit.getDefaultToolkit().beep();
            } catch (ClassNotFoundException | InstantiationException | IllegalAccessException ex) {
                ex.printStackTrace();
                return;
            }
            JFrame frame = new JFrame("DnDReorderTable");
            frame.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
            frame.getContentPane().add(new MainPanel());
            frame.pack();
            frame.setLocationRelativeTo(null);
            frame.setVisible(true);
        }
    }

}
