package yagura;

import burp.BurpExtender;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import extend.util.external.gson.XMatchItemAdapter;
import extension.burp.HighlightColor;
import extension.burp.NotifyType;
import extension.burp.TargetTool;
import extension.helpers.FileUtil;
import extension.helpers.StringUtil;
import extension.helpers.json.JsonUtil;
import extension.view.base.MatchItem;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Timer;
import java.util.TimerTask;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import yagura.model.IOptionProperty;
import yagura.model.MatchAlertItem;
import yagura.model.MatchAlertProperty;
import yagura.model.MatchReplaceGroup;
import yagura.model.MatchReplaceItem;
import yagura.model.MatchReplaceProperty;
import yagura.model.OptionProperty;
import yagura.model.UniversalViewProperty.UniversalView;

/**
 *
 * @author isayan
 */
public class ConfigTest {

    public ConfigTest() {
    }

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }

    @Before
    public void setUp() {
        JsonUtil.registerTypeHierarchyAdapter(MatchItem.class, new XMatchItemAdapter());
    }

    @After
    public void tearDown() {
        JsonUtil.removeTypeHierarchyAdapter(MatchItem.class);
    }

    /**
     * Test of getToolLogName method, of class LegacyConfig.
     */
    @Test
    public void testGetToolLogName() {
        System.out.println("getToolLogName");
        String toolName = "Proxy";
        String expResult = "burp_tool_Proxy.log";
        String result = Config.getToolLogName(toolName);
        assertEquals(expResult, result);
    }

    @Test
    public void testConfig() {
        try {
            URL url = this.getClass().getResource("/resources/default_project_burp.json");
            byte [] test = FileUtil.bytesFromFile(new File(url.toURI()));
            JsonElement json = JsonUtil.parse(StringUtil.getStringUTF8(test));
            String value = JsonUtil.prettyJson(json, true);
            System.out.println(value);
        } catch (IOException ex) {
            Logger.getLogger(ConfigTest.class.getName()).log(Level.SEVERE, null, ex);
        } catch (URISyntaxException ex) {
            Logger.getLogger(ConfigTest.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

    private final IOptionProperty optionProperty = new OptionProperty();

    protected static final String LOGGING_PROPERTIES = "/yagura/resources/" + Config.getLoggingPropertyName();

    /**
     * Test of saveToXML method, of class LegacyConfig.
     */
    @Test
    public void testLoadLogPropertyXML() {
        InputStream inStream = BurpExtender.class.getResourceAsStream(LOGGING_PROPERTIES);
        Properties prop = new Properties();
        try {
            prop.load(inStream);
            ByteArrayOutputStream bstm = new ByteArrayOutputStream();
            prop.storeToXML(bstm, "");
            System.out.println(bstm.toString(StandardCharsets.ISO_8859_1.name()));
        } catch (IOException ex) {
            Logger.getLogger(ConfigTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    @Test
    public void testMatchAlertProperty() {
        MatchAlertProperty matchAlert = optionProperty.getMatchAlertProperty();
        List<MatchAlertItem> matchAlertList = new ArrayList<>();

        MatchAlertItem matchAlertItem0 = new MatchAlertItem();
        matchAlertItem0.setNotifyTypes(EnumSet.allOf(NotifyType.class));
        matchAlertItem0.setHighlightColor(HighlightColor.CYAN);
        matchAlertItem0.setComment("comment");
        matchAlertItem0.setTargetTools(EnumSet.allOf(TargetTool.class));
        matchAlertList.add(matchAlertItem0);

        MatchAlertItem matchAlertItem1 = new MatchAlertItem();
        matchAlertItem1.setNotifyTypes(EnumSet.noneOf(NotifyType.class));
        matchAlertItem1.setTargetTools(EnumSet.noneOf(TargetTool.class));
        matchAlertList.add(matchAlertItem1);

        matchAlert.setMatchAlertItemList(matchAlertList);

    }

    @Test
    public void testMatchItem() throws Exception {
        System.out.println("matchItem");
        MatchItem item = new MatchItem();
        item.setType("test");
        item.setReplace("replace");
        GsonBuilder gsonBuilder = new GsonBuilder().setPrettyPrinting().excludeFieldsWithoutExposeAnnotation().disableHtmlEscaping().serializeNulls();
        gsonBuilder.registerTypeAdapter(MatchItem.class, new XMatchItemAdapter());
        Gson gson = gsonBuilder.create();
        String json = gson.toJson(item);
        System.out.println(json);
    }


    @Test
    public void testMatchReplaceItem() throws Exception {
        System.out.println("matchReplaceItem");
        MatchReplaceItem item = new MatchReplaceItem();
        item.setType("test");
        item.setReplace("replace");
        GsonBuilder gsonBuilder = new GsonBuilder().setPrettyPrinting().excludeFieldsWithoutExposeAnnotation().disableHtmlEscaping().serializeNulls();
        gsonBuilder.registerTypeAdapter(MatchItem.class, new XMatchItemAdapter());
        Gson gson = gsonBuilder.create();
        String json = gson.toJson(item);
        System.out.println(json);
    }

    @Test
    public void testMatchReplaceItemHierarchy() throws Exception {
        System.out.println("matchReplaceItemHierarchy");
        MatchReplaceItem item = new MatchReplaceItem();
        item.setType("test");
        item.setReplace("replace");
        GsonBuilder gsonBuilder = new GsonBuilder().setPrettyPrinting().excludeFieldsWithoutExposeAnnotation().disableHtmlEscaping().serializeNulls();
        gsonBuilder.registerTypeHierarchyAdapter(MatchItem.class, new XMatchItemAdapter());
        Gson gson = gsonBuilder.create();
        String json = gson.toJson(item);
        System.out.println(json);
    }

    @Test
    public void testSaveOptionHierarchy() throws Exception {
        System.out.println("saveOoptionHierarchy");
        OptionProperty option = new OptionProperty();
        MatchReplaceProperty matchReplaceProperty = new MatchReplaceProperty();
        Map<String, MatchReplaceGroup> replaceMap = new HashMap<>();
        MatchReplaceGroup group = new MatchReplaceGroup();
        group.setInScopeOnly(true);
        List<MatchReplaceItem> replaceList = new ArrayList<>();
        MatchReplaceItem item = new MatchReplaceItem();
        item.setType("test");
        item.setReplace("replace");
        replaceList.add(item);
        group.setReplaceList(replaceList);
        replaceMap.put("test", group);
        matchReplaceProperty.setReplaceMap(replaceMap);
        option.setMatchReplaceProperty(matchReplaceProperty);
        GsonBuilder gsonBuilder = new GsonBuilder().setPrettyPrinting().excludeFieldsWithoutExposeAnnotation().disableHtmlEscaping().serializeNulls();
        Gson gson = gsonBuilder.create();
        String json = gson.toJson(option);
        System.out.println(json);
    }

    @Test
    public void testLoadOptionHierarchy() throws Exception {
        System.out.println("loadOptionHierarchy");
        URL url = this.getClass().getResource("/resources/YaguraExtender.json");
        File fi = new File(url.toURI());
        if (fi.exists()) {
            OptionProperty option = JsonUtil.loadFromJson(fi, OptionProperty.class, true);
            assertEquals(5, option.getEncodingProperty().getEncodingList().size());
            assertEquals(EnumSet.of(UniversalView.JRAW, UniversalView.GENERATE_POC, UniversalView.HTML_COMMENT, UniversalView.JSON), option.getEncodingProperty().getMessageView());
            assertEquals(1, option.getMatchReplaceProperty().getReplaceNameList().size());
            assertEquals(1, option.getMatchReplaceProperty().getReplaceMap().size());
            assertEquals(null, option.getMatchReplaceProperty().getReplaceSelectedGroup(option.getMatchReplaceProperty().getSelectedName()));
            assertEquals(false, option.getMatchReplaceProperty().getReplaceSelectedGroup("xxx").isInScopeOnly());
            assertEquals(1, option.getMatchReplaceProperty().getReplaceSelectedList("xxx").size());
        }
    }

    @Test
    public void testLoadOptionHierarchyLegacy1() throws Exception {
        System.out.println("loadOptionHierarchyLegacy1");
        URL url = this.getClass().getResource("/resources/YaguraExtender_legacy1.json");
        File fi = new File(url.toURI());
        if (fi.exists()) {
            OptionProperty option = JsonUtil.loadFromJson(fi, OptionProperty.class, true);
            assertEquals(5, option.getEncodingProperty().getEncodingList().size());
            assertEquals(EnumSet.of(UniversalView.JRAW, UniversalView.GENERATE_POC, UniversalView.HTML_COMMENT, UniversalView.JSON), option.getEncodingProperty().getMessageView());
            assertEquals(1, option.getMatchReplaceProperty().getReplaceNameList().size());
            assertEquals(1, option.getMatchReplaceProperty().getReplaceMap().size());
            assertEquals(null, option.getMatchReplaceProperty().getReplaceSelectedGroup(option.getMatchReplaceProperty().getSelectedName()));
            assertEquals(false, option.getMatchReplaceProperty().getReplaceSelectedGroup("xxx").isInScopeOnly());
            assertEquals(1, option.getMatchReplaceProperty().getReplaceSelectedList("xxx").size());
        }
    }

}
