package yagura;

import burp.BurpExtension;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import extend.util.external.gson.XMatchItemAdapter;
import extension.burp.MessageHighlightColor;
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
import java.util.logging.Level;
import java.util.logging.Logger;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
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

    private final static Logger logger = Logger.getLogger(ConfigTest.class.getName());

    public ConfigTest() {
    }

    @BeforeAll
    public static void setUpClass() {
    }

    @AfterAll
    public static void tearDownClass() {
    }

    @BeforeEach
    public void setUp() {
        JsonUtil.registerTypeHierarchyAdapter(MatchItem.class, new XMatchItemAdapter());
    }

    @AfterEach
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
            byte[] test = FileUtil.bytesFromFile(new File(url.toURI()));
            JsonElement json = JsonUtil.parseJson(StringUtil.getStringUTF8(test));
            String value = JsonUtil.prettyJson(json, true);
            System.out.println(value);
        } catch (IOException | URISyntaxException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
            fail(ex.getMessage());
        }

    }

    private final OptionProperty optionProperty = new OptionProperty();

    protected static final String LOGGING_PROPERTIES = "/yagura/resources/" + Config.getLoggingPropertyName();

    /**
     * Test of saveToXML method, of class LegacyConfig.
     */
    @Test
    public void testLoadLogPropertyXML() {
        InputStream inStream = BurpExtension.class.getResourceAsStream(LOGGING_PROPERTIES);
        Properties prop = new Properties();
        try {
            prop.load(inStream);
            ByteArrayOutputStream bstm = new ByteArrayOutputStream();
            prop.storeToXML(bstm, "");
            System.out.println(bstm.toString(StandardCharsets.ISO_8859_1.name()));
        } catch (IOException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
            fail(ex.getMessage());
        }
    }

    @Test
    public void testMatchAlertProperty() {
        MatchAlertProperty matchAlert = optionProperty.getMatchAlertProperty();
        List<MatchAlertItem> matchAlertList = new ArrayList<>();

        MatchAlertItem matchAlertItem0 = new MatchAlertItem();
        matchAlertItem0.setNotifyTypes(EnumSet.allOf(NotifyType.class));
        matchAlertItem0.setHighlightColor(MessageHighlightColor.CYAN);
        matchAlertItem0.setNotes("comment");
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
        OptionProperty option = new OptionProperty();
        Map<String, String> config = option.loadConfigSetting();
        if (fi.exists()) {
            JsonUtil.loadFromJson(fi, config);
            option.setProperty(config);
            assertEquals(5, option.getEncodingProperty().getEncodingList().size());
            assertEquals(EnumSet.of(UniversalView.JRAW, UniversalView.GENERATE_POC, UniversalView.HTML_COMMENT, UniversalView.JSON), option.getEncodingProperty().getMessageView());
            assertEquals(1, option.getMatchReplaceProperty().getReplaceNameList().size());
            assertEquals(1, option.getMatchReplaceProperty().getReplaceMap().size());
            assertEquals(null, option.getMatchReplaceProperty().getReplaceSelectedGroup(option.getMatchReplaceProperty().getSelectedName()));
            assertEquals(false, option.getMatchReplaceProperty().getReplaceSelectedGroup("xxx").isInScopeOnly());
            assertEquals(1, option.getMatchReplaceProperty().getReplaceSelectedList("xxx").size());
            assertEquals(true, option.getAutoResponderProperty().getAutoResponderEnable());
            assertEquals(1234, option.getAutoResponderProperty().getRedirectPort());
            assertEquals(1, option.getAutoResponderProperty().getAutoResponderItemList().size());
        }
        File fo = File.createTempFile("yagura", "json");
        option.getAutoResponderProperty().setAutoResponderEnable(false);
        option.getAutoResponderProperty().setRedirectPort(4567);
        System.out.println(fo.getAbsoluteFile());
        config = option.getProperty();
        JsonUtil.saveToJson(fo, config);

    }

    @Test
    public void testLoadOptionHierarchyLegacy1() throws Exception {
        System.out.println("loadOptionHierarchyLegacy1");
        URL url = this.getClass().getResource("/resources/YaguraExtender_legacy1.json");
        File fi = new File(url.toURI());
        OptionProperty option = new OptionProperty();
        if (fi.exists()) {
            Map<String, String> config = option.loadConfigSetting();
            JsonUtil.loadFromJson(fi, config);
            option.setProperty(config);
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
