package yagura;

import burp.BurpExtender;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import extend.util.IniProp;
import extend.util.Util;
import extend.util.external.JsonUtil;
import extend.util.external.MatchItemAdapter;
import extend.util.external.gson.XMatchItemAdapter;
import extend.view.base.MatchItem;
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
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import yagura.Config;
import yagura.model.IOptionProperty;
import yagura.model.MatchAlertItem;
import yagura.model.MatchAlertProperty;
import yagura.model.MatchReplaceGroup;
import yagura.model.MatchReplaceItem;
import yagura.model.MatchReplaceProperty;
import yagura.model.OptionProperty;
import yagura.model.UniversalViewProperty;

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
//        JsonUtil.registerTypeHierarchyAdapter(MatchItem.class, new XMatchItemAdapter());
        JsonUtil.registerTypeAdapter(MatchAlertItem.class, new XMatchItemAdapter());
        JsonUtil.registerTypeAdapter(MatchReplaceItem.class, new XMatchItemAdapter());
    }
    
    @After
    public void tearDown() {
        JsonUtil.removeTypeAdapter(MatchAlertItem.class);
        JsonUtil.removeTypeAdapter(MatchReplaceItem.class);
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
            byte [] test = Util.bytesFromFile(new File(url.toURI()));
            JsonElement json = JsonUtil.parse(Util.decodeMessage(test, "UTF-8")); 
            String value = JsonUtil.prettyJson(json, true);
            System.out.println(value);
        } catch (IOException ex) {
            Logger.getLogger(ConfigTest.class.getName()).log(Level.SEVERE, null, ex);
        } catch (URISyntaxException ex) {
            Logger.getLogger(ConfigTest.class.getName()).log(Level.SEVERE, null, ex);
        }
        
    }
                
//    /**
//     * Test of toCharsetMode method, of class LegacyConfig.
//     */
//    @Test
//    public void testToCharsetMode() {
//        System.out.println("toCharsetMode");
//        {
//            String encodeName = "PlatformDefault";
//            String expResult = "__CharsetUsePlatformDefault";
//            String result = LegacyConfig.toCharsetMode(encodeName);
//            assertEquals(expResult, result);            
//        }
//        {
//            String encodeName = "AutoRecognise";
//            String expResult = "__CharsetAutoRecognise";
//            String result = LegacyConfig.toCharsetMode(encodeName);
//            assertEquals(expResult, result);            
//        }
//        {
//            String encodeName = "RawBytes";
//            String expResult = "__CharsetRawBytes";
//            String result = LegacyConfig.toCharsetMode(encodeName);
//            assertEquals(expResult, result);            
//        }
//    }

//    /**
//     * Test of toEncodingName method, of class LegacyConfig.
//     */
//    @Test
//    public void testToEncodingName() {
//        System.out.println("toEncodingName");
//        {
//            String charSetMode = "__CharsetUsePlatformDefault";
//            String expResult = "PlatformDefault";
//            String result = LegacyConfig.toEncodingName(charSetMode);
//            assertEquals(expResult, result);        
//        }
//        {
//            String charSetMode = "__CharsetAutoRecognise";
//            String expResult = "AutoRecognise";
//            String result = LegacyConfig.toEncodingName(charSetMode);
//            assertEquals(expResult, result);        
//        }
//        {
//            String charSetMode = "__CharsetRawBytes";
//            String expResult = "RawBytes";
//            String result = LegacyConfig.toEncodingName(charSetMode);
//            assertEquals(expResult, result);        
//        }
//    }

//    /**
//     * Test of isEncodingName method, of class LegacyConfig.
//     */
//    @Test
//    public void testIsEncodingName() {
//        System.out.println("isEncodingName");
//        {
//            String charSetMode = "__CharsetUsePlatformDefault";
//            boolean expResult = false;
//            boolean result = LegacyConfig.isEncodingName(charSetMode);
//            assertEquals(expResult, result);        
//        }
//        {
//            String charSetMode = "PlatformDefault";
//            boolean expResult = true;
//            boolean result = LegacyConfig.isEncodingName(charSetMode);
//            assertEquals(expResult, result);        
//        }        
//    }

    private final IOptionProperty optionProperty = new OptionProperty();
    
    /**
     * Test of saveToXML method, of class LegacyConfig.
     */
    @Test
    public void testLoadSaveXML() {
        {
            try {
                System.out.println("saveToXML");
                File fo = new File(System.getProperty("java.io.tmpdir"), "configTest.xml");
                System.out.println("Path:" + fo);
                LegacyConfig.saveToXML(fo, optionProperty);                        
                assertTrue(fo.exists());
            } catch (IOException ex) {
                Logger.getLogger(ConfigTest.class.getName()).log(Level.SEVERE, null, ex);
                assertTrue(false);
            }
        }
        {
            try {
                System.out.println("loadFromXml");
                File fi = new File(System.getProperty("java.io.tmpdir"), "configTest.xml");
                LegacyConfig.loadFromXml(fi, optionProperty);
                assertEquals(3, optionProperty.getEncodingProperty().getEncodingList().size());
                assertEquals(0, optionProperty.getMatchAlertProperty().getMatchAlertItemList().size());
                assertEquals(0, optionProperty.getMatchReplaceProperty().getReplaceNameList().size());
                assertEquals("", optionProperty.getMatchReplaceProperty().getSelectedName());
                assertEquals(null, optionProperty.getMatchReplaceProperty().getMatchReplaceList());
                assertEquals(false, optionProperty.getMatchReplaceProperty().isSelectedMatchReplace());
                assertEquals(0, optionProperty.getSendToProperty().getSendToItemList().size());
                assertEquals(false, optionProperty.getLoggingProperty().isAutoLogging());
                assertEquals(true, optionProperty.getLoggingProperty().isToolLog());
                assertEquals(true, optionProperty.getLoggingProperty().isProxyLog());
                assertEquals(0, optionProperty.getLoggingProperty().getLogFileLimitSize());                    
                assertEquals(0, optionProperty.getLoggingProperty().getLogFileByteLimitSize());
            } catch (IOException ex) {
                Logger.getLogger(ConfigTest.class.getName()).log(Level.SEVERE, null, ex);
                assertTrue(false);
            }
        }
    }

    @Test
    public void testEncoding() {
        IniProp prop = new IniProp();
        UniversalViewProperty encProp = new UniversalViewProperty();
        //encProp.setClipbordAutoDecode(prop.readEntryBool("encoding", "clipbordAutoDecode", false));
        encProp.setClipbordAutoDecode(false);
        List<String> encList = prop.readEntryList("encoding", "list", UniversalViewProperty.getDefaultEncodingList());
        encProp.setEncodingList(encList);
        for (String l : encList) {
            System.out.println(l);
        }
        
    }

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
        List<MatchAlertItem> matchAlertList = new ArrayList<MatchAlertItem>();

        MatchAlertItem matchAlertItem0 = new MatchAlertItem();
        matchAlertItem0.setNotifyTypes(EnumSet.allOf(MatchItem.NotifyType.class));
        matchAlertItem0.setHighlightColor(MatchItem.HighlightColor.CYAN);
        matchAlertItem0.setComment("comment");
        matchAlertItem0.setTargetTools(EnumSet.allOf(MatchItem.TargetTool.class));
        matchAlertList.add(matchAlertItem0);

        MatchAlertItem matchAlertItem1 = new MatchAlertItem();
        matchAlertItem1.setNotifyTypes(EnumSet.noneOf(MatchItem.NotifyType.class));
        matchAlertItem1.setTargetTools(EnumSet.noneOf(MatchItem.TargetTool.class));
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
        gsonBuilder.registerTypeAdapter(MatchItem.class, new MatchItemAdapter());
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
        gsonBuilder.registerTypeHierarchyAdapter(MatchItem.class, new MatchItemAdapter());
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
        }        
    }
    
}
