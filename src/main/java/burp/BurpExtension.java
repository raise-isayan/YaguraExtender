package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.message.Cookie;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.sessions.CookieJar;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;
import burp.api.montoya.ui.editor.extension.HttpResponseEditorProvider;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedWebSocketMessageEditor;
import burp.api.montoya.ui.editor.extension.WebSocketMessageEditorProvider;
import java.awt.Component;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.Logger;
import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.awt.event.WindowListener;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import javax.swing.JFrame;
import java.awt.BorderLayout;
import java.awt.Frame;
import java.util.EnumSet;
import javax.swing.JMenuItem;
import extend.util.external.ThemeUI;
import extension.burp.BurpConfig;
import extension.burp.BurpExtensionImpl;
import extension.burp.BurpUtil;
import extension.burp.BurpVersion;
import extension.burp.IBurpTab;
import extension.helpers.HttpUtil;
import extension.helpers.StringUtil;
import extension.helpers.SwingUtil;
import extension.helpers.json.JsonUtil;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import yagura.Config;
import yagura.Version;
import yagura.handler.AutoResponderHandler;
import yagura.model.SendToMenu;
import yagura.view.TabbetOption;
import yagura.model.OptionProperty;
import yagura.model.AutoResponderProperty;
import yagura.model.JSearchProperty;
import yagura.model.JTransCoderProperty;
import yagura.model.Logging;
import yagura.model.LoggingProperty;
import yagura.model.MatchAlertProperty;
import yagura.model.MatchReplaceProperty;
import yagura.handler.MenuHander;
import yagura.handler.ProxyHander;
import yagura.handler.WebSocketHander;
import yagura.model.ResultFilterProperty;
import yagura.model.SendToProperty;
import yagura.model.UniversalViewProperty;
import yagura.view.BurpToolBar;
import yagura.view.GeneratePoCTabEditor;
import yagura.view.GenerateWebsocktPoCEditor;
import yagura.view.HtmlCommetViewTabEditor;
import yagura.view.JSONViewTabEditor;
import yagura.view.JWSViewTabEditor;
import yagura.view.ParamsViewTabEditor;
import yagura.view.PopupMessage;
import yagura.view.RawViewTabEditor;
import yagura.view.ViewStateTabEditor;

/**
 * @author isayan
 */
public class BurpExtension extends BurpExtensionImpl implements ExtensionUnloadingHandler {

    private final static Logger logger = Logger.getLogger(BurpExtension.class.getName());

    private final static java.util.ResourceBundle BUNDLE = java.util.ResourceBundle.getBundle("burp/resources/release");

    private final static File CONFIG_FILE = new File(Config.getExtensionHomeDir(), Config.getExtensionName());

    /**
     * ログ設定プロパティファイルのファイル名
     */
    protected static final String LOGGING_PROPERTIES = "/yagura/resources/" + Config.getLoggingPropertyName();

    private boolean DEBUG = false;

    private MenuHander menuHandler;
    private ProxyHander proxyHandler;
    private WebSocketHander websocektHandler;
    private EditorProvider editorProvider;
    private AutoResponderHandler autoResponderHandler;
    private Registration registerContextMenu;
    private final List<Registration> registerHotkeys = new ArrayList<>();

    private boolean isTemporaryProject = false;

    private BurpToolBar toolbar;
    private final PopupMessage popupMessage = new PopupMessage(null);

    static {
        try (ByteArrayOutputStream bout = new ByteArrayOutputStream()) {
            Properties prop = new Properties();
            File logDir = Config.getExtensionHomeDir();
            logDir.mkdirs();
            File logPropFile = new File(Config.getExtensionHomeDir(), Config.getLoggingPropertyName());
            if (logPropFile.exists()) {
                prop.load(new FileInputStream(logPropFile));
            } else {
                prop.load(BurpExtension.class.getResourceAsStream(LOGGING_PROPERTIES));
            }
            String pattern = prop.getProperty(FileHandler.class.getName() + ".pattern");
            prop.setProperty(FileHandler.class.getName() + ".pattern", new File(logDir, pattern).getAbsolutePath());
            prop.store(bout, "");
            LogManager.getLogManager().readConfiguration(new ByteArrayInputStream(bout.toByteArray()));
        } catch (IOException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        // JsonUtil.registerTypeHierarchyAdapter(MatchItem.class, new XMatchItemAdapter());
    }

    public BurpExtension() {
        Thread.setDefaultUncaughtExceptionHandler(new Thread.UncaughtExceptionHandler() {
            @Override
            public void uncaughtException(Thread t, Throwable ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        });
    }

    final PropertyChangeListener propertyListener = new PropertyChangeListener() {
        @Override
        public void propertyChange(PropertyChangeEvent evt) {
            api().userInterface().applyThemeToComponent(popupMessage);
        }
    };

    private final WindowListener windowPopupListener = new WindowAdapter() {
        @Override
        public void windowClosing(WindowEvent e) {
            if (BurpUtil.suiteFrame() instanceof JFrame) {
                if (option.getLoggingProperty().isWarnClosingTemporaryProject() && isTemporaryProject) {
                    int popupTime = option.getLoggingProperty().getPopupTime();
                    popupMessage.show("Project is Temporary.", popupTime);
                }
            }
        }
    };

    private void registerTemporaryProject() {
        // MainFrame閉じる処理
        if (BurpUtil.suiteFrame() instanceof JFrame burpFrame) {
            this.isTemporaryProject = BurpUtil.isTemporaryProject();
            synchronized (JFrame.class) {
                //burpFrame.setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);
                WindowListener[] wl = burpFrame.getWindowListeners();
                for (WindowListener l : wl) {
                    burpFrame.removeWindowListener(l);
                }
                burpFrame.addWindowListener(windowPopupListener);
                for (WindowListener l : wl) {
                    burpFrame.addWindowListener(l);
                }
            }
        }
    }

    // Professional / Community 2024.2.1.3 build:28102 BuldNumber:20240201003028102
    @Override
    public void initialize(MontoyaApi api) {
        super.initialize(api);

        BurpVersion burpVersion = this.getBurpVersion();
        if (BurpVersion.isUnsupportVersion(burpVersion)) {
            BurpVersion.showUnsupporttDlg(burpVersion, Version.getInstance().getProjectName());
            throw new UnsupportedOperationException("Unsupported burp version");
        }

        if (DEBUG) {
            burp.api.montoya.core.Version version = api().burpSuite().version();
            api.logging().logToOutput("name:" + version.name());
            api.logging().logToOutput("major:" + version.major());
            api.logging().logToOutput("minor:" + version.minor());
            api.logging().logToOutput("build:" + version.build());
            api.logging().logToOutput("buildNumber:" + version.buildNumber());
        }

        this.registerTemporaryProject();

        ThemeUI.addPropertyChangeListener(propertyListener);

        Version version = Version.getInstance();
        api.extension().setName(String.format("%s v%d.%d", version.getTabCaption(), version.getMajorVersion(), version.getMinorVersion()));

        // 設定ファイル読み込み
        Map<String, String> config = this.option.loadConfigSetting();
        try {
            if (CONFIG_FILE.exists()) {
                JsonUtil.loadFromJson(CONFIG_FILE, config);
            }
        } catch (IOException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        this.option.setProperty(config);

        // Logging
        try {
            this.logging.setLoggingProperty(this.option.getLoggingProperty());
            if (this.logging.getLoggingProperty().isAutoLogging()) {
                File file = this.logging.mkLog();
                this.logging.open(file);
            }
        } catch (IOException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }

        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                BurpExtension.this.registerView();
                BurpExtension.this.menuHandler = new MenuHander(api);
                BurpExtension.this.proxyHandler = new ProxyHander(api);
                BurpExtension.this.websocektHandler = new WebSocketHander(api);
                BurpExtension.this.autoResponderHandler = new AutoResponderHandler(api);
                api.extension().registerUnloadingHandler(BurpExtension.this);
                // init
                BurpExtension.this.menuHandler.setYaguraSelectEncode(option.getYaguraProperty().getSelectEncoding());
                BurpExtension.this.menuHandler.setYaguraEncodeType(option.getYaguraProperty().getEncodeType());
                if (BurpConfig.isSupportApi(api, BurpConfig.SupportApi.PROXY_IS_INTERCEPT)) {
                    BurpExtension.this.toolbar = new BurpToolBar(api);
                    BurpExtension.this.applyUniversalProperty();
                }
            }
        });

    }

    @SuppressWarnings("unchecked")
    public static BurpExtension getInstance() {
        return BurpExtensionImpl.<BurpExtension>getInstance();
    }

    private final Logging logging = new Logging();

    public Logging getLogging() {
        return this.logging;
    }

    public IBurpTab getRootTabComponent() {
        return this.tabbetOption;
    }

    public Component getUiComponent() {
        return this.tabbetOption;
    }

    private TabbetOption tabbetOption;

    public TabbetOption getTabbetOption() {
        return this.tabbetOption;
    }

    private MouseListener newContextMenu(HttpRequestResponse httpRequestResponse) {
        return new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                getSendToMenu().showBurpMenu(httpRequestResponse, e);
            }
        };
    }

    public void registerView() {
        final MontoyaApi api = api();
        // 順序重要のため変更は要注意
        this.setSendToMenu(new SendToMenu(api, this.option.getSendToProperty()));
        this.registerContextMenu = api.userInterface().registerContextMenuItemsProvider(this.getSendToMenu());
        final Registration registerContextMenuItemsProvider = api.userInterface().registerContextMenuItemsProvider(new ContextMenuItemsProvider() {
            @Override
            public List<Component> provideMenuItems(ContextMenuEvent event) {
                List<Component> menuList = new ArrayList<>();
                JMenuItem item = new JMenuItem();
                item.setText("Send To");
                menuList.add(item);
                MenuHander.changeContextMenuLevel(item, option.getSendToProperty().getMenuPlace());
                return menuList;
            }
        });
        this.editorProvider = new EditorProvider(api);
        this.tabbetOption = new TabbetOption();
        this.tabbetOption.setProperty(this.option);
        this.tabbetOption.addPropertyChangeListener(newPropertyChangeListener());
        api.userInterface().registerSuiteTab(this.tabbetOption.getTabCaption(), this.tabbetOption);
//        this.registerHotKey();
    }

//    public void registerHotKey() {
//        final MontoyaApi api = api();
//        // HotKey 削除
//        for (Registration reg : this.registerHotkeys) {
//            reg.deregister();
//        }
//        this.registerHotkeys.clear();
//        SendToMenu menus = this.getSendToMenu();
//        api.logging().logToOutput("registerHotKey:" + menus.getHotKeys().size());
//      for (HotKeyAssign registerKey : menus.getHotKeys()) {
//            api.logging().logToOutput(registerKey.getHotKey().name() + ":" + registerKey.getHotKey());
//            Registration regster = api().userInterface().registerHotKeyHandler(HotKeyContext.PROXY_HTTP_HISTORY, registerKey.getHotKey(), registerKey.getHotKeyHandler());
//            this.registerHotkeys.add(regster);
//        }
//    }

    public List<Cookie> getCookies(Predicate<? super Cookie> filter) {
        CookieJar cookieJar = api().http().cookieJar();
        return cookieJar.cookies().stream().filter(filter).collect(Collectors.toList());
    }

    /**
     *
     * @return タイムスタンプ
     */
    public synchronized String getCurrentLogTimestamp() {
        DateTimeFormatter format = this.option.getLoggingProperty().getLogTimestampDateFormat();
        return format.format(ZonedDateTime.now());
    }

    /**
     * 選択可能なエンコーディングリストの取得
     *
     * @return リスト
     */
    public List<String> getSelectEncodingList() {
        String defaultCharset = HttpUtil.normalizeCharset(StringUtil.DEFAULT_ENCODING);
        List<String> list = new ArrayList<>();
        list.addAll(this.option.getUniversalViewProperty().getEncodingList());
        // リストにない場合追加
        BurpConfig.CharacterSets burpCharset = BurpConfig.getCharacterSets(api());
        if (BurpConfig.CharacterSetMode.SPECIFIC_CHARACTER_SET.toIdent().equals(burpCharset.getMode()) && burpCharset.getCharacterSet() != null && !list.contains(burpCharset.getCharacterSet())) {
            list.add(burpCharset.getCharacterSet());
        }
        // リストにない場合追加(デフォルトエンコーディング)
        if (!list.contains(defaultCharset)) {
            list.add(defaultCharset);
        }
        return list;
    }

    private SendToMenu sendToMenu = null;

    /**
     * @return the sendToMenu
     */
    public SendToMenu getSendToMenu() {
        return this.sendToMenu;
    }

    public void setSendToMenu(SendToMenu sendToMenu) {
        this.sendToMenu = sendToMenu;
    }

    final OptionProperty option = new OptionProperty();

    public OptionProperty getProperty() {
        return option;
    }

    protected PropertyChangeListener newPropertyChangeListener() {
        return new PropertyChangeListener() {
            @Override
            public void propertyChange(PropertyChangeEvent evt) {
                if (UniversalViewProperty.UNIVERSAL_VIEW_PROPERTY.equals(evt.getPropertyName())) {
                    option.setUniversalViewProperty(tabbetOption.getEncodingProperty());
                    tabbetOption.setJTransCoderProperty(tabbetOption.getEncodingProperty());
                    //// menuHandler.updateUI();
                    applyUniversalProperty();
                    applyOptionProperty();
                } else if (MatchReplaceProperty.MATCHREPLACE_PROPERTY.equals(evt.getPropertyName())) {
                    option.setMatchReplaceProperty(tabbetOption.getMatchReplaceProperty());
                    applyOptionProperty();
                } else if (SendToProperty.SENDTO_PROPERTY.equals(evt.getPropertyName())) {
                    option.setSendToProperty(tabbetOption.getSendToProperty());
                    MontoyaApi api = api();
                    if (api != null) {
                        // 登録を解除すると遅いため､削除しないで再作成
                        setSendToMenu(new SendToMenu(api, option.getSendToProperty()));
                    }
                    applyOptionProperty();
                } else if (LoggingProperty.LOGGING_PROPERTY.equals(evt.getPropertyName())) {
                    option.setLoggingProperty(tabbetOption.getLoggingProperty());
                    if (tabbetOption.isLoggingChanged()) {
                        try {
                            logging.close();
                            logging.setLoggingProperty(tabbetOption.getLoggingProperty());
                            File file = logging.mkLog();
                            logging.open(file);
                            if (tabbetOption.isHistoryLogInclude()) {
                                proxyHandler.historyLogAppend();
                            }
                        } catch (IOException ex) {
                            JOptionPane.showMessageDialog(null, ex.getMessage(), Version.getInstance().getVersion(), JOptionPane.INFORMATION_MESSAGE);
                            option.getLoggingProperty().setAutoLogging(false);
                            tabbetOption.setLoggingProperty(option.getLoggingProperty());
                        }
                    }
                    applyOptionProperty();
                } else if (MatchAlertProperty.MATCH_ALERT_PROPERTY.equals(evt.getPropertyName())) {
                    option.setMatchAlertProperty(tabbetOption.getMatchAlertProperty());
                    applyOptionProperty();
                } else if (ResultFilterProperty.RESULT_FILTER_PROPERTY.equals(evt.getPropertyName())) {
                    option.setResultFilterProperty(tabbetOption.getResultFilterProperty());
                    ////                    menuHandler.updateUI();
                    applyOptionProperty();
                } else if (AutoResponderProperty.AUTO_RESPONDER_PROPERTY.equals(evt.getPropertyName())) {
                    option.setAutoResponderProperty(tabbetOption.getAutoResponderProperty());
                    applyOptionProperty();
                } else if (JSearchProperty.JSEARCH_FILTER_PROPERTY.equals(evt.getPropertyName())) {
                    option.setJSearchProperty(tabbetOption.getJSearchProperty());
                    applyOptionProperty();
                } else if (JTransCoderProperty.JTRANS_CODER_PROPERTY.equals(evt.getPropertyName())) {
                    option.setJTransCoderProperty(tabbetOption.getJTransCoderProperty());
                    applyOptionProperty();
                } else if (TabbetOption.VERSION_PROPERTY.equals(evt.getPropertyName())) {
                    option.setDebugMode(tabbetOption.getDebugMode());
                    applyOptionProperty();
                } else if (TabbetOption.LOAD_CONFIG_PROPERTY.equals(evt.getPropertyName())) {
                    tabbetOption.setProperty(option);
                    applyOptionProperty();
                }
            }
        };
    }

    public void applyUniversalProperty() {
        if (this.toolbar == null) {
            return;
        }
        UniversalViewProperty property = option.getUniversalViewProperty();
        EnumSet<UniversalViewProperty.BurpView> burpView = property.getBurpView();
        EnumSet<UniversalViewProperty.BurpToolBar> burpToolBar = property.getBurpToolBar();
        if (burpView.contains(UniversalViewProperty.BurpView.TOOL_BAR)) {
            api().userInterface().applyThemeToComponent(this.toolbar);
            Frame frame = BurpUtil.suiteFrame();
            this.toolbar.setFloatable(burpToolBar.contains(UniversalViewProperty.BurpToolBar.FLOATABLE));
            frame.add(this.toolbar, BorderLayout.NORTH);
        } else {
            Frame frame = BurpUtil.suiteFrame();
            this.toolbar.setFloatable(burpToolBar.contains(UniversalViewProperty.BurpToolBar.FLOATABLE));
            this.toolbar.setFlotingBar(false);
            frame.remove(this.toolbar);
        }
    }

    public void applyOptionProperty() {
        try {
            Map<String, String> config = this.option.getProperty();
            JsonUtil.saveToJson(CONFIG_FILE, config);
        } catch (IOException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }

    /**
     * Send to JTransCoder
     *
     * @param text
     */
    public void sendToJTransCoder(String text) {
        this.tabbetOption.sendToJTransCoder(text);
    }

    public byte[] receiveFromJTransCoder() {
        return this.tabbetOption.receiveFromJTransCoder();
    }

    public byte[] receiveFromClipbord(String encoding) throws UnsupportedEncodingException {
        String clipbord = SwingUtil.systemClipboardPaste();
        return StringUtil.getBytesCharset(clipbord, encoding);
    }

    public void sendToJWSDecoder(String header, String payload, String signature) {
        this.tabbetOption.sendToJWSDecoder(header, payload, signature);
    }

    public void sendToJWSEncoder(String header, String payload, String secret) {
        this.tabbetOption.sendToJWSEncoder(header, payload, secret);
    }

    @Override
    public void extensionUnloaded() {
        this.tabbetOption.extensionUnloaded();
        this.autoResponderHandler.extensionUnloaded();
        if (BurpUtil.suiteFrame() instanceof JFrame burpFrame) {
            burpFrame.removeWindowListener(this.windowPopupListener);
        }
        if (this.toolbar != null) {
            Frame frame = BurpUtil.suiteFrame();
            this.toolbar.setFlotingBar(false);
            frame.remove(this.toolbar);
            this.toolbar.extensionUnloaded();
        }
        ThemeUI.removePropertyChangeListener();
        try {
            this.logging.close();
        } catch (IOException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }

    protected final class EditorProvider {

        private final MontoyaApi api;

        public EditorProvider(MontoyaApi api) {
            this.api = api;
            api.userInterface().registerHttpRequestEditorProvider(this.requestRawTab);
            api.userInterface().registerHttpResponseEditorProvider(this.responseRawTab);
            api.userInterface().registerHttpRequestEditorProvider(this.requestParamsTab);
            api.userInterface().registerHttpRequestEditorProvider(this.requestGeneratePoCTab);
            api.userInterface().registerHttpRequestEditorProvider(this.requestViewStateTab);
            api.userInterface().registerHttpResponseEditorProvider(this.responseCommentViewTab);
            api.userInterface().registerHttpRequestEditorProvider(this.requestJSONTab);
            api.userInterface().registerHttpResponseEditorProvider(this.responseJSONTab);
            api.userInterface().registerHttpResponseEditorProvider(this.responseJSONPTab);
            api.userInterface().registerHttpRequestEditorProvider(this.requestJwtViewTab);
            api.userInterface().registerWebSocketMessageEditorProvider(this.requestGenerateWebSocketPoCTab);
        }

        private final HttpRequestEditorProvider requestRawTab = new HttpRequestEditorProvider() {

            @Override
            public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext editorCreationContext) {
                final RawViewTabEditor tab = new RawViewTabEditor(editorCreationContext, true);
                return tab;
            }
        };

        private final HttpResponseEditorProvider responseRawTab = new HttpResponseEditorProvider() {

            @Override
            public ExtensionProvidedHttpResponseEditor provideHttpResponseEditor(EditorCreationContext editorCreationContext) {
                final RawViewTabEditor tab = new RawViewTabEditor(editorCreationContext, false);
                return tab;
            }
        };

        private final HttpRequestEditorProvider requestParamsTab = new HttpRequestEditorProvider() {

            @Override
            public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext editorCreationContext) {
                final ParamsViewTabEditor tab = new ParamsViewTabEditor(editorCreationContext);
                return tab;
            }
        };

        private final HttpRequestEditorProvider requestJSONTab = new HttpRequestEditorProvider() {
            @Override
            public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext editorCreationContext) {
                final JSONViewTabEditor tab = new JSONViewTabEditor(editorCreationContext, true);
                return tab;
            }
        };

        private final HttpResponseEditorProvider responseJSONTab = new HttpResponseEditorProvider() {

            @Override
            public ExtensionProvidedHttpResponseEditor provideHttpResponseEditor(EditorCreationContext editorCreationContext) {
                final JSONViewTabEditor tab = new JSONViewTabEditor(editorCreationContext, false);
                return tab;
            }
        };

        private final HttpResponseEditorProvider responseJSONPTab = new HttpResponseEditorProvider() {

            @Override
            public ExtensionProvidedHttpResponseEditor provideHttpResponseEditor(EditorCreationContext editorCreationContext) {
                final JSONViewTabEditor tab = new JSONViewTabEditor(editorCreationContext, false) {
                    @Override
                    public boolean isJsonp() {
                        return true;
                    }
                };
                return tab;
            }
        };

        private final HttpResponseEditorProvider responseCommentViewTab = new HttpResponseEditorProvider() {

            @Override
            public ExtensionProvidedHttpResponseEditor provideHttpResponseEditor(EditorCreationContext editorCreationContext) {
                final HtmlCommetViewTabEditor tab = new HtmlCommetViewTabEditor(editorCreationContext);
                return tab;
            }
        };

        private final HttpRequestEditorProvider requestViewStateTab = new HttpRequestEditorProvider() {

            @Override
            public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext editorCreationContext) {
                final ViewStateTabEditor tab = new ViewStateTabEditor(editorCreationContext);
                return tab;
            }
        };

        private final HttpRequestEditorProvider requestJwtViewTab = new HttpRequestEditorProvider() {

            @Override
            public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext editorCreationContext) {
                final JWSViewTabEditor tab = new JWSViewTabEditor(editorCreationContext);
                return tab;
            }
        };

        private final HttpRequestEditorProvider requestGeneratePoCTab = new HttpRequestEditorProvider() {

            @Override
            public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext editorCreationContext) {
                final GeneratePoCTabEditor tab = new GeneratePoCTabEditor(editorCreationContext);
                return tab;
            }
        };

        private final WebSocketMessageEditorProvider requestGenerateWebSocketPoCTab = new WebSocketMessageEditorProvider() {
            @Override
            public ExtensionProvidedWebSocketMessageEditor provideMessageEditor(EditorCreationContext editorCreationContext) {
                final GenerateWebsocktPoCEditor tab = new GenerateWebsocktPoCEditor(editorCreationContext);
                return tab;
            }
        };

    }
}
