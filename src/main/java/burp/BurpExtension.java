package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Registration;
import burp.api.montoya.core.ToolSource;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;
import burp.api.montoya.ui.editor.extension.HttpResponseEditorProvider;
import extend.util.external.ThemeUI;
import extend.util.external.TransUtil;
import extend.util.external.gson.XMatchItemAdapter;
import extension.burp.BurpConfig;
import extension.burp.BurpConfig.HostnameResolution;
import extension.burp.BurpConfig.SSLPassThroughRule;
import extension.burp.BurpExtensionImpl;
import extension.burp.HttpTarget;
import extension.burp.NotifyType;
import extension.burp.TargetTool;
import extension.burp.BurpUtil;
import extension.burp.BurpVersion;
import extension.burp.ExtensionHelper;
import extension.burp.FilterProperty;
import extension.burp.TargetScopeItem;
import extension.helpers.FileUtil;
import extension.helpers.HttpMessageWapper;
import extension.helpers.HttpUtil;
import extension.helpers.StringUtil;
import extension.helpers.SwingUtil;
import extension.helpers.json.JsonUtil;
import extension.view.base.MatchItem;
import java.awt.Component;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;
import extension.burp.scanner.IssueItem;
import extension.helpers.HttpRequestWapper;
import extension.helpers.SmartCodec;
import java.awt.KeyboardFocusManager;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.nio.charset.StandardCharsets;
import java.util.Enumeration;
import javax.swing.AbstractButton;
import javax.swing.ButtonGroup;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JRadioButtonMenuItem;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.event.MenuEvent;
import javax.swing.event.MenuListener;
import passive.signature.MatchAlert;
import yagura.Config;
import yagura.Version;
import yagura.model.SendToMenu;
import yagura.view.TabbetOption;
import yagura.model.OptionProperty;
import yagura.model.AutoResponderItem;
import yagura.model.AutoResponderProperty;
import yagura.model.ITranslateAction;
import yagura.model.JSearchProperty;
import yagura.model.JTransCoderProperty;
import yagura.model.LoggingProperty;
import yagura.model.MatchAlertItem;
import yagura.model.MatchAlertProperty;
import yagura.model.MatchReplaceGroup;
import yagura.model.MatchReplaceItem;
import yagura.model.MatchReplaceProperty;
import yagura.model.ResultFilterProperty;
import yagura.model.SendToProperty;
import yagura.model.UniversalViewProperty;
import yagura.view.GeneratePoCTabEditor;
import yagura.view.HtmlCommetViewTabEditor;
import yagura.view.JSONViewTabEditor;
import yagura.view.JWTViewTabEditor;
import yagura.view.ParamsViewTabEditor;
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
    private EditorProvider editorProvider;
    private AutoResponderHandler autoResponderHandler;
    private Registration registerContextMenu;

    public BurpExtension() {
        Thread.setDefaultUncaughtExceptionHandler(new Thread.UncaughtExceptionHandler() {
            @Override
            public void uncaughtException(Thread t, Throwable ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        });
    }

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
        JsonUtil.registerTypeHierarchyAdapter(MatchItem.class, new XMatchItemAdapter());
    }

    /**
     * 古い Montoya API ではメソッド名をあやまっており ここにくる場合は必ず古いバージョン
     *
     * @param api
     *
     */
    public void initialise(MontoyaApi api) {
        BurpVersion burp_version = BurpUtil.suiteVersion();
        BurpVersion.showUnsupporttDlg(burp_version, Version.getInstance().getProjectName());
    }

    @Override
    public void initialize(MontoyaApi api) {
        super.initialize(api);
        BurpVersion burpVersion = this.getBurpVersion();
        if (BurpVersion.isUnsupportVersion(burpVersion)) {
            BurpVersion.showUnsupporttDlg(burpVersion, Version.getInstance().getProjectName());
            throw new UnsupportedOperationException("Unsupported burp version");
        }

        if (DEBUG) {
            api.logging().logToOutput("name:" + burpVersion.getProductName());
            api.logging().logToOutput("major:" + burpVersion.getMajor());
            api.logging().logToOutput("minor:" + burpVersion.getMinor());
            api.logging().logToOutput("build:" + burpVersion.getBuild());
        }
        Version version = Version.getInstance();
        api.extension().setName(String.format("%s v%d.%d", version.getProjectName(), version.getMajorVersion(), version.getMinorVersion()));

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

        try {
            // 自動ログ作成時のみディレクトリ作成
            if (this.option.getLoggingProperty().isAutoLogging()) {
                this.setLogDir(mkLogDir(this.option.getLoggingProperty().getBaseDir(), this.option.getLoggingProperty().getLogDirFormat()));
            }
        } catch (IOException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }

        SwingUtilities.invokeLater(() -> {
            this.registerView();
            this.menuHandler = new MenuHander(api);
            this.proxyHandler = new ProxyHander(api);
            this.autoResponderHandler = new AutoResponderHandler(api);
            api.extension().registerUnloadingHandler(this);
        });

    }

    @SuppressWarnings("unchecked")
    public static BurpExtension getInstance() {
        return BurpExtensionImpl.<BurpExtension>getInstance();
    }

    public Component getUiComponent() {
        return this.tabbetOption;
    }

    private TabbetOption tabbetOption;

    protected URL getMockServiceURL() {
        return this.tabbetOption.getMockServer().serviceURL();
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
        this.editorProvider = new EditorProvider(api);
        this.tabbetOption = new TabbetOption();
        this.tabbetOption.setProperty(this.option);
        this.tabbetOption.addPropertyChangeListener(newPropertyChangeListener());
        api.userInterface().registerSuiteTab(this.tabbetOption.getTabCaption(), this.tabbetOption);
    }

    /**
     *
     * @return タイムスタンプ
     */
    public synchronized String getCurrentLogTimestamp() {
        DateFormat format = this.option.getLoggingProperty().getLogTimestampDateFormat();
        return format.format(new java.util.Date());
    }

    /**
     * 選択可能なエンコーディングリストの取得
     *
     * @return リスト
     */
    public List<String> getSelectEncodingList() {
        String defaultCharset = HttpUtil.normalizeCharset(StringUtil.DEFAULT_ENCODING);
        List<String> list = new ArrayList<>();
        list.addAll(this.option.getEncodingProperty().getEncodingList());
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

    private File logdir = null;

    /**
     * ログディレクトリの取得
     *
     * @return ディレクトリ
     */
    protected File getLogDir() {
        return this.logdir;
    }

    /**
     * ログディレクトリの設定
     *
     * @param logdir ログディレクトリ
     */
    protected void setLogDir(File logdir) {
        this.logdir = logdir;
    }

    /**
     * ログディレクトリの作成
     *
     * @param logBaseDir 基準ディレクトリ
     * @param logdirFormat フォーマット
     * @return 作成ディレクトリ
     * @throws java.io.IOException
     */
    public static File mkLogDir(String logBaseDir, String logdirFormat) throws IOException {
        File logdir = null;
        int countup = 0;
        SimpleDateFormat logfmt = new SimpleDateFormat(logdirFormat);
        do {
            String prefix = "burp_";
            String suffix = (countup == 0) ? "" : String.format("_%d", countup);
            String fname = String.format("%s%s%s", prefix, logfmt.format(new java.util.Date()), suffix);
            logdir = new File(logBaseDir, fname);
            File lists[] = logdir.listFiles();
            if (lists != null && lists.length == 0) {
                break;
            }
            countup++;
            if (logdir.exists()) {
                // ディレクトリが存在した場合は無条件にログディレクトリの対象にする
                break;
            } else if (logdir.mkdir()) {
                break;
            } else {
                throw new IOException("mkdir error:" + logdir.getAbsolutePath());
            }
        } while (true);
        return logdir;
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

    public final OptionProperty option = new OptionProperty();

    public OptionProperty getProperty() {
        return option;
    }

    protected PropertyChangeListener newPropertyChangeListener() {
        return new PropertyChangeListener() {
            @Override
            public void propertyChange(PropertyChangeEvent evt) {
                if (UniversalViewProperty.CJK_VIEW_PROPERTY.equals(evt.getPropertyName())) {
                    option.setEncodingProperty(tabbetOption.getEncodingProperty());
                    tabbetOption.setJTransCoderProperty(tabbetOption.getEncodingProperty());
////                    menuHandler.updateUI();
                    applyOptionProperty();
                } else if (MatchReplaceProperty.MATCHREPLACE_PROPERTY.equals(evt.getPropertyName())) {
                    option.setMatchReplaceProperty(tabbetOption.getMatchReplaceProperty());
                    applyOptionProperty();
                } else if (SendToProperty.SENDTO_PROPERTY.equals(evt.getPropertyName())) {
                    option.setSendToProperty(tabbetOption.getSendToProperty());
                    MontoyaApi api = api();
                    if (api != null) {
                        registerContextMenu.deregister();
                        setSendToMenu(new SendToMenu(api, option.getSendToProperty()));
                        registerContextMenu = api.userInterface().registerContextMenuItemsProvider(getSendToMenu());
                    }
                    applyOptionProperty();
                } else if (LoggingProperty.LOGGING_PROPERTY.equals(evt.getPropertyName())) {
                    option.setLoggingProperty(tabbetOption.getLoggingProperty());
                    applyOptionProperty();
                } else if (MatchAlertProperty.MATCHALERT_PROPERTY.equals(evt.getPropertyName())) {
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

    protected void applyOptionProperty() {
        if (this.tabbetOption.isLogDirChanged()) {
            try {
                this.setLogDir(mkLogDir(this.option.getLoggingProperty().getBaseDir(), this.option.getLoggingProperty().getLogDirFormat()));
                if (this.tabbetOption.isHistoryLogInclude()) {
                    this.proxyHandler.historyLogAppend();
                }
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(null, ex.getMessage(), Version.getInstance().getVersion(), JOptionPane.INFORMATION_MESSAGE);
                this.option.getLoggingProperty().setAutoLogging(false);
                this.tabbetOption.setLoggingProperty(this.option.getLoggingProperty());
            }
        }

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

    @Override
    public void extensionUnloaded() {
        this.tabbetOption.extensionUnloaded();
        this.autoResponderHandler.extensionUnloaded();
        ThemeUI.removePropertyChangeListener();
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
                final JWTViewTabEditor tab = new JWTViewTabEditor(editorCreationContext);
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

    }

    protected final class MenuHander {
        private final MontoyaApi api;
        private final ButtonGroup menuBurpCharsetsGroup = new ButtonGroup();
        private final ButtonGroup menuYaguraCharsetsGroup = new ButtonGroup();
        private final ButtonGroup menuBurpResultFilterGroup = new ButtonGroup();
        private final JMenu burpCharsetMenu = new JMenu();
        private final JMenu yaguraCharsetMenu = new JMenu();
        private final JMenu yaguraResultFilterMenu = new JMenu();
        private String yaguraCharset = StandardCharsets.UTF_8.name();

        /**
         * @param selectedText
         * @return the yaguraCharset
         */
        public String getYaguraCharset(String selectedText) {
            if (yaguraCharset != null) {
                return yaguraCharset;
            } else {
                if (BurpConfig.isSupportApi(api, BurpConfig.SupportApi.BURPSUITE_USEROPTION)) {
                    BurpConfig.CharacterSets burpCharset = BurpConfig.getCharacterSets(api);
                    if (BurpConfig.CharacterSetMode.PLATFORM_DEFAULT.toIdent().equals(burpCharset.getMode())) {
                        return StringUtil.DEFAULT_ENCODING;
                    } else if (BurpConfig.CharacterSetMode.RAW_BYTES.toIdent().equals(burpCharset.getMode())) {
                        return StandardCharsets.ISO_8859_1.name();
                    } else if (BurpConfig.CharacterSetMode.SPECIFIC_CHARACTER_SET.toIdent().equals(burpCharset.getMode())) {
                        return burpCharset.getCharacterSet();
                    } else if (BurpConfig.CharacterSetMode.RECOGNIZE_AUTO.toIdent().equals(burpCharset.getMode())) {
                        return HttpUtil.getGuessCode(StringUtil.getBytesRaw(selectedText));
                    }
                }
            }
            return StandardCharsets.ISO_8859_1.name();
        }

        public void setBamba(FilterProperty filter) {
            BurpConfig.configBambda(api, filter);
        }

        private final static String USE_BURP_CHARSETS = "Use Burp Charsets";

        public MenuHander(MontoyaApi api) {
            this.api = api;

            final JMenu yaguraMenu = new JMenu();
            yaguraMenu.setText("Yagura");
            yaguraMenu.setMnemonic(KeyEvent.VK_Y);
            yaguraMenu.addMenuListener(new MenuListener() {
                @Override
                public void menuSelected(MenuEvent e) {
                    SwingUtilities.invokeLater(new Runnable() {
                        @Override
                        public void run() {
                            updateUI();
                        }
                    });
                }

                @Override
                public void menuDeselected(MenuEvent e) {
                }

                @Override
                public void menuCanceled(MenuEvent e) {
                }
            });

            /**
             * Yagura Charsets
             */
            yaguraCharsetMenu.setText("Yagura Charsets");
            yaguraCharsetMenu.setMnemonic(KeyEvent.VK_Y);

//            updateYaguraCharsetUI(this.yaguraCharsetMenu);
            yaguraMenu.add(this.yaguraCharsetMenu);

            /**
             * Yagura Encoder
             */
            JMenu yaguraEncoderMenu = new JMenu();
            yaguraEncoderMenu.setText("Encoder (E)");
            yaguraEncoderMenu.setMnemonic(KeyEvent.VK_E);

            JMenuItem yaguraEncoderURLMenu = createMenuItem("URL(%hh)", KeyEvent.VK_U, new ITranslateAction() {
                @Override
                public String translate(String allText, String selectedText) {
                    try {
                        return SmartCodec.toUrlEncode(selectedText, getYaguraCharset(selectedText), SmartCodec.ENCODE_PATTERN_BURP, false);
                    } catch (UnsupportedEncodingException ex) {
                        return selectedText;
                    }
                }
            });

            yaguraEncoderMenu.add(yaguraEncoderURLMenu);

            JMenuItem yaguraEncoderURLUnicodeMenu = createMenuItem("Unicode(%uhhhh) - URL", KeyEvent.VK_N, new ITranslateAction() {
                @Override
                public String translate(String allText, String selectedText) {
                    return SmartCodec.toUnocodeUrlEncode(selectedText, SmartCodec.ENCODE_PATTERN_BURP, false);
                }
            });

            yaguraEncoderMenu.add(yaguraEncoderURLUnicodeMenu);

            JMenuItem yaguraEncoderUnicodeMenu = createMenuItem("Unicode(\\uhhhh) - JSON", KeyEvent.VK_J, new ITranslateAction() {
                @Override
                public String translate(String allText, String selectedText) {
                    return SmartCodec.toUnocodeEncode(selectedText, SmartCodec.ENCODE_PATTERN_BURP, false);
                }
            });

            yaguraEncoderMenu.add(yaguraEncoderUnicodeMenu);

            JMenuItem yaguraEncoderBase64Menu = createMenuItem("Base64", KeyEvent.VK_B, new ITranslateAction() {
                @Override
                public String translate(String allText, String selectedText) {
                    try {
                        return TransUtil.toBase64Encode(selectedText, getYaguraCharset(selectedText));
                    } catch (UnsupportedEncodingException ex) {
                        return selectedText;
                    }
                }
            });

            yaguraEncoderMenu.add(yaguraEncoderBase64Menu);

            JMenuItem yaguraEncoderBase64UrlSafeMenu = createMenuItem("Base64URLSafe", KeyEvent.VK_S, new ITranslateAction() {
                @Override
                public String translate(String allText, String selectedText) {
                    try {
                        return TransUtil.toBase64URLSafeEncode(selectedText, getYaguraCharset(selectedText));
                    } catch (UnsupportedEncodingException ex) {
                        return selectedText;
                    }
                }
            });

            yaguraEncoderMenu.add(yaguraEncoderBase64UrlSafeMenu);

            JMenuItem yaguraEncoderHtmlMenu = createMenuItem("Html", KeyEvent.VK_H, new ITranslateAction() {
                @Override
                public String translate(String allText, String selectedText) {
                    return SmartCodec.toHtmlDecEncode(selectedText, SmartCodec.ENCODE_PATTERN_BURP);
                }
            });

            yaguraEncoderMenu.add(yaguraEncoderHtmlMenu);

            JMenuItem yaguraEncoderMetacharMenu = createMenuItem("JSON with Meta", KeyEvent.VK_J, new ITranslateAction() {
                @Override
                public String translate(String allText, String selectedText) {
                    return TransUtil.encodeJsonLiteral(selectedText, true);
                }
            });

            yaguraEncoderMenu.add(yaguraEncoderMetacharMenu);

            yaguraMenu.add(yaguraEncoderMenu);

            /**
             * Yagura Decoder
             */
            JMenu yaguraDecoderMenu = new JMenu();
            yaguraDecoderMenu.setText("Decoder (D)");
            yaguraDecoderMenu.setMnemonic(KeyEvent.VK_D);

            JMenuItem yaguraDecoderURLMenu = createMenuItem("URL(%hh)", KeyEvent.VK_U, new ITranslateAction() {
                @Override
                public String translate(String allText, String selectedText) {
                    try {
                        return SmartCodec.toUrlDecode(selectedText, getYaguraCharset(selectedText));
                    } catch (UnsupportedEncodingException ex) {
                        return selectedText;
                    }
                }
            });

            yaguraDecoderMenu.add(yaguraDecoderURLMenu);

            JMenuItem yaguraDecoderURLUnicodeMenu = createMenuItem("Unicode(%uhhhh) - URL", KeyEvent.VK_N, new ITranslateAction() {
                @Override
                public String translate(String allText, String selectedText) {
                    return SmartCodec.toUnicodeUrlDecode(selectedText);
                }
            });

            yaguraDecoderMenu.add(yaguraDecoderURLUnicodeMenu);

            JMenuItem yaguraDecoderUnicodeMenu = createMenuItem("Unicode(\\uhhhh) - JSON", KeyEvent.VK_J, new ITranslateAction() {
                @Override
                public String translate(String allText, String selectedText) {
                    return SmartCodec.toUnocodeDecode(selectedText);
                }
            });

            yaguraDecoderMenu.add(yaguraDecoderUnicodeMenu);

            JMenuItem yaguraDecoderBase64Menu = createMenuItem("Base64", KeyEvent.VK_B, new ITranslateAction() {

                @Override
                public String translate(String allText, String selectedText) {
                    try {
                        return TransUtil.toBase64Decode(selectedText, getYaguraCharset(selectedText));
                    } catch (UnsupportedEncodingException ex) {
                        return selectedText;
                    }
                }
            });

            yaguraDecoderMenu.add(yaguraDecoderBase64Menu);

            JMenuItem yaguraDecoderBase64UrlSafeMenu = createMenuItem("Base64URLSafe", KeyEvent.VK_S, new ITranslateAction() {
                @Override
                public String translate(String allText, String selectedText) {
                    try {
                        return TransUtil.toBase64URLSafeDecode(selectedText, getYaguraCharset(selectedText));
                    } catch (UnsupportedEncodingException ex) {
                        return selectedText;
                    }
                }
            });

            yaguraDecoderMenu.add(yaguraDecoderBase64UrlSafeMenu);

            JMenuItem yaguraDecoderHtmlMenu = createMenuItem("Html", KeyEvent.VK_H, new ITranslateAction() {

                @Override
                public String translate(String allText, String selectedText) {
                    return SmartCodec.toHtmlDecode(selectedText, SmartCodec.ENCODE_PATTERN_BURP);
                }
            });

            yaguraDecoderMenu.add(yaguraDecoderHtmlMenu);

            JMenuItem yaguraDecoderMetacharMenu = createMenuItem("JSON with Meta", KeyEvent.VK_J, new ITranslateAction() {
                @Override
                public String translate(String allText, String selectedText) {
                    return TransUtil.encodeJsonLiteral(selectedText, true);
                }
            });

            yaguraDecoderMenu.add(yaguraDecoderMetacharMenu);

            yaguraMenu.add(yaguraDecoderMenu);

            /**
             * Yagura Converter
             */
            JMenu yaguraConverterMenu = new JMenu();
            yaguraConverterMenu.setText("Converter (C)");
            yaguraConverterMenu.setMnemonic(KeyEvent.VK_C);

            JMenuItem yaguraDecoderUpperCaseItemMenu = createMenuItem("Upper Case", KeyEvent.VK_U, new ITranslateAction() {
                @Override
                public String translate(String allText, String selectedText) {
                    return selectedText.toUpperCase();
                }
            });

            yaguraConverterMenu.add(yaguraDecoderUpperCaseItemMenu);

            JMenuItem yaguraDecoderLowlerCaseItemMenu = createMenuItem("Lowler Case", KeyEvent.VK_L, new ITranslateAction() {
                @Override
                public String translate(String allText, String selectedText) {
                    return selectedText.toLowerCase();
                }
            });

            yaguraConverterMenu.add(yaguraDecoderLowlerCaseItemMenu);

            JMenuItem yaguraConverterBin2HexMenu = createMenuItem("bin2hex", KeyEvent.VK_B, new ITranslateAction() {
                @Override
                public String translate(String allText, String selectedText) {
                    try {
                        return TransUtil.toByteHexEncode(selectedText, getYaguraCharset(selectedText), false);
                    } catch (UnsupportedEncodingException ex) {
                        return selectedText;
                    }
                }
            });

            yaguraConverterMenu.add(yaguraConverterBin2HexMenu);

            JMenuItem yaguraConverterHex2BinMenu = createMenuItem("hex2bin", KeyEvent.VK_H, new ITranslateAction() {
                @Override
                public String translate(String allText, String selectedText) {
                    try {
                        return TransUtil.toByteHexDecode(selectedText, getYaguraCharset(selectedText));
                    } catch (UnsupportedEncodingException ex) {
                        return selectedText;
                    }
                }
            });

            yaguraConverterMenu.add(yaguraConverterHex2BinMenu);

            JMenuItem yaguraConverterFull2Half = createMenuItem("Full width -> Half width", KeyEvent.VK_F, new ITranslateAction() {
                @Override
                public String translate(String allText, String selectedText) {
                    return TransUtil.translateFullWidth2HalfWidth(selectedText);
                }
            });
            yaguraConverterMenu.add(yaguraConverterFull2Half);

            JMenuItem yaguraConverterHalf2Full = createMenuItem("Half width -> Full width", KeyEvent.VK_K, new ITranslateAction() {
                @Override
                public String translate(String allText, String selectedText) {
                    return TransUtil.translateHalfWidth2FullWidth(selectedText);
                }
            });
            yaguraConverterMenu.add(yaguraConverterHalf2Full);
            yaguraMenu.add(yaguraConverterMenu);

            /**
             * Yagura Hash
             */
            JMenu yaguraHashMenu = new JMenu();
            yaguraHashMenu.setText("Hash (H)");
            yaguraHashMenu.setMnemonic(KeyEvent.VK_H);

            JMenuItem yaguraHashMD2Menu = createMenuItem("md2", KeyEvent.VK_0, new ITranslateAction() {
                @Override
                public String translate(String allText, String selectedText) {
                    try {
                        return TransUtil.toMd2Sum(selectedText, getYaguraCharset(selectedText), false);
                    } catch (UnsupportedEncodingException ex) {
                        return selectedText;
                    }
                }
            });

            yaguraHashMenu.add(yaguraHashMD2Menu);

            JMenuItem yaguraHashMD5Menu = createMenuItem("md5", KeyEvent.VK_1, new ITranslateAction() {
                @Override
                public String translate(String allText, String selectedText) {
                    try {
                        return TransUtil.toMd5Sum(selectedText, getYaguraCharset(selectedText), false);
                    } catch (UnsupportedEncodingException ex) {
                        return selectedText;
                    }
                }
            });

            yaguraHashMenu.add(yaguraHashMD5Menu);

            JMenuItem yaguraHashSha1Menu = createMenuItem("sha1", KeyEvent.VK_2, new ITranslateAction() {
                @Override
                public String translate(String allText, String selectedText) {
                    try {
                        return TransUtil.toSHA1Sum(selectedText, getYaguraCharset(selectedText), false);
                    } catch (UnsupportedEncodingException ex) {
                        return selectedText;
                    }
                }
            });

            yaguraHashMenu.add(yaguraHashSha1Menu);

            JMenuItem yaguraHashSha256Menu = createMenuItem("sha256", KeyEvent.VK_3, new ITranslateAction() {

                @Override
                public String translate(String allText, String selectedText) {
                    try {
                        return TransUtil.toSHA256Sum(selectedText, getYaguraCharset(selectedText), false);
                    } catch (UnsupportedEncodingException ex) {
                        return selectedText;
                    }
                }
            });

            yaguraHashMenu.add(yaguraHashSha256Menu);

            JMenuItem yaguraHashSha384Menu = createMenuItem("sha384", KeyEvent.VK_4, new ITranslateAction() {

                @Override
                public String translate(String allText, String selectedText) {
                    try {
                        return TransUtil.toSHA384Sum(selectedText, getYaguraCharset(selectedText), false);
                    } catch (UnsupportedEncodingException ex) {
                        return selectedText;
                    }
                }
            });

            yaguraHashMenu.add(yaguraHashSha384Menu);

            JMenuItem yaguraHashSha512Menu = createMenuItem("sha512", KeyEvent.VK_5, new ITranslateAction() {

                @Override
                public String translate(String allText, String selectedText) {
                    try {
                        return TransUtil.toSHA512Sum(selectedText, getYaguraCharset(selectedText), false);
                    } catch (UnsupportedEncodingException ex) {
                        return selectedText;
                    }
                }
            });

            yaguraHashMenu.add(yaguraHashSha512Menu);
            yaguraMenu.add(yaguraHashMenu);

            /**
             * Yagura Result Filter
             */
            yaguraResultFilterMenu.setText("Result Filter (F)");
            yaguraResultFilterMenu.setMnemonic(KeyEvent.VK_F);
            yaguraResultFilterMenu.setEnabled(BurpConfig.isSupportApi(api, BurpConfig.SupportApi.BURPSUITE_BAMBDA));
//            updateResultFilterUI(this.yaguraResultFilterMenu);
            yaguraMenu.add(this.yaguraResultFilterMenu);

            /**
             * Yagura Extension
             */
            JMenu yaguraExtensionMenu = new JMenu();
            yaguraExtensionMenu.setText("Extension (X)");
            yaguraExtensionMenu.setMnemonic(KeyEvent.VK_X);

            JMenuItem yaguraPasteIncludeScopeMenu = createMenuItem("Paste include scope(multi-line)", KeyEvent.VK_I, includeScopeAction);

            yaguraExtensionMenu.add(yaguraPasteIncludeScopeMenu);

            JMenuItem yaguraPasteIncludeHostScopeMenu = createMenuItem("Paste include Host scope(multi-line)", KeyEvent.VK_H, includeHostScopeAction);

            yaguraExtensionMenu.add(yaguraPasteIncludeHostScopeMenu);

            JMenuItem yaguraPasteExludeScopeMenu = createMenuItem("Paste exclude scope(multi-line)", KeyEvent.VK_E, excludeScopeAction);

            yaguraExtensionMenu.add(yaguraPasteExludeScopeMenu);

            JMenuItem yaguraPasteSSLPassThroughMenu = createMenuItem("Paste SSL pass through(multi-line)", KeyEvent.VK_P, sslPassThroughAction);

            yaguraExtensionMenu.add(yaguraPasteSSLPassThroughMenu);
            yaguraMenu.add(yaguraExtensionMenu);

            /**
             * Burp Charsets
             */
            this.burpCharsetMenu.setText("Burp Charsets");
            this.burpCharsetMenu.setMnemonic(KeyEvent.VK_B);
            this.burpCharsetMenu.setEnabled(BurpConfig.isSupportApi(api, BurpConfig.SupportApi.BURPSUITE_USEROPTION));
//            updateBurpCharsetUI(this.burpCharsetMenu);
            yaguraMenu.addSeparator();
            yaguraMenu.add(this.burpCharsetMenu);
            api.userInterface().menuBar().registerMenu(yaguraMenu);
        }

        public static JMenuItem createMenuItem(String caption, int mnemonic, ActionListener actionListener) {
            final JMenuItem yaguraMenuItem = new JMenuItem();
            yaguraMenuItem.setText(caption + " (" + (char) mnemonic + ")");
            yaguraMenuItem.setMnemonic(mnemonic);
            yaguraMenuItem.addActionListener(actionListener);
            return yaguraMenuItem;
        }

        public static JMenuItem createMenuItem(String caption, int mnemonic, ITranslateAction action) {
            return createMenuItem(caption, mnemonic, new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    KeyboardFocusManager mgr = KeyboardFocusManager.getCurrentKeyboardFocusManager();
                    Component owner = mgr.getPermanentFocusOwner();
                    if (owner instanceof JTextArea textArea) {
                        String allText = textArea.getText();
                        String selectedText = textArea.getSelectedText();
                        String encode = action.translate(allText, selectedText);
                        if (encode != null) {
                            textArea.replaceSelection(encode);
                        }
                    }
                }
            });
        }

        private ActionListener burpCharsetModeAction = new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                final List<String> encodngList = getSelectEncodingList();
                BurpConfig.CharacterSets burpCharset = BurpConfig.getCharacterSets(BurpConfig.CharacterSetMode.SPECIFIC_CHARACTER_SET, StandardCharsets.UTF_8.name());
                Enumeration<AbstractButton> rdoCharsets = menuBurpCharsetsGroup.getElements();
                while (rdoCharsets.hasMoreElements()) {
                    JRadioButtonMenuItem item = (JRadioButtonMenuItem) rdoCharsets.nextElement();
                    if (item.isSelected()) {
                        if (encodngList.contains(item.getText())) {
                            burpCharset.setMode(BurpConfig.CharacterSetMode.SPECIFIC_CHARACTER_SET.toIdent());
                            burpCharset.setCharacterSet(item.getText());
                        } else {
                            burpCharset.setMode(item.getText());
                        }
                        break;
                    }
                }
                BurpConfig.configCharacterSets(api, burpCharset);
            }
        };

        private ActionListener resultFilterModeAction = new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                ResultFilterProperty resultFilterProperty = option.getResultFilterProperty();
                Map<String, FilterProperty> filterMap = resultFilterProperty.getFilterMap();
                FilterProperty filterProperty = null;
                if (e.getSource() instanceof JMenuItem menuItem) {
                    String selectedName = menuItem.getText();
                    filterProperty = filterMap.get(selectedName);
                    if (filterProperty != null) {
                        resultFilterProperty.setSelectedName(selectedName);
                        BurpConfig.configBambda(api, filterProperty);
                        JTabbedPane tab = BurpUtil.suiteTabbedPane();
                        if (tab != null) {
                            BurpUtil.sendToTextHighlight(tab, "Proxy");
                        }
                    }
                }
            }
        };

        private ActionListener includeScopeAction = new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    String paste = SwingUtil.systemClipboardPaste();
                    BurpExtension.helpers().addIncludeScope(paste);
                } catch (Exception ex) {
                    logger.log(Level.SEVERE, ex.getMessage(), ex);
                }
            }
        };

        private ActionListener includeHostScopeAction = new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    String paste = SwingUtil.systemClipboardPaste();
                    URL url = new URL(paste);
                    BurpExtension.helpers().addIncludeScope(String.format("%s://%s/", url.getProtocol(), url.getHost()));
                } catch (Exception ex) {
                    logger.log(Level.SEVERE, ex.getMessage(), ex);
                }
            }
        };

        private ActionListener excludeScopeAction = new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    String paste = SwingUtil.systemClipboardPaste();
                    BurpExtension.helpers().addExcludeScope(paste);
                } catch (Exception ex) {
                    logger.log(Level.SEVERE, ex.getMessage(), ex);
                }
            }
        };

        private ActionListener sslPassThroughAction = new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    String paste = SwingUtil.systemClipboardPaste();
                    URL[] urls = TargetScopeItem.parseMultilineURL(paste);
                    List<SSLPassThroughRule> rules = new ArrayList<>();
                    for (URL u : urls) {
                        rules.add(new SSLPassThroughRule(true, u.getHost(), u.getPort() > 0 ? u.getPort() : u.getDefaultPort()));
                    }
                    BurpConfig.configSSLPassThroughRules(api, rules, false);
                    JTabbedPane tab = BurpUtil.suiteTabbedPane();
                    if (tab != null) {
                        BurpUtil.sendToTextHighlight(tab, "Target");
                    }
                } catch (Exception ex) {
                    logger.log(Level.SEVERE, ex.getMessage(), ex);
                }
            }
        };

        private ChangeListener yaguraCharsetModeAction = new ChangeListener() {

            @Override
            public void stateChanged(ChangeEvent e) {
                if (e.getSource() instanceof JRadioButtonMenuItem item) {
                    if (item.isSelected()) {
                        String caption = item.getText();
                        if (USE_BURP_CHARSETS.equals(caption)) {
                            yaguraCharset = null;
                        } else {
                            yaguraCharset = caption;
                        }
                    }
                }
            }
        };

        public void updateUI() {
            updateYaguraCharsetUI(this.yaguraCharsetMenu);
            updateBurpCharsetUI(this.burpCharsetMenu);
            updateResultFilterUI(this.yaguraResultFilterMenu);
        }

        /**
         * Yagura Charset Menu
         */
        private void updateYaguraCharsetUI(JMenu yaguraCharsetMenu) {
            yaguraCharsetMenu.removeAll();
            for (Enumeration<AbstractButton> e = this.menuYaguraCharsetsGroup.getElements(); e.hasMoreElements();) {
                this.menuYaguraCharsetsGroup.remove(e.nextElement());
            }
            JRadioButtonMenuItem selectedYaguraCharSet = null;
            final List<String> encodngList = getSelectEncodingList();
            for (int i = 0; i < encodngList.size(); i++) {
                JRadioButtonMenuItem specificCharsetMenuCharSet = new JRadioButtonMenuItem();
                specificCharsetMenuCharSet.setText(encodngList.get(i));
                if (this.yaguraCharset != null && this.yaguraCharset.equals(encodngList.get(i))) {
                    selectedYaguraCharSet = specificCharsetMenuCharSet;
                }
                yaguraCharsetMenu.add(specificCharsetMenuCharSet);
                this.menuYaguraCharsetsGroup.add(specificCharsetMenuCharSet);
            }

            // Use Burp Charsets
            yaguraCharsetMenu.addSeparator();
            JRadioButtonMenuItem useBurpCharSet = new JRadioButtonMenuItem();
            useBurpCharSet.setText(USE_BURP_CHARSETS);
            if (this.yaguraCharset == null) {
                selectedYaguraCharSet = useBurpCharSet;
            }
            useBurpCharSet.setEnabled(BurpConfig.isSupportApi(api, BurpConfig.SupportApi.BURPSUITE_USEROPTION));
            yaguraCharsetMenu.add(useBurpCharSet);
            this.menuYaguraCharsetsGroup.add(useBurpCharSet);

            // Yagura Charset 選択状態
            if (selectedYaguraCharSet != null) {
                this.menuYaguraCharsetsGroup.setSelected(selectedYaguraCharSet.getModel(), true);
            }
            else {
                this.menuYaguraCharsetsGroup.setSelected(useBurpCharSet.getModel(), true);
            }
            Enumeration<AbstractButton> emu = this.menuYaguraCharsetsGroup.getElements();
            while (emu.hasMoreElements()) {
                if (emu.nextElement() instanceof JRadioButtonMenuItem yaguraCharsetMenuItem) {
                    yaguraCharsetMenuItem.addChangeListener(this.yaguraCharsetModeAction);
                }
            }
        }

        /**
         * Burp Charsets
         */
        private void updateBurpCharsetUI(JMenu burpCharsetMenu) {
            burpCharsetMenu.removeAll();
            for (Enumeration<AbstractButton> e = this.menuBurpCharsetsGroup.getElements(); e.hasMoreElements();) {
                this.menuBurpCharsetsGroup.remove(e.nextElement());
            }
            if (!BurpConfig.isSupportApi(api, BurpConfig.SupportApi.BURPSUITE_USEROPTION)) {
                return;
            }
            JRadioButtonMenuItem selectedBurpCharSet = null;
            BurpConfig.CharacterSets burpCharset = BurpConfig.getCharacterSets(api);
            if (burpCharset.getCharacterSet() == null) {
                burpCharset.setCharacterSet(StandardCharsets.UTF_8.name());
            }

            JRadioButtonMenuItem burpCharsetItemMenuAuto = new JRadioButtonMenuItem();
            burpCharsetItemMenuAuto.setText(BurpConfig.CharacterSetMode.RECOGNIZE_AUTO.toIdent());
            burpCharsetMenu.add(burpCharsetItemMenuAuto);
            this.menuBurpCharsetsGroup.add(burpCharsetItemMenuAuto);
            if (BurpConfig.CharacterSetMode.RECOGNIZE_AUTO.toIdent().equals(burpCharset.getMode())) {
                selectedBurpCharSet = burpCharsetItemMenuAuto;
            }

            JRadioButtonMenuItem burpCharsetItemMenuDefault = new JRadioButtonMenuItem();
            burpCharsetItemMenuDefault.setText(BurpConfig.CharacterSetMode.PLATFORM_DEFAULT.toIdent());
            burpCharsetMenu.add(burpCharsetItemMenuDefault);
            this.menuBurpCharsetsGroup.add(burpCharsetItemMenuDefault);
            if (BurpConfig.CharacterSetMode.PLATFORM_DEFAULT.toIdent().equals(burpCharset.getMode())) {
                selectedBurpCharSet = burpCharsetItemMenuDefault;
            }

            JRadioButtonMenuItem burpCharsetItemMenuRaw = new JRadioButtonMenuItem();
            burpCharsetItemMenuRaw.setText(BurpConfig.CharacterSetMode.RAW_BYTES.toIdent());
            burpCharsetMenu.add(burpCharsetItemMenuRaw);
            this.menuBurpCharsetsGroup.add(burpCharsetItemMenuRaw);
            if (BurpConfig.CharacterSetMode.RAW_BYTES.toIdent().equals(burpCharset.getMode())) {
                selectedBurpCharSet = burpCharsetItemMenuRaw;
            }

            burpCharsetMenu.addSeparator();

            final List<String> encodngList = getSelectEncodingList();
            for (int i = 0; i < encodngList.size(); i++) {
                JRadioButtonMenuItem specificCharsetMenuCharSet = new JRadioButtonMenuItem();
                specificCharsetMenuCharSet.setText(encodngList.get(i));
                if (BurpConfig.CharacterSetMode.SPECIFIC_CHARACTER_SET.toIdent().equals(burpCharset.getMode()) && burpCharset.getCharacterSet().equals(encodngList.get(i))) {
                    selectedBurpCharSet = specificCharsetMenuCharSet;
                }
                burpCharsetMenu.add(specificCharsetMenuCharSet);
                this.menuBurpCharsetsGroup.add(specificCharsetMenuCharSet);
            }

            // Burp Charset 選択状態
            if (selectedBurpCharSet != null) {
                this.menuBurpCharsetsGroup.setSelected(selectedBurpCharSet.getModel(), true);
            }
            Enumeration<AbstractButton> emu = this.menuBurpCharsetsGroup.getElements();
            while (emu.hasMoreElements()) {
                if (emu.nextElement() instanceof JRadioButtonMenuItem burpCharsetMenuItem) {
                    burpCharsetMenuItem.addActionListener(this.burpCharsetModeAction);
                }
            }
        }

        /**
         * Result Filter
         */
        private void updateResultFilterUI(JMenu yaguraResultFilterMenu) {
            yaguraResultFilterMenu.removeAll();
//            for (Enumeration<AbstractButton> e = this.menuBurpResultFilterGroup.getElements(); e.hasMoreElements();) {
//                this.menuBurpResultFilterGroup.remove(e.nextElement());
//            }
            Map<String, FilterProperty> filterMap = option.getResultFilterProperty().getFilterMap();
            for (String name : filterMap.keySet()) {
                JMenuItem chkResultFilterItem = new JMenuItem();
                chkResultFilterItem.setText(name);
                chkResultFilterItem.addActionListener(this.resultFilterModeAction);
                yaguraResultFilterMenu.add(chkResultFilterItem);
 //               this.menuBurpResultFilterGroup.add(chkResultFilterItem);
            }
//            Enumeration<AbstractButton> rdoCheckGroup = this.menuBurpResultFilterGroup.getElements();
//            while (rdoCheckGroup.hasMoreElements()) {
//                AbstractButton rdoCheck = rdoCheckGroup.nextElement();
//                String name = rdoCheck.getText();
//                if (name.equals(option.getResultFilterProperty().getSelectedName())) {
//                    rdoCheck.setSelected(true);
//                }
//            }
        }
    }

    protected final class ProxyHander implements HttpHandler, ProxyRequestHandler, ProxyResponseHandler {

        private final MontoyaApi api;

        public ProxyHander(MontoyaApi api) {
            this.api = api;
            api.http().registerHttpHandler(this);
            api.proxy().registerRequestHandler(this);
            api.proxy().registerResponseHandler(this);
        }

        private final static Pattern HTTP2_VERSION_PATTERN = Pattern.compile("(\\S+) +(\\S+) +HTTP/2\r\n");

        /**
         * implements HttpHandler
         *
         * @param httpRequestToBeSent
         * @return
         */
        @Override
        public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent httpRequestToBeSent) {
            return RequestToBeSentAction.continueWith(httpRequestToBeSent, httpRequestToBeSent.annotations());
        }

        @Override
        public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived httpResponseReceived) {
            ToolSource toolSource = httpResponseReceived.toolSource();
            HttpRequestResponse messageInfo = HttpRequestResponse.httpRequestResponse(httpResponseReceived.initiatingRequest(), httpResponseReceived, httpResponseReceived.annotations());
            // Tool Log 出力
            if (getProperty().getLoggingProperty().isAutoLogging() && getProperty().getLoggingProperty().isToolLog()) {
                this.writeToolMessage(toolSource.toolType(), false, messageInfo);
            }
            return ResponseReceivedAction.continueWith(httpResponseReceived, httpResponseReceived.annotations());
        }

        /**
         * implements ProxyRequestHandler
         */
        /**
         *
         * @param interceptedRequest
         * @return
         */
        @Override
        public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {
            ProxyRequestReceivedAction requestResult = this.processProxyMessage(interceptedRequest, interceptedRequest.annotations());
            return ProxyRequestReceivedAction.proxyRequestReceivedAction(requestResult.request(), requestResult.annotations(), requestResult.action());
        }

        @Override
        public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest) {
            return ProxyRequestToBeSentAction.continueWith(interceptedRequest, interceptedRequest.annotations());
        }

        /**
         * implements ProxyResponseHandler
         */
        /**
         * @param interceptedResponse
         * @return
         */
        @Override
        public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse interceptedResponse) {
            ProxyResponseReceivedAction responseResult = this.processProxyMessage(interceptedResponse, interceptedResponse.initiatingRequest(), interceptedResponse.annotations());
            if (option.getMatchAlertProperty().isMatchAlertEnable()) {
                HttpRequestResponse modifyHttpRequestResponse = this.matchAlertMessage(ToolType.SUITE, true, HttpRequestResponse.httpRequestResponse(interceptedResponse.initiatingRequest(), responseResult.response(), responseResult.annotations()));
                modifyHttpRequestResponse = this.matchAlertMessage(ToolType.SUITE, false, modifyHttpRequestResponse);
                return ProxyResponseReceivedAction.proxyResponseReceivedAction(modifyHttpRequestResponse.response(), modifyHttpRequestResponse.annotations(), responseResult.action());
            } else {
                return ProxyResponseReceivedAction.continueWith(interceptedResponse, interceptedResponse.annotations());
            }
        }

        /**
         * @param interceptedResponse
         * @return
         */
        @Override
        public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse interceptedResponse) {
            // autologging 出力
            if (getProperty().getLoggingProperty().isAutoLogging() && getProperty().getLoggingProperty().isProxyLog()) {
                this.writeProxyMessage(interceptedResponse.messageId(), interceptedResponse.initiatingRequest().httpService(), interceptedResponse.initiatingRequest(), interceptedResponse);
            }
            return ProxyResponseToBeSentAction.continueWith(interceptedResponse, interceptedResponse.annotations());
        }

        /**
         * プロキシログの出力
         *
         * @param messageId
         * @param httpService
         * @param httpResuest
         * @param httpResponse
         */
        protected synchronized void writeProxyMessage(
                int messageId,
                HttpService httpService,
                HttpRequest httpResuest,
                HttpResponse httpResponse) {
            if (httpResponse != null) {
                try {
                    File fname = new File(getLogDir(), Config.getProxyLogMessageName());
                    if (fname.length() > getProperty().getLoggingProperty().getLogFileByteLimitSize()
                            && getProperty().getLoggingProperty().getLogFileByteLimitSize() > 0) {
                        File renameFile = FileUtil.rotateFile(getLogDir(), Config.getProxyLogMessageName());
                        fname.renameTo(renameFile);
                    }
                    boolean includeLog = true;
                    if (getProperty().getLoggingProperty().isExclude()) {
                        Pattern patternExclude = Pattern.compile(BurpUtil.parseFilterPattern(getProperty().getLoggingProperty().getExcludeExtension()));
                        Matcher matchExclude = patternExclude.matcher((new URL(httpResuest.url())).getFile());
                        if (matchExclude.find()) {
                            includeLog = false;
                        }
                    }
                    if (includeLog) {
                        try (BufferedOutputStream fostm = new BufferedOutputStream(new FileOutputStream(fname, true))) {
                            fostm.write(StringUtil.getBytesRaw(HttpUtil.LINE_TERMINATE));
                            fostm.write(StringUtil.getBytesRaw("======================================================" + HttpUtil.LINE_TERMINATE));
                            fostm.write(StringUtil.getBytesRaw(getCurrentLogTimestamp() + " " + HttpTarget.toURLString(httpService) + HttpUtil.LINE_TERMINATE));
                            fostm.write(StringUtil.getBytesRaw("======================================================" + HttpUtil.LINE_TERMINATE));
                            fostm.write(StringUtil.getBytesRaw(HttpUtil.LINE_TERMINATE));
                            fostm.write(httpResuest.toByteArray().getBytes());
                            fostm.write(StringUtil.getBytesRaw(HttpUtil.LINE_TERMINATE));
                            fostm.write(StringUtil.getBytesRaw("=========================================================" + HttpUtil.LINE_TERMINATE));
                            fostm.write(httpResponse.toByteArray().getBytes());
                            fostm.write(StringUtil.getBytesRaw(HttpUtil.LINE_TERMINATE));
                            fostm.write(StringUtil.getBytesRaw("=========================================================" + HttpUtil.LINE_TERMINATE));
                        }
                    }
                } catch (IOException ex) {
                    helpers().issueAlert("logger", ex.getMessage(), extension.burp.MessageType.ERROR);
                    logger.log(Level.SEVERE, ex.getMessage(), ex);
                } catch (Exception ex) {
                    logger.log(Level.SEVERE, ex.getMessage(), ex);
                }
            }
        }

        /**
         * tool ログの出力
         *
         * @param toolType ツール名
         * @param messageIsRequest リクエストかどうか
         * @param messageInfo メッセージ情報
         */
        protected synchronized void writeToolMessage(
                ToolType toolType,
                boolean messageIsRequest,
                HttpRequestResponse messageInfo) {
            String baselogfname = Config.getToolLogName(toolType.name());
            try {
                if (!messageIsRequest) {
                    File fname = new File(getLogDir(), baselogfname);
                    if (fname.length() > getProperty().getLoggingProperty().getLogFileByteLimitSize()
                            && getProperty().getLoggingProperty().getLogFileByteLimitSize() > 0) {
                        File renameFile = FileUtil.rotateFile(getLogDir(), baselogfname);
                        fname.renameTo(renameFile);
                    }
                    boolean includeLog = true;
                    if (getProperty().getLoggingProperty().isExclude()) {
                        Pattern patternExclude = Pattern.compile(BurpUtil.parseFilterPattern(getProperty().getLoggingProperty().getExcludeExtension()));
                        Matcher matchExclude = patternExclude.matcher(messageInfo.request().url());
                        if (matchExclude.find()) {
                            includeLog = false;
                        }
                    }
                    if (includeLog) {
                        try (BufferedOutputStream fostm = new BufferedOutputStream(new FileOutputStream(fname, true))) {
                            fostm.write(StringUtil.getBytesRaw("======================================================" + HttpUtil.LINE_TERMINATE));
                            fostm.write(StringUtil.getBytesRaw(getCurrentLogTimestamp() + " " + HttpTarget.toURLString(messageInfo.request().httpService()) + HttpUtil.LINE_TERMINATE));
                            fostm.write(StringUtil.getBytesRaw("======================================================" + HttpUtil.LINE_TERMINATE));
                            if (messageInfo.response() != null) {
                                fostm.write(messageInfo.response().toByteArray().getBytes());
                                fostm.write(StringUtil.getBytesRaw(HttpUtil.LINE_TERMINATE));
                            }
                            if (messageInfo.response() != null) {
                                fostm.write(StringUtil.getBytesRaw("======================================================" + HttpUtil.LINE_TERMINATE));
                                fostm.write(messageInfo.response().toByteArray().getBytes());
                                fostm.write(StringUtil.getBytesRaw(HttpUtil.LINE_TERMINATE));
                            }
                            fostm.write(StringUtil.getBytesRaw("======================================================" + HttpUtil.LINE_TERMINATE));
                        }
                    }
                }
            } catch (IOException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            } catch (Exception ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }

        protected void historyLogAppend() {
            if (this.api != null) {
                List<ProxyHttpRequestResponse> messageInfo = this.api.proxy().history();
                for (ProxyHttpRequestResponse info : messageInfo) {
                    this.writeToolMessage(ToolType.PROXY, false, HttpRequestResponse.httpRequestResponse(info.finalRequest(), info.originalResponse(), info.annotations()));
                }
            }
        }

        /**
         * Request
         *
         * @param httpRequest
         * @return
         */
        public ProxyRequestReceivedAction processProxyMessage(InterceptedRequest httpRequest) {
            return this.processProxyMessage(httpRequest, Annotations.annotations());
        }

        private ProxyRequestReceivedAction processProxyMessage(InterceptedRequest interceptedHttpRequest, Annotations annotations) {
            byte[] requestBytes = interceptedHttpRequest.toByteArray().getBytes();
            byte[] resultBytes = requestBytes;
            // Match and Replace
            if (getProperty().getMatchReplaceProperty().isSelectedMatchReplace()) {
                MatchReplaceGroup group = getProperty().getMatchReplaceProperty().getReplaceSelectedGroup(getProperty().getMatchReplaceProperty().getSelectedName());
                if (group != null && group.isInScopeOnly()) {
                    if (helpers().isInScope(interceptedHttpRequest.url())) {
                        resultBytes = this.replaceProxyMessage(true, requestBytes, interceptedHttpRequest.bodyOffset());
                    }
                } else {
                    resultBytes = this.replaceProxyMessage(true, requestBytes, interceptedHttpRequest.bodyOffset());
                }
            }
            if (requestBytes != resultBytes) {
//                HttpRequest modifyRequest = HttpRequest.httpRequest(interceptedHttpRequest.httpService(), ByteArray.byteArray(resultBytes));
                HttpRequest modifyRequest = ExtensionHelper.httpRequest(interceptedHttpRequest.httpService(), ByteArray.byteArray(resultBytes));
                return ProxyRequestReceivedAction.continueWith(modifyRequest, annotations);
            } else {
                return ProxyRequestReceivedAction.continueWith(interceptedHttpRequest, annotations);
            }
        }

        /**
         * Response
         *
         * @param interceptedHttpResponse
         * @param httpRequest
         * @return
         */
        public ProxyResponseReceivedAction processProxyMessage(InterceptedResponse interceptedHttpResponse, HttpRequest httpRequest) {
            return this.processProxyMessage(interceptedHttpResponse, httpRequest, Annotations.annotations());
        }

        private ProxyResponseReceivedAction processProxyMessage(InterceptedResponse interceptedHttpResponse, HttpRequest httpRequest, Annotations annotations) {
            byte[] responseByte = interceptedHttpResponse.toByteArray().getBytes();
            byte[] resultBytes = responseByte;

            // Match and Replace
            if (getProperty().getMatchReplaceProperty().isSelectedMatchReplace()) {
                MatchReplaceGroup group = getProperty().getMatchReplaceProperty().getReplaceSelectedGroup(getProperty().getMatchReplaceProperty().getSelectedName());
                if (group != null && group.isInScopeOnly()) {
                    if (helpers().isInScope(httpRequest.url())) {
                        resultBytes = this.replaceProxyMessage(false, responseByte, interceptedHttpResponse.bodyOffset());
                    }
                } else {
                    resultBytes = this.replaceProxyMessage(false, responseByte, interceptedHttpResponse.bodyOffset());
                }
            }
            if (responseByte != resultBytes) {
                HttpResponse modifyResponse = HttpResponse.httpResponse(ByteArray.byteArray(resultBytes));
                return ProxyResponseReceivedAction.continueWith(modifyResponse, annotations);
            } else {
                return ProxyResponseReceivedAction.continueWith(interceptedHttpResponse, annotations);
            }
        }

        /**
         * MatchAlert
         *
         * @param toolType ツール名
         * @param messageIsRequest request の場合 true
         * @param httpRequestResponse メッセージ情報
         */
        private HttpRequestResponse matchAlertMessage(ToolType toolType, boolean messageIsRequest, HttpRequestResponse httpRequestResponse) {
            Annotations annotations = httpRequestResponse.annotations();
            List<MatchAlertItem> matchAlertItemList = option.getMatchAlertProperty().getMatchAlertItemList();
            for (int i = 0; i < matchAlertItemList.size(); i++) {
                MatchAlertItem bean = matchAlertItemList.get(i);
                if (!bean.isSelected()) {
                    continue;
                }
                try {
                    TargetTool tools = TargetTool.valueOf(toolType);
                    if (!(bean.getTargetTools().contains(tools) || tools.equals(TargetTool.SUITE))) {
                        continue;
                    }
                    Pattern p = bean.getRegexPattern();
                    String decodeMessage = "";
                    if (bean.isRequest() && messageIsRequest) {
                        decodeMessage = StringUtil.getStringRaw(httpRequestResponse.request().toByteArray().getBytes());
                    } else if (bean.isResponse() && !messageIsRequest) {
                        decodeMessage = StringUtil.getStringRaw(httpRequestResponse.response().toByteArray().getBytes());
                    }
                    String replacemeComment = null;
                    List<IssueItem> markList = new ArrayList<>();
                    Matcher m = p.matcher(decodeMessage);
                    int count = 0;
                    while (m.find()) {
                        IssueItem issue = new IssueItem();
                        issue.setMessageIsRequest(messageIsRequest);
                        issue.setType(bean.getIssueName());
                        issue.setServerity(bean.getSeverity());
                        issue.setConfidence(bean.getConfidence());
                        issue.setStart(m.start());
                        issue.setEnd(m.end());
                        // コメントは最初にマッチしたもののみ
                        if (bean.isCaptureGroup() && replacemeComment == null) {
                            String group = m.group();
                            replacemeComment = p.matcher(group).replaceFirst(bean.getComment());
                        }
                        markList.add(issue);
                        count++;
                    }
                    if (count > 0) {
                        if (bean.getNotifyTypes().contains(NotifyType.ALERTS_TAB)) {
                            helpers().issueAlert(toolType.name(), String.format("[%s]: %d matches:%s url:%s", toolType.name(), count, bean.getMatch(), httpRequestResponse.request().url()), extension.burp.MessageType.INFO);
                        }
                        if (bean.getNotifyTypes().contains(NotifyType.TRAY_MESSAGE)) {
                            // trayMenu.displayMessage(toolName, String.format("[%s]: %d matches:%s url:%s", toolName, count, bean.getMatch(), reqInfo.getUrl().toString()), TrayIcon.MessageType.WARNING);
                        }
                        if (bean.getNotifyTypes().contains(NotifyType.ITEM_HIGHLIGHT)) {
                            annotations.setHighlightColor(bean.getHighlightColor().toHighlightColor());
                        }
                        if (bean.getNotifyTypes().contains(NotifyType.COMMENT)) {
                            if (replacemeComment != null) {
                                annotations.setNotes(replacemeComment);
                            } else {
                                annotations.setNotes(bean.getComment());
                            }
                        }
                        if (bean.getNotifyTypes().contains(NotifyType.SCANNER_ISSUE)) {
                            MatchAlert alert = new MatchAlert(toolType.name(), getProperty().getMatchAlertProperty());
                            List<AuditIssue> issues = alert.makeIssueList(messageIsRequest, httpRequestResponse, markList);
                            for (AuditIssue scanissue : issues) {
                                this.api.siteMap().add(scanissue);
                            }
                        }
                    }
                } catch (Exception ex) {
                    logger.log(Level.SEVERE, ex.getMessage(), ex);
                }
            }
            HttpRequestResponse modifyRequestResponse = HttpRequestResponse.httpRequestResponse(httpRequestResponse.request(), httpRequestResponse.response(), annotations);
            return modifyRequestResponse;
        }

        /**
         * メッセージの置換
         *
         * @param messageIsRequest
         * @param httpMessage
         * @param bodyOffset
         * @return 変換後メッセージ
         */
        protected byte[] replaceProxyMessage(
                boolean messageIsRequest,
                byte[] httpMessage,
                int bodyOffset) {

            // headerとbodyに分割
            boolean edited = false;
            String header = StringUtil.getBytesRawString(Arrays.copyOfRange(httpMessage, 0, bodyOffset));
            String body = StringUtil.getBytesRawString(Arrays.copyOfRange(httpMessage, bodyOffset, httpMessage.length));

            List<MatchReplaceItem> matchReplaceList = option.getMatchReplaceProperty().getMatchReplaceList();
            for (int i = 0; i < matchReplaceList.size(); i++) {
                MatchReplaceItem bean = matchReplaceList.get(i);
                if (!bean.isSelected()) {
                    continue;
                }
                if ((messageIsRequest && bean.isRequest()) || (!messageIsRequest && bean.isResponse())) {
                    // body
                    Pattern pattern = bean.getRegexPattern();
                    if (bean.isBody() && !body.isEmpty()) {
                        Matcher m = pattern.matcher(body);
                        if (m.find()) {
                            body = m.replaceAll(bean.getReplace(!bean.isRegexp(), bean.isMetaChar()));
                            edited = true;
                        }
                    } else if (messageIsRequest && bean.isRequestLine()) {
                        // header
                        if (!"".equals(bean.getMatch())) {
                            // 置換
                            Matcher m = HttpRequestWapper.FIRST_LINE.matcher(header);
                            if (m.find()) {
                                String firstline = m.group(0);
                                Matcher m2 = pattern.matcher(firstline);
                                if (m2.find()) {
                                    firstline = m2.replaceFirst(bean.getReplace(!bean.isRegexp(), bean.isMetaChar()));
                                }
                                header = m.replaceFirst(Pattern.quote(firstline));
                                edited = true;
                            }
                        }
                    } else if (bean.isHeader()) {
                        // header
                        if ("".equals(bean.getMatch())) {
                            // 追加
                            StringBuilder builder = new StringBuilder(header);
                            builder.append(bean.getReplace(!bean.isRegexp(), bean.isMetaChar()));
                            builder.append(HttpMessageWapper.LINE_TERMINATE);
                            header = builder.toString();
                            edited = true;
                        } else {
                            // 置換
                            Matcher m = pattern.matcher(header);
                            if (m.find()) {
                                header = m.replaceAll(bean.getReplace(!bean.isRegexp(), bean.isMetaChar()));
                                edited = true;
                            }
                        }
                        Matcher m = HttpMessageWapper.HTTP_LINESEP.matcher(header);
                        header = m.replaceAll(HttpMessageWapper.LINE_TERMINATE);
                    }
                }
            }

            if (edited) {
                // messageの再構築
                StringBuilder message = new StringBuilder();
                Matcher m = HttpMessageWapper.HTTP_LINESEP.matcher(header);
                header = m.replaceAll(HttpMessageWapper.LINE_TERMINATE);
                message.append(header);
                message.append(HttpMessageWapper.LINE_TERMINATE);
                message.append(body);
                httpMessage = StringUtil.getBytesRaw(message.toString());
            }
            return httpMessage;
        }

    }

    protected class AutoResponderHandler implements HttpHandler, ProxyRequestHandler, ExtensionUnloadingHandler {

        private final MontoyaApi api;
        private final List resolvHost = new ArrayList<>();

        public AutoResponderHandler(MontoyaApi api) {
            this.api = api;
            api.http().registerHttpHandler(this);
            api.proxy().registerRequestHandler(this);
        }

        @Override
        public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent httpRequestToBeSent) {
            // Autoresponder
            if (option.getAutoResponderProperty().getAutoResponderEnable()) {
                final String url = httpRequestToBeSent.url();
                AutoResponderItem item = option.getAutoResponderProperty().findItem(url, httpRequestToBeSent.method());
                if (item != null) {
                    HttpTarget httpTarget = new HttpTarget(getMockServiceURL());
                    HttpRequest updatedHttpServiceRequest = httpRequestToBeSent.withService(httpTarget).withAddedHeader(AutoResponderProperty.AUTO_RESPONDER_HEADER, url);
                    return RequestToBeSentAction.continueWith(updatedHttpServiceRequest);
                }
            }
            return RequestToBeSentAction.continueWith(httpRequestToBeSent);
        }

        @Override
        public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived httpResponseReceived) {
            return ResponseReceivedAction.continueWith(httpResponseReceived);
        }

        @Override
        public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {
            if (option.getAutoResponderProperty().getAutoResponderEnable() && option.getAutoResponderProperty().isHostNameForceResolv()) {
                final String url = interceptedRequest.url();
                AutoResponderItem item = option.getAutoResponderProperty().findItem(url, interceptedRequest.method());
                if (item != null) {
                    if (!HttpUtil.isInetAddressByName(interceptedRequest.httpService().host())) {
                        BurpExtension.helpers().issueAlert("MockServer", "resolv:" + interceptedRequest.httpService().host(), extension.burp.MessageType.INFO);
                        this.resolvHost.add(new HostnameResolution(true, interceptedRequest.httpService().host(), "127.0.0.1"));
                        BurpConfig.configHostnameResolution(this.api, this.resolvHost);
                    }
                }
            }
            return ProxyRequestReceivedAction.continueWith(interceptedRequest);
        }

        @Override
        public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest) {
            return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
        }

        @Override
        public void extensionUnloaded() {
            BurpConfig.configHostnameResolution(this.api, this.resolvHost, true);
        }
    }

};
