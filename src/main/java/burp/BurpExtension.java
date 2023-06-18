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
import extension.burp.BurpExtensionImpl;
import extension.burp.HttpTarget;
import extension.burp.NotifyType;
import extension.burp.TargetTool;
import extension.burp.BurpUtil;
import extension.burp.BurpVersion;
import extension.burp.ExtensionHelper;
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
import javax.swing.JTextArea;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import passive.signature.MatchAlert;
import yagura.model.SendToMenu;
import yagura.view.TabbetOption;
import yagura.model.OptionProperty;
import yagura.Config;
import yagura.Version;
import yagura.model.AutoResponderItem;
import yagura.model.AutoResponderProperty;
import yagura.model.JSearchProperty;
import yagura.model.JTransCoderProperty;
import yagura.model.LoggingProperty;
import yagura.model.MatchAlertItem;
import yagura.model.MatchAlertProperty;
import yagura.model.MatchReplaceGroup;
import yagura.model.MatchReplaceItem;
import yagura.model.MatchReplaceProperty;
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

        //BurpConfig.configHostnameResolution(api);
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
        if (!this.option.getEncodingProperty().getEncodingList().contains(defaultCharset)) {
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
        private String yaguraCharset = StandardCharsets.UTF_8.name();

        public MenuHander(MontoyaApi api) {
            this.api = api;

            final JMenu yaguraMenu = new JMenu();
            yaguraMenu.setText("Yagura");
            yaguraMenu.setMnemonic(KeyEvent.VK_Y);

            /**
             * Yagura Charsets
             */
            JMenu yaguraCharsetMenu = new JMenu();
            yaguraCharsetMenu.setText("Yagura Charsets");
            yaguraCharsetMenu.setMnemonic(KeyEvent.VK_Y);
            final List<String> encodngList = getSelectEncodingList();
            for (int i = 0; i < encodngList.size(); i++) {
                JRadioButtonMenuItem specificCharsetMenuCharSet = new JRadioButtonMenuItem();
                specificCharsetMenuCharSet.setText(encodngList.get(i));
                specificCharsetMenuCharSet.addChangeListener(yaguraCharsetModeAction);
                yaguraCharsetMenu.add(specificCharsetMenuCharSet);
                menuYaguraCharsetsGroup.add(specificCharsetMenuCharSet);
            }

            /**
             * Yagura Encoder
             */
            JMenu yaguraEncoderMenu = new JMenu();
            yaguraEncoderMenu.setText("Encoder (E)");
            yaguraEncoderMenu.setMnemonic(KeyEvent.VK_E);

            JMenuItem yaguraEncoderURLMenu = createMenuItem("URL(%hh)", KeyEvent.VK_U, new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    KeyboardFocusManager mgr = KeyboardFocusManager.getCurrentKeyboardFocusManager();
                    Component owner = mgr.getPermanentFocusOwner();
                    if (owner instanceof JTextArea textArea) {
                        try {
                            String text = textArea.getSelectedText();
                            String encode = SmartCodec.toUrlEncode(text, yaguraCharset, SmartCodec.ENCODE_PATTERN_LIGHT, false);
                            textArea.replaceSelection(encode);
                        } catch (UnsupportedEncodingException ex) {
                            Logger.getLogger(BurpExtension.class.getName()).log(Level.SEVERE, ex.getMessage(), ex);
                        }
                    }
                }
            });

            yaguraEncoderMenu.add(yaguraEncoderURLMenu);

            JMenuItem yaguraEncoderUnicodeMenu = createMenuItem("Unicode(\\uhhhh)", KeyEvent.VK_N, new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    KeyboardFocusManager mgr = KeyboardFocusManager.getCurrentKeyboardFocusManager();
                    Component owner = mgr.getPermanentFocusOwner();
                    if (owner instanceof JTextArea textArea) {
                        String text = textArea.getSelectedText();
                        String encode = SmartCodec.toUnocodeEncode(text, SmartCodec.ENCODE_PATTERN_LIGHT, false);
                        textArea.replaceSelection(encode);
                    }
                }
            });

            yaguraEncoderMenu.add(yaguraEncoderUnicodeMenu);

            JMenuItem yaguraEncoderBase64Menu = createMenuItem("Base64", KeyEvent.VK_B, new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    KeyboardFocusManager mgr = KeyboardFocusManager.getCurrentKeyboardFocusManager();
                    Component owner = mgr.getPermanentFocusOwner();
                    if (owner instanceof JTextArea textArea) {
                        try {
                            String text = textArea.getSelectedText();
                            String encode = TransUtil.toBase64Encode(text, yaguraCharset);
                            textArea.replaceSelection(encode);
                        } catch (UnsupportedEncodingException ex) {
                            Logger.getLogger(BurpExtension.class.getName()).log(Level.SEVERE, ex.getMessage(), ex);
                        }
                    }
                }
            });

            yaguraEncoderMenu.add(yaguraEncoderBase64Menu);

            JMenuItem yaguraEncoderBase64UrlSafeMenu = createMenuItem("Base64URLSafe", KeyEvent.VK_S, new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    KeyboardFocusManager mgr = KeyboardFocusManager.getCurrentKeyboardFocusManager();
                    Component owner = mgr.getPermanentFocusOwner();
                    if (owner instanceof JTextArea textArea) {
                        try {
                            String text = textArea.getSelectedText();
                            String encode = TransUtil.toBase64URLSafeEncode(text, yaguraCharset);
                            textArea.replaceSelection(encode);
                        } catch (UnsupportedEncodingException ex) {
                            Logger.getLogger(BurpExtension.class.getName()).log(Level.SEVERE, ex.getMessage(), ex);
                        }
                    }
                }
            });

            yaguraEncoderMenu.add(yaguraEncoderBase64UrlSafeMenu);

            JMenuItem yaguraEncoderHtmlMenu = createMenuItem("Html", KeyEvent.VK_H, new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    KeyboardFocusManager mgr = KeyboardFocusManager.getCurrentKeyboardFocusManager();
                    Component owner = mgr.getPermanentFocusOwner();
                    if (owner instanceof JTextArea textArea) {
                        String text = textArea.getSelectedText();
                        String encode = SmartCodec.toHtmlDecEncode(text, SmartCodec.ENCODE_PATTERN_LIGHT);
                        textArea.replaceSelection(encode);
                    }
                }
            });

            yaguraEncoderMenu.add(yaguraEncoderHtmlMenu);

            /**
             * Yagura Decoder
             */
            JMenu yaguraDecoderMenu = new JMenu();
            yaguraDecoderMenu.setText("Decoder (D)");
            yaguraDecoderMenu.setMnemonic(KeyEvent.VK_D);

            JMenuItem yaguraDecoderURLMenu = createMenuItem("URL(%hh)", KeyEvent.VK_U, new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    KeyboardFocusManager mgr = KeyboardFocusManager.getCurrentKeyboardFocusManager();
                    Component owner = mgr.getPermanentFocusOwner();
                    if (owner instanceof JTextArea textArea) {
                        try {
                            String text = textArea.getSelectedText();
                            String encode = SmartCodec.toUrlDecode(text, yaguraCharset);
                            textArea.replaceSelection(encode);
                        } catch (UnsupportedEncodingException ex) {
                            Logger.getLogger(BurpExtension.class.getName()).log(Level.SEVERE, ex.getMessage(), ex);
                        }
                    }
                }
            });

            yaguraDecoderMenu.add(yaguraDecoderURLMenu);

            JMenuItem yaguraDecoderUnicodeMenu = createMenuItem("Unicode(\\uhhhh)", KeyEvent.VK_N, new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    KeyboardFocusManager mgr = KeyboardFocusManager.getCurrentKeyboardFocusManager();
                    Component owner = mgr.getPermanentFocusOwner();
                    if (owner instanceof JTextArea textArea) {
                        String text = textArea.getSelectedText();
                        String encode = SmartCodec.toUnocodeDecode(text);
                        textArea.replaceSelection(encode);
                    }
                }
            });

            yaguraDecoderMenu.add(yaguraDecoderUnicodeMenu);

            JMenuItem yaguraDecoderBase64Menu = createMenuItem("Base64", KeyEvent.VK_B, new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    KeyboardFocusManager mgr = KeyboardFocusManager.getCurrentKeyboardFocusManager();
                    Component owner = mgr.getPermanentFocusOwner();
                    if (owner instanceof JTextArea textArea) {
                        try {
                            String text = textArea.getSelectedText();
                            String encode = TransUtil.toBase64Decode(text, yaguraCharset);
                            textArea.replaceSelection(encode);
                        } catch (UnsupportedEncodingException ex) {
                            Logger.getLogger(BurpExtension.class.getName()).log(Level.SEVERE, ex.getMessage(), ex);
                        }
                    }
                }
            });

            yaguraDecoderMenu.add(yaguraDecoderBase64Menu);

            JMenuItem yaguraDecoderBase64UrlSafeMenu = createMenuItem("Base64URLSafe", KeyEvent.VK_S, new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    KeyboardFocusManager mgr = KeyboardFocusManager.getCurrentKeyboardFocusManager();
                    Component owner = mgr.getPermanentFocusOwner();
                    if (owner instanceof JTextArea textArea) {
                        try {
                            String text = textArea.getSelectedText();
                            String encode = TransUtil.toBase64URLSafeEncode(text, yaguraCharset);
                            textArea.replaceSelection(encode);
                        } catch (UnsupportedEncodingException ex) {
                            Logger.getLogger(BurpExtension.class.getName()).log(Level.SEVERE, ex.getMessage(), ex);
                        }
                    }
                }
            });

            yaguraDecoderMenu.add(yaguraDecoderBase64UrlSafeMenu);

            JMenuItem yaguraDecoderHtmlMenu = createMenuItem("Html", KeyEvent.VK_H, new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    KeyboardFocusManager mgr = KeyboardFocusManager.getCurrentKeyboardFocusManager();
                    Component owner = mgr.getPermanentFocusOwner();
                    if (owner instanceof JTextArea textArea) {
                        String text = textArea.getSelectedText();
                        String encode = SmartCodec.toHtmlDecode(text, SmartCodec.ENCODE_PATTERN_LIGHT);
                        textArea.replaceSelection(encode);
                    }
                }
            });

            yaguraDecoderMenu.add(yaguraDecoderHtmlMenu);

            /**
             * Yagura Converter
             */
            JMenu yaguraConverterMenu = new JMenu();
            yaguraConverterMenu.setText("Converter (C)");
            yaguraConverterMenu.setMnemonic(KeyEvent.VK_C);

            JMenuItem yaguraDecoderUpperCaseItemMenu = createMenuItem("Upper Case", KeyEvent.VK_U, new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    KeyboardFocusManager mgr = KeyboardFocusManager.getCurrentKeyboardFocusManager();
                    Component owner = mgr.getPermanentFocusOwner();
                    if (owner instanceof JTextArea textArea) {
                        String text = textArea.getSelectedText();
                        textArea.replaceSelection(text.toUpperCase());
                    }
                }
            });

            yaguraConverterMenu.add(yaguraDecoderUpperCaseItemMenu);

            JMenuItem yaguraDecoderLowlerCaseItemMenu = createMenuItem("Lowler Case", KeyEvent.VK_L, new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    KeyboardFocusManager mgr = KeyboardFocusManager.getCurrentKeyboardFocusManager();
                    Component owner = mgr.getPermanentFocusOwner();
                    if (owner instanceof JTextArea textArea) {
                        String text = textArea.getSelectedText();
                        textArea.replaceSelection(text.toLowerCase());
                    }
                }
            });

            yaguraConverterMenu.add(yaguraDecoderLowlerCaseItemMenu);

            JMenuItem yaguraConverterBin2HexMenu = createMenuItem("bin2hex", KeyEvent.VK_B, new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    KeyboardFocusManager mgr = KeyboardFocusManager.getCurrentKeyboardFocusManager();
                    Component owner = mgr.getPermanentFocusOwner();
                    if (owner instanceof JTextArea textArea) {
                        try {
                            String text = textArea.getSelectedText();
                            String encode = TransUtil.toByteHexEncode(text, yaguraCharset, false);
                            textArea.replaceSelection(encode);
                        } catch (UnsupportedEncodingException ex) {
                            Logger.getLogger(BurpExtension.class.getName()).log(Level.SEVERE, ex.getMessage(), ex);
                        }
                    }
                }
            });

            yaguraConverterMenu.add(yaguraConverterBin2HexMenu);

            JMenuItem yaguraConverterHex2BinMenu = createMenuItem("hex2bin", KeyEvent.VK_H, new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    KeyboardFocusManager mgr = KeyboardFocusManager.getCurrentKeyboardFocusManager();
                    Component owner = mgr.getPermanentFocusOwner();
                    if (owner instanceof JTextArea textArea) {
                        try {
                            String text = textArea.getSelectedText();
                            String encode = TransUtil.toByteHexDecode(text, yaguraCharset);
                            textArea.replaceSelection(encode);
                        } catch (UnsupportedEncodingException ex) {
                            Logger.getLogger(BurpExtension.class.getName()).log(Level.SEVERE, ex.getMessage(), ex);
                        }
                    }
                }
            });

            yaguraConverterMenu.add(yaguraConverterHex2BinMenu);

            JMenuItem yaguraConverterFull2Half = createMenuItem("Full Height -> Half Height", KeyEvent.VK_F, new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    KeyboardFocusManager mgr = KeyboardFocusManager.getCurrentKeyboardFocusManager();
                    Component owner = mgr.getPermanentFocusOwner();
                    if (owner instanceof JTextArea textArea) {
                        String text = textArea.getSelectedText();
                        String encode = TransUtil.translateFullHeight2HalfHeight(text);
                        textArea.replaceSelection(encode);
                    }
                }
            });
            yaguraConverterMenu.add(yaguraConverterFull2Half);

            JMenuItem yaguraConverterHalf2Full = createMenuItem("Half Height -> Full Height", KeyEvent.VK_K, new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    KeyboardFocusManager mgr = KeyboardFocusManager.getCurrentKeyboardFocusManager();
                    Component owner = mgr.getPermanentFocusOwner();
                    if (owner instanceof JTextArea textArea) {
                        String text = textArea.getSelectedText();
                        String encode = TransUtil.translateHalfHeight2FullHeight(text);
                        textArea.replaceSelection(encode);
                    }
                }
            });
            yaguraConverterMenu.add(yaguraConverterHalf2Full);

            /**
             * Yagura Hash
             */
            JMenu yaguraHashMenu = new JMenu();
            yaguraHashMenu.setText("Hash (H)");
            yaguraHashMenu.setMnemonic(KeyEvent.VK_H);

            JMenuItem yaguraHashMD5Menu = createMenuItem("md5", KeyEvent.VK_0, new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    KeyboardFocusManager mgr = KeyboardFocusManager.getCurrentKeyboardFocusManager();
                    Component owner = mgr.getPermanentFocusOwner();
                    if (owner instanceof JTextArea textArea) {
                        try {
                            String text = textArea.getSelectedText();
                            String hash = TransUtil.toMd5Sum(text, yaguraCharset, false);
                            textArea.replaceSelection(hash);
                        } catch (UnsupportedEncodingException ex) {
                            Logger.getLogger(BurpExtension.class.getName()).log(Level.SEVERE, ex.getMessage(), ex);
                        }
                    }
                }
            });

            yaguraHashMenu.add(yaguraHashMD5Menu);

            JMenuItem yaguraHashSha1Menu = createMenuItem("sha1", KeyEvent.VK_1, new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    KeyboardFocusManager mgr = KeyboardFocusManager.getCurrentKeyboardFocusManager();
                    Component owner = mgr.getPermanentFocusOwner();
                    if (owner instanceof JTextArea textArea) {
                        try {
                            String text = textArea.getSelectedText();
                            String hash = TransUtil.toSHA1Sum(text, yaguraCharset, false);
                            textArea.replaceSelection(hash);
                        } catch (UnsupportedEncodingException ex) {
                            Logger.getLogger(BurpExtension.class.getName()).log(Level.SEVERE, ex.getMessage(), ex);
                        }
                    }
                }
            });

            yaguraHashMenu.add(yaguraHashSha1Menu);

            JMenuItem yaguraHashSha256Menu = createMenuItem("sha256", KeyEvent.VK_2, new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    KeyboardFocusManager mgr = KeyboardFocusManager.getCurrentKeyboardFocusManager();
                    Component owner = mgr.getPermanentFocusOwner();
                    if (owner instanceof JTextArea textArea) {
                        try {
                            String text = textArea.getSelectedText();
                            String hash = TransUtil.toSHA256Sum(text, yaguraCharset, false);
                            textArea.replaceSelection(hash);
                        } catch (UnsupportedEncodingException ex) {
                            Logger.getLogger(BurpExtension.class.getName()).log(Level.SEVERE, ex.getMessage(), ex);
                        }
                    }
                }
            });

            yaguraHashMenu.add(yaguraHashSha256Menu);

            JMenuItem yaguraHashSha512Menu = createMenuItem("sha512", KeyEvent.VK_3, new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    KeyboardFocusManager mgr = KeyboardFocusManager.getCurrentKeyboardFocusManager();
                    Component owner = mgr.getPermanentFocusOwner();
                    if (owner instanceof JTextArea textArea) {
                        try {
                            String text = textArea.getSelectedText();
                            String hash = TransUtil.toSHA512Sum(text, yaguraCharset, false);
                            textArea.replaceSelection(hash);
                        } catch (UnsupportedEncodingException ex) {
                            Logger.getLogger(BurpExtension.class.getName()).log(Level.SEVERE, ex.getMessage(), ex);
                        }
                    }
                }
            });

            yaguraHashMenu.add(yaguraHashSha512Menu);

            JMenu burpCharsetMenu = new JMenu();
            burpCharsetMenu.setText("Burp Charsets");
            burpCharsetMenu.setMnemonic(KeyEvent.VK_B);

            // Burp Charsets
            JRadioButtonMenuItem burpCharsetItemMenuAuto = new JRadioButtonMenuItem();
            burpCharsetItemMenuAuto.setText(BurpConfig.CharacterSetMode.RECOGNIZE_AUTO.toIdent());
            burpCharsetItemMenuAuto.addActionListener(burpCharsetModeAction);
            burpCharsetMenu.add(burpCharsetItemMenuAuto);
            menuBurpCharsetsGroup.add(burpCharsetItemMenuAuto);

            JRadioButtonMenuItem burpCharsetItemMenuDefault = new JRadioButtonMenuItem();
            burpCharsetItemMenuDefault.setText(BurpConfig.CharacterSetMode.PLATFORM_DEFAULT.toIdent());
            burpCharsetItemMenuDefault.addActionListener(burpCharsetModeAction);
            burpCharsetMenu.add(burpCharsetItemMenuDefault);
            menuBurpCharsetsGroup.add(burpCharsetItemMenuDefault);

            JRadioButtonMenuItem burpCharsetItemMenuRaw = new JRadioButtonMenuItem();
            burpCharsetItemMenuRaw.setText(BurpConfig.CharacterSetMode.RAW_BYTES.toIdent());
            burpCharsetItemMenuRaw.addActionListener(burpCharsetModeAction);
            burpCharsetMenu.add(burpCharsetItemMenuRaw);
            menuBurpCharsetsGroup.add(burpCharsetItemMenuRaw);

            burpCharsetMenu.addSeparator();

            BurpConfig.CharacterSets burpCharset = BurpConfig.getCharacterSets(BurpConfig.CharacterSetMode.SPECIFIC_CHARACTER_SET, StandardCharsets.UTF_8.name());
            if (BurpConfig.isSupportApi(api, BurpConfig.SupportApi.BURPSUITE_USEROPTION)) {
                burpCharset = BurpConfig.getCharacterSets(api);
                if (burpCharset.getCharacterSet() == null) {
                    burpCharset.setCharacterSet(StandardCharsets.UTF_8.name());
                }
            }

            for (int i = 0; i < encodngList.size(); i++) {
                JRadioButtonMenuItem specificCharsetMenuCharSet = new JRadioButtonMenuItem();
                specificCharsetMenuCharSet.setText(encodngList.get(i));
                specificCharsetMenuCharSet.addActionListener(burpCharsetModeAction);
                burpCharsetMenu.add(specificCharsetMenuCharSet);
                menuBurpCharsetsGroup.add(specificCharsetMenuCharSet);
            }
            burpCharsetMenu.add(burpCharsetMenu);

            yaguraMenu.add(yaguraCharsetMenu);
            yaguraMenu.add(yaguraEncoderMenu);
            yaguraMenu.add(yaguraDecoderMenu);
            yaguraMenu.add(yaguraConverterMenu);
            yaguraMenu.add(yaguraHashMenu);
            if (BurpConfig.isSupportApi(api, BurpConfig.SupportApi.BURPSUITE_USEROPTION)) {
                yaguraMenu.addSeparator();
                yaguraMenu.add(burpCharsetMenu);
            }

            Enumeration<AbstractButton> rdoYaguraCharsets = menuYaguraCharsetsGroup.getElements();
            while (rdoYaguraCharsets.hasMoreElements()) {
                JRadioButtonMenuItem item = (JRadioButtonMenuItem) rdoYaguraCharsets.nextElement();
                if (burpCharset.getCharacterSet().equals(item.getText())) {
                    item.setSelected(true);
                }
            }

            Enumeration<AbstractButton> rdoBurpCharsets = menuBurpCharsetsGroup.getElements();
            while (rdoBurpCharsets.hasMoreElements()) {
                JRadioButtonMenuItem item = (JRadioButtonMenuItem) rdoBurpCharsets.nextElement();
                if (burpCharset.getMode().equals(BurpConfig.CharacterSetMode.SPECIFIC_CHARACTER_SET.toIdent())) {
                    if (burpCharset.getCharacterSet().equals(item.getText())) {
                        item.setSelected(true);
                    }
                } else {
                    if (burpCharset.getMode().equals(item.getText())) {
                        item.setSelected(true);
                        break;
                    }
                }
            }

            api.userInterface().menuBar().registerMenu(yaguraMenu);
        }

        public static JMenuItem createMenuItem(String caption, int mnemonic, ActionListener action) {
            final JMenuItem yaguraMenuItem = new JMenuItem();
            yaguraMenuItem.setText(caption + " (" + (char) mnemonic + ")");
            yaguraMenuItem.setMnemonic(mnemonic);
            yaguraMenuItem.addActionListener(action);
            return yaguraMenuItem;
        }

        private ActionListener burpCharsetModeAction = new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                Enumeration<AbstractButton> rdoCharsets = menuBurpCharsetsGroup.getElements();
                BurpConfig.CharacterSets burpCharset = BurpConfig.getCharacterSets(BurpConfig.CharacterSetMode.SPECIFIC_CHARACTER_SET, StandardCharsets.UTF_8.name());
                final List<String> encodngList = getSelectEncodingList();
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

        private ChangeListener yaguraCharsetModeAction = new ChangeListener() {

            @Override
            public void stateChanged(ChangeEvent e) {
                if (e.getSource() instanceof JRadioButtonMenuItem item) {
                    if (item.isSelected()) {
                        yaguraCharset = item.getText();
                    }
                }
            }
        };

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
            HttpRequestResponse modifyHttpRequestResponse = this.matchAlertMessage(ToolType.SUITE, true, HttpRequestResponse.httpRequestResponse(interceptedResponse.initiatingRequest(), responseResult.response(), responseResult.annotations()));
            modifyHttpRequestResponse = this.matchAlertMessage(ToolType.SUITE, false, modifyHttpRequestResponse);
            return ProxyResponseReceivedAction.proxyResponseReceivedAction(modifyHttpRequestResponse.response(), modifyHttpRequestResponse.annotations(), responseResult.action());
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
            if (api != null) {
                List<ProxyHttpRequestResponse> messageInfo = api.proxy().history();
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
                            annotations = annotations.withHighlightColor(bean.getHighlightColor().toHighlightColor());
                        }
                        if (bean.getNotifyTypes().contains(NotifyType.COMMENT)) {
                            if (replacemeComment != null) {
                                annotations = annotations.withNotes(replacemeComment);
                            } else {
                                annotations = annotations.withNotes(bean.getComment());
                            }
                        }
                        if (bean.getNotifyTypes().contains(NotifyType.SCANNER_ISSUE)) {
                            MatchAlert alert = new MatchAlert(toolType.name(), getProperty().getMatchAlertProperty());
                            List<AuditIssue> issues = alert.makeIssueList(messageIsRequest, httpRequestResponse, markList);
                            for (AuditIssue scanissue : issues) {
                                api.siteMap().add(scanissue);
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
                    Pattern p = bean.getRegexPattern();
                    if (bean.isBody() && !body.isEmpty()) {
                        Matcher m = p.matcher(body);
                        if (m.find()) {
                            body = m.replaceAll(bean.getReplace(!bean.isRegexp(), bean.isMetaChar()));
                            edited = true;
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
                            Matcher m = p.matcher(header);
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
