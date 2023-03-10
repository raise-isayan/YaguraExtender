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
import extend.util.external.gson.XMatchItemAdapter;
import extension.burp.BurpConfig;
import extension.burp.BurpConfig.HostnameResolution;
import extension.burp.BurpExtensionImpl;
import extension.burp.HttpTarget;
import extension.burp.MessageType;
import extension.burp.NotifyType;
import extension.burp.TargetTool;
import extension.burp.BurpUtil;
import extension.burp.BurpVersion;
import extension.helpers.FileUtil;
import extension.helpers.HttpMesageHelper;
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
import passive.IssueItem;
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

    private ProxyHander proxyHandler;
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

    /*
     * 古い Montoya API ではメソッド名をあやまっており
     * ここにくる場合は必ず古いバージョン
     **/
    public void initialise(MontoyaApi api) {
        BurpVersion burp_version = BurpUtil.suiteVersion();
        BurpVersion.showUnsupporttDlg(burp_version);
    }

    @Override
    public void initialize(MontoyaApi api) {
        super.initialize(api);
        BurpVersion burpVersion = this.getBurpVersion();
        if (BurpVersion.isUnsupportVersion(burpVersion)) {
            BurpVersion.showUnsupporttDlg(burpVersion);
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
            this.proxyHandler = new ProxyHander(api);
            this.autoResponderHandler = new AutoResponderHandler(api);
            this.registerView();
            api.userInterface().registerSuiteTab(this.tabbetOption.getTabCaption(), this.tabbetOption);
            setSendToMenu(new SendToMenu(api, this.option.getSendToProperty()));

            this.registerContextMenu = api.userInterface().registerContextMenuItemsProvider(this.getSendToMenu());
            api.extension().registerUnloadingHandler(this);
        });
        this.tabbetOption.setProperty(this.option);
        this.tabbetOption.addPropertyChangeListener(newPropertyChangeListener());

    }

    @SuppressWarnings("unchecked")
    public static BurpExtension getInstance() {
        return BurpExtensionImpl.<BurpExtension>getInstance();
    }

    public Component getUiComponent() {
        return this.tabbetOption;
    }

    private final TabbetOption tabbetOption = new TabbetOption();

    protected URL getMockServiceURL() {
        return this.tabbetOption.getMockServer().serviceURL();
    }

    private final HttpRequestEditorProvider requestRawTab = new HttpRequestEditorProvider() {

        @Override
        public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext editorCreationContext) {
            final RawViewTabEditor tab = new RawViewTabEditor(editorCreationContext, true);
//            tab.getMessageComponent().addMouseListener(newContextMenu(editorCreationContext));
            return tab;
        }
    };

    private final HttpResponseEditorProvider responseRawTab = new HttpResponseEditorProvider() {

        @Override
        public ExtensionProvidedHttpResponseEditor provideHttpResponseEditor(EditorCreationContext editorCreationContext) {
            final RawViewTabEditor tab = new RawViewTabEditor(editorCreationContext, false);
//            tab.getMessageComponent().addMouseListener(newContextMenu(editorCreationContext));
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
//            tab.getMessageComponent().addMouseListener(newContextMenu(httpRequestResponse));
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

    private MouseListener newContextMenu(HttpRequestResponse httpRequestResponse) {
        return new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                getSendToMenu().showBurpMenu(httpRequestResponse, e);
            }
        };
    }

    public void registerView() {
        MontoyaApi api = api();
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

    protected final class ProxyHander implements HttpHandler, ProxyRequestHandler, ProxyResponseHandler {

        private final MontoyaApi api;

        public ProxyHander(MontoyaApi api) {
            this.api = api;
            api.http().registerHttpHandler(this);
            api.proxy().registerRequestHandler(this);
            api.proxy().registerResponseHandler(this);
        }

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
                    helpers().issueAlert("logger", ex.getMessage(), MessageType.ERROR);
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
         * processToolMessage
         *
         * @param toolType
         * @param messageIsRequest
         * @param messageInfo
         * @return
         */
        public HttpRequestResponse processToolMessage(
                ToolType toolType,
                boolean messageIsRequest,
                HttpRequestResponse messageInfo) {
            HttpRequestResponse httpRequestResponse = messageInfo;
            if (getProperty().getMatchAlertProperty().isMatchAlertEnable() && getProperty().getMatchAlertProperty().isSelectedMatchAlert()) {
                httpRequestResponse = this.matchAlertMessage(toolType, messageIsRequest, messageInfo);
            }
            return httpRequestResponse;
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
                HttpRequest modifyRequest = HttpRequest.httpRequest(interceptedHttpRequest.httpService(), ByteArray.byteArray(resultBytes));
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
                            helpers().issueAlert(toolType.name(), String.format("[%s]: %d matches:%s url:%s", toolType.name(), count, bean.getMatch(), httpRequestResponse.request().url()), MessageType.INFO);
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
                            builder.append(HttpMesageHelper.LINE_TERMINATE);
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
                        Matcher m = HttpMesageHelper.HTTP_LINESEP.matcher(header);
                        header = m.replaceAll(HttpMesageHelper.LINE_TERMINATE);
                    }
                }
            }

            if (edited) {
                // messageの再構築
                StringBuilder message = new StringBuilder();
                message.append(header);
                message.append(HttpMesageHelper.LINE_TERMINATE);
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
                HttpService service = httpRequestToBeSent.httpService();
                final String url = httpRequestToBeSent.url();
                AutoResponderItem item = option.getAutoResponderProperty().findItem(url);
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
                AutoResponderItem item = option.getAutoResponderProperty().findItem(url);
                if (item != null) {
                    if (!HttpUtil.isInetAddressByName(interceptedRequest.httpService().host())) {
                        BurpExtension.helpers().issueAlert("MockServer", "resolv:" + interceptedRequest.httpService().host(), MessageType.INFO);
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

}
