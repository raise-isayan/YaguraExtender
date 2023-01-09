package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Registration;
import burp.api.montoya.core.ToolSource;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.HttpHandler;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.RequestResult;
import burp.api.montoya.http.ResponseResult;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.InitialInterceptAction;
import burp.api.montoya.proxy.InterceptedHttpRequest;
import burp.api.montoya.proxy.InterceptedHttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestHandler;
import burp.api.montoya.proxy.ProxyHttpResponseHandler;
import burp.api.montoya.proxy.ProxyRequestResponse;
import burp.api.montoya.proxy.RequestFinalInterceptResult;
import burp.api.montoya.proxy.RequestInitialInterceptResult;
import burp.api.montoya.proxy.ResponseFinalInterceptResult;
import burp.api.montoya.proxy.ResponseInitialInterceptResult;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.ui.editor.extension.EditorMode;
import burp.api.montoya.ui.editor.extension.ExtensionHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.ExtensionHttpRequestEditorProvider;
import burp.api.montoya.ui.editor.extension.ExtensionHttpResponseEditor;
import burp.api.montoya.ui.editor.extension.ExtensionHttpResponseEditorProvider;
import extend.util.external.ThemeUI;
import extend.util.external.gson.XMatchItemAdapter;
import extension.burp.BurpExtenderImpl;
import extension.burp.HttpTarget;
import extension.burp.MessageType;
import extension.burp.NotifyType;
import extension.burp.TargetTool;
import extension.helpers.BurpUtil;
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
import yagura.view.GeneratePoCTab;
import yagura.view.HtmlCommetViewTab;
import yagura.view.TabbetOption;
import yagura.model.OptionProperty;
import yagura.Config;
import yagura.Version;
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
import yagura.view.JSONViewTab;
import yagura.view.JWTViewTab;
import yagura.view.ParamsViewTab;
import yagura.view.RawViewTab;
import yagura.view.ViewStateTab;

/**
 * @author isayan
 */
public class BurpExtender extends BurpExtenderImpl implements ExtensionUnloadingHandler {

    private final static Logger logger = Logger.getLogger(BurpExtender.class.getName());
    private ProxyHander proxyHandler;
    private Registration registerContextMenu;

    public BurpExtender() {
        Thread.setDefaultUncaughtExceptionHandler(new Thread.UncaughtExceptionHandler() {
            @Override
            public void uncaughtException(Thread t, Throwable ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        });
    }

    protected final java.util.ResourceBundle BUNDLE = java.util.ResourceBundle.getBundle("burp/resources/release");

    private static final File CONFIG_FILE = new File(Config.getExtensionHomeDir(), Config.getExtensionName());

    /**
     * ログ設定プロパティファイルのファイル名
     */
    protected static final String LOGGING_PROPERTIES = "/yagura/resources/" + Config.getLoggingPropertyName();

    static {
        try (ByteArrayOutputStream bout = new ByteArrayOutputStream()) {
            Properties prop = new Properties();
            File logDir = Config.getExtensionHomeDir();
            logDir.mkdirs();
            File logPropFile = new File(Config.getExtensionHomeDir(), Config.getLoggingPropertyName());
            if (logPropFile.exists()) {
                prop.load(new FileInputStream(logPropFile));
            } else {
                prop.load(BurpExtender.class.getResourceAsStream(LOGGING_PROPERTIES));
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

    @SuppressWarnings("unchecked")
    public static BurpExtender getInstance() {
        return BurpExtenderImpl.<BurpExtender>getInstance();
    }

    public Component getUiComponent() {
        return this.tabbetOption;
    }

    private final TabbetOption tabbetOption = new TabbetOption();

    private final ExtensionHttpRequestEditorProvider requestRawTab = new ExtensionHttpRequestEditorProvider() {

        @Override
        public ExtensionHttpRequestEditor provideHttpRequestEditor(HttpRequestResponse httpRequestResponse, EditorMode editorMode) {
            final RawViewTab tab = new RawViewTab(httpRequestResponse, editorMode, true);
            tab.getMessageComponent().addMouseListener(newContextMenu(httpRequestResponse));
            return tab;
        }
    };

    private final ExtensionHttpResponseEditorProvider responseRawTab = new ExtensionHttpResponseEditorProvider() {

        @Override
        public ExtensionHttpResponseEditor provideHttpResponseEditor(HttpRequestResponse httpRequestResponse, EditorMode editorMode) {
            final RawViewTab tab = new RawViewTab(httpRequestResponse, editorMode, false);
            tab.getMessageComponent().addMouseListener(newContextMenu(httpRequestResponse));
            return tab;
        }
    };

    private final ExtensionHttpRequestEditorProvider requestParamsTab = new ExtensionHttpRequestEditorProvider() {

        @Override
        public ExtensionHttpRequestEditor provideHttpRequestEditor(HttpRequestResponse httpRequestResponse, EditorMode editorMode) {
            final ParamsViewTab tab = new ParamsViewTab(httpRequestResponse, editorMode);
            return tab;
        }
    };

    private final ExtensionHttpRequestEditorProvider requestJSONTab = new ExtensionHttpRequestEditorProvider() {

        @Override
        public ExtensionHttpRequestEditor provideHttpRequestEditor(HttpRequestResponse httpRequestResponse, EditorMode editorMode) {
            final JSONViewTab tab = new JSONViewTab(httpRequestResponse, editorMode, true);
            return tab;
        }
    };

    private final ExtensionHttpResponseEditorProvider responseJSONTab = new ExtensionHttpResponseEditorProvider() {

        @Override
        public ExtensionHttpResponseEditor provideHttpResponseEditor(HttpRequestResponse httpRequestResponse, EditorMode editorMode) {
            final JSONViewTab tab = new JSONViewTab(httpRequestResponse, editorMode, false);
            return tab;
        }
    };

    private final ExtensionHttpResponseEditorProvider responseJSONPTab = new ExtensionHttpResponseEditorProvider() {

        @Override
        public ExtensionHttpResponseEditor provideHttpResponseEditor(HttpRequestResponse httpRequestResponse, EditorMode editorMode) {
            final JSONViewTab tab = new JSONViewTab(httpRequestResponse, editorMode, false) {
                @Override
                public boolean isJsonp() {
                    return true;
                }
            };
            return tab;
        }
    };

    private final ExtensionHttpResponseEditorProvider responseCommentViewTab = new ExtensionHttpResponseEditorProvider() {

        @Override
        public ExtensionHttpResponseEditor provideHttpResponseEditor(HttpRequestResponse httpRequestResponse, EditorMode editorMode) {
            final HtmlCommetViewTab tab = new HtmlCommetViewTab();
            tab.getMessageComponent().addMouseListener(newContextMenu(httpRequestResponse));
            return tab;
        }
    };

    private final ExtensionHttpRequestEditorProvider requestViewStateTab = new ExtensionHttpRequestEditorProvider() {

        @Override
        public ExtensionHttpRequestEditor provideHttpRequestEditor(HttpRequestResponse httpRequestResponse, EditorMode editorMode) {
            final ViewStateTab tab = new ViewStateTab(httpRequestResponse);
            return tab;
        }
    };

    private final ExtensionHttpRequestEditorProvider requestJwtViewTab = new ExtensionHttpRequestEditorProvider() {

        @Override
        public ExtensionHttpRequestEditor provideHttpRequestEditor(HttpRequestResponse httpRequestResponse, EditorMode editorMode) {
            final JWTViewTab tab = new JWTViewTab();
            return tab;
        }
    };

    private final ExtensionHttpRequestEditorProvider requestGeneratePoCTab = new ExtensionHttpRequestEditorProvider() {

        @Override
        public ExtensionHttpRequestEditor provideHttpRequestEditor(HttpRequestResponse httpRequestResponse, EditorMode editorMode) {
            final GeneratePoCTab tab = new GeneratePoCTab();
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

    @Override
    public void initialize(MontoyaApi api) {
        super.initialize(api);
        api.extension().setName(String.format("%s v%s", BUNDLE.getString("projname"), BUNDLE.getString("version")));

        // 設定ファイル読み込み
        Map<String, String> config = this.option.loadConfigSetting();
        try {
            if (CONFIG_FILE.exists()) {
                Config.loadFromJson(CONFIG_FILE, config);
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
            this.proxyHandler = new ProxyHander(api);
            api.userInterface().registerSuiteTab(this.tabbetOption.getTabCaption(), this.tabbetOption);
            this.registerView();
            setSendToMenu(new SendToMenu(api, this.option.getSendToProperty()));
            this.registerContextMenu = api.userInterface().registerContextMenuItemsProvider(this.getSendToMenu());
            api.extension().registerUnloadingHandler(this);
        });
        this.tabbetOption.setProperty(this.option);
        this.tabbetOption.addPropertyChangeListener(newPropertyChangeListener());

    }

    public void registerView() {
        MontoyaApi api = getMontoyaApi();
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
     * @return  タイムスタンプ
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
                    MontoyaApi api = getMontoyaApi();
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
            Config.saveToJson(CONFIG_FILE, config);
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
        ThemeUI.removeAllUIManagerListener();
    }

    public final class ProxyHander implements HttpHandler, ProxyHttpRequestHandler, ProxyHttpResponseHandler {
        private final MontoyaApi api;

        public ProxyHander(MontoyaApi api) {
            this.api = api;
            api.http().registerHttpHandler(this);
            api.proxy().registerRequestHandler(this);
            api.proxy().registerResponseHandler(this);
        }

        @Override
        public ResponseInitialInterceptResult handleReceivedResponse(InterceptedHttpResponse interceptedHttpResponse, HttpRequest httpRequest, Annotations annotations) {
            ResponseInitialInterceptResult responseResult = this.processProxyMessage(interceptedHttpResponse, httpRequest, annotations);
            HttpRequestResponse modifyHttpRequestResponse = this.matchAlertMessage(ToolType.SUITE, true, HttpRequestResponse.httpRequestResponse(httpRequest, responseResult.response(), annotations));
            modifyHttpRequestResponse = this.matchAlertMessage(ToolType.SUITE, false, modifyHttpRequestResponse);
            return ResponseInitialInterceptResult.doNotIntercept(modifyHttpRequestResponse.httpResponse(), modifyHttpRequestResponse.messageAnnotations());
        }

        @Override
        public RequestInitialInterceptResult handleReceivedRequest(InterceptedHttpRequest interceptedHttpRequest, Annotations annotations) {
            return RequestInitialInterceptResult.doNotIntercept(interceptedHttpRequest, annotations);
        }

        @Override
        public ResponseFinalInterceptResult handleResponseToReturn(InterceptedHttpResponse interceptedHttpResponse, HttpRequest httpRequest, Annotations annotations) {

            // autologging 出力
            if (getProperty().getLoggingProperty().isAutoLogging() && getProperty().getLoggingProperty().isProxyLog()) {
                this.writeProxyMessage(interceptedHttpResponse.messageId(), httpRequest.httpService(), httpRequest, interceptedHttpResponse);
            }

            return ResponseFinalInterceptResult.continueWith(interceptedHttpResponse, annotations);
        }

        @Override
        public RequestFinalInterceptResult handleRequestToIssue(InterceptedHttpRequest httpRequest, Annotations annotations) {
            return RequestFinalInterceptResult.continueWith(httpRequest, annotations);
        }

        @Override
        public RequestResult handleHttpRequest(HttpRequest httpRequest, Annotations annotations, ToolSource toolSource) {
            return RequestResult.requestResult(httpRequest, annotations);
        }

        @Override
        public ResponseResult handleHttpResponse(HttpResponse httpResponse, HttpRequest httpRequest, Annotations annotations, ToolSource toolSource) {
            HttpRequestResponse httpRequestResponse = HttpRequestResponse.httpRequestResponse(httpRequest, httpResponse, annotations);

            // Tool Log 出力
            if (getProperty().getLoggingProperty().isAutoLogging() && getProperty().getLoggingProperty().isToolLog()) {
                this.writeToolMessage(toolSource.toolType(), false, httpRequestResponse);
            }

            return ResponseResult.responseResult(httpResponse, annotations);
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
                            fostm.write(httpResuest.asBytes().getBytes());
                            fostm.write(StringUtil.getBytesRaw(HttpUtil.LINE_TERMINATE));
                            fostm.write(StringUtil.getBytesRaw("=========================================================" + HttpUtil.LINE_TERMINATE));
                            fostm.write(httpResponse.asBytes().getBytes());
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
                        Matcher matchExclude = patternExclude.matcher(messageInfo.httpRequest().url());
                        if (matchExclude.find()) {
                            includeLog = false;
                        }
                    }
                    if (includeLog) {
                        try (BufferedOutputStream fostm = new BufferedOutputStream(new FileOutputStream(fname, true))) {
                            fostm.write(StringUtil.getBytesRaw("======================================================" + HttpUtil.LINE_TERMINATE));
                            fostm.write(StringUtil.getBytesRaw(getCurrentLogTimestamp() + " " + HttpTarget.toURLString(messageInfo.httpRequest().httpService()) + HttpUtil.LINE_TERMINATE));
                            fostm.write(StringUtil.getBytesRaw("======================================================" + HttpUtil.LINE_TERMINATE));
                            if (messageInfo.httpRequest() != null) {
                                fostm.write(messageInfo.httpRequest().asBytes().getBytes());
                                fostm.write(StringUtil.getBytesRaw(HttpUtil.LINE_TERMINATE));
                            }
                            if (messageInfo.httpResponse() != null) {
                                fostm.write(StringUtil.getBytesRaw("======================================================" + HttpUtil.LINE_TERMINATE));
                                fostm.write(messageInfo.httpResponse().asBytes().getBytes());
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
                List<ProxyRequestResponse> messageInfo = api.proxy().history();
                for (ProxyRequestResponse info : messageInfo) {
                    this.writeToolMessage(ToolType.PROXY, false, HttpRequestResponse.httpRequestResponse(info.finalRequest(), info.originalResponse(), info.messageAnnotations()));
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

        public RequestInitialInterceptResult processProxyMessage(InterceptedHttpRequest httpRequest) {
            return this.processProxyMessage(httpRequest, Annotations.annotations());
        }

        private RequestInitialInterceptResult processProxyMessage(InterceptedHttpRequest interceptedHttpRequest, Annotations annotations) {
            byte[] requestBytes = interceptedHttpRequest.asBytes().getBytes();
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
                return RequestInitialInterceptResult.initialInterceptResult(modifyRequest, annotations, InitialInterceptAction.DO_NOT_INTERCEPT);
            } else {
                return RequestInitialInterceptResult.doNotIntercept(interceptedHttpRequest, annotations);
            }
        }

        public ResponseInitialInterceptResult processProxyMessage(InterceptedHttpResponse interceptedHttpResponse, HttpRequest httpRequest) {
            return this.processProxyMessage(interceptedHttpResponse, httpRequest, Annotations.annotations());
        }

        private ResponseInitialInterceptResult processProxyMessage(InterceptedHttpResponse interceptedHttpResponse, HttpRequest httpRequest, Annotations annotations) {
            byte[] responseByte = interceptedHttpResponse.asBytes().getBytes();
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
                return ResponseInitialInterceptResult.initialInterceptResult(modifyResponse, annotations, InitialInterceptAction.DO_NOT_INTERCEPT);
            } else {
                return ResponseInitialInterceptResult.doNotIntercept(interceptedHttpResponse, annotations);
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
            Annotations annotations = httpRequestResponse.messageAnnotations();
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
                        decodeMessage = StringUtil.getStringRaw(httpRequestResponse.httpRequest().asBytes().getBytes());
                    } else if (bean.isResponse() && !messageIsRequest) {
                        decodeMessage = StringUtil.getStringRaw(httpRequestResponse.httpResponse().asBytes().getBytes());
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
                            helpers().issueAlert(toolType.name(), String.format("[%s]: %d matches:%s url:%s", toolType.name(), count, bean.getMatch(), httpRequestResponse.httpRequest().url()), MessageType.INFO);
                        }
                        if (bean.getNotifyTypes().contains(NotifyType.TRAY_MESSAGE)) {
                            // trayMenu.displayMessage(toolName, String.format("[%s]: %d matches:%s url:%s", toolName, count, bean.getMatch(), reqInfo.getUrl().toString()), TrayIcon.MessageType.WARNING);
                        }
                        if (bean.getNotifyTypes().contains(NotifyType.ITEM_HIGHLIGHT)) {
                            annotations = annotations.withHighlightColor(bean.getHighlightColor().toHighlightColor());
                            BurpExtender.helpers().outPrintln("Highlight c:" + bean.getHighlightColor() + "," + annotations.highlightColor());
                        }
                        if (bean.getNotifyTypes().contains(NotifyType.COMMENT)) {
                            if (replacemeComment != null) {
                                annotations = annotations.withComment(replacemeComment);
                                BurpExtender.helpers().outPrintln("Comment r:" + annotations.comment());
                            } else {
                                annotations = annotations.withComment(bean.getComment());
                                BurpExtender.helpers().outPrintln("Comment b:" + annotations.comment());
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
            HttpRequestResponse modifyRequestResponse = HttpRequestResponse.httpRequestResponse(httpRequestResponse.httpRequest(), httpRequestResponse.httpResponse(), annotations);
            BurpExtender.helpers().outPrintln("matchAlertMessage:" + toolType + ":" + messageIsRequest + ":" + modifyRequestResponse.messageAnnotations().highlightColor() + ":" + modifyRequestResponse.messageAnnotations().comment());
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

}
