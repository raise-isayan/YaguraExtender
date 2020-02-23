package burp;

import static burp.BurpExtenderImpl.getCallbacks;
import yagura.model.AutoResponderItem;
import yagura.model.MatchAlertItem;
import yagura.model.MatchReplaceItem;
import yagura.model.SendToMenu;
import yagura.view.GeneratePoCTab;
import yagura.view.HtmlCommetViewTab;
import yagura.view.JSONViewTab;
import yagura.view.TabbetOption;
import yagura.model.MatchReplaceGroup;
import passive.signature.MatchAlert;
import yagura.model.OptionProperty;
import extend.view.base.HttpMessage;
import extend.view.base.MatchItem;
import extend.util.BurpWrap;
import extend.util.HttpUtil;
import extend.util.SwingUtil;
import extend.util.Util;
import extend.util.external.JsonUtil;
import extend.util.external.gson.HotKeyAdapter;
import extend.util.external.gson.XMatchItemAdapter;
import extend.view.base.HttpResponse;
import java.awt.Component;
import java.awt.KeyEventPostProcessor;
import java.awt.KeyboardFocusManager;
import java.awt.TrayIcon;
import java.awt.event.KeyEvent;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.HashMap;
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
import javax.swing.JTable;
import javax.swing.table.TableModel;
import passive.IssueItem;
import yagura.Config;
import yagura.model.HotKey;
import yagura.view.JWTViewTab;
import yagura.view.ParamsViewTab;
import yagura.view.RawViewTab;

/**
 * @author isayan
 */
public class BurpExtender extends BurpExtenderImpl
        implements IHttpListener, IProxyListener, IExtensionStateListener {

    public BurpExtender() {
    }

    private final File CONFIG_FILE = new File(Config.getExtensionHomeDir(), Config.getExtensionFile());

    /**
     * ログ設定プロパティファイルのファイル名
     */
    protected static final String LOGGING_PROPERTIES = "/yagura/resources/" + Config.getLoggingPropertyName();
    
    static {
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        try {
            Properties prop = new Properties();
            prop.load(BurpExtender.class.getResourceAsStream(LOGGING_PROPERTIES));
            String pattern = prop.getProperty(FileHandler.class.getName() + ".pattern");
            File logDir = Config.getExtensionHomeDir();
            logDir.mkdirs();
            prop.setProperty(FileHandler.class.getName() + ".pattern", new File(logDir, pattern).getAbsolutePath());
            prop.store(bout, "");
            LogManager.getLogManager().readConfiguration(new ByteArrayInputStream(bout.toByteArray()));
        } catch (IOException ex) {
            Logger.getLogger(BurpExtender.class.getName()).log(Level.SEVERE, null, ex);
        }
        JsonUtil.registerTypeHierarchyAdapter(MatchItem.class, new XMatchItemAdapter());
        JsonUtil.registerTypeHierarchyAdapter(HotKey.class, new HotKeyAdapter());
    }

    public static BurpExtender getInstance() {
        return BurpExtenderImpl.<BurpExtender>getInstance();
    }

    public Component getUiComponent() {
        return this.tabbetOption;
    }

    private final TabbetOption tabbetOption = new TabbetOption();
    private final JWTViewTab jwtViewTab = new JWTViewTab();

    private final HtmlCommetViewTab commentViewTab = new HtmlCommetViewTab();
    private final GeneratePoCTab generatePoCTab = new GeneratePoCTab();

    private final IMessageEditorTabFactory requestRawTab = new IMessageEditorTabFactory() {
        @Override
        public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
            final RawViewTab tab = new RawViewTab(controller, editable, true);
            return tab;
        }
    };

    private final IMessageEditorTabFactory responseRawTab = new IMessageEditorTabFactory() {
        @Override
        public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
            final RawViewTab tab = new RawViewTab(controller, editable, false);
            return tab;
        }
    };

    private final IMessageEditorTabFactory requestParamsTab = new IMessageEditorTabFactory() {
        @Override
        public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
            final ParamsViewTab tab = new ParamsViewTab(controller, editable);
            return tab;
        }
    };

    private final IMessageEditorTabFactory requestJSONTab = new IMessageEditorTabFactory() {
        @Override
        public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
            final JSONViewTab tab = new JSONViewTab(controller, editable, true);
            return tab;
        }
    };

    private final IMessageEditorTabFactory responseJSONTab = new IMessageEditorTabFactory() {
        @Override
        public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
            final JSONViewTab tab = new JSONViewTab(controller, editable, false);
            return tab;
        }
    };

    private final KeyEventPostProcessor dispatcher = new KeyEventPostProcessor() {
        @Override
        public boolean postProcessKeyEvent(KeyEvent e) {
            SendToMenu menu = getSendToMenu();
            menu.doKeyEventAction(e);
            return false;
        }
    };

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks cb) {
        super.registerExtenderCallbacks(cb);
        Thread.setDefaultUncaughtExceptionHandler(new Thread.UncaughtExceptionHandler() {
            @Override
            public void uncaughtException(Thread t, Throwable e) {
                Logger.getLogger(BurpExtender.class.getName()).log(Level.SEVERE, null, e);
            }
        });
        if (this.getBurpVersion().isExtendSupport()) {
            // 設定ファイル読み込み
            try {
                if (CONFIG_FILE.exists()) {
                    Config.loadFromJson(CONFIG_FILE, this.option);                            
                }                             
            } catch (IOException ex) {
                Logger.getLogger(BurpExtender.class.getName()).log(Level.SEVERE, null, ex);
            } catch (RuntimeException ex) {
                Logger.getLogger(BurpExtender.class.getName()).log(Level.WARNING, null, ex);
            }

            try {
                // 自動ログ作成時のみディレクトリ作成
                if (this.option.getLoggingProperty().isAutoLogging()) {
                    this.setLogDir(mkLogDir(this.option.getLoggingProperty().getBaseDir(), this.option.getLoggingProperty().getLogDirFormat()));
                }
            } catch (IOException ex) {
                Logger.getLogger(BurpExtender.class.getName()).log(Level.SEVERE, null, ex);
            }

            setSendToMenu(new SendToMenu(cb, this.option.getSendToProperty()));
            cb.registerHttpListener(this);
            cb.registerProxyListener(this);
            cb.addSuiteTab(this.tabbetOption);
            cb.registerExtensionStateListener(this.tabbetOption);
            cb.registerExtensionStateListener(this);
            cb.registerContextMenuFactory(this.getSendToMenu());
            this.tabbetOption.setProperty(this.option);
            this.tabbetOption.addPropertyChangeListener(newPropertyChangeListener());
            this.registerView();

            //
//            DefaultKeyboardFocusManager.getCurrentKeyboardFocusManager().addKeyEventPostProcessor(dispatcher);

        } else {
            JOptionPane.showMessageDialog(null, "This burp version is not supported.\r\nversion 1.7 required", "YaguraExtender", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    @Override
    public void extensionUnloaded() {
//        DefaultKeyboardFocusManager.getCurrentKeyboardFocusManager().removeKeyEventPostProcessor(dispatcher);
    }

    public void registerView() {
        IBurpExtenderCallbacks cb = getCallbacks();
        cb.registerMessageEditorTabFactory(this.requestRawTab);
        cb.registerMessageEditorTabFactory(this.responseRawTab);
        cb.registerMessageEditorTabFactory(this.requestParamsTab);
        cb.registerMessageEditorTabFactory(this.generatePoCTab);
        cb.registerMessageEditorTabFactory(this.commentViewTab);
        cb.registerMessageEditorTabFactory(this.requestJSONTab);
        cb.registerMessageEditorTabFactory(this.responseJSONTab);
        cb.registerMessageEditorTabFactory(this.jwtViewTab);
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        String toolName = getCallbacks().getToolName(toolFlag);
        this.processToolMessage(toolName, messageIsRequest, messageInfo);
    }

    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
        byte[] messageByte = new byte[0];
        byte[] resultBytes = new byte[0];

        if (messageIsRequest) {
            messageByte = message.getMessageInfo().getRequest();
        } else {
            messageByte = message.getMessageInfo().getResponse();
        }
        resultBytes = messageByte;
        IHttpRequestResponse msgInfo = message.getMessageInfo();

        // Autoresponder
        if (messageIsRequest && this.option.getAutoResponderProperty().getAutoResponderEnable()) {
            boolean apply = this.autoresponderProxyMessage(msgInfo.getHttpService(), msgInfo);
            if (apply) {
                return;
            }
        }

        // Match and Replace
        if (this.option.getMatchReplaceProperty().isSelectedMatchReplace()) {
            MatchReplaceGroup group = this.option.getMatchReplaceProperty().getReplaceSelectedGroup(this.option.getMatchReplaceProperty().getSelectedName());
            if (group != null && group.isInScopeOnly()) {
                IRequestInfo reqInfo = BurpExtender.getHelpers().analyzeRequest(msgInfo.getHttpService(), messageByte);
                if (BurpExtender.getCallbacks().isInScope(reqInfo.getUrl())) {
                    resultBytes = this.replaceProxyMessage(message.getMessageReference(), messageIsRequest, messageByte);
                }
            } else {
                resultBytes = this.replaceProxyMessage(message.getMessageReference(), messageIsRequest, messageByte);
            }
        }

        if (messageByte != resultBytes) {
            if (messageIsRequest) {
                message.getMessageInfo().setRequest(resultBytes);
            } else {
                message.getMessageInfo().setResponse(resultBytes);
            }
        }

        // autologging
        if (this.option.getLoggingProperty().isAutoLogging() && this.option.getLoggingProperty().isProxyLog()) {
            this.writeProxyMessage(message.getMessageReference(), messageIsRequest, msgInfo.getHttpService(), resultBytes);
        }

    }

    public synchronized String getCurrentLogTimestamp() {
        DateFormat format = this.option.getLoggingProperty().getLogTimestampDateFormat();
        return format.format(new java.util.Date());
    }

    /**
     * processToolMessage
     *
     * @param toolName
     * @param messageIsRequest
     * @param messageInfo
     */
    public void processToolMessage(
            String toolName,
            boolean messageIsRequest,
            IHttpRequestResponse messageInfo) {
        if (this.option.getMatchAlertProperty().isMatchAlertEnable() && this.option.getMatchAlertProperty().isSelectedMatchAlert()) {
            this.matchAlertMessage(toolName, messageIsRequest, messageInfo);
        }
        if (this.option.getLoggingProperty().isAutoLogging() && this.option.getLoggingProperty().isToolLog()) {
            this.writeToolMessage(toolName, messageIsRequest, messageInfo);
        }
    }

    private final Map<Integer, byte[]> proxyLogs = new HashMap<>();

    /**
     * プロキシログの出力
     *
     * @param messageReference
     * @param messageIsRequest
     * @param httpService
     * @param message
     */
    protected synchronized void writeProxyMessage(
            int messageReference,
            boolean messageIsRequest,
            IHttpService httpService,
            byte[] message) {
        if (messageIsRequest) {
            this.proxyLogs.put(messageReference, message);
        } else {
            byte[] request = this.proxyLogs.get(messageReference);
            if (request != null) {
                try {
                    File fname = new File(this.getLogDir(), Config.getProxyLogMessageName());
                    if (fname.length() > this.option.getLoggingProperty().getLogFileByteLimitSize()
                            && this.option.getLoggingProperty().getLogFileByteLimitSize() > 0) {
                        File renameFile = Util.rotateFile(this.getLogDir(), Config.getProxyLogMessageName());
                        fname.renameTo(renameFile);
                    }
                    boolean includeLog = true;
                    if (this.option.getLoggingProperty().isExclude()) {
                        Pattern patternExclude = Pattern.compile(BurpWrap.parseFilterPattern(this.option.getLoggingProperty().getExcludeExtension()));
                        Matcher matchExclude = patternExclude.matcher(BurpWrap.getURL(httpService, request).getFile());
                        if (matchExclude.find()) {
                            includeLog = false;
                        }
                    }
                    if (includeLog) {
                        try (BufferedOutputStream fostm = new BufferedOutputStream(new FileOutputStream(fname, true))) {
                            fostm.write(Util.getRawByte(Util.NEW_LINE));
                            fostm.write(Util.getRawByte("======================================================" + Util.NEW_LINE));
                            fostm.write(Util.getRawByte(getCurrentLogTimestamp() + " " + BurpWrap.getURLString(httpService) + Util.NEW_LINE));
                            fostm.write(Util.getRawByte("======================================================" + Util.NEW_LINE));
                            fostm.write(Util.getRawByte(Util.NEW_LINE));
                            fostm.write(request);
                            fostm.write(Util.getRawByte(Util.NEW_LINE));
                            fostm.write(Util.getRawByte("=========================================================" + Util.NEW_LINE));
                            fostm.write(message);
                            fostm.write(Util.getRawByte(Util.NEW_LINE));
                            fostm.write(Util.getRawByte("=========================================================" + Util.NEW_LINE));
                        }
                    }
                } catch (IOException ex) {
                    getCallbacks().issueAlert(ex.getMessage());
                    Logger.getLogger(BurpExtender.class.getName()).log(Level.SEVERE, null, ex);
                } catch (Exception ex) {
                    Logger.getLogger(BurpExtender.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
            // ログを出力したら消す
            this.proxyLogs.remove(messageReference);
        }
    }

    protected void historyLogAppend() {
        if (getCallbacks() != null) {
            IHttpRequestResponse[] messageInfo = getCallbacks().getProxyHistory();
            for (IHttpRequestResponse info : messageInfo) {
                this.writeToolMessage("proxy", false, info);
            }
        }
    }

    /**
     * tool ログの出力
     *
     * @param toolName ツール名
     * @param messageIsRequest リクエストかどうか
     * @param messageInfo メッセージ情報
     */
    protected synchronized void writeToolMessage(
            String toolName,
            boolean messageIsRequest,
            IHttpRequestResponse messageInfo) {
        String baselogfname = Config.getToolLogName(toolName);
        try {
            if (!messageIsRequest) {
                File fname = new File(this.getLogDir(), baselogfname);
                if (fname.length() > this.option.getLoggingProperty().getLogFileByteLimitSize()
                        && this.option.getLoggingProperty().getLogFileByteLimitSize() > 0) {
                    File renameFile = Util.rotateFile(this.getLogDir(), baselogfname);
                    fname.renameTo(renameFile);
                }
                boolean includeLog = true;
                if (this.option.getLoggingProperty().isExclude()) {
                    Pattern patternExclude = Pattern.compile(BurpWrap.parseFilterPattern(this.option.getLoggingProperty().getExcludeExtension()));
                    Matcher matchExclude = patternExclude.matcher(BurpWrap.getURL(messageInfo).getFile());
                    if (matchExclude.find()) {
                        includeLog = false;
                    }
                }
                if (includeLog) {
                    try (BufferedOutputStream fostm = new BufferedOutputStream(new FileOutputStream(fname, true))) {
                        fostm.write(Util.getRawByte("======================================================" + Util.NEW_LINE));
                        fostm.write(Util.getRawByte(getCurrentLogTimestamp() + " " + BurpWrap.getURLString(messageInfo.getHttpService()) + Util.NEW_LINE));
                        fostm.write(Util.getRawByte("======================================================" + Util.NEW_LINE));
                        if (messageInfo.getRequest() != null) {
                            fostm.write(messageInfo.getRequest());
                            fostm.write(Util.getRawByte(Util.NEW_LINE));
                        }
                        if (messageInfo.getResponse() != null) {
                            fostm.write(Util.getRawByte("======================================================" + Util.NEW_LINE));
                            fostm.write(messageInfo.getResponse());
                            fostm.write(Util.getRawByte(Util.NEW_LINE));
                        }
                        fostm.write(Util.getRawByte("======================================================" + Util.NEW_LINE));
                    }
                }
            }
        } catch (IOException ex) {
            Logger.getLogger(BurpExtender.class.getName()).log(Level.SEVERE, null, ex);
        } catch (Exception ex) {
            Logger.getLogger(BurpExtender.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    private final static Pattern REQUEST_URI = Pattern.compile("^(.*?\\s+)(.*?)(\\s+.*)");
    private final static Pattern HTTP_LINESEP = Pattern.compile("\\r\\n\\r\\n");

    private boolean autoresponderProxyMessage(
            IHttpService httpService, IHttpRequestResponse messageInfo) {

        boolean apply = false;
        try {
            IRequestInfo reqInfo = getHelpers().analyzeRequest(httpService, messageInfo.getRequest());
            String url = HttpUtil.normalizeURL(reqInfo.getUrl().toExternalForm());
            AutoResponderItem item = this.option.getAutoResponderProperty().findItem(url);
            if (item != null) {
                // FullパスをRequestヘッダに追加
                String request = Util.decodeMessage(messageInfo.getRequest());
                Matcher m = REQUEST_URI.matcher(request);
                StringBuffer sb = new StringBuffer();
                if (m.find()) {
                    m.appendReplacement(sb, m.group(0));
                    sb.append("\r\nX-AutoResponder: ").append(url);
                }
                m.appendTail(sb);
                request = sb.toString();
                messageInfo.setRequest(Util.encodeMessage(request));
                messageInfo.setHttpService(getHelpers().buildHttpService("127.0.0.1", option.getAutoResponderProperty().getRedirectPort(), "http"));
                apply = true;
            }

        } catch (Exception ex) {
            Logger.getLogger(BurpExtender.class.getName()).log(Level.SEVERE, null, ex);
        }
        return apply;
    }

    /**
     * メッセージの置換
     *
     * @param messageReference
     * @param messageIsRequest
     * @param message メッセージ
     * @return 変換後メッセージ
     */
    protected byte[] replaceProxyMessage(
            int messageReference,
            boolean messageIsRequest,
            byte[] message) {
        // headerとbodyに分割
        boolean edited = false;
        boolean updateLength = false;
        String decodeMessage = Util.decodeMessage(message);
        HttpMessage httpMsg = HttpMessage.parseHttpMessage(decodeMessage);
        List<MatchReplaceItem> matchReplaceList = this.option.getMatchReplaceProperty().getMatchReplaceList();
        for (int i = 0; i < matchReplaceList.size(); i++) {
            MatchReplaceItem bean = matchReplaceList.get(i);
            if (!bean.isSelected()) {
                continue;
            }
            if ((messageIsRequest == bean.isRequest()) || (!messageIsRequest == bean.isResponse())) {
                // body
                Pattern p = bean.getRegexPattern();
                if (bean.isBody() && httpMsg.isBody()) {
                    Matcher m = p.matcher(httpMsg.getBody());
                    if (m.find()) {
                        httpMsg.setBody(m.replaceAll(bean.getReplace(!bean.isRegexp(), bean.isMetaChar())));
                        edited = true;
                        updateLength = true;
                    }
                } else if (bean.isHeader()) {
                    // header
                    if ("".equals(bean.getMatch())) {
                        // 追加
                        StringBuilder builder = new StringBuilder(httpMsg.getHeader());
                        builder.append(HttpMessage.LINE_TERMINATE);
                        builder.append(bean.getReplace(!bean.isRegexp(), bean.isMetaChar()));
                        httpMsg.setHeader(builder.toString());
                        edited = true;
                    } else {
                        // 置換
                        Matcher m = p.matcher(httpMsg.getHeader());
                        if (m.find()) {
                            httpMsg.setHeader(m.replaceAll(bean.getReplace(!bean.isRegexp(), bean.isMetaChar())));
                            edited = true;
                        }
                    }
                    Matcher m = HTTP_LINESEP.matcher(httpMsg.getHeader());
                    httpMsg.setHeader(m.replaceAll(HttpMessage.LINE_TERMINATE));
                }
            }
        }
        if (edited) {
            // messageの再構築
            httpMsg.updateContentLength(updateLength);
            message = Util.encodeMessage(httpMsg.getMessage());
        }
        return message;
    }

    /**
     * MatchAlert
     *
     * @param toolName ツール名
     * @param messageIsRequest request の場合 true
     * @param messageInfo メッセージ情報
     */
    private void matchAlertMessage(String toolName, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        IRequestInfo reqInfo = getHelpers().analyzeRequest(messageInfo.getHttpService(), messageInfo.getRequest());
        List<MatchAlertItem> matchAlertItemList = option.getMatchAlertProperty().getMatchAlertItemList();
        for (int i = 0; i < matchAlertItemList.size(); i++) {
            MatchAlertItem bean = matchAlertItemList.get(i);
            if (!bean.isSelected()) {
                continue;
            }
            try {
                MatchItem.TargetTool tools = MatchItem.TargetTool.valueOf(toolName.toUpperCase());
                if (!bean.getTargetTools().contains(tools)) {
                    continue;
                }
                Pattern p = bean.getRegexPattern();
                String decodeMessage = "";
                if (bean.isRequest() && messageIsRequest) {
                    decodeMessage = Util.decodeMessage(messageInfo.getRequest());
                } else if (bean.isResponse() && !messageIsRequest) {
                    decodeMessage = Util.decodeMessage(messageInfo.getResponse());
                }
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
                    markList.add(issue);
                    count++;
                }
                if (count > 0) {
                    if (bean.getNotifyTypes().contains(MatchAlertItem.NotifyType.ALERTS_TAB)) {
                        issueAlert(toolName, String.format("[%s]: %d matches:%s url:%s", toolName, count, bean.getMatch(), reqInfo.getUrl().toString()), TrayIcon.MessageType.WARNING);
                    }
                    if (bean.getNotifyTypes().contains(MatchAlertItem.NotifyType.TRAY_MESSAGE)) {
//                        trayMenu.displayMessage(toolName, String.format("[%s]: %d matches:%s url:%s", toolName, count, bean.getMatch(), reqInfo.getUrl().toString()), TrayIcon.MessageType.WARNING);
                    }
                    if (bean.getNotifyTypes().contains(MatchAlertItem.NotifyType.ITEM_HIGHLIGHT)) {
                        BurpWrap.setHighlightColor(messageInfo, Util.toString(bean.getHighlightColor()));
                    }
                    if (bean.getNotifyTypes().contains(MatchAlertItem.NotifyType.COMMENT)) {
                        messageInfo.setComment(bean.getComment());
                    }
                    if (bean.getNotifyTypes().contains(MatchAlertItem.NotifyType.SCANNER_ISSUE)) {
                        MatchAlert alert = new MatchAlert(toolName, this.option.getMatchAlertProperty());
                        List<IScanIssue> issues = alert.makeIssueList(messageIsRequest, messageInfo, markList);
                        for (IScanIssue scanissue : issues) {
                            BurpExtender.getCallbacks().addScanIssue(scanissue);
                        }
                    }
                }
            } catch (Exception ex) {
                Logger.getLogger(BurpExtender.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    /**
     * 選択可能なエンコーディングリストの取得
     *
     * @return リスト
     */
    public List<String> getSelectEncodingList() {
        String defaultCharset = HttpUtil.normalizeCharset(Util.DEFAULT_ENCODING);
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

    public PropertyChangeListener newPropertyChangeListener() {
        return new PropertyChangeListener() {
            @Override
            public void propertyChange(PropertyChangeEvent evt) {
                if (TabbetOption.CJK_VIEW_PROPERTY.equals(evt.getPropertyName())) {
                    option.setEncodingProperty(tabbetOption.getEncodingProperty());
                    tabbetOption.setJTransCoderProperty(tabbetOption.getEncodingProperty());
                    applyOptionProperty();
                } else if (TabbetOption.MATCHREPLACE_PROPERTY.equals(evt.getPropertyName())) {
                    option.setMatchReplaceProperty(tabbetOption.getMatchReplaceProperty());
                    applyOptionProperty();
                } else if (TabbetOption.AUTO_RESPONDER_PROPERTY.equals(evt.getPropertyName())) {
                    option.setAutoResponderProperty(tabbetOption.getAutoResponderProperty());
                    applyOptionProperty();
                } else if (TabbetOption.SENDTO_PROPERTY.equals(evt.getPropertyName())) {
                    option.setSendToProperty(tabbetOption.getSendToProperty());
                    if (getCallbacks() != null) {
                        IBurpExtenderCallbacks cb = getCallbacks();
                        cb.removeContextMenuFactory(getSendToMenu());
                        setSendToMenu(new SendToMenu(cb, option.getSendToProperty()));
                        cb.registerContextMenuFactory(getSendToMenu());
                    }
                    applyOptionProperty();
                } else if (TabbetOption.LOGGING_PROPERTY.equals(evt.getPropertyName())) {
                    option.setLoggingProperty(tabbetOption.getLoggingProperty());
                    applyOptionProperty();
                } else if (TabbetOption.MATCHALERT_PROPERTY.equals(evt.getPropertyName())) {
                    option.setMatchAlertProperty(tabbetOption.getMatchAlertProperty());
                    applyOptionProperty();
                } else if (TabbetOption.JSEARCH_FILTER_PROPERTY.equals(evt.getPropertyName())) {
                    option.setJSearchProperty(tabbetOption.getJSearchProperty());
                    applyOptionProperty();
                } else if (TabbetOption.JTRANS_CODER_PROPERTY.equals(evt.getPropertyName())) {
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
                    this.historyLogAppend();
                }
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(null, ex.getMessage() , "YaguraExtender", JOptionPane.INFORMATION_MESSAGE);
                this.option.getLoggingProperty().setAutoLogging(false);
                this.tabbetOption.setLoggingProperty(this.option.getLoggingProperty());
            }
        }

        try {
            Config.saveToJson(CONFIG_FILE, this.option);
        } catch (IOException ex) {
            Logger.getLogger(BurpExtender.class.getName()).log(Level.SEVERE, null, ex);
        } catch (Exception ex) {
            Logger.getLogger(BurpExtender.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /**
     * Send to JTransCoder
     *
     * @param text
     */
    public void sendToJTransCoder(String text) {
        tabbetOption.sendToJTransCoder(text);
    }

    public byte[] receiveFromJTransCoder() {
        return this.tabbetOption.receiveFromJTransCoder();
    }

    public byte[] receiveFromClipbord(String encoding) {
        String clipbord = SwingUtil.systemClipboardPaste();
        return Util.encodeMessage(clipbord, encoding);
    }
    
    
    /**
     * Message Info Copy
     *
     * @param contextMenu
     * @param messageInfoList
     */
    public void sendToMessageInfoCopy(IContextMenuInvocation contextMenu, IHttpRequestResponse[] messageInfoList) {
        StringBuilder buff = new StringBuilder();
        try {
            buff.append("url\tquery\tmethod\tstatus\tlength\r\n");
            for (IHttpRequestResponse messageInfo : messageInfoList) {
                IRequestInfo reqInfo = BurpExtender.getHelpers().analyzeRequest(messageInfo);
                URL url = reqInfo.getUrl();
                buff.append(HttpUtil.toURL(url.getProtocol(), url.getHost(), url.getPort(), url.getPath()));
                buff.append("\t");
                buff.append(url.getQuery());
                buff.append("\t");
                buff.append(reqInfo.getMethod());
                if (messageInfo.getResponse() != null) {
                    HttpResponse httpResponse = HttpResponse.parseHttpResponse(messageInfo.getResponse());
                    buff.append("\t");
                    buff.append(httpResponse.getStatusCode());
                    buff.append("\t");
                    buff.append(messageInfo.getResponse().length);
                }
                buff.append("\r\n");
            }
        } catch (ParseException ex) {
            Logger.getLogger(BurpExtender.class.getName()).log(Level.SEVERE, null, ex);
        }
        SwingUtil.systemClipboardCopy(buff.toString());
    }

    public void sendToTableInfoCopy(IContextMenuInvocation contextMenu, IHttpRequestResponse[] messageInfoList) {
        StringBuilder buff = new StringBuilder();
        Component c = KeyboardFocusManager.getCurrentKeyboardFocusManager().getPermanentFocusOwner();
        if (c instanceof JTable) {
            JTable table = (JTable) c;
            buff.append(copyJTable(table));
        }
        SwingUtil.systemClipboardCopy(buff.toString());
    }

    public String copyJTable(JTable table) {
        StringBuilder export = new StringBuilder();
        TableModel model = table.getModel();
        int colcount = table.getColumnCount();
        boolean[] cols = new boolean[colcount];
        for (int i = 0; i < cols.length; i++) {
            cols[i] = false;
            try {
                table.getColumnClass(i).asSubclass(String.class);
                cols[i] = true;
            } catch (ClassCastException ex) {
                try {
                    table.getColumnClass(i).asSubclass(Integer.class);
                    cols[i] = true;
                } catch (ClassCastException ex2) {
                }
            }
            if (cols[i]) {
                export.append(table.getColumnName(i));
                export.append("\t");
            }
        }
        export.append("\r\n");
        int[] rows = table.getSelectedRows();
        for (int k = 0; k < rows.length; k++) {
            for (int i = 0; i < colcount; i++) {
                if (cols[i]) {
                    int rawRow = table.convertRowIndexToModel(rows[k]);
                    Object data = model.getValueAt(rawRow, i);
                    export.append(Util.toString(data));
                    export.append("\t");
                }
            }
            export.append("\r\n");
        }
        return export.toString();
    }

    /**
     * Add Host To Scope
     *
     * @param contextMenu
     * @param messageInfoList
     */
    public void sendToAddHostIncludeToScope(IContextMenuInvocation contextMenu, IHttpRequestResponse[] messageInfoList) {
        try {
            for (IHttpRequestResponse messageInfo : messageInfoList) {
                IRequestInfo reqInfo = BurpExtender.getHelpers().analyzeRequest(messageInfo);
                URL url = reqInfo.getUrl();
                BurpExtender.getCallbacks().includeInScope(new URL(HttpUtil.toURL(url.getProtocol(), url.getHost(), url.getPort())));
            }
        } catch (MalformedURLException ex) {
            Logger.getLogger(BurpExtender.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /**
     * Add Host To Exclude Scope
     *
     * @param contextMenu
     * @param messageInfoList
     */
    public void sendToAddHostToExcludeScope(IContextMenuInvocation contextMenu, IHttpRequestResponse[] messageInfoList) {
        try {
            for (IHttpRequestResponse messageInfo : messageInfoList) {
                IRequestInfo reqInfo = BurpExtender.getHelpers().analyzeRequest(messageInfo);
                URL url = reqInfo.getUrl();
                BurpExtender.getCallbacks().excludeFromScope(new URL(HttpUtil.toURL(url.getProtocol(), url.getHost(), url.getPort())));
            }
        } catch (MalformedURLException ex) {
            Logger.getLogger(BurpExtender.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    
    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
    }
    
    
}
