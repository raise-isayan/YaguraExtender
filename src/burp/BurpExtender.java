package burp;

import yagura.Config;
import yagura.model.AutoResponderItem;
import yagura.model.EncodingProperty;
import extend.view.base.HttpMessage;
import yagura.model.LoggingProperty;
import yagura.model.MatchAlertItem;
import yagura.model.MatchAlertProperty;
import extend.view.base.MatchItem;
import yagura.model.MatchReplaceItem;
import yagura.model.MatchReplaceProperty;
import yagura.model.OptionProperty;
import yagura.model.SendToMenu;
import yagura.model.SendToProperty;
import extend.util.BurpWrap;
import extend.util.ConvertUtil;
import extend.util.HttpUtil;
import extend.util.SwingUtil;
import extend.util.Util;
import extend.view.base.HttpResponse;
import yagura.model.AutoResponderProperty;
import yagura.view.GeneratePoCTab;
import yagura.view.HtmlCommetViewTab;
import yagura.view.JSONViewTab;
import yagura.view.TabbetOption;
import java.awt.TrayIcon;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.JOptionPane;
import yagura.model.JSearchProperty;
import yagura.model.JTransCoderProperty;
import yagura.model.MatchReplaceGroup;
import yagura.signature.MarkIssue;
import yagura.signature.MatchAlert;
import yagura.signature.MatchAlertIssue;

/**
 * @author isayan
 */
public class BurpExtender extends BurpExtenderImpl
        implements IHttpListener, IProxyListener, OptionProperty {

    public BurpExtender() {
    }

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
    //  JOptionPane.showMessageDialog(null, "This starting method is not supported.", "Burp Extension", JOptionPane.INFORMATION_MESSAGE);
    //  burp.StartBurp.main(args);
    }

    /**
     * ログ設定プロパティファイルのファイル名
     */
    protected static final String LOGGING_PROPERTIES = "/yagura/resources/" + Config.getLoggingPropertyName();

    static {
        InputStream inStream = null;
        if (inStream == null) {
            inStream = BurpExtender.class.getResourceAsStream(LOGGING_PROPERTIES);
        }
        if (inStream != null) {
            try {
                LogManager.getLogManager().readConfiguration(inStream);
            } catch (IOException e) {
                Logger.getLogger(BurpExtender.class.getName()).log(Level.SEVERE, null, e);
            } finally {
                try {
                    inStream.close();
                } catch (IOException e) {
                    Logger.getLogger(BurpExtender.class.getName()).log(Level.SEVERE, null, e);
                }
            }
        }
    }
    
    public static BurpExtender getInstance() {
        return BurpExtenderImpl.<BurpExtender>getInstance();
    }

    private final TabbetOption tabbetOption = new TabbetOption();
    private final HtmlCommetViewTab commentViewTab = new HtmlCommetViewTab();
    private final GeneratePoCTab generatePoCTab = new GeneratePoCTab();

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks cb) {
        super.registerExtenderCallbacks(cb);
        if (this.getBurpVersion().isExtendSupport()) {
            // 設定ファイル読み込み
            try {
                String configXML = getCallbacks().loadExtensionSetting("configXML");
                if (configXML != null) {
                    Config.loadFromXml(ConvertUtil.decompressZlibBase64(configXML), this.getProperty());                
                }
            } catch (IOException ex) {
                Logger.getLogger(BurpExtender.class.getName()).log(Level.SEVERE, null, ex);
            }

            try {
                // 自動ログ作成時のみディレクトリ作成
                if (this.getLoggingProperty().isAutoLogging()) {
                    this.setLogDir(mkLogDir(this.getLoggingProperty().getBaseDir(), this.getLoggingProperty().getLogDirFormat()));
                }
            } catch (IOException ex) {
                Logger.getLogger(BurpExtender.class.getName()).log(Level.SEVERE, null, ex);
            }
            
            setSendToMenu(new SendToMenu(cb, this.getSendToProperty()));
            cb.registerHttpListener(this);
            cb.registerProxyListener(this);
            cb.addSuiteTab(this.tabbetOption);
//            cb.registerIntruderPayloadGeneratorFactory(factory);
            cb.registerExtensionStateListener(this.tabbetOption);
            cb.registerContextMenuFactory(this.getSendToMenu());
            this.tabbetOption.setProperty(this);
            this.tabbetOption.addPropertyChangeListener(newPropertyChangeListener());
           
            cb.registerMessageEditorTabFactory(this.commentViewTab);
            cb.registerMessageEditorTabFactory(new IMessageEditorTabFactory() {
                @Override
                public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
                   return new JSONViewTab(controller, editable, true);
                }
            });
            cb.registerMessageEditorTabFactory(new IMessageEditorTabFactory() {
                @Override
                public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
                    return new JSONViewTab(controller, editable, false);
                }
            });
            cb.registerMessageEditorTabFactory(this.generatePoCTab);
            
        } else {
            JOptionPane.showMessageDialog(null, "This burp version is not supported.\r\nversion 1.7 required", "Burp Extension", JOptionPane.INFORMATION_MESSAGE);
        }
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
        if (messageIsRequest &&  this.getAutoResponderProperty().getAutoResponderEnable()) {            
           boolean apply = this.autoresponderProxyMessage(msgInfo.getHttpService(), msgInfo);                
            if (apply) {
                return ;
            }
        } 
                        
        // Match and Replace
        if (this.getMatchReplaceProperty().isSelectedMatchReplace()) {
            MatchReplaceGroup group = this.getMatchReplaceProperty().getMatchReplaceGroup();
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
        if (this.getLoggingProperty().isAutoLogging() && this.getLoggingProperty().isProxyLog()) {
            this.writeProxyMessage(message.getMessageReference(), messageIsRequest, msgInfo.getHttpService(), resultBytes);
        }
                
    }

    public synchronized String getCurrentLogTimestamp() {
        SimpleDateFormat format = this.logProperty.getLogTimestampDateFormat();
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
        if (this.getMatchAlertProperty().isMatchAlertEnable() && this.getMatchAlertProperty().isSelectedMatchAlert()) {
            this.matchAlertMessage(toolName, messageIsRequest, messageInfo);
        }
        if (this.getLoggingProperty().isAutoLogging() && this.getLoggingProperty().isToolLog()) {
            this.writeToolMessage(toolName, messageIsRequest, messageInfo);
        }
    }
    
    private final Map<Integer, byte[]> proxyLogs = new HashMap<Integer, byte[]>();

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
                    if (fname.length() > this.getLoggingProperty().getLogFileByteLimitSize()
                            && this.getLoggingProperty().getLogFileByteLimitSize() > 0) {
                        File renameFile = Util.rotateFile(this.getLogDir(), Config.getProxyLogMessageName());
                        fname.renameTo(renameFile);
                    }
                    boolean includeLog = true;
                    if (this.getProperty().getLoggingProperty().isExludeFilter()) {
                        Pattern patternExlude = Pattern.compile(BurpWrap.parseFilterPattern(this.getProperty().getLoggingProperty().getExludeFilterExtension()));
                        Matcher matchExlude = patternExlude.matcher(BurpWrap.getURL(request).getFile());
                        if (matchExlude.find()) {
                            includeLog = false;
                        }
                    }
                    if (includeLog) {
                        try (FileOutputStream fostm = new FileOutputStream(fname, true)) {
                            fostm.write(Util.getRawByte(Util.NEW_LINE));
                            fostm.write(Util.getRawByte("======================================================"+ Util.NEW_LINE));
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
                if (fname.length() > this.getLoggingProperty().getLogFileByteLimitSize()
                        && this.getLoggingProperty().getLogFileByteLimitSize() > 0) {
                    File renameFile = Util.rotateFile(this.getLogDir(), baselogfname);
                    fname.renameTo(renameFile);
                }
                boolean includeLog = true;
                if (this.getProperty().getLoggingProperty().isExludeFilter()) {
                    Pattern patternExlude = Pattern.compile(BurpWrap.parseFilterPattern(this.getProperty().getLoggingProperty().getExludeFilterExtension()));
                    Matcher matchExlude = patternExlude.matcher(BurpWrap.getURL(messageInfo).getFile());
                    if (matchExlude.find()) {
                        includeLog = false;
                    }
                }
                if (includeLog) {
                    try(FileOutputStream fostm = new FileOutputStream(fname, true)) {
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
            AutoResponderItem item = this.autoResponderProperty.findItem(url);
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
                messageInfo.setHttpService(getHelpers().buildHttpService("127.0.0.1", autoResponderProperty.getRedirectPort(), "http"));
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
        List<MatchReplaceItem> matchReplaceList = this.getMatchReplaceProperty().getMatchReplaceList();
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
        List<MatchAlertItem> matchAlertItemList = getMatchAlertProperty().getMatchAlertItemList();
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
                List<MarkIssue> markList = new ArrayList<>();
                Matcher m = p.matcher(decodeMessage);
                int count = 0;
                while (m.find()) {
                    markList.add(new MarkIssue(messageIsRequest, m.start(), m.end()));
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
                        BurpWrap.setHighlightColor(messageInfo, String.valueOf(bean.getHighlightColor()));
                    }
                    if (bean.getNotifyTypes().contains(MatchAlertItem.NotifyType.COMMENT)) {
                        messageInfo.setComment(bean.getComment());
                    }
                    if (bean.getNotifyTypes().contains(MatchAlertItem.NotifyType.SCANNER_ISSUE)) {
                        MatchAlert alert = new MatchAlert(toolName, this.getMatchAlertProperty());
                        MatchAlertIssue issue = new MatchAlertIssue(bean, markList);
                        List<IScanIssue> issues = alert.makeIssueList(messageIsRequest, messageInfo, issue, markList);
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
     * debugModeの取得
     */
    private boolean debugMode = false;

    @Override
    public boolean getDebugMode() {
        return this.debugMode;
    }

    @Override
    public void setDebugMode(boolean debugMode) {
        this.debugMode = debugMode;
    }

    /**
     * CharsetModeの取得
     *
     * @return CharSetMode
     */
    public String getCharsetMode() {
        String charSetMode = Util.DEFAULT_ENCODING;
//        if (getCallbacks() != null) {
//            BurpPreferences pref = new BurpPreferences(getCallbacks().saveConfig());
//            pref.dump();
//            String json = getCallbacks().saveConfigAsJson("");
//            Logger.getLogger(BurpExtender.class.getName()).log(Level.SEVERE, json);
//            charSetMode = pref.getCharsetMode();
//            outPrintln("charsetMode:" + charSetMode);
//        }
        return charSetMode;
    }
    
    /**
     * 選択可能なエンコーディングリストの取得
     *
     * @return リスト
     */
    public List<String> getSelectEncodingList() {
        String charsetMode = this.getCharsetMode();
        List<String> list = new ArrayList<String>();
        list.addAll(this.getEncodingProperty().getEncodingList());
        // リストにない場合追加
        if (!this.getEncodingProperty().getEncodingList().contains(charsetMode) && Config.isEncodingName(charsetMode)) {
            list.add(charsetMode);
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
      
    /**
     * ***********************************************************************
     * OptionProperty
     * ***********************************************************************
     */

    /**
     * @param property
     */
    public void setProperty(OptionProperty property) {
        this.setEncodingProperty(property.getEncodingProperty());
        this.setMatchReplaceProperty(property.getMatchReplaceProperty());
        this.setAutoResponderProperty(property.getAutoResponderProperty());
        this.setSendToProperty(property.getSendToProperty());
        this.setLoggingProperty(property.getLoggingProperty());
        this.setMatchAlertProperty(property.getMatchAlertProperty());        
        this.setJSearchProperty(property.getJSearchProperty());
        this.setDebugMode(property.getDebugMode());
    }

    public OptionProperty getProperty() {
        return this;
    }

    /**
     * ***********************************************************************
     * Encoding
     * ***********************************************************************
     */
    private EncodingProperty encodingProperty = new EncodingProperty();

    /**
     * @return the encodingProperty
     */
    @Override
    public EncodingProperty getEncodingProperty() {
        return this.encodingProperty;
    }

    /**
     * @param encodingProperty the encodingProperty to set
     */
    @Override
    public void setEncodingProperty(EncodingProperty encodingProperty) {
        this.encodingProperty = encodingProperty;
    }

    /**
     * ***********************************************************************
     * MatchReplace
     * ***********************************************************************
     */
    private MatchReplaceProperty matchReplaceProperty = new MatchReplaceProperty();

    /**
     * @return the matchReplaceProperty
     */
    @Override
    public MatchReplaceProperty getMatchReplaceProperty() {
        return this.matchReplaceProperty;
    }

    /**
     * @param matchReplaceProperty the matchReplaceProperty to set
     */
    @Override
    public void setMatchReplaceProperty(MatchReplaceProperty matchReplaceProperty) {
        this.matchReplaceProperty = matchReplaceProperty;
    }

    /**
     * ***********************************************************************
     * MatchAlert
     * ***********************************************************************
     */
    private MatchAlertProperty matchAlertProperty = new MatchAlertProperty();

    /**
     * @return the matchAlertProperty
     */
    @Override
    public MatchAlertProperty getMatchAlertProperty() {
        return this.matchAlertProperty;
    }

    /**
     * @param matchAlertProperty the matchAlertProperty to set
     */
    @Override
    public void setMatchAlertProperty(MatchAlertProperty matchAlertProperty) {
        this.matchAlertProperty = matchAlertProperty;
    }

    /**
     * ***********************************************************************
     * AutoResponder
     * ***********************************************************************
     */

    private AutoResponderProperty autoResponderProperty = new AutoResponderProperty();
    
    /**
     * @return the autoResponderProperty
     */
    @Override
    public AutoResponderProperty getAutoResponderProperty() {
        return this.autoResponderProperty;
    }

    /**
     * 
     * @param autoResponderProperty 
     */
    @Override
    public void setAutoResponderProperty(AutoResponderProperty autoResponderProperty) {
        this.autoResponderProperty = autoResponderProperty;
    }
    
    /**
     * ***********************************************************************
     * SendTo
     * ***********************************************************************
     */
    private SendToProperty sendtoProperty = new SendToProperty();

    /**
     * @return the sendtoProperty
     */
    @Override
    public SendToProperty getSendToProperty() {
        return this.sendtoProperty;
    }

    /**
     * @param sendtoProperty the sendtoProperty to set
     */
    @Override
    public void setSendToProperty(SendToProperty sendtoProperty) {
        this.sendtoProperty = sendtoProperty;
    }

    public PropertyChangeListener newPropertyChangeListener() {
        return new PropertyChangeListener() {
            @Override
            public void propertyChange(PropertyChangeEvent evt) {
                String charsetMode = getCharsetMode();
                if (TabbetOption.ENCODING_PROPERTY.equals(evt.getPropertyName())) {
                    setEncodingProperty(tabbetOption.getEncodingProperty());
                    tabbetOption.setJTransCoderProperty(tabbetOption.getEncodingProperty());
                    applyOptionProperty();
                } else if (TabbetOption.MATCHREPLACE_PROPERTY.equals(evt.getPropertyName())) {
                    setMatchReplaceProperty(tabbetOption.getMatchReplaceProperty());
                    applyOptionProperty();
                } else if (TabbetOption.AUTO_RESPONDER_PROPERTY.equals(evt.getPropertyName())) {
                    setAutoResponderProperty(tabbetOption.getAutoResponderProperty());
                    applyOptionProperty();
                } else if (TabbetOption.SENDTO_PROPERTY.equals(evt.getPropertyName())) {
                    setSendToProperty(tabbetOption.getSendToProperty());
                    if (getCallbacks() != null) {
                        IBurpExtenderCallbacks cb = getCallbacks();
                        cb.removeContextMenuFactory(getSendToMenu());
                        setSendToMenu(new SendToMenu(cb, getSendToProperty()));
                        cb.registerContextMenuFactory(getSendToMenu());                                                
                    }                    
                    applyOptionProperty();                
                } else if (TabbetOption.LOGGING_PROPERTY.equals(evt.getPropertyName())) {
                    setLoggingProperty(tabbetOption.getLoggingProperty());
                    applyOptionProperty();                
                } else if (TabbetOption.MATCHALERT_PROPERTY.equals(evt.getPropertyName())) {
                    setMatchAlertProperty(tabbetOption.getMatchAlertProperty());
                    applyOptionProperty();                
                } else if (TabbetOption.JSEARCH_FILTER_PROPERTY.equals(evt.getPropertyName())) {
                    setJSearchProperty(tabbetOption.getJSearchProperty());
                    applyOptionProperty();                
                } else if (TabbetOption.JTRANS_CODER_PROPERTY.equals(evt.getPropertyName())) {
                    setJTransCoderProperty(tabbetOption.getJTransCoderProperty());
                    applyOptionProperty();                
                } else if (TabbetOption.VERSION_PROPERTY.equals(evt.getPropertyName())) {
                    setDebugMode(tabbetOption.getDebugMode());        
                    applyOptionProperty();
                } else if (TabbetOption.LOAD_CONFIG_PROPERTY.equals(evt.getPropertyName())) {
                    tabbetOption.setProperty(getProperty());
                    applyOptionProperty();
                }
            }
        };
    }

    protected void applyOptionProperty() {
        if (this.tabbetOption.isLogDirChanged()) {
            try {
                this.setLogDir(mkLogDir(this.getLoggingProperty().getBaseDir(), this.getLoggingProperty().getLogDirFormat()));
                if (this.tabbetOption.isHistoryLogInclude()) {
                    this.historyLogAppend();
                }
            } catch (IOException ex) {
                Logger.getLogger(BurpExtender.class.getName()).log(Level.SEVERE, null, ex);
            }
        }

        try {
            String configXML = Config.saveToXML(this.getProperty());
            getCallbacks().saveExtensionSetting("configXML", ConvertUtil.compressZlibBase64(configXML));

        } catch (IOException ex) {
            Logger.getLogger(BurpExtender.class.getName()).log(Level.SEVERE, null, ex);
        } catch (Exception ex) {
            Logger.getLogger(BurpExtender.class.getName()).log(Level.SEVERE, null, ex);
        }        
    }

    /**
     * ***********************************************************************
     * Logging
     * ***********************************************************************
     */
    private LoggingProperty logProperty = new LoggingProperty();

    /**
     * @return the logProperty
     */
    @Override
    public LoggingProperty getLoggingProperty() {
        return this.logProperty;
    }
    
    /**
     * @param logProperty the logProperty to set
     */
    @Override
    public void setLoggingProperty(LoggingProperty logProperty) {
        this.logProperty = logProperty;
    }

    /**
     * ***********************************************************************
     * JSearch
     * ***********************************************************************
     */
    private JSearchProperty searchProperty = new JSearchProperty();

    @Override
    public JSearchProperty getJSearchProperty() {
        return this.searchProperty;
    }

    @Override
    public void setJSearchProperty(JSearchProperty searchProperty) {
        this.searchProperty = searchProperty;
    }


    /**
     * ***********************************************************************
     * JTransCoder
     * ***********************************************************************
     */
    private JTransCoderProperty transcoderProperty = new JTransCoderProperty();

    
    @Override
    public JTransCoderProperty getJTransCoderProperty() {
        return this.transcoderProperty;
    }

    @Override
    public void setJTransCoderProperty(JTransCoderProperty transcoder) {
        this.transcoderProperty = transcoder;
    }

    
    /**
     * ***********************************************************************
     * Send to JTransCoder
     * ***********************************************************************
     */
    public void sendToJTransCoder(String text) {
        this.tabbetOption.sendToJTransCoder(text);
    }

    public byte [] receiveFromJTransCoder() {
        return this.tabbetOption.receiveFromJTransCoder();
    }

    /**
     * ***********************************************************************
     * Message Info Copy
     * ***********************************************************************
     */

    public void sendToMessageInfoCopy(IContextMenuInvocation contextMenu, IHttpRequestResponse[] messageInfoList) {
        StringBuilder buff = new StringBuilder();
        try {
            buff.append("url\tquery\tmethod\tstatus\tlength\r\n");
            for (IHttpRequestResponse messageInfo : messageInfoList) {    
                IRequestInfo reqInfo = BurpExtender.getHelpers().analyzeRequest(messageInfo);
                URL url = reqInfo.getUrl();
                buff.append(HttpUtil.toURL(url.getProtocol(), url.getHost(), url.getPort(), url.getPath()).toString());
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

    /**
     * ***********************************************************************
     * Add Host To Scope
     * ***********************************************************************
     */

    public void sendToAddHostToScope(IContextMenuInvocation contextMenu, IHttpRequestResponse[] messageInfoList) {
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

    
}
