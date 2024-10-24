package yagura.handler;

import burp.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.ToolSource;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpHandler;
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
import extension.burp.NotifyType;
import extension.burp.ProtocolType;
import extension.burp.TargetTool;
import extension.burp.scanner.IssueItem;
import extension.helpers.HttpMessage;
import extension.helpers.HttpMessageWapper;
import extension.helpers.HttpRequestWapper;
import extension.helpers.HttpResponseWapper;
import extension.helpers.StringUtil;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import passive.signature.MatchAlert;
import yagura.model.Logging;
import yagura.model.MatchAlertItem;
import yagura.model.MatchReplaceGroup;
import yagura.model.MatchReplaceItem;

/**
 *
 * @author isayan
 */
public class ProxyHander implements HttpHandler, ProxyRequestHandler, ProxyResponseHandler {

    private final static Logger logger = Logger.getLogger(ProxyHander.class.getName());

    private final MontoyaApi api;
    private final BurpExtension extenderImpl;
    private final Logging logging;

    public ProxyHander(MontoyaApi api) {
        this.api = api;
        this.extenderImpl = BurpExtension.getInstance();
        this.logging = extenderImpl.getLogging();
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
        if (extenderImpl.getProperty().getLoggingProperty().isAutoLogging() && extenderImpl.getProperty().getLoggingProperty().isToolLog()) {
            logging.writeToolMessage(toolSource.toolType(), false, messageInfo);
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
        if (extenderImpl.getProperty().getMatchAlertProperty().isMatchAlertEnable()) {
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
        if (extenderImpl.getProperty().getLoggingProperty().isAutoLogging() && extenderImpl.getProperty().getLoggingProperty().isProxyLog()) {
            logging.writeProxyMessage(interceptedResponse.messageId(), interceptedResponse.initiatingRequest().httpService(), interceptedResponse.initiatingRequest(), interceptedResponse);
        }
        return ProxyResponseToBeSentAction.continueWith(interceptedResponse, interceptedResponse.annotations());
    }

    public void historyLogAppend() {
        if (this.api != null) {
            List<ProxyHttpRequestResponse> messageInfo = this.api.proxy().history();
            for (ProxyHttpRequestResponse info : messageInfo) {
                logging.writeToolMessage(ToolType.PROXY, false, HttpRequestResponse.httpRequestResponse(info.finalRequest(), info.originalResponse(), info.annotations()));
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
        HttpRequest httpRequest = interceptedHttpRequest;
        // Match and Replace
        if (extenderImpl.getProperty().getMatchReplaceProperty().isSelectedMatchReplace()) {
            MatchReplaceGroup group = extenderImpl.getProperty().getMatchReplaceProperty().getReplaceSelectedGroup(extenderImpl.getProperty().getMatchReplaceProperty().getSelectedName());
            if (group != null && group.isInScopeOnly()) {
                if (extenderImpl.helpers().isInScope(interceptedHttpRequest.url())) {
                    httpRequest = this.replaceProxyMessage(interceptedHttpRequest);
                }
            } else {
                httpRequest = this.replaceProxyMessage(interceptedHttpRequest);
            }
        }
        return ProxyRequestReceivedAction.continueWith(httpRequest, annotations);
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
        HttpResponse httpResponse = interceptedHttpResponse;
        // Match and Replace
        if (extenderImpl.getProperty().getMatchReplaceProperty().isSelectedMatchReplace()) {
            MatchReplaceGroup group = extenderImpl.getProperty().getMatchReplaceProperty().getReplaceSelectedGroup(extenderImpl.getProperty().getMatchReplaceProperty().getSelectedName());
            if (group != null && group.isInScopeOnly()) {
                if (extenderImpl.helpers().isInScope(httpRequest.url())) {
                    httpResponse = this.replaceProxyMessage(httpResponse);
                }
            } else {
                httpResponse = this.replaceProxyMessage(httpResponse);
            }
        }
        return ProxyResponseReceivedAction.continueWith(httpResponse, annotations);
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
        List<MatchAlertItem> matchAlertItemList = extenderImpl.getProperty().getMatchAlertProperty().getMatchAlertItemList();
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
                        replacemeComment = p.matcher(group).replaceFirst(bean.getNotes());
                    }
                    markList.add(issue);
                    count++;
                }
                if (count > 0) {
                    if (bean.getNotifyTypes().contains(NotifyType.ALERTS_TAB)) {
                        extenderImpl.helpers().issueAlert(toolType.name(), String.format("[%s]: %d matches:%s url:%s", toolType.name(), count, bean.getMatch(), httpRequestResponse.request().url()), extension.burp.MessageType.INFO);
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
                            annotations.setNotes(bean.getNotes());
                        }
                    }
                    if (bean.getNotifyTypes().contains(NotifyType.SCANNER_ISSUE)) {
                        MatchAlert alert = new MatchAlert(toolType.name(), extenderImpl.getProperty().getMatchAlertProperty());
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
     *
     * @param httpRequest
     * @return
     */
    private HttpRequest replaceProxyMessage(HttpRequest httpRequest) {
        ByteArray message = httpRequest.toByteArray();
        HttpMessage updateMessage = replaceProxyMessage(true, HttpMessage.httpMessage(StringUtil.getStringRaw(message.getBytes())));
        if (updateMessage.isModifiedBody()) {
            HttpRequestWapper wrapRequest = new HttpRequestWapper(HttpRequest.httpRequest(httpRequest.httpService(), updateMessage.getMessage()));
            return wrapRequest.withAjustContentLength();
        } else if (updateMessage.isModifiedHeader()) {
            HttpRequestWapper wrapRequest = new HttpRequestWapper(HttpRequest.httpRequest(httpRequest.httpService(), updateMessage.getMessage()));
            return wrapRequest;
        } else {
            HttpRequestWapper wrapRequest = new HttpRequestWapper(HttpRequest.httpRequest(httpRequest.httpService(), message));
            return wrapRequest;
        }
    }

    /**
     *
     * @param httpResponse
     * @return
     */
    private HttpResponse replaceProxyMessage(HttpResponse httpResponse) {
        ByteArray message = httpResponse.toByteArray();
        HttpMessage updateMessage = replaceProxyMessage(false, HttpMessage.httpMessage(StringUtil.getStringRaw(message.getBytes())));
        if (updateMessage.isModifiedBody() || updateMessage.isModifiedHeader()) {
            HttpResponseWapper wrapResponse = new HttpResponseWapper(HttpResponse.httpResponse(updateMessage.getMessage()));
            return wrapResponse;
        } else {
            HttpResponseWapper wrapResponse = new HttpResponseWapper(HttpResponse.httpResponse(message));
            return wrapResponse;
        }
    }

    private HttpMessage replaceProxyMessage(
            boolean messageIsRequest,
            HttpMessage message) {

        // headerとbodyに分割
        boolean edited = false;
        String header = message.getHeader();
        String body = message.getBody();

        List<MatchReplaceItem> matchReplaceList = extenderImpl.getProperty().getMatchReplaceProperty().getMatchReplaceList(ProtocolType.HTTP);
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
                }
            }
        }
        if (edited) {
            message.setHeader(header);
            message.setBody(body);
        }
        return message;
    }

}
