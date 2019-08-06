package passive.signature;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IHttpRequestResponseWithMarkers;
import burp.IHttpService;
import burp.IRequestInfo;
import burp.IScanIssue;
import burp.IScannerCheck;
import extend.util.HttpUtil;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import extend.view.base.MatchItem;
import passive.IssueItem;
import passive.PassiveCheckAdapter;
import passive.SignatureItem;
import yagura.model.MatchAlertProperty;

/**
 *
 * @author isayan
 */
public class MatchAlert extends SignatureItem<IssueItem> {

    private final String toolName;
    private final MatchAlertProperty option;

    public MatchAlert(final String toolName, final MatchAlertProperty option) {
        super("MatchAlert", MatchItem.Severity.HIGH);
        this.toolName = toolName;
        this.option = option;
    }

    /**
     * @return the toolName
     */
    public String getToolName() {
        return toolName;
    }

    @Override
    public IScanIssue makeScanIssue(IHttpRequestResponse messageInfo, List<IssueItem> issueItem) {

        return new IScanIssue() {

            public IssueItem getItem() {
                if (issueItem.size() > 0) {
                    return issueItem.get(0);
                } else {
                    return null;
                }
            }

            @Override
            public URL getUrl() {
                IRequestInfo reqInfo = BurpExtender.getHelpers().analyzeRequest(messageInfo.getHttpService(), messageInfo.getRequest());
                return reqInfo.getUrl();
            }

            @Override
            public String getIssueName() {
                return String.format("Match Alert(%s)", getItem().getType());
            }

            @Override
            public int getIssueType() {
                /**
                 * https://portswigger.net/knowledgebase/issues/ Extension
                 * generated issue
                 */
                return 0x08000000;
            }

            @Override
            public String getSeverity() {
                return getItem().getServerity().toString();
            }

            @Override
            public String getConfidence() {
                return getItem().getConfidence().toString();
            }

            @Override
            public String getIssueBackground() {
                final String ISSUE_BACKGROUND = "\r\n"
                        + "<h4>Reference:</h4>"
                        + "<p>MatchAlert for YaguraExtender</p>";
                return ISSUE_BACKGROUND;
            }

            @Override
            public String getRemediationBackground() {
                return null;
            }

            @Override
            public String getIssueDetail() {
                StringBuilder buff = new StringBuilder();
                buff.append("<h4>Match:</h4>");
                buff.append(String.format("<p>toolName: %s</p>", HttpUtil.toHtmlEncode(toolName)));
                buff.append(String.format("<p>Scan Date: %s</p>", BurpExtender.getInstance().getCurrentLogTimestamp()));
                return buff.toString();
            }

            @Override
            public String getRemediationDetail() {
                return null;
            }

            @Override
            public IHttpRequestResponse[] getHttpMessages() {
                return new IHttpRequestResponse[]{messageInfo};
            }

            @Override
            public IHttpService getHttpService() {
                return messageInfo.getHttpService();
            }
        };
    }

    @Override
    public IScannerCheck passiveScanCheck() {
        return new PassiveCheckAdapter();
    }

    public List<IScanIssue> makeIssueList(boolean messageIsRequest, IHttpRequestResponse baseRequestResponse, List<IssueItem> markIssueList) {
        List<int[]> requestResponseMarkers = new ArrayList<>();
        for (int i = 0; i < markIssueList.size(); i++) {
            IssueItem pos = markIssueList.get(i);
            requestResponseMarkers.add(new int[]{pos.start(), pos.end()});
        }
        IHttpRequestResponseWithMarkers messageInfoMark = null;
        if (messageIsRequest) {
            messageInfoMark = BurpExtender.getCallbacks().applyMarkers(baseRequestResponse, requestResponseMarkers, null);
        } else {
            messageInfoMark = BurpExtender.getCallbacks().applyMarkers(baseRequestResponse, null, requestResponseMarkers);
        }

        List<IScanIssue> issues = new ArrayList<>();
        issues.add(makeScanIssue(messageInfoMark, markIssueList));
        return issues;
    }
}
