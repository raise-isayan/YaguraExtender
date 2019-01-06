package yagura.signature;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IHttpRequestResponseWithMarkers;
import burp.IHttpService;
import burp.IRequestInfo;
import burp.IScanIssue;
import burp.IScannerCheck;
import burp.IScannerInsertionPoint;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import yagura.external.TransUtil;
import yagura.model.MatchAlertItem;
import yagura.model.MatchAlertProperty;

/**
 *
 * @author isayan
 */
public class MatchAlert implements Signature<MatchAlertIssue> {

    private final String toolName;
    private final MatchAlertProperty option;
    
    public MatchAlert(final String toolName, final MatchAlertProperty option) {
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
    public IScanIssue makeScanIssue(final IHttpRequestResponse messageInfo, final MatchAlertIssue issue) {
        MatchAlertItem item = issue.getMatchAlertItem();                
        
        return new IScanIssue() {
            @Override
            public URL getUrl() {
                IRequestInfo reqInfo = BurpExtender.getHelpers().analyzeRequest(messageInfo.getHttpService(), messageInfo.getRequest());
                return reqInfo.getUrl();
            }

            @Override
            public String getIssueName() {
                return String.format("Match Alert(%s)", item.getIssueName());
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
                return item.getSeverity().toString();
            }

            @Override
            public String getConfidence() {
                return item.getConfidence().toString();
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
                buff.append("<h4>Datail:</h4>");
                buff.append(String.format("<p>toolName: %s</p>", TransUtil.toHtmlEncode(toolName)));
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
        return new IScannerCheck() {
            @Override
            public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
                return null;
            }

            @Override
            public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
                return null;
            }

            @Override
            public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
                if (existingIssue.getIssueName().equals(newIssue.getIssueName())) {
                    // 同一とみなせる場合は報告をスキップ                    
                    return -1;
                }
                return 0;
            }
            
        };
    }

    public List<IScanIssue> makeIssueList(boolean messageIsRequest, IHttpRequestResponse baseRequestResponse, MatchAlertIssue issue, List<MarkIssue> markIssueList) {
        List<int[]> requestResponseMarkers = new ArrayList<>();
        for (int i = 0; i < markIssueList.size(); i++) {
            MarkIssue pos = markIssueList.get(i);
            requestResponseMarkers.add(new int[]{pos.getStartPos(), pos.getEndPos()});
        }
        IHttpRequestResponseWithMarkers messageInfoMark = null;
        if (messageIsRequest) {
            messageInfoMark = BurpExtender.getCallbacks().applyMarkers(baseRequestResponse, requestResponseMarkers, null);
        } else {
            messageInfoMark = BurpExtender.getCallbacks().applyMarkers(baseRequestResponse, null, requestResponseMarkers);
        }
        
        List<IScanIssue> issues = new ArrayList<>();
        issues.add(makeScanIssue(messageInfoMark, issue));
        return issues;
    }

    
}
