package passive.signature;

import burp.BurpExtension;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.core.Marker;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueDefinition;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import extension.helpers.HttpUtil;
import java.util.ArrayList;
import java.util.List;
import extension.burp.scanner.IssueItem;
import extension.burp.scanner.ScannerCheckAdapter;
import extension.burp.scanner.SignatureScanBase;
import yagura.model.MatchAlertProperty;

/**
 *
 * @author isayan
 */
public class MatchAlert extends SignatureScanBase<IssueItem> {

    private final String toolName;
    private final MatchAlertProperty option;

    public MatchAlert(final String toolName, final MatchAlertProperty option) {
        super("MatchAlert");
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
    public AuditIssue makeScanIssue(HttpRequestResponse messageInfo, List<IssueItem> issueItem) {

        return new AuditIssue() {

            public IssueItem getItem() {
                if (issueItem.isEmpty()) {
                    return null;
                } else {
                    return issueItem.get(0);
                }
            }

            private final String ISSUE_BACKGROUND = "\r\n<h4>Reference:</h4><p>MatchAlert for YaguraExtender</p>\r\n";

            @Override
            public String name() {
                return String.format("Match Alert(%s)", getItem().getType());
            }

            @Override
            public String detail() {
                StringBuilder buff = new StringBuilder();
                buff.append("<h4>Match:</h4>");
                buff.append(String.format("<p>toolName: %s</p>", HttpUtil.toHtmlEncode(toolName)));
                buff.append(String.format("<p>Scan Date: %s</p>", BurpExtension.getInstance().getCurrentLogTimestamp()));
                return buff.toString();
            }

            @Override
            public String remediation() {
                return null;
            }

            @Override
            public HttpService httpService() {
                return messageInfo.request().httpService();
            }

            @Override
            public String baseUrl() {
                return messageInfo.request().url();
            }

            @Override
            public AuditIssueSeverity severity() {
                return getItem().getServerity().toAuditIssueSeverity();
            }

            @Override
            public AuditIssueConfidence confidence() {
                return getItem().getConfidence().toAuditIssueConfidence();
            }

            @Override
            public List<HttpRequestResponse> requestResponses() {
                return List.of(messageInfo);
            }

            @Override
            public AuditIssueDefinition definition() {
                return AuditIssueDefinition.auditIssueDefinition(name(), ISSUE_BACKGROUND, remediation(), severity());
            }

            @Override
            public List<Interaction> collaboratorInteractions() {
                return new ArrayList<>();
            }

        };
    }

    @Override
    public ScanCheck passiveScanCheck() {
        return new ScannerCheckAdapter();
    }

    public List<AuditIssue> makeIssueList(boolean messageIsRequest, HttpRequestResponse baseRequestResponse, List<IssueItem> markIssueList) {
        List<Marker> requestResponseMarkers = new ArrayList<>();
        for (int i = 0; i < markIssueList.size(); i++) {
            IssueItem pos = markIssueList.get(i);
            requestResponseMarkers.add(Marker.marker(Range.range(pos.start(), pos.end())));
        }
        HttpRequestResponse messageInfoMark = null;
        if (messageIsRequest) {
            messageInfoMark = baseRequestResponse.withRequestMarkers(requestResponseMarkers);
        } else {
            messageInfoMark = baseRequestResponse.withResponseMarkers(requestResponseMarkers);
        }
        List<AuditIssue> issues = new ArrayList<>();
        issues.add(makeScanIssue(messageInfoMark, markIssueList));
        return issues;
    }

}
