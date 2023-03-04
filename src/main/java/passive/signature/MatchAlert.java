package passive.signature;

import burp.BurpExtension;
import burp.api.montoya.core.Marker;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueDefinition;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import extension.burp.ScannerCheckAdapter;
import extension.burp.Severity;
import extension.helpers.HttpUtil;
import java.util.ArrayList;
import java.util.List;
import passive.IssueItem;
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
        super("MatchAlert", Severity.HIGH);
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
                return AuditIssueSeverity.FALSE_POSITIVE;
            }

            @Override
            public AuditIssueConfidence confidence() {
                return AuditIssueConfidence.CERTAIN;
            }

            @Override
            public List<HttpRequestResponse> requestResponses() {
                return List.of(messageInfo);
            }

            @Override
            public AuditIssueDefinition definition() {
                return new AuditIssueDefinition() {
                    @Override
                    public String name() {
                        return String.format("Match Alert(%s)", getItem().getType());
                    }

                    @Override
                    public String background() {
                        final String ISSUE_BACKGROUND = "\r\n"
                                + "<h4>Reference:</h4>"
                                + "<p>MatchAlert for YaguraExtender</p>";
                        return ISSUE_BACKGROUND;
                    }

                    @Override
                    public String remediation() {
                        return null;
                    }

                    @Override
                    public AuditIssueSeverity typicalSeverity() {
                        return AuditIssueSeverity.FALSE_POSITIVE;
                    }

                    /**
                     * https://portswigger.net/knowledgebase/issues/ Extension
                     * generated issue
                     */
                    @Override
                    public int typeIndex() {
                        return 0x08000000;
                    }

                };
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
