package extension.burp;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import java.util.List;

/**
 *
 * @author raise.isayan
 */
public class ScannerCheckAdapter implements ScanCheck {

    @Override
    public List<AuditIssue> activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint) {
        return null;
    }

    @Override
    public List<AuditIssue> passiveAudit(HttpRequestResponse baseRequestResponse) {
        return null;
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue newIssue, AuditIssue existingIssue) {
        if (existingIssue.name().equals(newIssue.name())) {
            // 同一とみなせる場合は報告をスキップ
            return ConsolidationAction.KEEP_EXISTING;
        }
        return ConsolidationAction.KEEP_BOTH;
    }

    public static List<AuditIssue> getAuditIssue(List<AuditIssue> issues) {
        return issues.isEmpty() ? null : issues;
    }

}
