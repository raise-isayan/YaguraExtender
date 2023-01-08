package extension.burp;

import extension.helpers.StringUtil;
import java.util.EnumMap;
import java.util.EnumSet;

/**
 *
 * @author isayan
 */
public enum Confidence {
    CERTAIN, FIRM, TENTATIVE;

    private final static EnumMap<Confidence, burp.api.montoya.scanner.audit.issues.AuditIssueConfidence> toConfidence = new EnumMap<>(Confidence.class);
    private final static EnumMap<burp.api.montoya.scanner.audit.issues.AuditIssueConfidence, Confidence> fromConfidence = new EnumMap<>(burp.api.montoya.scanner.audit.issues.AuditIssueConfidence.class);

    static {
        toConfidence.put(CERTAIN, burp.api.montoya.scanner.audit.issues.AuditIssueConfidence.CERTAIN);
        toConfidence.put(FIRM, burp.api.montoya.scanner.audit.issues.AuditIssueConfidence.FIRM);
        toConfidence.put(TENTATIVE, burp.api.montoya.scanner.audit.issues.AuditIssueConfidence.TENTATIVE);

        fromConfidence.put(burp.api.montoya.scanner.audit.issues.AuditIssueConfidence.CERTAIN, CERTAIN);
        fromConfidence.put(burp.api.montoya.scanner.audit.issues.AuditIssueConfidence.FIRM, FIRM);
        fromConfidence.put(burp.api.montoya.scanner.audit.issues.AuditIssueConfidence.TENTATIVE, TENTATIVE);
    }

    public static Confidence parseEnum(String s) {
        String value = s.toUpperCase();
        return Enum.valueOf(Confidence.class, value);
    }

    public static EnumSet<Confidence> parseEnumSet(String s) {
        EnumSet<Confidence> confidence = EnumSet.noneOf(Confidence.class);
        if (!s.startsWith("[") && s.endsWith("]")) {
            throw new IllegalArgumentException("No enum constant " + Confidence.class.getCanonicalName() + "." + s);
        }
        String content = s.substring(1, s.length() - 1).trim();
        if (content.isEmpty()) {
            return confidence;
        }
        for (String t : content.split(",")) {
            String v = t.trim();
            confidence.add(parseEnum(v.replaceAll("\"", "")));
        }
        return confidence;
    }

    @Override
    public String toString() {
        String value = StringUtil.toPascalCase(name());
        return value.replace('_', ' ');
    }

    public burp.api.montoya.scanner.audit.issues.AuditIssueConfidence toAuditIssueConfidence() {
        return toConfidence.get(this);
    }

    public static Confidence valueOf(burp.api.montoya.scanner.audit.issues.AuditIssueConfidence auditIssueConfidence) {
        return fromConfidence.get(auditIssueConfidence);
    }

}
