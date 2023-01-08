package extension.burp;

import java.util.EnumMap;
import java.util.EnumSet;

/**
 *
 * @author isayan
 */
public enum Severity {
    HIGH, MEDIUM, LOW, INFORMATION, FALSE_POSITIVE;

    private final static EnumMap<Severity, burp.api.montoya.scanner.audit.issues.AuditIssueSeverity> toSeverity = new EnumMap<>(Severity.class);
    private final static EnumMap<burp.api.montoya.scanner.audit.issues.AuditIssueSeverity, Severity> fromSeverity = new EnumMap<>(burp.api.montoya.scanner.audit.issues.AuditIssueSeverity.class);

    static {
        toSeverity.put(HIGH, burp.api.montoya.scanner.audit.issues.AuditIssueSeverity.HIGH);
        toSeverity.put(MEDIUM, burp.api.montoya.scanner.audit.issues.AuditIssueSeverity.MEDIUM);
        toSeverity.put(LOW, burp.api.montoya.scanner.audit.issues.AuditIssueSeverity.LOW);
        toSeverity.put(INFORMATION, burp.api.montoya.scanner.audit.issues.AuditIssueSeverity.INFORMATION);
        toSeverity.put(FALSE_POSITIVE, burp.api.montoya.scanner.audit.issues.AuditIssueSeverity.FALSE_POSITIVE);

        fromSeverity.put(burp.api.montoya.scanner.audit.issues.AuditIssueSeverity.HIGH, HIGH);
        fromSeverity.put(burp.api.montoya.scanner.audit.issues.AuditIssueSeverity.MEDIUM, MEDIUM);
        fromSeverity.put(burp.api.montoya.scanner.audit.issues.AuditIssueSeverity.LOW, LOW);
        fromSeverity.put(burp.api.montoya.scanner.audit.issues.AuditIssueSeverity.INFORMATION, INFORMATION);
        fromSeverity.put(burp.api.montoya.scanner.audit.issues.AuditIssueSeverity.FALSE_POSITIVE, FALSE_POSITIVE);
    }

    public static Severity parseEnum(String s) {
        String value = s.toUpperCase().replace(' ', '_');
        return Enum.valueOf(Severity.class, value);
    }

    public static EnumSet<Severity> parseEnumSet(String s) {
        EnumSet<Severity> severity = EnumSet.noneOf(Severity.class);
        if (!s.startsWith("[") && s.endsWith("]")) {
            throw new IllegalArgumentException("No enum constant " + Severity.class.getCanonicalName() + "." + s);
        }
        String content = s.substring(1, s.length() - 1).trim();
        if (content.isEmpty()) {
            return severity;
        }
        for (String t : content.split(",")) {
            String v = t.trim();
            severity.add(parseEnum(v.replaceAll("\"", "")));
        }
        return severity;
    }

    @Override
    public String toString() {
        char ch[] = name().toLowerCase().toCharArray();
        if (ch.length > 0) {
            ch[0] = Character.toUpperCase(ch[0]);
        }
        String value = new String(ch);
        return value.replace('_', ' ');
    }

    public burp.api.montoya.scanner.audit.issues.AuditIssueSeverity toAuditIssueSeverity() {
        return toSeverity.get(this);
    }

    public static Severity valueOf(burp.api.montoya.scanner.audit.issues.AuditIssueSeverity auditIssueSeverity) {
        return fromSeverity.get(auditIssueSeverity);
    }

}
