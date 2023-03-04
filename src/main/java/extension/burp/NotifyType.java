package extension.burp;

import java.util.EnumSet;

/**
 *
 * @author isayan
 */
public enum NotifyType {

    ALERTS_TAB, TRAY_MESSAGE, ITEM_HIGHLIGHT, COMMENT, SCANNER_ISSUE;

    public static NotifyType parseEnum(String s) {
        String value = s.toUpperCase().replace(' ', '_');
        return Enum.valueOf(NotifyType.class, value);
    }

    public static EnumSet<NotifyType> parseEnumSet(String s) {
        EnumSet<NotifyType> notifyType = EnumSet.noneOf(NotifyType.class);
        if (!s.startsWith("[") && s.endsWith("]")) {
            throw new IllegalArgumentException("No enum constant " + NotifyType.class.getCanonicalName() + "." + s);
        }
        String content = s.substring(1, s.length() - 1).trim();
        if (content.isEmpty()) {
            return notifyType;
        }
        for (String t : content.split(",")) {
            String v = t.trim();
            notifyType.add(parseEnum(v.replaceAll("\"", "")));
        }
        return notifyType;
    }

    @Override
    public String toString() {
        String value = name().toLowerCase();
        return value.replace('_', ' ');
    }

};
