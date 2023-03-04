package extension.burp;

import extension.helpers.SwingUtil;
import java.awt.Color;
import java.util.EnumMap;
import java.util.EnumSet;
import javax.swing.ImageIcon;
import burp.api.montoya.core.HighlightColor;

/**
 *
 * @author isayan
 */
public enum MessageHighlightColor {
    WHITE, RED, ORANGE, YELLOW, GREEN, CYAN, BLUE, PINK, MAGENTA, GRAY;

    private final static EnumMap<MessageHighlightColor, Color> namedColor = new EnumMap<>(MessageHighlightColor.class);
    private final static EnumMap<MessageHighlightColor, ImageIcon> namedIcon = new EnumMap<>(MessageHighlightColor.class);
    private final static EnumMap<MessageHighlightColor, HighlightColor> toHighlightColor = new EnumMap<>(MessageHighlightColor.class);
    private final static EnumMap<HighlightColor, MessageHighlightColor> fromHighlightColor = new EnumMap<>(HighlightColor.class);

    static {
        // WHITE == unselect
        namedColor.put(WHITE, Color.WHITE);
        namedColor.put(RED, Color.RED);
        namedColor.put(ORANGE, Color.ORANGE);
        namedColor.put(YELLOW, Color.YELLOW);
        namedColor.put(GREEN, Color.GREEN);
        namedColor.put(CYAN, Color.CYAN);
        namedColor.put(BLUE, Color.BLUE);
        namedColor.put(PINK, Color.PINK);
        namedColor.put(MAGENTA, Color.MAGENTA);
        namedColor.put(GRAY, Color.GRAY);

        namedIcon.put(WHITE, SwingUtil.createSquareIcon(Color.WHITE, 12, 12));
        namedIcon.put(RED, SwingUtil.createSquareIcon(Color.RED, 12, 12));
        namedIcon.put(ORANGE, SwingUtil.createSquareIcon(Color.ORANGE, 12, 12));
        namedIcon.put(YELLOW, SwingUtil.createSquareIcon(Color.YELLOW, 12, 12));
        namedIcon.put(GREEN, SwingUtil.createSquareIcon(Color.GREEN, 12, 12));
        namedIcon.put(CYAN, SwingUtil.createSquareIcon(Color.CYAN, 12, 12));
        namedIcon.put(BLUE, SwingUtil.createSquareIcon(Color.BLUE, 12, 12));
        namedIcon.put(PINK, SwingUtil.createSquareIcon(Color.PINK, 12, 12));
        namedIcon.put(MAGENTA, SwingUtil.createSquareIcon(Color.MAGENTA, 12, 12));
        namedIcon.put(GRAY, SwingUtil.createSquareIcon(Color.GRAY, 12, 12));

        toHighlightColor.put(WHITE, HighlightColor.NONE);
        toHighlightColor.put(RED, HighlightColor.RED);
        toHighlightColor.put(ORANGE, HighlightColor.ORANGE);
        toHighlightColor.put(YELLOW, HighlightColor.YELLOW);
        toHighlightColor.put(GREEN, HighlightColor.GREEN);
        toHighlightColor.put(CYAN, HighlightColor.CYAN);
        toHighlightColor.put(BLUE, HighlightColor.BLUE);
        toHighlightColor.put(PINK, HighlightColor.PINK);
        toHighlightColor.put(MAGENTA, HighlightColor.MAGENTA);
        toHighlightColor.put(GRAY, HighlightColor.GRAY);

        fromHighlightColor.put(HighlightColor.NONE, WHITE);
        fromHighlightColor.put(HighlightColor.RED, RED);
        fromHighlightColor.put(HighlightColor.ORANGE, ORANGE);
        fromHighlightColor.put(HighlightColor.YELLOW, YELLOW);
        fromHighlightColor.put(HighlightColor.GREEN, GREEN);
        fromHighlightColor.put(HighlightColor.CYAN, CYAN);
        fromHighlightColor.put(HighlightColor.BLUE, BLUE);
        fromHighlightColor.put(HighlightColor.PINK, PINK);
        fromHighlightColor.put(HighlightColor.MAGENTA, MAGENTA);
        fromHighlightColor.put(HighlightColor.GRAY, GRAY);
    }

    public Color toColor() {
        return namedColor.get(this);
    }

    public ImageIcon toIcon() {
        return namedIcon.get(this);
    }

    @Override
    public String toString() {
        String value = name().toLowerCase();
        return value.replace('_', ' ');
    }

    public static MessageHighlightColor parseEnum(String value) {
        if (value == null) {
            // no select color
            return MessageHighlightColor.WHITE;
        } else {
            value = value.toUpperCase();
            value = value.replace(' ', '_');
            return Enum.valueOf(MessageHighlightColor.class, value);
        }
    }

    public static EnumSet<MessageHighlightColor> parseEnumSet(String s) {
        EnumSet<MessageHighlightColor> highlightColor = EnumSet.noneOf(MessageHighlightColor.class);
        if (!s.startsWith("[") && s.endsWith("]")) {
            throw new IllegalArgumentException("No enum constant " + MessageHighlightColor.class.getCanonicalName() + "." + s);
        }
        String content = s.substring(1, s.length() - 1).trim();
        if (content.isEmpty()) {
            return highlightColor;
        }
        for (String t : content.split(",")) {
            String v = t.trim();
            highlightColor.add(parseEnum(v.replaceAll("\"", "")));
        }
        return highlightColor;
    }

    public HighlightColor toHighlightColor() {
        return toHighlightColor.get(this);
    }

    public static MessageHighlightColor valueOf(burp.api.montoya.core.HighlightColor highlightColor) {
        return fromHighlightColor.get(highlightColor);
    }

}
