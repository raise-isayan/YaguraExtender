package extension.burp;

import java.util.EnumMap;
import java.util.EnumSet;

/**
 *
 * @author isayan
 */
public enum TargetTool {
    SUITE, TARGET, PROXY, SCANNER, INTRUDER, REPEATER, LOGGER, SEQUENCER, DECODER, COMPARER, EXTENSIONS, RECORDED_LOGIN_REPLAYER, EXTENDER;

    private final static EnumMap<TargetTool, burp.api.montoya.core.ToolType> toToolType = new EnumMap<>(TargetTool.class);
    private final static EnumMap<burp.api.montoya.core.ToolType, TargetTool> fromToolType = new EnumMap<>(burp.api.montoya.core.ToolType.class);

    static {
        toToolType.put(SUITE, burp.api.montoya.core.ToolType.SUITE);
        toToolType.put(TARGET, burp.api.montoya.core.ToolType.TARGET);
        toToolType.put(PROXY, burp.api.montoya.core.ToolType.PROXY);
        toToolType.put(SCANNER, burp.api.montoya.core.ToolType.SCANNER);
        toToolType.put(INTRUDER, burp.api.montoya.core.ToolType.INTRUDER);
        toToolType.put(REPEATER, burp.api.montoya.core.ToolType.REPEATER);
        toToolType.put(LOGGER, burp.api.montoya.core.ToolType.LOGGER);
        toToolType.put(SEQUENCER, burp.api.montoya.core.ToolType.SEQUENCER);
        toToolType.put(DECODER, burp.api.montoya.core.ToolType.DECODER);
        toToolType.put(COMPARER, burp.api.montoya.core.ToolType.COMPARER);
        toToolType.put(EXTENDER, burp.api.montoya.core.ToolType.EXTENSIONS);
        toToolType.put(EXTENSIONS, burp.api.montoya.core.ToolType.EXTENSIONS);
        toToolType.put(RECORDED_LOGIN_REPLAYER, burp.api.montoya.core.ToolType.RECORDED_LOGIN_REPLAYER);

        fromToolType.put(burp.api.montoya.core.ToolType.SUITE, SUITE);
        fromToolType.put(burp.api.montoya.core.ToolType.TARGET, TARGET);
        fromToolType.put(burp.api.montoya.core.ToolType.PROXY, PROXY);
        fromToolType.put(burp.api.montoya.core.ToolType.SCANNER, SCANNER);
        fromToolType.put(burp.api.montoya.core.ToolType.INTRUDER, INTRUDER);
        fromToolType.put(burp.api.montoya.core.ToolType.REPEATER, REPEATER);
        fromToolType.put(burp.api.montoya.core.ToolType.LOGGER, LOGGER);
        fromToolType.put(burp.api.montoya.core.ToolType.SEQUENCER, SEQUENCER);
        fromToolType.put(burp.api.montoya.core.ToolType.DECODER, DECODER);
        fromToolType.put(burp.api.montoya.core.ToolType.COMPARER, COMPARER);
        fromToolType.put(burp.api.montoya.core.ToolType.EXTENSIONS, EXTENSIONS);
        fromToolType.put(burp.api.montoya.core.ToolType.RECORDED_LOGIN_REPLAYER, RECORDED_LOGIN_REPLAYER);
    }

    public static boolean isParseEnum(String s) {
        try {
            parseEnum(s);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    public static TargetTool parseEnum(String s) {
        String value = s.toUpperCase().replace(' ', '_');
        return Enum.valueOf(TargetTool.class, value);
    }

    public static EnumSet<TargetTool> parseEnumSet(String s) {
        EnumSet<TargetTool> targetTool = EnumSet.noneOf(TargetTool.class);
        if (!s.startsWith("[") && s.endsWith("]")) {
            throw new IllegalArgumentException("No enum constant " + TargetTool.class.getCanonicalName() + "." + s);
        }
        String content = s.substring(1, s.length() - 1).trim();
        if (content.isEmpty()) {
            return targetTool;
        }
        for (String t : content.split(",")) {
            String v = t.trim();
            v = v.replaceAll("\"", "");
            if (isParseEnum(v)) {
                TargetTool tool = parseEnum(v);
                targetTool.add(tool);
                if (TargetTool.EXTENDER.equals(tool)) {
                    targetTool.add(TargetTool.EXTENSIONS);
                }
                if (TargetTool.EXTENSIONS.equals(tool)) {
                    targetTool.add(TargetTool.EXTENDER);
                }
            }
        }
        return targetTool;
    }

    @Override
    public String toString() {
        String value = name().toLowerCase();
        return value.replace('_', ' ');
    }

    public burp.api.montoya.core.ToolType toToolType() {
        return toToolType.get(this);
    }

    public static TargetTool valueOf(burp.api.montoya.core.ToolType targetTool) {
        return fromToolType.get(targetTool);
    }

}
