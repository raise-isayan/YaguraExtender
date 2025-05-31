package yagura.model;

import com.google.gson.annotations.Expose;
import extension.burp.IPropertyConfig;
import extension.helpers.json.JsonUtil;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.SortedMap;

/**
 *
 * @author isayan
 */
public class UniversalViewProperty implements IPropertyConfig {

    public final static String UNIVERSAL_VIEW_PROPERTY = "universalViewProperty";

    /**
     * https://l0.cm/encodings/table/
     * http://userguide.icu-project.org/conversion/detection
     * https://code.google.com/archive/p/juniversalchardet/
     */
    private static final String[] ENCODING_REQUIRED_LIST = {
        StandardCharsets.UTF_8.name(),
        StandardCharsets.ISO_8859_1.name()
    };

    private static final String[] ENCODING_DEFAULT_JAPANESE_LIST = {
        StandardCharsets.UTF_8.name(),
        StandardCharsets.ISO_8859_1.name(),
        "Shift_JIS",
        "EUC-JP",
        "ISO-2022-JP"
    };

    private static final String[] ENCODING_DEFAULT_KOREAN_LIST = {
        StandardCharsets.UTF_8.name(),
        StandardCharsets.ISO_8859_1.name(),
        "EUC-KR",
        "ISO-2022-KR"
    };

    private static final String[] ENCODING_DEFAULT_CHINESE_LIST = {
        StandardCharsets.UTF_8.name(),
        StandardCharsets.ISO_8859_1.name(),
        "BIG5",
        "x-EUC-TW",
        "GB18030",
        "GB2312", // HZ-GB-2312 (GBK/EUC-CN)
        "ISO-2022-CN"
    };

    private static final String[] ENCODING_DEFAULT_OTHER_LIST = {
        StandardCharsets.UTF_8.name(),
        StandardCharsets.ISO_8859_1.name(),
        StandardCharsets.US_ASCII.name()
    };

    public static boolean isRequiredCharset(String charSet) {
        final List<String> required_list = List.of(ENCODING_REQUIRED_LIST);
        return required_list.contains(charSet);
    }

    // Encoding tab
    public static List<String> getDefaultEncodingList() {
        return getDefaultEncodingList(Locale.getDefault());
    }

    public static List<String> getDefaultEncodingList(Locale lang) {
        SortedMap<String, Charset> charSets = Charset.availableCharsets();

        List<String> list = new ArrayList<>();
        if (lang == null) {
            for (String enc : ENCODING_DEFAULT_OTHER_LIST) {
                if (charSets.get(enc) != null) {
                    list.add(enc);
                }
            }
        } else if (lang.equals(Locale.JAPANESE)) {
            for (String enc : ENCODING_DEFAULT_JAPANESE_LIST) {
                if (charSets.get(enc) != null) {
                    list.add(enc);
                }
            }
        } else if (lang.equals(Locale.CHINESE)) {
            for (String enc : ENCODING_DEFAULT_CHINESE_LIST) {
                if (charSets.get(enc) != null) {
                    list.add(enc);
                }
            }
        } else if (lang.equals(Locale.KOREAN)) {
            for (String enc : ENCODING_DEFAULT_KOREAN_LIST) {
                if (charSets.get(enc) != null) {
                    list.add(enc);
                }
            }
        } else {
            for (String enc : ENCODING_DEFAULT_OTHER_LIST) {
                if (charSets.get(enc) != null) {
                    list.add(enc);
                }
            }
        }
        return Collections.unmodifiableList(list);
    }

    @Expose
    private boolean lineWrap = false;

    /**
     * @return the lineWrap
     */
    public boolean isLineWrap() {
        return lineWrap;
    }

    /**
     * @param lineWrap the lineWrap to set
     */
    public void setLineWrap(boolean lineWrap) {
        this.lineWrap = lineWrap;
    }

    @Expose
    private int dispayMaxLength = 100000;

    public int getDispayMaxLength() {
        return this.dispayMaxLength;
    }

    public void setDispayMaxLength(int dispayMaxLength) {
        this.dispayMaxLength = dispayMaxLength;
    }

    // non Expose
    private boolean clipbordAutoDecode = true;

    public void setClipbordAutoDecode(boolean value) {
        this.clipbordAutoDecode = value;
    }

    public boolean getClipbordAutoDecode() {
        return this.clipbordAutoDecode;
    }

    @Expose
    private final List<String> encodingList = new ArrayList<>(getDefaultEncodingList());

    public void setEncodingList(List<String> encodingList) {
        this.encodingList.clear();
        this.encodingList.addAll(encodingList);
    }

    public List<String> getEncodingList() {
        return this.encodingList;
    }

    public enum MessageView {
        GENERATE_POC, HTML_COMMENT, JSON, JSONP, JWT, VIEW_STATE, JRAW, JPARAM;

        public static MessageView parseEnum(String s) {
            String value = s.toUpperCase();
            return Enum.valueOf(MessageView.class, value);
        }

        public static EnumSet<MessageView> parseEnumSet(String s) {
            EnumSet<MessageView> universal = EnumSet.noneOf(MessageView.class);
            if (!s.startsWith("[") && s.endsWith("]")) {
                throw new IllegalArgumentException("No enum constant " + MessageView.class.getCanonicalName() + "." + s);
            }
            String content = s.substring(1, s.length() - 1).trim();
            if (content.isEmpty()) {
                return universal;
            }
            for (String t : content.split(",")) {
                String v = t.trim();
                universal.add(parseEnum(v.replaceAll("\"", "")));
            }
            return universal;
        }

        @Override
        public String toString() {
            String value = name().toLowerCase();
            return value.replace('_', ' ');
        }

    };

    @Expose
    private EnumSet<MessageView> mesageView = EnumSet.of(MessageView.GENERATE_POC, MessageView.HTML_COMMENT, MessageView.JSON, MessageView.JSONP);

    public EnumSet<MessageView> getMessageView() {
        return mesageView;
    }

    public void setMessageView(EnumSet<MessageView> view) {
        this.mesageView = view;
    }

    public enum BurpView {
        TOOL_BAR;
    }

    @Expose
    private EnumSet<BurpView> burpView = EnumSet.of(BurpView.TOOL_BAR);

    public EnumSet<BurpView> getBurpView() {
        return burpView;
    }

    public void setBurpView(EnumSet<BurpView> view) {
        this.burpView = view;
    }

    public enum BurpToolBar {
        FLOATABLE;
    }

    @Expose
    private EnumSet<BurpToolBar> burpToolBar = EnumSet.of(BurpToolBar.FLOATABLE);

    public EnumSet<BurpToolBar> getBurpToolBar() {
        return burpToolBar;
    }

    public void setBurpToolBar(EnumSet<BurpToolBar> burpToolBar) {
        this.burpToolBar = burpToolBar;
    }

    public void setProperty(UniversalViewProperty property) {
        this.setClipbordAutoDecode(property.getClipbordAutoDecode());
        this.setEncodingList(property.getEncodingList());
        this.setMessageView(property.getMessageView());
        this.setDispayMaxLength(property.getDispayMaxLength());
        this.setLineWrap(property.isLineWrap());
        this.setBurpView(property.getBurpView());
        this.setBurpToolBar(property.getBurpToolBar());
    }

    @Override
    public String getSettingName() {
        return UNIVERSAL_VIEW_PROPERTY;
    }

    @Override
    public void saveSetting(String value) {
        UniversalViewProperty property = JsonUtil.jsonFromString(value, UniversalViewProperty.class, true);
        this.setProperty(property);
    }

    @Override
    public String loadSetting() {
        return JsonUtil.jsonToString(this, true);
    }

    @Override
    public String defaultSetting() {
        UniversalViewProperty property = new UniversalViewProperty();
        return JsonUtil.jsonToString(property, true);
    }

}
