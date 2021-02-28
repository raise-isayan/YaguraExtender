package yagura.model;

import com.google.gson.annotations.Expose;
import extension.helpers.ConvertUtil;
import extension.helpers.StringUtil;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.SortedMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 * @author isayan
 */
public class UniversalViewProperty {

    /**
     * https://l0.cm/encodings/table/ http://userguide.icu-project.org/conversion/detection
     * https://code.google.com/archive/p/juniversalchardet/
     */
    private static final String[] ENCODING_DEFAULT_JAPANESE_LIST = {
        StandardCharsets.UTF_8.name(),
        "Shift_JIS",
        "EUC-JP",
        "ISO-2022-JP",
        StandardCharsets.ISO_8859_1.name(),};

    private static final String[] ENCODING_DEFAULT_KOREAN_LIST = {
        StandardCharsets.UTF_8.name(),
        "EUC-KR",
        "ISO-2022-KR",
        StandardCharsets.ISO_8859_1.name(),};

    private static final String[] ENCODING_DEFAULT_CHINESE_LIST = {
        StandardCharsets.UTF_8.name(),
        "BIG5",
        "x-EUC-TW",
        "GB18030",
        "GB2312", // HZ-GB-2312 (GBK/EUC-CN)
        "ISO-2022-CN",
        StandardCharsets.ISO_8859_1.name(),};

    private static final String[] ENCODING_DEFAULT_OTHER_LIST = {
        StandardCharsets.UTF_8.name(),
        StandardCharsets.US_ASCII.name(),
        StandardCharsets.ISO_8859_1.name(),};

    // Encoding tab
    public static List<String> getDefaultEncodingList() {
        return getDefaultEncodingList(Locale.getDefault());
    }

    public static List<String> getDefaultEncodingList(Locale lang) {
        SortedMap<String, Charset> charSets = Charset.availableCharsets();

        List<String> list = new ArrayList<>();
        if (lang == null) {
            for (String enc : ENCODING_DEFAULT_OTHER_LIST) {
               if (charSets.get(enc) != null)  list.add(enc);
            }
        }
        else if (lang.equals(Locale.JAPANESE)) {
            for (String enc : ENCODING_DEFAULT_JAPANESE_LIST) {
               if (charSets.get(enc) != null)  list.add(enc);
            }
        } else if (lang.equals(Locale.CHINESE)) {
            for (String enc : ENCODING_DEFAULT_CHINESE_LIST) {
               if (charSets.get(enc) != null)  list.add(enc);
            }
        } else if (lang.equals(Locale.KOREAN)) {
            for (String enc : ENCODING_DEFAULT_KOREAN_LIST) {
               if (charSets.get(enc) != null)  list.add(enc);
            }
        } else {
            for (String enc : ENCODING_DEFAULT_OTHER_LIST) {
               if (charSets.get(enc) != null)  list.add(enc);
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
    private int dispayMaxLength = 10000000;

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

    public enum UniversalView {
        GENERATE_POC, HTML_COMMENT, JSON, JSONP, JWT, VIEW_STATE, JRAW, JPARAM;

        public static UniversalView parseEnum(String s) {
            String value = s.toUpperCase();
            return Enum.valueOf(UniversalView.class, value);
        }

        public static EnumSet<UniversalView> parseEnumSet(String s) {
            EnumSet<UniversalView> universal = EnumSet.noneOf(UniversalView.class);
            if (!s.startsWith("[") && s.endsWith("]")) {
                throw new IllegalArgumentException("No enum constant " + UniversalView.class.getCanonicalName() + "." + s);
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
    private EnumSet<UniversalView> mesageView = EnumSet.of(UniversalView.GENERATE_POC, UniversalView.HTML_COMMENT, UniversalView.JSON, UniversalView.JSONP);

    public EnumSet<UniversalView> getMessageView() {
        return mesageView;
    }

    public void setMessageView(EnumSet<UniversalView> view) {
        this.mesageView = view;
    }

    public void setProperty(UniversalViewProperty property) {
        this.setClipbordAutoDecode(property.getClipbordAutoDecode());
        this.setEncodingList(property.getEncodingList());
        this.setMessageView(property.getMessageView());
        this.setDispayMaxLength(property.getDispayMaxLength());
        this.setLineWrap(property.isLineWrap());
    }

}
