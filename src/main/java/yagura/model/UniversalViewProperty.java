package yagura.model;

import com.google.gson.annotations.Expose;
import extend.util.Util;
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
        GENERATE_POC, HTML_COMMENT, JSON, JSONP, JWT, JRAW, JPARAM;

        public static UniversalView parseValue(String value) {
            UniversalView eval = (UniversalView) Util.parseEnumValue(UniversalView.class, value);
            if (eval == null) {
                return null;
            } else {
                return eval;
            }
        }

        private static final Pattern ENUM_SPLIT = Pattern.compile("\\w+");

        public static EnumSet<UniversalView> enumSetValueOf(String s) {
            EnumSet<UniversalView> values = EnumSet.noneOf(UniversalView.class);
            Matcher m = ENUM_SPLIT.matcher(s.toUpperCase());
            while (m.find()) {
                values.add((UniversalView) Util.parseEnumValue(UniversalView.class, m.group()));
            }
            return values;
        }

        @Override
        public String toString() {
            String value = name().toLowerCase();
            return value.replace('_', ' ');
        }

    };

    @Expose
    private EnumSet<UniversalView> mesageView = EnumSet.of(UniversalView.GENERATE_POC, UniversalView.HTML_COMMENT, UniversalView.JSON);

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
    }

}
