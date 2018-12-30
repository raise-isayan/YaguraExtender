package yagura.model;

import extend.util.Util;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 * @author isayan
 */
public class UniversalViewProperty {

    /**
     * https://l0.cm/encodings/table/
     * http://userguide.icu-project.org/conversion/detection
     * https://code.google.com/archive/p/juniversalchardet/
     */
    private static final String[] ENCODING_DEFAULT_JAPANESE_LIST
            = {"UTF-8",
                "Shift_JIS",
                "EUC-JP",
                "ISO-2022-JP",
                "ISO-8859-1",};

    private static final String[] ENCODING_DEFAULT_KOREAN_LIST
            = {"UTF-8",
                "EUC-KR",
                "ISO-2022-KR",
                "ISO-8859-1",};

    private static final String[] ENCODING_DEFAULT_CHINESE_LIST
            = {"UTF-8",
                "BIG5",
                "x-EUC-TW",
                "GB18030",
                "GB2312", // HZ-GB-2312 (GBK/EUC-CN)
                "ISO-2022-CN",
                "ISO-8859-1",};

    private static final String[] ENCODING_DEFAULT_OTHER_LIST
            = {"UTF-8",
                "US-ASCII",
                "ISO-8859-1",};

    // Encoding tab
    public static List<String> getDefaultEncodingList() {
        return getDefaultEncodingList(Locale.getDefault());
    }

    public static List<String> getDefaultEncodingList(Locale lang) {
        List<String> list = new ArrayList<>();
        if (lang.equals(Locale.JAPANESE)) {
            list.addAll(Arrays.asList(ENCODING_DEFAULT_JAPANESE_LIST));
        } else if (lang.equals(Locale.CHINESE)) {
            list.addAll(Arrays.asList(ENCODING_DEFAULT_CHINESE_LIST));
        } else if (lang.equals(Locale.KOREAN)) {
            list.addAll(Arrays.asList(ENCODING_DEFAULT_KOREAN_LIST));
        } else {
            list.addAll(Arrays.asList(ENCODING_DEFAULT_OTHER_LIST));
        }
        return Collections.unmodifiableList(list);
    }

    // Encoding
    private boolean clipbordAutoDecode = true;

    public void setClipbordAutoDecode(boolean value) {
        this.clipbordAutoDecode = value;
    }

    public boolean getClipbordAutoDecode() {
        return this.clipbordAutoDecode;
    }

    private final List<String> encodingList = new ArrayList(getDefaultEncodingList());
    
    public void setEncodingList(List<String> encodingList) {
        this.encodingList.clear();
        this.encodingList.addAll(encodingList);
    }

    public List<String> getEncodingList() {
        return this.encodingList;
    }

    public enum UniversalView {
        GENERATE_POC, HTML_COMMENT, JSON, JRAW, JPARAM;
    
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
                values.add((UniversalView)Util.parseEnumValue(UniversalView.class, m.group()));
            }
            return values;
        }
        
        @Override
        public String toString() {
            String value = name().toLowerCase();
            return value.replace('_', ' ');
        }
        
    };
    
    private EnumSet<UniversalView> view = EnumSet.of(UniversalView.GENERATE_POC, UniversalView.HTML_COMMENT, UniversalView.JSON);
    
    public EnumSet<UniversalView> getMessageView() {
        return view;
    }

    public void setMessageView(EnumSet<UniversalView> view) {
        this.view = view;
    }
        
    public void setProperty(UniversalViewProperty property) {
        this.setClipbordAutoDecode(property.getClipbordAutoDecode());
        this.setEncodingList(property.getEncodingList());
        this.setMessageView(property.getMessageView());
    }

}
