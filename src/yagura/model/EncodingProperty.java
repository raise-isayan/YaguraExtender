/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package yagura.model;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 *
 * @author isayan
 */
public class EncodingProperty {

    /**
     * https://l0.cm/encodings/table/
     * http://userguide.icu-project.org/conversion/detection
     * https://code.google.com/archive/p/juniversalchardet/
     */
    private static final String[] ENCODING_DEFAULT_JAPANESE_LIST  = 
        {"UTF-8", 
         "Shift_JIS", 
         "EUC-JP", 
         "ISO-2022-JP",
         "ISO-8859-1",};

    private static final String[] ENCODING_DEFAULT_KOREAN_LIST =
        {"UTF-8", 
         "EUC-KR", 
         "ISO-2022-KR",
         "ISO-8859-1",};

    private static final String[] ENCODING_DEFAULT_CHINESE_LIST = 
        {"UTF-8", 
         "BIG5", 
         "x-EUC-TW", 
         "GB18030",
         "GB2312", // HZ-GB-2312 (GBK/EUC-CN)
         "ISO-2022-CN",
         "ISO-8859-1",};

    private static final String[] ENCODING_DEFAULT_OTHER_LIST = 
        {"UTF-8", 
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
        }
        else if (lang.equals(Locale.CHINESE)) {
            list.addAll(Arrays.asList(ENCODING_DEFAULT_CHINESE_LIST));                    
        }
        else if (lang.equals(Locale.KOREAN)) {
            list.addAll(Arrays.asList(ENCODING_DEFAULT_KOREAN_LIST));                                
        }
        else {
            list.addAll(Arrays.asList(ENCODING_DEFAULT_OTHER_LIST));                                        
        }
        return Collections.unmodifiableList(list);
    }

    private final List<String> encodingList = new ArrayList(getDefaultEncodingList());

    // Encoding
    private boolean clipbordAutoDecode = true;

    public void setClipbordAutoDecode(boolean value) {
        this.clipbordAutoDecode = value;
    }

    public boolean getClipbordAutoDecode() {
        return this.clipbordAutoDecode;
    }

    public void setEncodingList(List<String> encodingList) {
        this.encodingList.clear();
        this.encodingList.addAll(encodingList);
    }

    public List<String> getEncodingList() {
        return this.encodingList;
    }
}
