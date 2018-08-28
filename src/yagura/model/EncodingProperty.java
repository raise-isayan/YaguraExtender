/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package yagura.model;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 *
 * @author isayan
 */
public class EncodingProperty {

    private static final String[] ENCODING_DEFAULT_LIST = {
        "Shift_JIS",
        "EUC-JP",
        "UTF-8",
        "ISO-2022-JP",};

    // Encoding tab
    public static List<String> getDefaultEncodingList() {
        List<String> list = new ArrayList<String>();
        list.addAll(Arrays.asList(ENCODING_DEFAULT_LIST));
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
