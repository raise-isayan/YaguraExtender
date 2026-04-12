package yagura.model;

import com.google.gson.annotations.Expose;
import java.util.EnumSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 * @author isayan
 */
public class TranslateItemAction {

    @Expose
    private String caption = "";

    @Expose
    private int mnemonic = -1;

    @Expose
    private String hotKey = "";

    @Expose
    private TranslateAction action = null;

    public TranslateItemAction() {
    }

    public TranslateItemAction(String caption, String hotKey, TranslateAction action) {
        this.caption = caption;
        this.hotKey = hotKey;
        this.action = action;
    }

    public TranslateItemAction(String caption, int mnemonic, String hotKey, TranslateAction action) {
        this.caption = caption;
        this.mnemonic = mnemonic;
        this.hotKey = hotKey;
        this.action = action;
    }

    /**
     * @return the caption
     */
    public String getCaption() {
        return caption;
    }

    /**
     * @param caption the caption to set
     */
    public void setCaption(String caption) {
        this.caption = caption;
    }

    /**
     * @return the hotKey
     */
    public String getHotKey() {
        return hotKey;
    }

    /**
     * @param hotKey the hotKey to set
     */
    public void setHotKey(String hotKey) {
        this.hotKey = hotKey;
    }

    /**
     * @return the Mnemonic
     */
    public int getMnemonic() {
        if (mnemonic < 0) {
            return parseMnemonic(this.caption);
        } else {
            return mnemonic;
        }
    }

    /**
     * @param mnemonic the mnemonic to set
     */
    public void setMnemonic(int mnemonic) {
        this.mnemonic = mnemonic;
    }

    /**
     * @return the action
     */
    public TranslateAction getAction() {
        return this.action;
    }

    private final static Pattern MNEMONIC = Pattern.compile("\\(\\[0-9A-Z]\\)");

    private static int parseMnemonic(String caption) {
        Matcher m = MNEMONIC.matcher(caption);
        if (m.find()) {
            String n = m.group(0);
            if (!n.isEmpty()) {
                return (int) n.charAt(0);
            }
        }
        return -1;
    }

    public enum TranslateAction {
        /* Encode */
        ENCODE_URL,
        ENCODE_UNICODE_URL,
        ENCODE_UNICODE_JSON,
        ENCODE_BASE64,
        ENCODE_BASE64_SAFE,
        ENCODE_BASE64_URL,
        ENCODE_HTML,
        ENCODE_JSON_META,
        /* Decode */
        DECODE_URL,
        DECODE_UNICODE_URL,
        DECODE_UNICODE_JSON,
        DECODE_BASE64,
        DECODE_BASE64_SAFE,
        DECODE_BASE64_URL,
        DECODE_HTML,
        DECODE_JSON_META,
        /* Convert */
        CONVERT_UPPER_CASE,
        CONVERT_LOWLER_CASE,
        CONVERT_BIN2HEX,
        CONVERT_HEX2BIN,
        CONVERT_FULL2HALF,
        CONVERT_HALF2FULL,
        /* Hash */
        HASH_MD2,
        HASH_MD5,
        HASH_SHA1,
        HASH_SHA256,
        HASH_SHA384,
        HASH_SHA512,
    }

    public final static EnumSet MENU_ENCODE_ACTION_GROUP = EnumSet.of(
            TranslateAction.ENCODE_URL,
            TranslateAction.ENCODE_UNICODE_URL,
            TranslateAction.ENCODE_UNICODE_JSON,
            TranslateAction.ENCODE_BASE64,
            TranslateAction.ENCODE_BASE64_SAFE,
            TranslateAction.ENCODE_BASE64_URL,
            TranslateAction.ENCODE_HTML,
            TranslateAction.ENCODE_JSON_META
    );

    public final static EnumSet MENU_DECODE_ACTION_GROUP = EnumSet.of(
            TranslateAction.DECODE_URL,
            TranslateAction.DECODE_UNICODE_URL,
            TranslateAction.DECODE_UNICODE_JSON,
            TranslateAction.DECODE_BASE64,
            TranslateAction.DECODE_BASE64_SAFE,
            TranslateAction.DECODE_BASE64_URL,
            TranslateAction.DECODE_HTML,
            TranslateAction.DECODE_JSON_META
    );

    public final static EnumSet MENU_CONVERT_ACTION_GROUP = EnumSet.of(
            TranslateAction.CONVERT_UPPER_CASE,
            TranslateAction.CONVERT_LOWLER_CASE,
            TranslateAction.CONVERT_BIN2HEX,
            TranslateAction.CONVERT_HEX2BIN,
            TranslateAction.CONVERT_FULL2HALF,
            TranslateAction.CONVERT_HALF2FULL
    );

    public final static EnumSet MENU_HASH_ACTION_GROUP = EnumSet.of(
            TranslateAction.HASH_MD2,
            TranslateAction.HASH_MD5,
            TranslateAction.HASH_SHA1,
            TranslateAction.HASH_SHA256,
            TranslateAction.HASH_SHA384,
            TranslateAction.HASH_SHA512
    );

}
