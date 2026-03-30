package yagura.model;

import com.google.gson.annotations.Expose;

/**
 *
 * @author isayan
 */
public class ActionMenuItem {

    public ActionMenuItem() {

    }

    @Expose
    private String caption;

    @Expose
    private int mnemonic = -1;

    @Expose
    private String hotKey = "";

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
     * @return the mnemonic
     */
    public int getMnemonic() {
        return mnemonic;
    }

    /**
     * @param mnemonic the mnemonic to set
     */
    public void setMnemonic(int mnemonic) {
        this.mnemonic = mnemonic;
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
     * @return the action
     */
    public ITranslateAction getAction() {
        ITranslateAction action = null;
        return action;
    }
}
