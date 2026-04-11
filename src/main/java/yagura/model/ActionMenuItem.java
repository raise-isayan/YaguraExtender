package yagura.model;

import com.google.gson.annotations.Expose;
import java.util.function.BiFunction;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 * @author isayan
 */
public class ActionMenuItem {
    @Expose
    private String caption = "";

    @Expose
    private String hotKey = "";

    public ActionMenuItem() {
    }

    public ActionMenuItem(String caption, String hotKey) {
        this.caption = caption;
        this.hotKey = hotKey;
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
     * @return the action
     */
    public BiFunction<String,String,String> getAction() {
        return null;
    }

    private final static Pattern MNEMONIC = Pattern.compile("\\(\\[0-9A-Z]\\)");

    public int getMnemonic() {
        Matcher m = MNEMONIC.matcher(this.caption);
        if (m.find()) {
            String n = m.group(0);
            if (!n.isEmpty()) {
                return (int)n.charAt(0);
            }
        }
        return -1;
    }


}
