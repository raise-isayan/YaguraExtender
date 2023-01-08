package extension.view.base;

import java.util.regex.Matcher;

/**
 *
 * @author isayan
 */
public class MatchItem extends RegexItem {

    private boolean selected = true;

    private String type;

    /**
     * @return the selected
     */
    public boolean isSelected() {
        return this.selected;
    }

    /**
     * @param selected the selected to set
     */
    public void setSelected(boolean selected) {
        this.selected = selected;
    }

    /**
     * @return the type
     */
    public String getType() {
        return this.type;
    }

    /**
     * @param type the type to set
     */
    public void setType(String type) {
        this.type = type;
    }

    private String replace = "";

    /**
     * @return the replace
     */
    public String getReplace() {
        return this.getReplace(false);
    }

    /**
     * @param quote
     * @return the replace
     */
    public String getReplace(boolean quote) {
        if (quote) {
            return Matcher.quoteReplacement(this.replace);
        } else {
            return this.replace;
        }
    }

    /**
     * @param replace the replace to set
     */
    public void setReplace(String replace) {
        this.replace = replace;
    }

}
