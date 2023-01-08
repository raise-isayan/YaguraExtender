package yagura.model;

import com.google.gson.annotations.Expose;
import extension.burp.MessageHighlightColor;
import java.util.EnumSet;

/**
 *
 * @author isayan
 */
public class FilterProperty {

    @Expose
    private boolean showOnlyScopeItems = false;

    public boolean getShowOnlyScopeItems() {
        return this.showOnlyScopeItems;
    }

    public void setShowOnlyScopeItems(boolean value) {
        this.showOnlyScopeItems = value;
    }

    @Expose
    private boolean hideItemsWithoutResponses = false;

    /**
     * @return the hideItemsWithoutResponses
     */
    public boolean isHideItemsWithoutResponses() {
        return hideItemsWithoutResponses;
    }

    /**
     * @param hideItemsWithoutResponses the hideItemsWithoutResponses to set
     */
    public void setHideItemsWithoutResponses(boolean hideItemsWithoutResponses) {
        this.hideItemsWithoutResponses = hideItemsWithoutResponses;
    }

    @Expose
    private boolean showOnly = false;

    public boolean getShowOnly() {
        return this.showOnly;
    }

    public void setShowOnly(boolean value) {
        this.showOnly = value;
    }

    @Expose
    private boolean hide = false;

    public boolean getHide() {
        return this.hide;
    }

    public void setHide(boolean value) {
        this.hide = value;
    }

    @Expose
    private String showOnlyExtension = "asp,aspx,jsp,php";

    public String getShowOnlyExtension() {
        return this.showOnlyExtension;
    }

    public void setShowOnlyExtension(String value) {
        this.showOnlyExtension = value;
    }

    @Expose
    private String hideExtension = "js,gif,jpg,png,css";

    public String getHideExtension() {
        return this.hideExtension;
    }

    public void setHideExtension(String value) {
        this.hideExtension = value;
    }

    @Expose
    private boolean stat2xx = true;

    public boolean getStat2xx() {
        return this.stat2xx;
    }

    public void setStat2xx(boolean value) {
        this.stat2xx = value;
    }

    @Expose
    private boolean stat3xx = true;

    public boolean getStat3xx() {
        return this.stat3xx;
    }

    public void setStat3xx(boolean value) {
        this.stat3xx = value;
    }

    @Expose
    private boolean stat4xx = true;

    public boolean getStat4xx() {
        return this.stat4xx;
    }

    public void setStat4xx(boolean value) {
        this.stat4xx = value;
    }

    @Expose
    private boolean stat5xx = true;

    public boolean getStat5xx() {
        return this.stat5xx;
    }

    public void setStat5xx(boolean value) {
        this.stat5xx = value;
    }

    @Expose
    private EnumSet<MessageHighlightColor> colors = EnumSet.allOf(MessageHighlightColor.class);

    public EnumSet<MessageHighlightColor> getHighlightColors() {
        return this.colors;
    }

    public void setHighlightColors(EnumSet<MessageHighlightColor> colors) {
        this.colors = colors;
    }

    @Expose
    private boolean comments = false;

    public boolean getComments() {
        return this.comments;
    }

    public void setComments(boolean comments) {
        this.comments = comments;
    }

}
