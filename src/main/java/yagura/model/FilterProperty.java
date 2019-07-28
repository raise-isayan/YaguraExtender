package yagura.model;

import extend.view.base.MatchItem;
import java.util.EnumSet;

/**
 *
 * @author isayan
 */
public class FilterProperty {

    private boolean showOnlyScopeItems = false;

    public boolean getShowOnlyScopeItems() {
        return this.showOnlyScopeItems;
    }

    public void setShowOnlyScopeItems(boolean value) {
        this.showOnlyScopeItems = value;
    }

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

    private boolean showOnly = false;

    public boolean getShowOnly() {
        return this.showOnly;
    }

    public void setShowOnly(boolean value) {
        this.showOnly = value;
    }

    private boolean hide = false;

    public boolean getHide() {
        return this.hide;
    }

    public void setHide(boolean value) {
        this.hide = value;
    }

    private String showOnlyExtension = "asp,aspx,jsp,php";

    public String getShowOnlyExtension() {
        return this.showOnlyExtension;
    }

    public void setShowOnlyExtension(String value) {
        this.showOnlyExtension = value;
    }

    private String hideExtension = "js,gif,jpg,png,css";

    public String getHideExtension() {
        return this.hideExtension;
    }

    public void setHideExtension(String value) {
        this.hideExtension = value;
    }

    private boolean stat2xx = true;

    public boolean getStat2xx() {
        return this.stat2xx;
    }

    public void setStat2xx(boolean value) {
        this.stat2xx = value;
    }

    private boolean stat3xx = true;

    public boolean getStat3xx() {
        return this.stat3xx;
    }

    public void setStat3xx(boolean value) {
        this.stat3xx = value;
    }

    private boolean stat4xx = true;

    public boolean getStat4xx() {
        return this.stat4xx;
    }

    public void setStat4xx(boolean value) {
        this.stat4xx = value;
    }

    private boolean stat5xx = true;

    public boolean getStat5xx() {
        return this.stat5xx;
    }

    public void setStat5xx(boolean value) {
        this.stat5xx = value;
    }

    private EnumSet<MatchItem.HighlightColor> colors = EnumSet.allOf(MatchItem.HighlightColor.class);

    public EnumSet<MatchItem.HighlightColor> getHighlightColors() {
        return this.colors;
    }

    public void setHighlightColors(EnumSet<MatchItem.HighlightColor> colors) {
        this.colors = colors;
    }

    private boolean comments = false;

    public boolean getComments() {
        return this.comments;
    }

    public void setComments(boolean comments) {
        this.comments = comments;
    }

}
