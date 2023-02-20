package yagura.model;

import com.google.gson.annotations.Expose;
import extend.util.external.TransUtil;
import extension.view.base.MatchItem;
import java.util.regex.Matcher;

/**
 *
 * @author isayan
 */
public class AutoResponderItem extends MatchItem {
    public static final String TYPE_AUTO_RESPONDER = "auto responder";

    public AutoResponderItem() {
        setType(TYPE_AUTO_RESPONDER);
    }

    @Expose
    private boolean bodyOnly = true;

    /**
     * body only
     * @return
     */
    public boolean getBodyOnly() {
        return this.bodyOnly;
    }

    /**
     * @param bodyOnly body only
     */
    public void setBodyOnly(boolean bodyOnly) {
        this.bodyOnly = bodyOnly;
    }

    @Expose
    private String contentType = "";

    public String getContentType() {
        return contentType;
    }

    public void setContentType(String contentType) {
        this.contentType = contentType;
    }

    public static Object[] toObjects(AutoResponderItem matchReplace) {
        Object[] beans = new Object[7];
        beans[0] = matchReplace.isSelected();
        beans[1] = matchReplace.getMatch();
        beans[2] = matchReplace.isRegexp();
        beans[3] = matchReplace.isIgnoreCase();
        beans[4] = matchReplace.getBodyOnly();
        beans[5] = matchReplace.getContentType();
        beans[6] = matchReplace.getReplace();
        return beans;
    }

    public static AutoResponderItem fromObjects(Object[] rows) {
        AutoResponderItem autoResponder = new AutoResponderItem();
        autoResponder.setSelected(((Boolean) rows[0]));
        autoResponder.setMatch((String) rows[1]);
        autoResponder.setRegexp((Boolean) rows[2]);
        autoResponder.setIgnoreCase((Boolean) rows[3]);
        autoResponder.setBodyOnly(((Boolean) rows[4]));
        autoResponder.setContentType(((String) rows[5]));
        autoResponder.setReplace((String) rows[6]);
        return autoResponder;
    }

    public void setProperty(MatchItem matchItem) {
        this.setSelected(matchItem.isSelected());
        this.setType(matchItem.getType());
        this.setMatch(matchItem.getMatch());
        this.setIgnoreCase(matchItem.isIgnoreCase());
        this.setRegexp(matchItem.isRegexp());
        this.setReplace(matchItem.getReplace());
    }

    public void setProperty(AutoResponderItem item) {
        this.setProperty((MatchItem)item);
        this.setBodyOnly(item.getBodyOnly());
        this.setContentType(item.getContentType());
    }

}
