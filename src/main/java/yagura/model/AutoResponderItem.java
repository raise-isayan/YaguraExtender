package yagura.model;

import extend.view.base.MatchItem;
import extend.util.external.TransUtil;
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

    private String replace = "";

    /**
     * @return the replace
     */
    @Override
    public String getReplace() {
        return this.getReplace(false);
    }

    /**
     * @param quote
     * @return the replace
     */
    @Override
    public String getReplace(boolean quote) {
        return getReplace(quote, false);
    }

    /**
     * @param quote
     * @param metachar
     * @return the replace
     */
    public String getReplace(boolean quote, boolean metachar) {
        if (quote) {
            if (metachar) {
                return Matcher.quoteReplacement(TransUtil.decodeJsLangMeta(this.replace));
            } else {
                return Matcher.quoteReplacement(this.replace);
            }
        } else {
            if (metachar) {
                return TransUtil.decodeJsLangMeta(this.replace);
            } else {
                return this.replace;
            }
        }
    }

    /**
     * @param replace the replace to set
     */
    @Override
    public void setReplace(String replace) {
        this.replace = replace;
    }

    private boolean bodyOnly = true;

    /**
     * body only
     *
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

}
