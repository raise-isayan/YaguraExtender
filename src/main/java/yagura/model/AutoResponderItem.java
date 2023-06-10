package yagura.model;

import com.google.gson.annotations.Expose;
import extension.view.base.MatchItem;

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
    private String method = null;

    /**
     * @return the method
     */
    public String getMethod() {
        return method;
    }

    /**
     * @param method the method to set
     */
    public void setMethod(String method) {
        this.method = method;
    }

    @Expose
    private boolean bodyOnly = true;

    /**
     * body only
     *
     * @return
     */
    public boolean isBodyOnly() {
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
        Object[] beans = new Object[8];
        beans[0] = matchReplace.isSelected();
        beans[1] = matchReplace.getMethod();
        beans[2] = matchReplace.getMatch();
        beans[3] = matchReplace.isRegexp();
        beans[4] = matchReplace.isIgnoreCase();
        beans[5] = matchReplace.isBodyOnly();
        beans[6] = matchReplace.getContentType();
        beans[7] = matchReplace.getReplace();
        return beans;
    }

    public static AutoResponderItem fromObjects(Object[] rows) {
        AutoResponderItem autoResponder = new AutoResponderItem();
        autoResponder.setSelected(((Boolean) rows[0]));
        autoResponder.setMethod((String) rows[1]);
        autoResponder.setMatch((String) rows[2]);
        autoResponder.setRegexp((Boolean) rows[3]);
        autoResponder.setIgnoreCase((Boolean) rows[4]);
        autoResponder.setBodyOnly(((Boolean) rows[5]));
        autoResponder.setContentType(((String) rows[6]));
        autoResponder.setReplace((String) rows[7]);
        autoResponder.recompileRegex();
        return autoResponder;
    }

    public void setProperty(AutoResponderItem item) {
        this.setProperty((MatchItem) item);
        this.setMethod(item.getMethod());
        this.setBodyOnly(item.isBodyOnly());
        this.setContentType(item.getContentType());
    }

}
