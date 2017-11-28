/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package yagura.model;

import extend.view.base.MatchItem;
import yagura.external.TransUtil;
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
    public String getReplace() {
        return this.getReplace(false);
    }

    /**
     * @param quote
     * @return the replace
     */
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
            }
            else {
                return Matcher.quoteReplacement(this.replace);
            }
        } else {
            if (metachar) {
                return TransUtil.decodeJsLangMeta(this.replace);
            }
            else {
                return this.replace;
            }
        }
    }
    
    /**
     * @param replace the replace to set
     */
    public void setReplace(String replace) {
        this.replace = replace;
    }

    private boolean bodyOnly = false;

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

    
    public static Object[] toObjects(AutoResponderItem matchReplace) {
        Object[] beans = new Object[6];
        beans[0] = matchReplace.isSelected();
        beans[1] = matchReplace.getMatch();
        beans[2] = matchReplace.isRegexp();
        beans[3] = matchReplace.isIgnoreCase();
        beans[4] = matchReplace.getBodyOnly();
        beans[5] = matchReplace.getReplace();
        return beans;
    }

    public static AutoResponderItem fromObjects(Object[] rows) {
        AutoResponderItem autoResponder = new AutoResponderItem();
        autoResponder.setSelected(((Boolean) rows[0]).booleanValue());
        autoResponder.setMatch((String) rows[1]);
        autoResponder.setRegexp((Boolean) rows[2]);
        autoResponder.setIgnoreCase((Boolean) rows[3]);
        autoResponder.setBodyOnly(((Boolean) rows[4]).booleanValue());
        autoResponder.setReplace((String) rows[5]);
        return autoResponder;
    }
    
}
