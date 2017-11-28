/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package yagura.model;

import extend.view.base.MatchItem;
import yagura.external.TransUtil;
import java.util.regex.Matcher;

/**
 * @author isayan
 */
public class MatchReplaceItem extends MatchItem {

    public MatchReplaceItem() {
        super();
        this.setType(types[0]);
    }
    
    public static final String TYPE_REQUEST_HEADER = "request header";
    public static final String TYPE_REQUEST_BODY = "request body";
    public static final String TYPE_RESPONSE_HEADER = "response header";
    public static final String TYPE_RESPONSE_BODY = "response body";

    public static final String TYPE_REQUEST_PARAM_NAME = "request param name";
    public static final String TYPE_REQUEST_PARAM_VALUE = "request param value";
    
    public static final String TYPE_REQUEST_FIRST_LINE = "request first line";
    
    private static final String types[] = {TYPE_REQUEST_HEADER, TYPE_REQUEST_BODY, TYPE_RESPONSE_HEADER, TYPE_RESPONSE_BODY};

    public static String[] getTypes() {
        return types;
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

    private boolean metachar = false;

    /**
     * @return the metachar
     */
    public boolean isMetaChar() {
        return this.metachar;
    }

    /**
     * @param metachar the metachar to set
     */
    public void setMetaChar(boolean metachar) {
        this.metachar = metachar;
    }
    
    public boolean isRequestLine() {
        return this.getType().startsWith(TYPE_REQUEST_FIRST_LINE);
    }
    
    public boolean isRequest() {
        return this.getType().startsWith("request");
    }
    
    public boolean isResponse() {
        return this.getType().startsWith("response");
    }

    public boolean isHeader() {
        return this.getType().endsWith("header");
    }

    public boolean isBody() {
        return this.getType().endsWith("body");
    }

    public static Object[] toObjects(MatchReplaceItem matchReplace) {
        Object[] beans = new Object[7];
        beans[0] = matchReplace.isSelected();
        beans[1] = matchReplace.getType();
        beans[2] = matchReplace.getMatch();
        beans[3] = matchReplace.isRegexp();
        beans[4] = matchReplace.isIgnoreCase();
        beans[5] = matchReplace.getReplace();
        beans[6] = matchReplace.isMetaChar();
        return beans;
    }

    public static MatchReplaceItem fromObjects(Object[] rows) {
        MatchReplaceItem matchReplace = new MatchReplaceItem();
        matchReplace.setSelected(((Boolean) rows[0]).booleanValue());
        matchReplace.setType((String) rows[1]);
        matchReplace.setMatch((String) rows[2]);
        matchReplace.setRegexp((Boolean) rows[3]);
        matchReplace.setIgnoreCase((Boolean) rows[4]);
        matchReplace.setReplace((String) rows[5]);
        matchReplace.setMetaChar((Boolean) rows[6]);
        matchReplace.recompileRegex(!matchReplace.isRegexp());
        return matchReplace;
    }

}
