package yagura.model;

import java.util.EventObject;

/**
 *
 * @author isayan
 */
public class QuickSearchEvent extends EventObject {

    private String keyword;
    private boolean smartMatch = false;
    private boolean regexp = false;
    private boolean ignoreCase = false;
    public boolean clearView = false;
    
    public QuickSearchEvent(Object source, String keyword, boolean smartMatch, boolean regexp, boolean ignoreCase, boolean clearView) {
        super(source);
        this.keyword = keyword;
        this.smartMatch = smartMatch;
        this.regexp = regexp;
        this.ignoreCase = ignoreCase;
        this.clearView = clearView;
    }

    /**
     * @return the keyword
     */
    public String getKeyword() {
        return this.keyword;
    }
    
    /**
     * @return the smartMatch
     */
    public boolean isSmartMatch() {
        return smartMatch;
    }

    /**
     * @return the regexp
     */
    public boolean isRegexp() {
        return regexp;
    }

    /**
     * @return the ignoreCase
     */
    public boolean isIgnoreCase() {
        return ignoreCase;
    }
    
    /**
     * @return the clearView
     */
    public boolean isClearView() {
        return clearView;
    }

}
