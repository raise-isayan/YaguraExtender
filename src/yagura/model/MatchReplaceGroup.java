/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package yagura.model;

import extend.util.Util;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 *
 * @author isayan
 */
public class MatchReplaceGroup {

    private final List<MatchReplaceItem> replaceList = new ArrayList<MatchReplaceItem>();

    /**
     * @return the replaceMap
     */
    public List<MatchReplaceItem> getReplaceList() {
        return Collections.unmodifiableList(this.replaceList);
    }

    /**
     * @return the replaceMap
     */
    public void setReplaceList(List<MatchReplaceItem> replaceList) {
        this.replaceList.clear();
        this.replaceList.addAll(replaceList);
    }
        
    private boolean inScopeOnly = false;

    /**
     * @return the inScopeOnly
     */
    public boolean isInScopeOnly() {
        return this.inScopeOnly;
    }

    /**
     * @param inScopeOnly the inScopeOnly to set
     */
    public void setInScopeOnly(boolean inScopeOnly) {
        this.inScopeOnly = inScopeOnly;
    }
    
}
