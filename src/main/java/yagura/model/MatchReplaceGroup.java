package yagura.model;

import com.google.gson.annotations.Expose;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 *
 * @author isayan
 */
public class MatchReplaceGroup {

    @Expose
    private final List<MatchReplaceItem> replaceList = new ArrayList<>();

    /**
     * @return the replaceMap
     */
    public List<MatchReplaceItem> getReplaceList() {
        return Collections.unmodifiableList(this.replaceList);
    }

    public void setReplaceList(List<MatchReplaceItem> replaceList) {
        this.replaceList.clear();
        this.replaceList.addAll(replaceList);
    }

    @Expose
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
