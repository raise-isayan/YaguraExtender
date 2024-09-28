package yagura.model;

import com.google.gson.annotations.Expose;
import extension.burp.ProtocolType;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

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

    /**
     * @param protocolType
     * @return the replaceMap
     */
    public List<MatchReplaceItem> getReplaceList(final ProtocolType protocolType) {
        return Collections.unmodifiableList(this.replaceList.stream().filter(item -> item.getProtocolType() == protocolType).collect(Collectors.toList()));
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
