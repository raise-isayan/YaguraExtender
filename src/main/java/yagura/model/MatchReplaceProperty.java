package yagura.model;

import com.google.gson.annotations.Expose;
import extend.util.Util;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 *
 * @author isayan
 */
public class MatchReplaceProperty {

    @Expose
    private String selectedName = "";

    /**
     * @return the selectedName
     */
    public String getSelectedName() {
        return this.selectedName;
    }

    /**
     * @param selectedName the selectedName to set
     */
    public void setSelectedName(String selectedName) {
        this.selectedName = selectedName;
    }

    @Expose
    private final Map<String, MatchReplaceGroup> replaceMap = new LinkedHashMap<String, MatchReplaceGroup>(16, (float) 0.75, true);

    /**
     * @return the replaceMap
     */
    public Map<String, MatchReplaceGroup> getReplaceMap() {
        return this.replaceMap;
    }

    /**
     * @param replaceMap the replaceMap to set
     */
    public void setReplaceMap(Map<String, MatchReplaceGroup> replaceMap) {
        if (replaceMap.get(this.selectedName) == null) {
            this.selectedName = "";
        }
        this.replaceMap.clear();
        this.replaceMap.putAll(replaceMap);
    }

    /**
     *
     * @param selectedName
     * @return
     */
    public MatchReplaceGroup getReplaceSelectedGroup(String selectedName) {
        return this.replaceMap.get(selectedName);
    }

    /**
     *
     * @param selectedName
     * @return
     */
    public List<MatchReplaceItem> getReplaceSelectedList(String selectedName) {
        MatchReplaceGroup group = this.replaceMap.get(selectedName);
        if (group == null) {
            return new ArrayList<>();
        } else {
            return group.getReplaceList();
        }
    }

    /**
     * @return the matchReplaceGroup
     */
    public MatchReplaceGroup getMatchReplaceGroup() {
        return this.replaceMap.get(this.selectedName);
    }

    /**
     * @return the matchReplaceList
     */
    public List<MatchReplaceItem> getMatchReplaceList() {
        MatchReplaceGroup group = this.replaceMap.get(this.selectedName);
        if (group != null) {
            return group.getReplaceList();
        } else {
            return null;
        }
    }

    public boolean isSelectedMatchReplace() {
        MatchReplaceGroup group = this.replaceMap.get(this.selectedName);
        return (group != null);
    }

    public List<String> getReplaceNameList() {
        return Util.toList(this.replaceMap.keySet().iterator());
    }

    @Expose
    private boolean autoRecognise = false;

    public boolean getAutoRecogniseEncoding() {
        return this.autoRecognise;
    }

    public void setAutoRecogniseEncoding(boolean autoRecognise) {
        this.autoRecognise = autoRecognise;
    }

    public void setProperty(MatchReplaceProperty property) {
        this.setSelectedName(property.getSelectedName());
        this.setReplaceMap(property.getReplaceMap());
        this.setAutoRecogniseEncoding(property.getAutoRecogniseEncoding());
    }

}
