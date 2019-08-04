package yagura.model;

import com.google.gson.annotations.Expose;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 *
 * @author isayan
 */
public class MatchAlertProperty {

    @Expose
    private boolean selectedMatchAlert = false;

    public boolean isSelectedMatchAlert() {
        return (this.selectedMatchAlert && this.matchAlertEnable);
    }

    @Expose
    private boolean matchAlertEnable = false;
    
    public boolean isMatchAlertEnable() {
        return this.matchAlertEnable;
    }

    public void setMatchAlertEnable(boolean enable) {
        this.matchAlertEnable = enable;
    }

    @Expose
    private final List<MatchAlertItem> matchAlertItemList = new ArrayList<MatchAlertItem>();

    public List<MatchAlertItem> getMatchAlertItemList() {
        return Collections.unmodifiableList(this.matchAlertItemList);
    }

    public void setMatchAlertItemList(List<MatchAlertItem> list) {
        boolean find = false;
        this.matchAlertItemList.clear();
        this.matchAlertItemList.addAll(list);
        for (MatchAlertItem bean : this.matchAlertItemList) {
            if (bean.isSelected()) {
                find = true;
                break;
            }
        }
        this.selectedMatchAlert = find;
    }

    public void setProperty(MatchAlertProperty property) {
        this.setMatchAlertEnable(property.isMatchAlertEnable());
        this.setMatchAlertItemList(property.getMatchAlertItemList());
    }

}
