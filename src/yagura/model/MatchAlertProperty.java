/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package yagura.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 *
 * @author isayan
 */
public class MatchAlertProperty {
    private boolean selectedMatchAlert = false;
    private final List<MatchAlertItem> matchAlertItemList = new ArrayList<MatchAlertItem>();
    private boolean matchAlertEnable = false;

    public boolean isSelectedMatchAlert() {
        return (this.selectedMatchAlert && this.matchAlertEnable);
    }
    
    public boolean isMatchAlertEnable() {
        return this.matchAlertEnable;
    }

    public void setMatchAlertEnable(boolean enable) {
        this.matchAlertEnable = enable;
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

    public List<MatchAlertItem> getMatchAlertItemList() {
        return Collections.unmodifiableList(this.matchAlertItemList);
    }
    
}
