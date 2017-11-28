/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package yagura.view;

import yagura.model.AutoResponderItem;
import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author isayan
 */
public class AutoResponderProperty {
    private boolean autoResponderEnable = false;
    
    public void setAutoResponderEnable(boolean selected) {
        autoResponderEnable = selected;
    }

    public boolean getAutoResponderEnable() {
        return autoResponderEnable;
    }
    
    private List<AutoResponderItem> autoResponderList = new ArrayList<AutoResponderItem>();
    
    public void setAutoResponderItemList(List<AutoResponderItem> autoResponderItemList) {
        this.autoResponderList = autoResponderItemList;
    }

    public List<AutoResponderItem> getAutoResponderItemList() {
        return this.autoResponderList;
    }
    
}
