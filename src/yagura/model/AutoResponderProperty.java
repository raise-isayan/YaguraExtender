/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package yagura.model;

import yagura.model.AutoResponderItem;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 * @author isayan
 */
public class AutoResponderProperty {
    private int redirectPort = 7777;

    /**
     * @return the redirectPort
     */
    public int getRedirectPort() {
        return redirectPort;
    }

    /**
     * @param redirectTo the redirectPort to set
     */
    public void setRedirectPort(int redirectPort) {
        this.redirectPort = redirectPort;
    }

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

    public AutoResponderItem findItem(String url) {
        AutoResponderItem matchItem = null;
        for (int i = 0; i < autoResponderList.size(); i++) {
            AutoResponderItem bean = autoResponderList.get(i);
            if (!bean.isSelected()) {
                continue;
            }
            Pattern p = bean.getRegexPattern();
            Matcher m = p.matcher(url);
            if (m.lookingAt()) {            
                matchItem = bean;
                break;
            }
        }        
        return matchItem;
    }
           
}