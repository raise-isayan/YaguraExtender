package yagura.model;

import com.google.gson.annotations.Expose;
import extension.burp.IPropertyConfig;
import extension.helpers.json.JsonUtil;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 *
 * @author isayan
 */
public class MatchAlertProperty implements IPropertyConfig {

    public final static String MATCHALERT_PROPERTY = "matchAlertProperty";
    
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

    @Override
    public String getSettingName() {
        return MATCHALERT_PROPERTY;
    }

    @Override
    public void saveSetting(String value) {
        MatchAlertProperty property = JsonUtil.jsonFromString(value, MatchAlertProperty.class, true);
        this.setProperty(property);
    }

    @Override
    public String loadSetting() {
        return JsonUtil.jsonToString(this, true);
    }

    @Override
    public String defaultSetting() {
        MatchAlertProperty property = new MatchAlertProperty();
        return JsonUtil.jsonToString(property, true);
    }

}
