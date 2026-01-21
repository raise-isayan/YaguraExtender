package yagura.model;

import extension.burp.IPropertyConfig;
import extension.helpers.json.JsonUtil;

/**
 *
 * @author isayan
 */
public class MatchAction implements IPropertyConfig {

    public final static String MATCH_ACTION_PROPERTY = "matchActionProperty";

    public MatchAction() {
    }

    @Override
    public String getSettingName() {
        return MATCH_ACTION_PROPERTY;
    }

    public void setProperty(MatchAction property) {

    }

    @Override
    public void saveSetting(String value) {
        MatchAction property = JsonUtil.jsonFromString(value, MatchAction.class, true);
        this.setProperty(property);
    }

    @Override
    public String loadSetting() {
        return JsonUtil.jsonToString(this, true);
    }

    @Override
    public String defaultSetting() {
        MatchAction property = new MatchAction();
        return JsonUtil.jsonToString(property, true);
    }

}
