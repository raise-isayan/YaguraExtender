package yagura.model;

import com.google.gson.annotations.Expose;
import extension.burp.IPropertyConfig;
import extension.helpers.json.JsonUtil;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 * @author isayan
 */
public class AutoResponderProperty implements IPropertyConfig {

    public final static String AUTO_RESPONDER_PROPERTY = "autoResponderProperty";
    public final static String AUTO_RESPONDER_HEADER = "X-Yagura-AutoResponder";

    @Expose
    private int redirectPort = 0;

    /**
     * @return the redirectPort
     */
    public int getRedirectPort() {
        return redirectPort;
    }

    /**
     * @param redirectPort
     */
    public void setRedirectPort(int redirectPort) {
        this.redirectPort = redirectPort;
    }

    @Expose
    private boolean autoResponderEnable = false;

    public void setAutoResponderEnable(boolean selected) {
        this.autoResponderEnable = selected;
    }

    public boolean getAutoResponderEnable() {
        return this.autoResponderEnable;
    }

    @Expose
    private boolean hostNameForceResolv = true;

    /**
     * @return the hostNameForceResolv
     */
    public boolean isHostNameForceResolv() {
        return hostNameForceResolv;
    }

    /**
     * @param hostNameForceResolv the hostNameForceResolv to set
     */
    public void setForceHostNameResolv(boolean hostNameForceResolv) {
        this.hostNameForceResolv = hostNameForceResolv;
    }

    @Expose
    private final List<AutoResponderItem> autoResponderList = new ArrayList<>();

    public void setAutoResponderItemList(List<AutoResponderItem> autoResponderItemList) {
        this.autoResponderList.clear();
        this.autoResponderList.addAll(autoResponderItemList);
    }

    public List<AutoResponderItem> getAutoResponderItemList() {
        return this.autoResponderList;
    }

    public AutoResponderItem findItem(String url) {
        return findItem(url, null);
    }

    public AutoResponderItem findItem(String url, String method) {
        AutoResponderItem matchItem = null;
        for (int i = 0; i < autoResponderList.size(); i++) {
            AutoResponderItem bean = autoResponderList.get(i);
            if (!bean.isSelected()) {
                continue;
            }
            if (method != null && bean.getMethod() != null && !bean.getMethod().equals(method)) {
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

    public void setProperty(AutoResponderProperty property) {
        this.setAutoResponderEnable(property.getAutoResponderEnable());
        this.setRedirectPort(property.getRedirectPort());
        this.setForceHostNameResolv(property.isHostNameForceResolv());
        this.setAutoResponderItemList(property.getAutoResponderItemList());
    }

    @Override
    public String getSettingName() {
        return AUTO_RESPONDER_PROPERTY;
    }

    @Override
    public void saveSetting(String value) {
        AutoResponderProperty property = JsonUtil.jsonFromString(value, AutoResponderProperty.class, true);
        this.setProperty(property);
    }

    @Override
    public String loadSetting() {
        return JsonUtil.jsonToString(this, true);
    }

    @Override
    public String defaultSetting() {
        AutoResponderProperty property = new AutoResponderProperty();
        return JsonUtil.jsonToString(property, true);
    }

}
