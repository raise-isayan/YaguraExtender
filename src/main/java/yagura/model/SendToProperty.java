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
public class SendToProperty implements IPropertyConfig {

    public final static String SENDTO_PROPERTY = "sendToProperty";

    public enum SendToMenuLevel {
        DEFAULT("Default"), TOP_LEVEL("Top Level");

        final String ident;

        SendToMenuLevel(String ident) {
            this.ident = ident;
        }

        public String toIdent() {
            return ident;
        }

        public static SendToMenuLevel parseEnum(String name) {
            for (SendToMenuLevel level : SendToMenuLevel.values()) {
                if (level.toIdent().equals(name)) {
                    return level;
                }
            }
            throw new IllegalArgumentException(
                "No enum constant " + SendToMenuLevel.class.getCanonicalName() + "." + name);
        }

    };

    @Expose
    private final List<SendToItem> sendToItemList = new ArrayList<>();

    /**
     * @return the sendToList
     */
    public List<SendToItem> getSendToItemList() {
        return Collections.unmodifiableList(this.sendToItemList);
    }

    /**
     * @param sendToItemList
     */
    public void setSendToItemList(List<SendToItem> sendToItemList) {
        this.sendToItemList.clear();
        this.sendToItemList.addAll(sendToItemList);
    }

    @Expose
    private SendToMenuLevel menuPlaceLevel = SendToMenuLevel.DEFAULT;

    public SendToMenuLevel getMenuPlaceLevel() {
        return this.menuPlaceLevel;
    }

    public void setMenuPlaceLevel(SendToMenuLevel menuPlaceLevel) {
        this.menuPlaceLevel = menuPlaceLevel;
    }

    @Expose
    private boolean submenu = false;

    public boolean isSubMenu() {
        return this.submenu;
    }

    public void setSubMenu(boolean submenu) {
        this.submenu = submenu;
    }

    @Expose
    private boolean forceSortOrder = false;

    /**
     * @return the forceSortOrder
     */
    public boolean isForceSortOrder() {
        return forceSortOrder;
    }

    /**
     * @param forceSortOrder the forceSortOrder to set
     */
    public void setForceSortOrder(boolean forceSortOrder) {
        this.forceSortOrder = forceSortOrder;
    }

    public void setProperty(SendToProperty property) {
        this.setSendToItemList(property.getSendToItemList());
        this.setMenuPlaceLevel(property.getMenuPlaceLevel());
        this.setSubMenu(property.isSubMenu());
        this.setForceSortOrder(property.isForceSortOrder());
    }

    @Override
    public String getSettingName() {
        return SENDTO_PROPERTY;
    }

    @Override
    public void saveSetting(String value) {
        SendToProperty property = JsonUtil.jsonFromString(value, SendToProperty.class, true);
        this.setProperty(property);
    }

    @Override
    public String loadSetting() {
        return JsonUtil.jsonToString(this, true);
    }

    @Override
    public String defaultSetting() {
        SendToProperty property = new SendToProperty();
        return JsonUtil.jsonToString(property, true);
    }

}
