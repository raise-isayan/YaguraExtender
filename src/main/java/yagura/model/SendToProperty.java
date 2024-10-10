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

    public enum SendToMenuPlace {
        DEFAULT("Default"), TOP_LEVEL("Top Level");

        final String ident;

        SendToMenuPlace(String ident) {
            this.ident = ident;
        }

        public String toIdent() {
            return ident;
        }

        public static SendToMenuPlace parseEnumIdent(String name) {
            for (SendToMenuPlace level : SendToMenuPlace.values()) {
                if (level.toIdent().equals(name)) {
                    return level;
                }
            }
            throw new IllegalArgumentException(
                "No enum constant " + SendToMenuPlace.class.getCanonicalName() + "." + name);
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
    private SendToMenuPlace menuPlace = SendToMenuPlace.DEFAULT;

    public SendToMenuPlace getMenuPlace() {
        return this.menuPlace;
    }

    public void setMenuPlace(SendToMenuPlace menuPlace) {
        this.menuPlace = menuPlace;
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
        this.setMenuPlace(property.getMenuPlace());
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
