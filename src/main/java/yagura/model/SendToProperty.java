package yagura.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 *
 * @author isayan
 */
public class SendToProperty {

    private final List<SendToItem> sendToItemList = new ArrayList<SendToItem>();

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

    private boolean submenu = false;

    public boolean isSubMenu() {
        return this.submenu;
    }

    public void setSubMenu(boolean submenu) {
        this.submenu = submenu;
    }

    public void setProperty(SendToProperty property) {
        this.setSendToItemList(property.getSendToItemList());
        this.setSubMenu(property.isSubMenu());
    }

}
