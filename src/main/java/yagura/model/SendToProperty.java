package yagura.model;

import com.google.gson.annotations.Expose;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 *
 * @author isayan
 */
public class SendToProperty {

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
