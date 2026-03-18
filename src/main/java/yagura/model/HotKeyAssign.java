package yagura.model;

import burp.api.montoya.ui.hotkey.HotKey;
import burp.api.montoya.ui.hotkey.HotKeyEvent;
import burp.api.montoya.ui.hotkey.HotKeyHandler;
import extension.burp.BurpHotKey;
import java.awt.event.KeyEvent;
import javax.swing.KeyStroke;

/**
 *
 * @author isayan
 */
public class HotKeyAssign {

    private final SendToItem sendToItem;
    private final HotKey hotKey;
    private final HotKeyHandler hotKeyHandler;

    public HotKeyAssign(SendToItem sendToItem) {
        this.sendToItem = sendToItem;
        this.hotKey = HotKey.hotKey(sendToItem.getCaption(), sendToItem.getHotKey());
        this.hotKeyHandler = new HotKeyHandler() {
            @Override
            public void handle(HotKeyEvent event) {
                SendToMenuItem actionMenu = sendToItem.getSendToMenuAction(event);
                actionMenu.sendToEvent();
            }
        };
    }

    public boolean isValidHotKey() {
        if (this.hotKey.hotkey() != null && !this.hotKey.hotkey().isEmpty()) {
            KeyStroke ks = BurpHotKey.parseKeyText(this.hotKey.hotkey());
            return (ks.getKeyCode() != KeyEvent.CHAR_UNDEFINED);
        }
        return false;
    }

    /**
     * @return the hotKey
     */
    public HotKey getHotKey() {
        return this.hotKey;
    }

    /**
     * @return the hotKeyHandler
     */
    public HotKeyHandler getHotKeyHandler() {
        return this.hotKeyHandler;
    }

    public SendToItem getSendToItem() {
        return this.sendToItem;
    }

}
