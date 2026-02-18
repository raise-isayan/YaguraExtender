package yagura.model;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.hotkey.HotKey;
import burp.api.montoya.ui.hotkey.HotKeyEvent;
import burp.api.montoya.ui.hotkey.HotKeyHandler;
import extension.burp.BurpHotKey;
import java.awt.event.KeyEvent;
import java.util.List;
import javax.swing.KeyStroke;

/**
 *
 * @author isayan
 */
public class HotKeyAssign {

    private final SendToMenuItem sendToMenuItem;
    private final HotKey hotKey;
    private final HotKeyHandler hotKeyHandler;

    public HotKeyAssign(SendToMenuItem sendToMenuItem) {
        this.sendToMenuItem = sendToMenuItem;
        this.hotKey = HotKey.hotKey(sendToMenuItem.getCaption(), sendToMenuItem.getHotKey());
        this.hotKeyHandler = new HotKeyHandler() {
            @Override
            public void handle(HotKeyEvent event) {
                List<HttpRequestResponse> list = event.selectedRequestResponses();
                sendToMenuItem.sendToEvent(list);
            }
        };
    }

    public boolean isValidHotKey() {
        KeyStroke ks = BurpHotKey.parseKeyText(this.hotKey.hotkey());        
        return (ks.getKeyCode() != KeyEvent.CHAR_UNDEFINED);
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

    public SendToMenuItem getSendToMenuItem() {
        return this.sendToMenuItem;
    }

}
