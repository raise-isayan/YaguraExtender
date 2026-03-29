package yagura.handler;

import burp.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import extension.burp.BurpConfig;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import yagura.model.HotKeyAssign;
import yagura.model.SendToItem;
import yagura.model.SendToProperty;

/**
 *
 * @author isayan
 */
public class HotKeyHander {

    private final MontoyaApi api;
    private final BurpExtension extenderImpl;
    private final SendToProperty sendto;
    private final List<Registration> registerHotkeys = Collections.synchronizedList(new ArrayList<>());

    public HotKeyHander(MontoyaApi api) {
        this.api = api;
        this.extenderImpl = BurpExtension.getInstance();
        this.sendto = extenderImpl.getProperty().getSendToProperty();
    }

    public boolean isSupport() {
        return BurpConfig.isSupportApi(api, BurpConfig.SupportApi.BURPSUITE_HOTKEY);
    }

    public synchronized void registers() {
        List<SendToItem> itemLists = this.sendto.getSendToItemList();
        for (SendToItem sendToItem : itemLists) {
            HotKeyAssign keyAssign = new HotKeyAssign(sendToItem);
            if (keyAssign.isValidHotKey()) {
                Registration regster = this.api.userInterface().registerHotKeyHandler(keyAssign.getHotKey(), keyAssign.getHotKeyHandler());
                this.registerHotkeys.add(regster);
            }
        }
    }

    public synchronized void deregisters() {
        for (Registration reg : this.registerHotkeys) {
            reg.deregister();
        }
        this.registerHotkeys.clear();
    }

    public boolean exists(String hotkey) {
        List<BurpConfig.Hotkey> hks = BurpConfig.getHotkey(this.api);
        boolean matchs = hks.stream().anyMatch(predicate -> hotkey.equals(predicate.getHotkey()));
        if (!matchs) {
            List<SendToItem> itemLists = this.sendto.getSendToItemList();
            matchs = itemLists.stream().anyMatch(predicate -> hotkey.equals(predicate.getHotKey()));
        }
        return matchs;
    }

}
