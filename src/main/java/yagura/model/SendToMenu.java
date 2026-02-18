package yagura.model;

import burp.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import extend.util.external.TransUtil;
import extension.burp.IssueAlert;
import extension.helpers.StringUtil;
import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JMenuItem;
import yagura.handler.MenuHander;

/**
 * burp new IF
 *
 * @author isayan
 */
public final class SendToMenu implements ContextMenuItemsProvider {
    private final static Logger logger = Logger.getLogger(SendToMenu.class.getName());
    private final MontoyaApi api;
    private final BurpExtension extenderImpl;

    private final SendToProperty property;
    private ContextMenuEvent contextMenuEvent;
    private final List<HotKeyAssign> hotKeyss = new ArrayList<>();
    private final IssueAlert issueAlert;

    private final javax.swing.JMenu mnuSendTo = new javax.swing.JMenu();

    public SendToMenu(MontoyaApi api, SendToProperty property) {
        this.api = api;
        this.extenderImpl = BurpExtension.getInstance();
        this.property = property;
        this.issueAlert = new IssueAlert(api);
    }

    private final List<Component> menuList = new ArrayList<>();

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent contextMenuEvent) {
        this.contextMenuEvent = contextMenuEvent;
        this.renewMenu(this.property);
        return this.menuList;
    }

    public void changeSendToMenu() {
        if (!this.menuList.isEmpty()) {
            if (this.menuList.get(0) instanceof javax.swing.JMenuItem menuItem) {
                MenuHander.changeContextMenuLevel(menuItem, this.property.getMenuPlace());
            }
        }
    }

    /**
     * @return the contextMenu
     */
    public ContextMenuEvent getContextMenu() {
        return this.contextMenuEvent;
    }

    private SendToMenuItem getMenuItemCaption(boolean forceSortOrder, int ord, SendToMenuItem menuItem) {
        if (forceSortOrder) {
            String caption = TransUtil.getOrderdChar(ord) + ") " + menuItem.getCaption();
            menuItem.setCaption(caption);
        }
        return menuItem;
    }

    private String getMenuItemCaption(boolean forceSortOrder, int ord, String caption) {
        if (forceSortOrder) {
            return TransUtil.getOrderdChar(ord) + ") " + caption;
        } else {
            return caption;
        }
    }

    private int getMenuItemCount(boolean isSubmenu) {
        if (isSubmenu) {
            return this.mnuSendTo.getItemCount();
        } else {
            return this.menuList.size();
        }
    }

    public void renewMenu() {
        this.renewMenu(this.property);
    }

    public void renewMenu(SendToProperty property) {
        this.mnuSendTo.setText("Send To");
        this.menuList.clear();
        this.mnuSendTo.removeAll();
        this.hotKeyss.clear();
        List<SendToItem> sendToItemList = property.getSendToItemList();
        List<javax.swing.JMenuItem> sendToList = new ArrayList<>();
        for (SendToItem item : sendToItemList) {
            if (item.isSelected()) {
                if (item.getExtend() != null) {
                    final SendToExtend sendToItem = new SendToExtend(item, this.contextMenuEvent);
                    if (sendToItem.getExtend() == SendToItem.ExtendType.PASTE_FROM_CLIPBOARD) {
                        // 解釈する文字コード一覧を追加
                        javax.swing.JMenu mnuItem = new javax.swing.JMenu();
                        mnuItem.setText(getMenuItemCaption(property.isForceSortOrder(), sendToList.size(), item.getCaption()));
                        List<String> encodingList = extenderImpl.getSelectEncodingList();
                        for (String encoding : encodingList) {
                            javax.swing.JMenuItem mnuItemEncoding = new javax.swing.JMenuItem();
                            mnuItemEncoding.setText(encoding);
                            mnuItemEncoding.addActionListener(sendToItem);
                            mnuItem.add(mnuItemEncoding);
                        }
                        if (sendToItem.isEnabled()) {
                            sendToList.add(mnuItem);
                        }
                    } else {
                        javax.swing.JMenuItem mnuItem = new javax.swing.JMenuItem();
                        mnuItem.setText(getMenuItemCaption(property.isForceSortOrder(), sendToList.size(), item.getCaption()));
                        mnuItem.addActionListener(sendToItem);
                        if (sendToItem.isEnabled()) {
                            sendToList.add(mnuItem);
                        }
                    }
                } else {
                    javax.swing.JMenuItem mnuItem = new javax.swing.JMenuItem();
                    mnuItem.setText(getMenuItemCaption(property.isForceSortOrder(), sendToList.size(), item.getCaption()));
                    if (item.isServer()) {
                        SendToMenuItem sendToItem = new SendToServer(item, this.contextMenuEvent);
                        sendToItem.addIssueAlertListener(this.issueAlert);
                        mnuItem.addActionListener(sendToItem);
                        if (sendToItem.isEnabled()) {
                            sendToList.add(mnuItem);
                        }
                    } else {
                        SendToMenuItem sendToItem = new SendToMultiEditor(item, this.contextMenuEvent);
                        mnuItem.addActionListener(sendToItem);
                        if (sendToItem.isEnabled()) {
                            sendToList.add(mnuItem);
                        }
                    }
                }
            }
        }

        if (property.isSubMenu()) {
            for (JMenuItem sendToItem : sendToList) {
                this.mnuSendTo.add(sendToItem);
            }
            this.menuList.add(this.mnuSendTo);
        } else {
            this.menuList.addAll(sendToList);
        }

    }

    public HotKeyAssign newHotKey(SendToMenuItem sendToMenuItem) {
        HotKeyAssign hotKey = new HotKeyAssign(sendToMenuItem);
        if (hotKey.isValidHotKey()) {
            return hotKey;
        }
        else {
            return null;
        }
    }

    /**
     * @return the hotKeyss
     */
    public List<HotKeyAssign> getHotKeys() {
        return this.hotKeyss;
    }

    private final javax.swing.JPopupMenu popBurpMenu = new javax.swing.JPopupMenu();

    public void showBurpMenu(HttpRequestResponse httpRequestResponse, MouseEvent e) {
        showBurpMenu(this.getSendToMessage(httpRequestResponse), e);
    }

    public void showBurpMenu(SendToMessage message, java.awt.event.MouseEvent evt) {
        if (evt.getButton() == java.awt.event.MouseEvent.BUTTON3) {
            this.getPopupMenu(message);
            this.popBurpMenu.show(evt.getComponent(), evt.getX(), evt.getY());
        }
    }

    public javax.swing.JPopupMenu appendSendToMenu(javax.swing.JPopupMenu popSendToMenu, final SendToMessage message, ContextMenuEvent contextMenuEvent) {

        final javax.swing.JMenuItem mnuRepeater = new javax.swing.JMenuItem();
        mnuRepeater.setText("Send to Repeater");
        mnuRepeater.addActionListener(new java.awt.event.ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                sendToRepeater(message);
            }
        });
        popSendToMenu.add(mnuRepeater);

        final javax.swing.JMenuItem mnuIntruder = new javax.swing.JMenuItem();
        mnuIntruder.setText("Snd to Intruder");
        mnuIntruder.addActionListener(new java.awt.event.ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                sendToIntruder(message);
            }
        });
        popSendToMenu.add(mnuIntruder);

        final javax.swing.JMenuItem mnuOrganizer = new javax.swing.JMenuItem();
        mnuOrganizer.setText("Snd to Organizer");
        mnuOrganizer.addActionListener(new java.awt.event.ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                sendToOrganizer(message);
            }
        });
        popSendToMenu.add(mnuOrganizer);

        String selectText = message.getSelectedText();
        if (selectText != null) {
            final javax.swing.JMenuItem mnuDecoder = new javax.swing.JMenuItem();
            mnuDecoder.setText("Send to Decoder");
            mnuDecoder.addActionListener(new java.awt.event.ActionListener() {
                @Override
                public void actionPerformed(java.awt.event.ActionEvent evt) {
                    sendToDecoder(StringUtil.getBytesRaw(selectText));
                }
            });
            popSendToMenu.add(mnuDecoder);
            final javax.swing.JMenuItem mnuComparer = new javax.swing.JMenuItem();
            mnuComparer.setText("Send to Comparer");
            mnuComparer.addActionListener(new java.awt.event.ActionListener() {
                @Override
                public void actionPerformed(java.awt.event.ActionEvent evt) {
                    sendToComparer(StringUtil.getBytesRaw(selectText));
                }
            });
            popSendToMenu.add(mnuComparer);
        }
        if (message.isExtendVisible()) {
            popSendToMenu.addSeparator();
            List<SendToItem> sendToItemList = property.getSendToItemList();
            for (SendToItem item : sendToItemList) {
                if (item.isSelected()) {
                    final javax.swing.JMenuItem mnuItem = new javax.swing.JMenuItem();
                    mnuItem.setText(item.getCaption());
                    if (item.getExtend() != null) {
                        final SendToExtend sendToItem = new SendToExtend(item, contextMenuEvent);
                        mnuItem.addActionListener(new ActionListener() {
                            @Override
                            public void actionPerformed(ActionEvent e) {
                                sendToItem.menuItemClicked(mnuItem.getText(), message);
                            }
                        });
                        popSendToMenu.add(mnuItem);
                    } else {
                        if (item.isServer()) {
                            final SendToMenuItem sendToItem = new SendToServer(item, contextMenuEvent);
                            sendToItem.addIssueAlertListener(this.issueAlert);
                            mnuItem.addActionListener(new ActionListener() {
                                @Override
                                public void actionPerformed(ActionEvent e) {
                                    sendToItem.menuItemClicked(mnuItem.getText(), message);
                                }
                            });
                            popSendToMenu.add(mnuItem);
                        } else {
                            final SendToMenuItem sendToItem = new SendToMultiEditor(item, contextMenuEvent);
                            mnuItem.addActionListener(new ActionListener() {
                                @Override
                                public void actionPerformed(ActionEvent e) {
                                    sendToItem.menuItemClicked(mnuItem.getText(), message);
                                }
                            });
                            popSendToMenu.add(mnuItem);
                        }
                    }
                }
            }
        }
        return popSendToMenu;
    }

    protected javax.swing.JPopupMenu getPopupMenu(final SendToMessage message) {
        this.popBurpMenu.removeAll();
        this.appendSendToMenu(this.popBurpMenu, message, this.contextMenuEvent);
        return this.popBurpMenu;
    }

    private int repeternum = 0;

    public SendToMessage getSendToMessage(HttpRequestResponse httpRequestResponse) {
        return new SendToMessage() {
            @Override
            public List<HttpRequestResponse> getSelectedMessages() {
                List<HttpRequestResponse> selectedMesage = new ArrayList<>();
                selectedMesage.add(httpRequestResponse);
                return selectedMesage;
            }

            @Override
            public String getSelectedText() {
                return null;
            }

            @Override
            public boolean isExtendVisible() {
                return false;
            }

        };
    }

    public void sendToRepeater(SendToMessage message) {
        try {
            List<HttpRequestResponse> messageItem = message.getSelectedMessages();
            if (!messageItem.isEmpty()) {
                HttpRequest httpRequest = messageItem.get(0).request();
                this.api.repeater().sendToRepeater(httpRequest, "v" + this.repeternum++);
            }
        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }

    public void sendToIntruder(SendToMessage message) {
        try {
            List<HttpRequestResponse> messageItem = message.getSelectedMessages();
            if (!messageItem.isEmpty()) {
                HttpRequest httpRequest = messageItem.get(0).request();
                this.api.intruder().sendToIntruder(httpRequest);
            }
        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }

    public void sendToOrganizer(SendToMessage message) {
        try {
            List<HttpRequestResponse> messageItem = message.getSelectedMessages();
            if (!messageItem.isEmpty()) {
                HttpRequestResponse httpRequestResponse = messageItem.get(0);
                if (!httpRequestResponse.hasResponse()) {
                    this.api.organizer().sendToOrganizer(httpRequestResponse.request());
                }
                else {
                    this.api.organizer().sendToOrganizer(httpRequestResponse);
                }
            }
        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }

    public void sendToCompareRequest(SendToMessage message) {
        try {
            List<HttpRequestResponse> messageItem = message.getSelectedMessages();
            if (!messageItem.isEmpty()) {
                HttpRequestResponse httpRequestResponse = messageItem.get(0);
                this.api.comparer().sendToComparer(httpRequestResponse.request().toByteArray());
            }
        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }

    public void sendToCompareResponse(SendToMessage message) {
        try {
            List<HttpRequestResponse> messageItem = message.getSelectedMessages();
            if (!messageItem.isEmpty()) {
                HttpRequestResponse httpRequestResponse = messageItem.get(0);
                if (httpRequestResponse.hasResponse()) {
                    this.api.comparer().sendToComparer(httpRequestResponse.response().toByteArray());
                }
            }
        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }

    public void sendTo(SendToMessage message) {
        try {
            List<HttpRequestResponse> messageItem = message.getSelectedMessages();
            if (!messageItem.isEmpty()) {
                HttpRequest httpRequest = messageItem.get(0).request();
                this.api.repeater().sendToRepeater(httpRequest, "v" + this.repeternum++);
            }
        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }

    public void sendToDecoder(byte[] message) {
        try {
            this.api.decoder().sendToDecoder(ByteArray.byteArray(message));
        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }

    public void sendToComparer(byte[] message) {
        try {
            this.api.comparer().sendToComparer(ByteArray.byteArray(message));
        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }

}
