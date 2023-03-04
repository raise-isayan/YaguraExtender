package yagura.model;

import burp.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import extend.util.external.TransUtil;
import extension.burp.MessageType;
import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * burp new IF
 *
 * @author isayan
 */
public class SendToMenu implements ContextMenuItemsProvider, SendToListener {

    private final static Logger logger = Logger.getLogger(SendToMenu.class.getName());

    private final SendToProperty property;
    private final MontoyaApi api;
    private ContextMenuEvent contextMenuEvent;

    private final javax.swing.JMenu mnuSendTo = new javax.swing.JMenu();

    public SendToMenu(MontoyaApi api, SendToProperty property) {
        this.api = api;
        this.property = property;

    }
    private final List<Component> menuList = new ArrayList<>();
    private final List<SendToMenuItem> sendToList = new ArrayList<>();

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent contextMenuEvent) {
        this.contextMenuEvent = contextMenuEvent;
        this.renewMenu(this.property);
        return this.menuList;
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

    public void renewMenu(SendToProperty property) {
        this.mnuSendTo.setText("Send To");
        this.sendToList.clear();
        this.menuList.clear();
        if (property.isSubMenu()) {
            this.mnuSendTo.removeAll();
            this.menuList.add(this.mnuSendTo);
        }
        List<SendToItem> sendToItemList = property.getSendToItemList();
        for (SendToItem item : sendToItemList) {
            if (item.isSelected()) {
                if (item.getExtend() != null) {
                    SendToExtend sendToItem = new SendToExtend(item, this.contextMenuEvent);
                    if (sendToItem.getExtend() == SendToItem.ExtendType.PASTE_FROM_CLIPBOARD) {
                        javax.swing.JMenu mnuItem = new javax.swing.JMenu();
                        mnuItem.setText(getMenuItemCaption(property.isForceSortOrder(), getMenuItemCount(property.isSubMenu()), item.getCaption()));
                        List<String> encodingList = BurpExtension.getInstance().getSelectEncodingList();
                        for (String encoding : encodingList) {
                            javax.swing.JMenuItem mnuItemEncoding = new javax.swing.JMenuItem();
                            mnuItemEncoding.setText(encoding);
                            mnuItemEncoding.addActionListener(sendToItem);
                            mnuItem.add(mnuItemEncoding);
                        }
                        if (property.isSubMenu()) {
                            if (sendToItem.isEnabled()) {
                                this.mnuSendTo.add(mnuItem);
                            }
                        } else {
                            if (sendToItem.isEnabled()) {
                                this.menuList.add(mnuItem);
                            }
                        }
                    } else {
                        javax.swing.JMenuItem mnuItem = new javax.swing.JMenuItem();
                        mnuItem.setText(getMenuItemCaption(property.isForceSortOrder(), getMenuItemCount(property.isSubMenu()), item.getCaption()));
                        sendToList.add(sendToItem);
                        mnuItem.addActionListener(sendToItem);
                        if (property.isSubMenu()) {
                            if (sendToItem.isEnabled()) {
                                this.mnuSendTo.add(mnuItem);
                            }
                        } else {
                            if (sendToItem.isEnabled()) {
                                this.menuList.add(mnuItem);
                            }
                        }
                    }
                } else {
                    javax.swing.JMenuItem mnuItem = new javax.swing.JMenuItem();
                    mnuItem.setText(getMenuItemCaption(property.isForceSortOrder(), getMenuItemCount(property.isSubMenu()), item.getCaption()));
                    if (item.isServer()) {
                        SendToMenuItem sendToItem = new SendToServer(item, this.contextMenuEvent);
                        sendToItem.addSendToListener(new SendToListener() {
                            @Override
                            public void complete(SendToEvent evt) {
                            }

                            @Override
                            public void warning(SendToEvent evt) {
                                BurpExtension.helpers().issueAlert("SendToServer", evt.getMessage(), MessageType.INFO);
                                logger.log(Level.WARNING, evt.getMessage());
                            }

                            @Override
                            public void error(SendToEvent evt) {
                                BurpExtension.helpers().issueAlert("SendToServer", evt.getMessage(), MessageType.ERROR);
                                logger.log(Level.SEVERE, evt.getMessage());
                            }

                        });
                        sendToList.add(sendToItem);
                        mnuItem.addActionListener(sendToItem);
                        if (property.isSubMenu()) {
                            if (sendToItem.isEnabled()) {
                                this.mnuSendTo.add(mnuItem);
                            }
                        } else {
                            if (sendToItem.isEnabled()) {
                                this.menuList.add(mnuItem);
                            }
                        }
                    } else {
                        SendToMenuItem sendToItem = new SendToMultiEditor(item, this.contextMenuEvent);
                        sendToList.add(sendToItem);
                        mnuItem.addActionListener(sendToItem);
                        if (property.isSubMenu()) {
                            if (sendToItem.isEnabled()) {
                                this.mnuSendTo.add(mnuItem);
                            }
                        } else {
                            if (sendToItem.isEnabled()) {
                                this.menuList.add(mnuItem);
                            }
                        }
                    }
                }
            }
        }

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

    protected javax.swing.JPopupMenu getPopupMenu(final SendToMessage message) {
        this.popBurpMenu.removeAll();
        javax.swing.JMenuItem mnuRepeater = new javax.swing.JMenuItem();
        mnuRepeater.setText("Sendto Repeater");
        mnuRepeater.addActionListener(new java.awt.event.ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                sendToRepeater(message);
            }
        });
        this.popBurpMenu.add(mnuRepeater);
        javax.swing.JMenuItem mnuIntruder = new javax.swing.JMenuItem();
        mnuIntruder.setText("Sndto Intruder");
        mnuIntruder.addActionListener(new java.awt.event.ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                sendToIntruder(message);
            }
        });
        this.popBurpMenu.add(mnuIntruder);
//        javax.swing.JMenuItem mnuSpider = new javax.swing.JMenuItem();
//        mnuSpider.setText("Sendto Spider");
//        mnuSpider.addActionListener(new java.awt.event.ActionListener() {
//            @Override
//            public void actionPerformed(java.awt.event.ActionEvent evt) {
//                sendToSpider(message);
//            }
//        });
//        this.popBurpMenu.add(mnuSpider);
        if (message.isExtendVisible()) {
            this.popBurpMenu.addSeparator();
            List<SendToItem> sendToItemList = property.getSendToItemList();
            for (SendToItem item : sendToItemList) {
                if (item.isSelected()) {
                    javax.swing.JMenuItem mnuItem = new javax.swing.JMenuItem();
                    mnuItem.setText(item.getCaption());
                    if (item.getExtend() != null) {
                        final SendToExtend sendToItem = new SendToExtend(item, this.contextMenuEvent);
                        mnuItem.addActionListener(new ActionListener() {
                            @Override
                            public void actionPerformed(ActionEvent e) {
                                sendToItem.menuItemClicked(mnuItem.getText(), message.getSelectedMessages());
                            }
                        });
                        this.popBurpMenu.add(mnuItem);
                    } else {
                        if (item.isServer()) {
                            final SendToMenuItem sendToItem = new SendToServer(item, this.contextMenuEvent);
                            sendToItem.addSendToListener(this);
                            mnuItem.addActionListener(new ActionListener() {
                                @Override
                                public void actionPerformed(ActionEvent e) {
                                    sendToItem.menuItemClicked(mnuItem.getText(), message.getSelectedMessages());
                                }
                            });
                            this.popBurpMenu.add(mnuItem);
                        } else {
                            final SendToMenuItem sendToItem = new SendToMultiEditor(item, this.contextMenuEvent);
                            mnuItem.addActionListener(new ActionListener() {
                                @Override
                                public void actionPerformed(ActionEvent e) {
                                    sendToItem.menuItemClicked(mnuItem.getText(), message.getSelectedMessages());
                                }
                            });
                            this.popBurpMenu.add(mnuItem);
                        }
                    }
                }
            }
        }
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

//    private ContextMenuEvent getContextMenuInvocation(KeyEvent evt, HttpRequestResponse messageInfo) {
//        return new ContextMenuEvent() {
//            @Override
//            public InputEvent getInputEvent() {
//                return evt;
//            }
//
//            @Override
//            public int getToolFlag() {
//                return IBurpExtenderCallbacks.TOOL_PROXY;
//            }
//
//            @Override
//            public byte getInvocationContext() {
//                return IContextMenuInvocation.CONTEXT_PROXY_HISTORY;
//            }
//
//            @Override
//            public int[] getSelectionBounds() {
//                return null;
//            }
//
//            @Override
//            public IHttpRequestResponse[] getSelectedMessages() {
//                return messageInfo;
//            }
//
//            @Override
//            public IScanIssue[] getSelectedIssues() {
//                return null;
//            }
//
//            @Override
//            public Optional<MessageEditorHttpRequestResponse> messageEditorRequestResponse() {
//                throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
//            }
//
//            @Override
//            public List<HttpRequestResponse> selectedRequestResponses() {
//                throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
//            }
//
//            @Override
//            public List<AuditIssue> selectedIssues() {
//                throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
//            }
//
//            @Override
//            public InputEvent inputEvent() {
//                throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
//            }
//
//            @Override
//            public ToolType toolType() {
//                throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
//            }
//
//            @Override
//            public boolean isFromTool(ToolType... tts) {
//                throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
//            }
//
//            @Override
//            public InvocationType invocationType() {
//                throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
//            }
//
//            @Override
//            public boolean isFrom(InvocationType... its) {
//                throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
//            }
//
//        };
//    }
    public void sendToRepeater(SendToMessage message) {
        try {
            List<HttpRequestResponse> messageItem = message.getSelectedMessages();
            HttpRequest httpRequest = messageItem.get(0).request();
            this.api.repeater().sendToRepeater(httpRequest, "v" + this.repeternum++);
        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }

    public void sendToIntruder(SendToMessage message) {
        try {
            List<HttpRequestResponse> messageItem = message.getSelectedMessages();
            HttpRequest httpRequest = messageItem.get(0).request();
            this.api.intruder().sendToIntruder(httpRequest);
        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }

    @Override
    public void complete(SendToEvent evt) {
    }

    @Override
    public void warning(SendToEvent evt) {
    }

    @Override
    public void error(SendToEvent evt) {
        this.api.logging().raiseErrorEvent(evt.getMessage());
    }

}
