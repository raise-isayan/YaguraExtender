package yagura.model;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IMessageEditorController;
import burp.IScanIssue;
import extension.helpers.HttpUtil;
import java.awt.TrayIcon;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JMenuItem;

/**
 * burp new IF
 *
 * @author isayan
 */
public class SendToMenu implements IContextMenuFactory, SendToListener {

    private final static Logger logger = Logger.getLogger(SendToMenu.class.getName());

    private final SendToProperty property;
    private final IBurpExtenderCallbacks callbacks;
    private IContextMenuInvocation invocation;

    private final javax.swing.JMenu mnuSendTo = new javax.swing.JMenu();

    public SendToMenu(IBurpExtenderCallbacks cb, SendToProperty property) {
        this.callbacks = cb;
        this.property = property;

    }
    private final List<JMenuItem> menuList = new ArrayList<>();
    private final List<SendToMenuItem> sendToList = new ArrayList<>();

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        this.invocation = invocation;
        this.renewMenu(this.property);
        return this.menuList;
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
                    SendToExtend sendToItem = new SendToExtend(item, this.invocation);
                    if (sendToItem.getExtend() == SendToItem.ExtendType.PASTE_FROM_CLIPBOARD) {
                        javax.swing.JMenu mnuItem = new javax.swing.JMenu();
                        mnuItem.setText(item.getCaption());
                        List<String> encodingList = BurpExtender.getInstance().getSelectEncodingList();
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
                        mnuItem.setText(item.getCaption());
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
                    mnuItem.setText(item.getCaption());
                    if (item.isServer()) {
                        SendToMenuItem sendToItem = new SendToServer(item, this.invocation);
                        sendToItem.addSendToListener(new SendToListener() {
                            @Override
                            public void complete(SendToEvent evt) {
                            }

                            @Override
                            public void warning(SendToEvent evt) {
                                BurpExtender.issueAlert("SendToServer", evt.getMessage(), TrayIcon.MessageType.WARNING);
                                logger.log(Level.WARNING, evt.getMessage());
                            }

                            @Override
                            public void error(SendToEvent evt) {
                                BurpExtender.issueAlert("SendToServer", evt.getMessage(), TrayIcon.MessageType.ERROR);
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
                        SendToMenuItem sendToItem = new SendToMultiEditor(item, this.invocation);
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

    public void showBurpMenu(IMessageEditorController controller, MouseEvent e) {
        showBurpMenu(this.getSendToMessage(controller), e);
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
        javax.swing.JMenuItem mnuSpider = new javax.swing.JMenuItem();
        mnuSpider.setText("Sendto Spider");
        mnuSpider.addActionListener(new java.awt.event.ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                sendToSpider(message);
            }
        });
        this.popBurpMenu.add(mnuSpider);
        if (message.isExtendVisible()) {
            this.popBurpMenu.addSeparator();
            List<SendToItem> sendToItemList = property.getSendToItemList();
            for (SendToItem item : sendToItemList) {
                if (item.isSelected()) {
                    javax.swing.JMenuItem mnuItem = new javax.swing.JMenuItem();
                    mnuItem.setText(item.getCaption());
                    if (item.getExtend() != null) {
                        final SendToExtend sendToItem = new SendToExtend(item, this.invocation);
                        mnuItem.addActionListener(new ActionListener() {
                            @Override
                            public void actionPerformed(ActionEvent e) {
                                sendToItem.menuItemClicked(mnuItem.getText(), message.getSelectedMessages());
                            }
                        });
                        this.popBurpMenu.add(mnuItem);
                    } else {
                        if (item.isServer()) {
                            final SendToMenuItem sendToItem = new SendToServer(item, this.invocation);
                            sendToItem.addSendToListener(this);
                            mnuItem.addActionListener(new ActionListener() {
                                @Override
                                public void actionPerformed(ActionEvent e) {
                                    sendToItem.menuItemClicked(mnuItem.getText(), message.getSelectedMessages());
                                }
                            });
                            this.popBurpMenu.add(mnuItem);
                        } else {
                            final SendToMenuItem sendToItem = new SendToMultiEditor(item, this.invocation);
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
        return popBurpMenu;
    }

    private int repeternum = 0;

    public SendToMessage getSendToMessage(IMessageEditorController controller) {
        return new SendToMessage() {
            @Override
            public IHttpRequestResponse[] getSelectedMessages() {
                return new IHttpRequestResponse[]{
                    new IHttpRequestResponse() {
                        @Override
                        public byte[] getRequest() {
                            return controller.getRequest();
                        }

                        @Override
                        public void setRequest(byte[] bytes) {

                        }

                        @Override
                        public byte[] getResponse() {
                            return controller.getResponse();
                        }

                        @Override
                        public void setResponse(byte[] bytes) {

                        }

                        @Override
                        public String getComment() {
                            return null;
                        }

                        @Override
                        public void setComment(String string) {
                        }

                        @Override
                        public String getHighlight() {
                            return null;
                        }

                        @Override
                        public void setHighlight(String string) {
                        }

                        @Override
                        public IHttpService getHttpService() {
                            return controller.getHttpService();
                        }

                        @Override
                        public void setHttpService(IHttpService ihs) {

                        }

                    }
                };
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

    private IContextMenuInvocation getContextMenuInvocation(KeyEvent evt, IHttpRequestResponse[] messageInfo) {
        return new IContextMenuInvocation() {
            @Override
            public InputEvent getInputEvent() {
                return evt;
            }

            @Override
            public int getToolFlag() {
                return IBurpExtenderCallbacks.TOOL_PROXY;
            }

            @Override
            public byte getInvocationContext() {
                return IContextMenuInvocation.CONTEXT_PROXY_HISTORY;
            }

            @Override
            public int[] getSelectionBounds() {
                return null;
            }

            @Override
            public IHttpRequestResponse[] getSelectedMessages() {
                return messageInfo;
            }

            @Override
            public IScanIssue[] getSelectedIssues() {
                return null;
            }

        };
    }

    public void sendToRepeater(SendToMessage message) {
        try {
            IHttpRequestResponse[] messageItem = message.getSelectedMessages();
            IHttpService httpService = messageItem[0].getHttpService();
            callbacks.sendToRepeater(httpService.getHost(), httpService.getPort(), HttpUtil.isSSL(httpService.getProtocol()),
                    messageItem[0].getRequest(), "v" + this.repeternum++);
        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }

    public void sendToIntruder(SendToMessage message) {
        try {
            IHttpRequestResponse[] messageItem = message.getSelectedMessages();
            IHttpService httpService = messageItem[0].getHttpService();
            callbacks.sendToIntruder(httpService.getHost(), httpService.getPort(), HttpUtil.isSSL(httpService.getProtocol()),
                    messageItem[0].getRequest());
        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }

    public void sendToSpider(SendToMessage message) {
        try {
            IHttpRequestResponse[] messageItem = message.getSelectedMessages();
            callbacks.sendToSpider(BurpExtender.getHelpers().getURL(messageItem[0]));
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
        this.callbacks.issueAlert(evt.getMessage());
    }

}
