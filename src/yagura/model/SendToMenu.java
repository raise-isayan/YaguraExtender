package yagura.model;

import burp.IBurpExtenderCallbacks;
import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import extend.util.BurpWrap;
import extend.util.HttpUtil;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
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
public class SendToMenu implements IContextMenuFactory,SendToListener {

    private final SendToProperty property;
    private final IBurpExtenderCallbacks callbacks;
    private IContextMenuInvocation invocation;

    private final javax.swing.JMenu mnuSendTo = new javax.swing.JMenu();

    public SendToMenu(IBurpExtenderCallbacks cb, SendToProperty property) {
        this.callbacks = cb;
        this.property = property;

    }
    private final List<JMenuItem> menuList = new ArrayList<JMenuItem>();

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        this.invocation = invocation;
        this.renewMenu(this.property);
        return this.menuList;
    }
    
    public void renewMenu(SendToProperty property) {
        this.mnuSendTo.setText("Send To");
        this.menuList.clear();
        if (property.isSubMenu()) {
            this.mnuSendTo.removeAll();
            this.menuList.add(this.mnuSendTo);
        }
        List<SendToItem> sendToItemList = property.getSendToItemList();
        for (SendToItem item : sendToItemList) {
            if (item.isSelected()) {
                javax.swing.JMenuItem mnuItem = new javax.swing.JMenuItem();
                mnuItem.setText(item.getCaption());
                if (item.getExtend() != null) {
                    SendToExtend sendToItem = new SendToExtend(item, this.invocation);
                    mnuItem.addActionListener(sendToItem);
                    if (property.isSubMenu()) {
                        if (sendToItem.isEnabled()) this.mnuSendTo.add(mnuItem);                                                
                    } else {
                        if (sendToItem.isEnabled()) this.menuList.add(mnuItem);                        
                    }                    
                } else {
                    if (item.isServer()) {
                        SendToMenuItem sendToItem = new SendToServer(item, this.invocation);
                        mnuItem.addActionListener(sendToItem);
                        if (property.isSubMenu()) {
                            if (sendToItem.isEnabled()) this.mnuSendTo.add(mnuItem);                                                
                        } else {
                            if (sendToItem.isEnabled()) this.menuList.add(mnuItem);                        
                        }                    
                    } else {
                        SendToMenuItem sendToItem = new SendToMultiEditor(item, this.invocation);
                        mnuItem.addActionListener(sendToItem);
                        if (property.isSubMenu()) {
                            if (sendToItem.isEnabled()) this.mnuSendTo.add(mnuItem);                                                
                        } else {
                            if (sendToItem.isEnabled()) this.menuList.add(mnuItem);                        
                        }                    
                    }
                }                        
            }            
        }            
        
    }

    private final javax.swing.JPopupMenu popBurpMenu = new javax.swing.JPopupMenu();
    
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
                                 sendToItem.menuItemClicked(sendToItem.getCaption(), message.getSelectedMessages());   
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
                                     sendToItem.menuItemClicked(sendToItem.getCaption(), message.getSelectedMessages());   
                                }                        
                            });
                            this.popBurpMenu.add(mnuItem);                        
                        } else {
                            final SendToMenuItem sendToItem = new SendToMultiEditor(item, this.invocation);
                            mnuItem.addActionListener(new ActionListener() {
                                @Override
                                public void actionPerformed(ActionEvent e) {
                                     sendToItem.menuItemClicked(sendToItem.getCaption(), message.getSelectedMessages());   
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
    
    public void sendToRepeater(SendToMessage message) {
        try {
            IHttpRequestResponse[] messageItem = message.getSelectedMessages();
            IHttpService httpService = messageItem[0].getHttpService();
            callbacks.sendToRepeater(httpService.getHost(), httpService.getPort(), HttpUtil.isSSL(httpService.getProtocol()),  
                    messageItem[0].getRequest(), "v" + this.repeternum++);
        } catch (Exception ex) {
            Logger.getLogger(SendToMenu.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public void sendToIntruder(SendToMessage message) {
        try {
            IHttpRequestResponse[] messageItem = message.getSelectedMessages();
            IHttpService httpService = messageItem[0].getHttpService();
            callbacks.sendToIntruder(httpService.getHost(), httpService.getPort(), HttpUtil.isSSL(httpService.getProtocol()), 
                    messageItem[0].getRequest());
        } catch (Exception ex) {
            Logger.getLogger(SendToMenu.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public void sendToSpider(SendToMessage message) {
        try {
            IHttpRequestResponse[] messageItem = message.getSelectedMessages();
            callbacks.sendToSpider(BurpWrap.getURL(messageItem[0]));
        } catch (Exception ex) {
            Logger.getLogger(SendToMenu.class.getName()).log(Level.SEVERE, null, ex);
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
