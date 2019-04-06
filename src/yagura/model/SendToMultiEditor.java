package yagura.model;

import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;
import extend.util.Util;
import java.awt.event.ActionEvent;
import java.io.File;
import java.io.IOException;

/**
 *
 * @author isayan
 */
public class SendToMultiEditor extends SendToMenuItem {

    public SendToMultiEditor(SendToItem item, IContextMenuInvocation contextMenu) {
        super(item, contextMenu);
    }

    @Override
    public void menuItemClicked(String menuItemCaption, IHttpRequestResponse[] messageInfo) {
        sendToEvent(messageInfo);
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        IHttpRequestResponse[] messageInfo = contextMenu.getSelectedMessages();
        sendToEvent(messageInfo);
    }
    
    public void sendToEvent(IHttpRequestResponse[] messageInfo) {
        if (messageInfo.length > 0) {
            File [] msgFiles = new File[messageInfo.length];
            if (this.isReverseOrder()) {
                for (int i = messageInfo.length - 1; i >= 0; i--) {
                   msgFiles[i] = tempMessageFile(messageInfo[i], i);
               }              
            }
            else {
                for (int i = 0; i < messageInfo.length; i++) {
                    msgFiles[i] = tempMessageFile(messageInfo[i], i);
                }            
            }
            try {
                String [] args = new String[msgFiles.length];
                for (int i = 0; i < args.length; i++) {
                    args[i] = msgFiles[i].toString();
                }               
                Util.executeFormat(this.getTarget(), args);
            } catch (IOException ex) {
                this.fireSendToErrorEvent(new SendToEvent(this, ex.getMessage()));
            }
        }    
    }
    
    @Override
    public boolean isEnabled() {
        return true;
    }
    
}
