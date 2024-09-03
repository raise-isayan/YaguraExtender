package yagura.model;

import burp.BurpExtension;
import extension.burp.IssueAlertEvent;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.InvocationType;
import extension.helpers.ConvertUtil;
import java.awt.event.ActionEvent;
import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author isayan
 */
public class SendToMultiEditor extends SendToMenuItem {

    private final static Logger logger = Logger.getLogger(SendToMultiEditor.class.getName());

    public SendToMultiEditor(SendToItem item, ContextMenuEvent contextMenu) {
        super(item, contextMenu);
    }

    @Override
    public boolean isEnabled() {
        BurpExtension.helpers().outPrintln("invocationType:" + this.contextMenu.invocationType());
        return !(this.contextMenu.invocationType() == InvocationType.SITE_MAP_TABLE
                || this.contextMenu.invocationType() == InvocationType.SITE_MAP_TABLE
                || this.contextMenu.invocationType() == InvocationType.INTRUDER_PAYLOAD_POSITIONS);
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        if (contextMenu.messageEditorRequestResponse().isPresent()) {
            List<HttpRequestResponse> messageInfo = List.of(contextMenu.messageEditorRequestResponse().get().requestResponse());
            sendToEvent(messageInfo);
        } else {
            List<HttpRequestResponse> messageInfo = contextMenu.selectedRequestResponses();
            sendToEvent(messageInfo);
        }

    }

    public void sendToEvent(List<HttpRequestResponse> messageInfo) {
        menuItemClicked(getCaption(), SendToMessage.newSendToMessage(messageInfo, this.isEnabled()));
    }

    @Override
    public void menuItemClicked(String menuItemCaption, SendToMessage sendToMessage) {
        List<HttpRequestResponse> messageInfo = sendToMessage.getSelectedMessages();
        if (!messageInfo.isEmpty()) {
            File[] msgFiles = new File[messageInfo.size()];
            if (this.isReverseOrder()) {
                for (int i = messageInfo.size() - 1; i >= 0; i--) {
                    msgFiles[i] = tempMessageFile(messageInfo.get(i), i);
                }
            } else {
                for (int i = 0; i < messageInfo.size(); i++) {
                    msgFiles[i] = tempMessageFile(messageInfo.get(i), i);
                }
            }
            try {
                String[] args = new String[msgFiles.length];
                for (int i = 0; i < args.length; i++) {
                    args[i] = msgFiles[i].toString();
                }
                ConvertUtil.executeFormat(this.getTarget(), args);
            } catch (IOException ex) {
                this.fireIssueAlertCriticalEvent(new IssueAlertEvent(this, ex.getMessage()));
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
    }

}
