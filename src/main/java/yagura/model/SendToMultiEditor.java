package yagura.model;

import extension.burp.IssueAlertEvent;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.InvocationType;
import extension.helpers.ConvertUtil;
import extension.helpers.FileUtil;
import extension.helpers.StringUtil;
import java.awt.event.ActionEvent;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
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
        return (this.contextMenu.invocationType() == InvocationType.PROXY_HISTORY)
                || (this.contextMenu.invocationType() == InvocationType.SEARCH_RESULTS)
                || (this.contextMenu.invocationType() == InvocationType.INTRUDER_ATTACK_RESULTS)
                || (this.contextMenu.invocationType() == InvocationType.MESSAGE_VIEWER_REQUEST)
                || (this.contextMenu.invocationType() == InvocationType.MESSAGE_VIEWER_RESPONSE)
                || (this.contextMenu.invocationType() == InvocationType.MESSAGE_EDITOR_REQUEST)
                || (this.contextMenu.invocationType() == InvocationType.MESSAGE_EDITOR_RESPONSE)
                || (this.contextMenu.invocationType() == null); // Orgnaizerではnull
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
        try {
            SendToArgsProperty argsProp  = this.getSendToExtend().getSendToArgsProperty();
            if (argsProp.isUseOverride()) {
                List<String> formatList = argsProp.getArgsList();
                if (!formatList.isEmpty()) {
                    List<String> argsList = new ArrayList<>();
                    if (this.isReverseOrder()) {
                        for (int i = messageInfo.size() - 1; i >= 0; i--) {
                            argsList.addAll(executeArgumentFormat(messageInfo.get(i), sendToMessage.getSelectedText(), formatList.toArray(String[]::new)));
                        }
                    } else {
                        for (int i = 0; i < messageInfo.size(); i++) {
                            argsList.addAll(executeArgumentFormat(messageInfo.get(i), sendToMessage.getSelectedText(), formatList.toArray(String[]::new)));
                        }
                    }
                    ConvertUtil.executeProcess(this.getTarget(), argsList);
                }
            }
            else {
                if (sendToMessage.getSelectedText() != null) {
                    File msgFile = FileUtil.tempFile(StringUtil.getBytesRaw(sendToMessage.getSelectedText()), ".tmp");
                    ConvertUtil.executeProcess(this.getTarget(), new String [] { msgFile.getAbsolutePath() });
                }
                else if (!messageInfo.isEmpty()) {
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
                    String[] args = new String[msgFiles.length];
                    for (int i = 0; i < args.length; i++) {
                        args[i] = msgFiles[i].getAbsolutePath();
                    }
                    ConvertUtil.executeProcess(this.getTarget(), args);
                }
            }
        } catch (IOException ex) {
            this.fireIssueAlertCriticalEvent(new IssueAlertEvent(this, ex.getMessage()));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }

}
