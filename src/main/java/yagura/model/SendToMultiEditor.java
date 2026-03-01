package yagura.model;

import extension.burp.IssueAlertEvent;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.InvocationSource;
import burp.api.montoya.ui.contextmenu.InvocationType;
import burp.api.montoya.ui.contextmenu.ComponentEvent;
import extension.burp.BurpVersion;
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

    public SendToMultiEditor(SendToItem item, ComponentEvent contextEvent) {
        super(item, contextEvent);
    }

    @Override
    public boolean isEnabled() {
        if (this.contextEvent instanceof InvocationSource invocation) {
            return (invocation.invocationType() == InvocationType.PROXY_HISTORY)
                    || (invocation.invocationType() == InvocationType.SEARCH_RESULTS)
                    || (invocation.invocationType() == InvocationType.INTRUDER_ATTACK_RESULTS)
                    || (invocation.invocationType() == InvocationType.MESSAGE_VIEWER_REQUEST)
                    || (invocation.invocationType() == InvocationType.MESSAGE_VIEWER_RESPONSE)
                    || (invocation.invocationType() == InvocationType.MESSAGE_EDITOR_REQUEST)
                    || (invocation.invocationType() == InvocationType.MESSAGE_EDITOR_RESPONSE)
                    || (invocation.invocationType() == null); // Orgnaizerではnull
        }
        return false;
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        if (this.contextEvent instanceof ContextMenuEvent context) {
            if (context.messageEditorRequestResponse().isPresent()) {
                List<HttpRequestResponse> messageInfo = List.of(context.messageEditorRequestResponse().get().requestResponse());
                sendToEvent(messageInfo);
            } else {
                List<HttpRequestResponse> messageInfo = context.selectedRequestResponses();
                sendToEvent(messageInfo);
            }
        }
    }

    public void sendToEvent(List<HttpRequestResponse> messageInfo) {
        menuItemClicked(getCaption(), SendToMessage.newSendToMessage(messageInfo, this.isEnabled()));
    }

    @Override
    public void menuItemClicked(String menuItemCaption, SendToMessage sendToMessage) {
        List<HttpRequestResponse> messageInfo = sendToMessage.getSelectedMessages();
        try {
            SendToArgsProperty argsProp = this.getSendToExtend().getSendToArgsProperty();
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
                    executeProcess(this.getTarget(), argsList);
                }
            } else {
                if (sendToMessage.getSelectedText() != null) {
                    File msgFile = FileUtil.tempFile(StringUtil.getBytesRaw(sendToMessage.getSelectedText()), ".tmp");
                    executeProcess(this.getTarget(), List.of(msgFile.getAbsolutePath()));
                } else if (!messageInfo.isEmpty()) {
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
                    List<String> argsList = new ArrayList<>();
                    for (int i = 0; i < msgFiles.length; i++) {
                        argsList.add(msgFiles[i].getAbsolutePath());
                    }
                    executeProcess(this.getTarget(), argsList);
                }
            }
        } catch (IOException ex) {
            this.fireIssueAlertCriticalEvent(new IssueAlertEvent(this, ex.getMessage()));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }

    public Process executeProcess(String target, final List<String> argsList) throws IOException {
        BurpVersion.OSType osType = BurpVersion.getOSType();
        SendToArgsProperty argsProp = this.getSendToExtend().getSendToArgsProperty();
        if (BurpVersion.OSType.MAC == osType && argsProp.isUseMacOpenCommand()) {
            return ConvertUtil.executeProcess(BurpVersion.OSType.MAC, target, argsList);
        } else {
            return ConvertUtil.executeProcess(target, argsList);
        }
    }

}
