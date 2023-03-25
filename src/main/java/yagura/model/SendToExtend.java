package yagura.model;

import burp.BurpExtension;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.InvocationType;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import extension.burp.BurpUtil;
import extension.helpers.ConvertUtil;
import extension.helpers.HttpUtil;
import extension.helpers.StringUtil;
import extension.helpers.SwingUtil;
import java.awt.HeadlessException;
import java.awt.event.ActionEvent;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JFileChooser;
import yagura.Config;

/**
 *
 * @author isayan
 */
public class SendToExtend extends SendToMenuItem {

    private final static Logger logger = Logger.getLogger(SendToExtend.class.getName());

    private final static java.util.ResourceBundle BUNDLE = java.util.ResourceBundle.getBundle("yagura/resources/Resource");

    private File currentDirectory = new File(Config.getUserHomePath());
    private int repeternum = 0;

    public SendToExtend(SendToItem item, ContextMenuEvent contextMenu) {
        super(item, contextMenu);
    }

    @Override
    public void menuItemClicked(String menuItemCaption, List<HttpRequestResponse> messageInfo) {
        sendToEvent(menuItemCaption, messageInfo);
    }

    public void sendToEvent(String menuItemCaption, List<HttpRequestResponse> messageInfo) {
        if (messageInfo.isEmpty()) {
            return;
        }
        switch (this.getExtend()) {
            case SEND_TO_JTRANSCODER: {
                String text = BurpUtil.copySelectionData(this.contextMenu, true);
                if (text != null) {
                    BurpExtension.getInstance().sendToJTransCoder(text);
                }
                break;
            }
            case REQUEST_AND_RESPONSE_TO_FILE: {
                saveAsMessage(SendToItem.MessageType.REQUEST_AND_RESPONSE, messageInfo);
                break;
            }
            case REQUEST_BODY_TO_FILE: {
                saveAsMessageBody(SendToItem.MessageType.REQUEST, messageInfo);
                break;
            }
            case RESPONSE_BODY_TO_FILE: {
                saveAsMessageBody(SendToItem.MessageType.RESPONSE, messageInfo);
                break;
            }
            case PASTE_FROM_JTRANSCODER: {
                byte[] text = BurpExtension.getInstance().receiveFromJTransCoder();
                if (text != null) {
                    BurpUtil.pasteSelectionData(this.contextMenu, StringUtil.getStringRaw(text), false);
                }
                break;
            }
            case PASTE_FROM_CLIPBOARD: {
                try {
                    // menuItemCaption にエンコーディングが入ってくる
                    byte[] text = BurpExtension.getInstance().receiveFromClipbord(menuItemCaption);
                    if (text != null) {
                        BurpUtil.pasteSelectionData(this.contextMenu, StringUtil.getStringRaw(text), false);
                    }
                    break;
                } catch (UnsupportedEncodingException ex) {
                    logger.log(Level.SEVERE, ex.getMessage(), ex);
                }
            }

            case MESSAGE_INFO_COPY: {
                BurpExtension.helpers().sendToTableInfoCopy(this.contextMenu);
                break;
            }
            case ADD_HOST_TO_INCLUDE_SCOPE: {
                BurpExtension.helpers().sendToAddHostIncludeToScope(this.contextMenu);
                break;
            }
            case ADD_HOST_TO_EXCLUDE_SCOPE: {
                BurpExtension.helpers().sendToAddHostToExcludeScope(this.contextMenu);
                break;
            }
            case ADD_TO_EXCLUDE_SCOPE: {
                BurpExtension.helpers().sendToAddToExcludeScope(this.contextMenu);
                break;
            }
            default:
                // ここには現状こない
                break;
        }
    }

    private void saveAsMessage(SendToItem.MessageType messageType, List<HttpRequestResponse> messageInfo) {
        HttpRequestResponse messageItem = messageInfo.get(0);
        try {
            JFileChooser filechooser = new JFileChooser(this.currentDirectory.getParentFile());
            filechooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
            filechooser.setSelectedFile(new File(HttpUtil.getBaseName(new URL(messageItem.request().url()))));
            int selected = filechooser.showSaveDialog(null);
            if (selected == JFileChooser.APPROVE_OPTION) {
                try {
                    File file = filechooser.getSelectedFile();
                    if (SwingUtil.isFileOverwriteConfirmed(file, String.format(BUNDLE.getString("extend.exists.overwrite.message"), file.getName()), BUNDLE.getString("extend.exists.overwrite.confirm"))) {
                        try (BufferedOutputStream fstm = new BufferedOutputStream(new FileOutputStream(file))) {
                            if (messageType == SendToItem.MessageType.REQUEST || messageType == SendToItem.MessageType.REQUEST_AND_RESPONSE) {
                                fstm.write(messageItem.request().toByteArray().getBytes());
                                fstm.write(StringUtil.getBytesRaw(HttpUtil.LINE_TERMINATE));
                            }
                            if (messageType == SendToItem.MessageType.RESPONSE || messageType == SendToItem.MessageType.REQUEST_AND_RESPONSE) {
                                fstm.write(messageItem.response().toByteArray().getBytes());
                                fstm.write(StringUtil.getBytesRaw(HttpUtil.LINE_TERMINATE));
                            }
                            fstm.flush();
                        }
                    }
                    this.currentDirectory = file;
                } catch (IOException ex) {
                    logger.log(Level.SEVERE, ex.getMessage(), ex);
                }
            }
        } catch (HeadlessException | MalformedURLException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }

    private void saveAsMessageBody(SendToItem.MessageType messageType, List<HttpRequestResponse> messageInfo) {
        HttpRequestResponse messageItem = messageInfo.get(0);
        try {
            JFileChooser filechooser = new JFileChooser(this.currentDirectory.getParentFile());
            filechooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
            filechooser.setSelectedFile(new File(HttpUtil.getBaseName(new URL(messageItem.request().url()))));
            int selected = filechooser.showSaveDialog(null);
            if (selected == JFileChooser.APPROVE_OPTION) {
                try {
                    File file = filechooser.getSelectedFile();
                    if (SwingUtil.isFileOverwriteConfirmed(file, String.format(BUNDLE.getString("extend.exists.overwrite.message"), file.getName()), BUNDLE.getString("extend.exists.overwrite.confirm"))) {
                        try (BufferedOutputStream fstm = new BufferedOutputStream(new FileOutputStream(file))) {
                            if (messageType == SendToItem.MessageType.REQUEST || messageType == SendToItem.MessageType.REQUEST_AND_RESPONSE) {
                                HttpRequest httpRequest = messageItem.request();
                                byte reqMessage[] = httpRequest.toByteArray().getBytes();
                                reqMessage = Arrays.copyOfRange(reqMessage, httpRequest.bodyOffset(), reqMessage.length);
                                fstm.write(reqMessage);
                            }
                            if (messageType == SendToItem.MessageType.RESPONSE || messageType == SendToItem.MessageType.REQUEST_AND_RESPONSE) {
                                HttpResponse httpResponse = messageItem.response();
                                byte resMessage[] = httpResponse.toByteArray().getBytes();
                                resMessage = Arrays.copyOfRange(resMessage, httpResponse.bodyOffset(), resMessage.length);
                                fstm.write(resMessage);
                            }
                            fstm.flush();
                        }
                    }
                    this.currentDirectory = file;
                } catch (IOException ex) {
                    logger.log(Level.SEVERE, ex.getMessage(), ex);
                }
            }
        } catch (HeadlessException | MalformedURLException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        javax.swing.JMenuItem item = (javax.swing.JMenuItem) e.getSource();
        List<HttpRequestResponse> messageInfo = this.contextMenu.selectedRequestResponses();
        sendToEvent(item.getText(), messageInfo);
    }

    @Override
    public boolean isEnabled() {
        boolean enabled = false;
        switch (this.getExtend()) {
            case SEND_TO_JTRANSCODER: {
                enabled = (this.contextMenu.messageEditorRequestResponse() != null);
                break;
            }
            case REQUEST_AND_RESPONSE_TO_FILE: {
                enabled = true;
                break;
            }
            case REQUEST_BODY_TO_FILE:
            case RESPONSE_BODY_TO_FILE: {
                enabled = true;
                break;
            }
            case PASTE_FROM_JTRANSCODER: {
                enabled = (this.contextMenu.invocationType() == InvocationType.MESSAGE_EDITOR_REQUEST)
                        || (this.contextMenu.invocationType() == InvocationType.MESSAGE_EDITOR_RESPONSE)
                        || (this.contextMenu.invocationType() == InvocationType.INTRUDER_PAYLOAD_POSITIONS);
                break;
            }
            case PASTE_FROM_CLIPBOARD: {
                enabled = (this.contextMenu.invocationType() == InvocationType.MESSAGE_EDITOR_REQUEST)
                        || (this.contextMenu.invocationType() == InvocationType.MESSAGE_EDITOR_RESPONSE)
                        || (this.contextMenu.invocationType() == InvocationType.INTRUDER_PAYLOAD_POSITIONS);
                break;
            }
            case MESSAGE_INFO_COPY:
            case ADD_HOST_TO_INCLUDE_SCOPE:
            case ADD_HOST_TO_EXCLUDE_SCOPE: {
                enabled = (this.contextMenu.invocationType() == InvocationType.PROXY_HISTORY)
                        || (this.contextMenu.invocationType() == InvocationType.SEARCH_RESULTS)
                        || (this.contextMenu.invocationType() == InvocationType.INTRUDER_ATTACK_RESULTS)
                        || (this.contextMenu.invocationType() == InvocationType.MESSAGE_VIEWER_REQUEST)
                        || (this.contextMenu.invocationType() == InvocationType.MESSAGE_EDITOR_RESPONSE)
                        || (this.contextMenu.invocationType() == InvocationType.MESSAGE_EDITOR_REQUEST)
                        || (this.contextMenu.invocationType() == InvocationType.MESSAGE_EDITOR_RESPONSE);
                break;
            }
            default:
                // ここには現状こない
                break;
        }
        return enabled;
    }
}
