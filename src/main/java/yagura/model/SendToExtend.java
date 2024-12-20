package yagura.model;

import burp.BurpExtension;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.InvocationType;
import extension.burp.BurpUtil;
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
import java.net.URI;
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

    private static File currentDirectory = new File(Config.getUserHomePath());
    private static int repeternum = 0;

    @Override
    public void actionPerformed(ActionEvent e) {
        if (e.getSource() instanceof javax.swing.JMenuItem) {
            sendToEvent(this.contextMenu);
        }
    }

    public SendToExtend(SendToItem item, ContextMenuEvent contextMenu) {
        super(item, contextMenu);
    }

    public void sendToEvent(ContextMenuEvent contextMenu) {
        List<HttpRequestResponse> messageInfo = null;
        if (contextMenu.messageEditorRequestResponse().isPresent()) {
            messageInfo = List.of(contextMenu.messageEditorRequestResponse().get().requestResponse());
        }
        else {
            messageInfo = contextMenu.selectedRequestResponses();
        }
        if (messageInfo != null) {
            menuItemClicked(getCaption(), SendToMessage.newSendToMessage(messageInfo, true));
        }
    }

    @Override
    public void menuItemClicked(String menuItemCaption, SendToMessage sendToMessage) {
        final BurpExtension extenderImpl = BurpExtension.getInstance();
        switch (this.getExtend()) {
            case SEND_TO_JTRANSCODER: {
                String text = BurpUtil.copySelectionData(this.contextMenu, this.isEnabled());
                if (text != null) {
                    extenderImpl.sendToJTransCoder(text);
                }
                break;
            }
            case REQUEST_AND_RESPONSE_TO_FILE: {
                saveAsMessage(SendToItem.MessageType.REQUEST_AND_RESPONSE, sendToMessage);
                break;
            }
            case REQUEST_BODY_TO_FILE: {
                saveAsMessageBody(SendToItem.MessageType.REQUEST, sendToMessage);
                break;
            }
            case RESPONSE_BODY_TO_FILE: {
                saveAsMessageBody(SendToItem.MessageType.RESPONSE, sendToMessage);
                break;
            }
            case PASTE_FROM_JTRANSCODER: {
                byte[] text = extenderImpl.receiveFromJTransCoder();
                if (text != null) {
                    BurpUtil.pasteSelectionData(this.contextMenu, StringUtil.getStringRaw(text), false);
                }
                break;
            }
            case PASTE_FROM_CLIPBOARD: {
                try {
                    // menuItemCaption にエンコーディングが入ってくる
                    byte[] text = extenderImpl.receiveFromClipbord(menuItemCaption);
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
                BurpExtension.helpers().addHostIncludeScope(this.contextMenu);
                break;
            }
            case ADD_HOST_TO_EXCLUDE_SCOPE: {
                BurpExtension.helpers().addHostExcludeScope(this.contextMenu);
                break;
            }
            case ADD_TO_EXCLUDE_SCOPE: {
                BurpExtension.helpers().addExcludeScope(this.contextMenu);
                break;
            }
            default:
                // ここには現状こない
                break;
        }
    }

    private void saveAsMessage(SendToItem.MessageType messageType, SendToMessage sendToMessage) {
        final HttpRequestResponse messageItem = sendToMessage.getSelectedMessages().get(0);
        try {
            JFileChooser filechooser = new JFileChooser();
            filechooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
            File chooseFile = new File(this.currentDirectory.getParentFile(), HttpUtil.getBaseName(URI.create(messageItem.request().url()).toURL()));
            filechooser.setSelectedFile(chooseFile);
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
                                if (messageItem.hasResponse()) {
                                    fstm.write(messageItem.response().toByteArray().getBytes());
                                }
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


    private void saveAsMessageBody(SendToItem.MessageType messageType, SendToMessage sendToMessage) {
        final HttpRequestResponse messageItem = sendToMessage.getSelectedMessages().get(0);
        try {
            JFileChooser filechooser = new JFileChooser();
            filechooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
            File chooseFile = new File(this.currentDirectory.getParentFile(), HttpUtil.getBaseName(URI.create(messageItem.request().url()).toURL()));
            filechooser.setSelectedFile(chooseFile);
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
                                if (messageItem.hasResponse()) {
                                    HttpResponse httpResponse = messageItem.response();
                                    byte resMessage[] = httpResponse.toByteArray().getBytes();
                                    resMessage = Arrays.copyOfRange(resMessage, httpResponse.bodyOffset(), resMessage.length);
                                    fstm.write(resMessage);
                                }
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
    public boolean isEnabled() {
        boolean enabled = false;
        switch (this.getExtend()) {
            case SEND_TO_JTRANSCODER: {
                enabled = (this.contextMenu.invocationType() == InvocationType.MESSAGE_EDITOR_REQUEST)
                        || (this.contextMenu.invocationType() == InvocationType.MESSAGE_EDITOR_RESPONSE)
                        || (this.contextMenu.invocationType() == InvocationType.MESSAGE_VIEWER_REQUEST)
                        || (this.contextMenu.invocationType() == InvocationType.MESSAGE_VIEWER_RESPONSE)
                        || (this.contextMenu.invocationType() == null); // Orgnaizerではnull
                break;
            }
            case REQUEST_AND_RESPONSE_TO_FILE: {
                enabled = (this.contextMenu.invocationType() == InvocationType.PROXY_HISTORY)
                        || (this.contextMenu.invocationType() == InvocationType.SEARCH_RESULTS)
                        || (this.contextMenu.invocationType() == InvocationType.MESSAGE_EDITOR_REQUEST)
                        || (this.contextMenu.invocationType() == InvocationType.MESSAGE_EDITOR_RESPONSE)
                        || (this.contextMenu.invocationType() == InvocationType.MESSAGE_VIEWER_REQUEST)
                        || (this.contextMenu.invocationType() == InvocationType.MESSAGE_VIEWER_RESPONSE)
                        || (this.contextMenu.invocationType() == null); // Orgnaizerではnull
                break;
            }
            case REQUEST_BODY_TO_FILE:
                enabled = (this.contextMenu.invocationType() == InvocationType.PROXY_HISTORY)
                        || (this.contextMenu.invocationType() == InvocationType.SEARCH_RESULTS)
                        || (this.contextMenu.invocationType() == InvocationType.MESSAGE_EDITOR_REQUEST)
                        || (this.contextMenu.invocationType() == InvocationType.MESSAGE_VIEWER_REQUEST)
                        || (this.contextMenu.invocationType() == null); // Orgnaizerではnull
                break;
            case RESPONSE_BODY_TO_FILE: {
                enabled = (this.contextMenu.invocationType() == InvocationType.PROXY_HISTORY)
                        || (this.contextMenu.invocationType() == InvocationType.SEARCH_RESULTS)
                        || (this.contextMenu.invocationType() == InvocationType.MESSAGE_EDITOR_RESPONSE)
                        || (this.contextMenu.invocationType() == InvocationType.MESSAGE_VIEWER_RESPONSE);
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
                        || (this.contextMenu.invocationType() == InvocationType.INTRUDER_PAYLOAD_POSITIONS)
                        || (this.contextMenu.invocationType() == null); // Orgnaizerではnull
                break;
            }
            case MESSAGE_INFO_COPY:
               enabled = (this.contextMenu.invocationType() == InvocationType.PROXY_HISTORY)
                        || (this.contextMenu.invocationType() == InvocationType.SEARCH_RESULTS)
                        || (this.contextMenu.invocationType() == InvocationType.MESSAGE_VIEWER_REQUEST)
                        || (this.contextMenu.invocationType() == InvocationType.MESSAGE_VIEWER_RESPONSE)
                        || (this.contextMenu.invocationType() == InvocationType.MESSAGE_EDITOR_REQUEST)
                        || (this.contextMenu.invocationType() == InvocationType.MESSAGE_EDITOR_RESPONSE)
                        || (this.contextMenu.invocationType() == null); // Orgnaizerではnull
                break;
            case ADD_HOST_TO_INCLUDE_SCOPE:
            case ADD_HOST_TO_EXCLUDE_SCOPE:
            case ADD_TO_EXCLUDE_SCOPE: {
                enabled = (this.contextMenu.invocationType() == InvocationType.PROXY_HISTORY)
                        || (this.contextMenu.invocationType() == InvocationType.SEARCH_RESULTS)
                        || (this.contextMenu.invocationType() == InvocationType.SITE_MAP_TREE)
                        || (this.contextMenu.invocationType() == InvocationType.SITE_MAP_TABLE)
                        || (this.contextMenu.invocationType() == InvocationType.MESSAGE_VIEWER_REQUEST)
                        || (this.contextMenu.invocationType() == InvocationType.MESSAGE_VIEWER_RESPONSE)
                        || (this.contextMenu.invocationType() == InvocationType.MESSAGE_EDITOR_REQUEST)
                        || (this.contextMenu.invocationType() == InvocationType.MESSAGE_EDITOR_RESPONSE)
                        || (this.contextMenu.invocationType() == null); // Orgnaizerではnull
                break;
            }
            default:
                // ここには現状こない
                break;
        }
        return enabled;
    }
}
