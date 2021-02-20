package yagura.model;

import burp.*;
import burp.BurpExtender;
import burp.IContextMenuInvocation;
import extension.helpers.BurpUtil;
import extension.helpers.HttpUtil;
import extension.helpers.StringUtil;
import extension.helpers.SwingUtil;
import java.awt.event.ActionEvent;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Arrays;
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

    protected final java.util.ResourceBundle BUNDLE = java.util.ResourceBundle.getBundle("yagura/resources/Resource");
    private File currentDirectory = new File(Config.getUserHomePath());
    private int repeternum = 0;

    public SendToExtend(SendToItem item, IContextMenuInvocation contextMenu) {
        super(item, contextMenu);
    }

    @Override
    public void menuItemClicked(String menuItemCaption, IHttpRequestResponse[] messageInfo) {
        sendToEvent(menuItemCaption, messageInfo);
    }

    public void sendToEvent(String menuItemCaption, IHttpRequestResponse[] messageInfo) {
        if (messageInfo.length == 0) {
            return;
        }
        switch (this.getExtend()) {
            case SEND_TO_JTRANSCODER: {
                String text = BurpUtil.copySelectionData(this.contextMenu, true);
                if (text != null) {
                    BurpExtender.getInstance().sendToJTransCoder(text);
                }
                break;
            }
            case REQUEST_AND_RESPONSE_TO_FILE: {
                saveAsMessage(SendToItem.MessageType.REQUEST_AND_RESPONSE, messageInfo);
                break;
            }
            case RESPONSE_BODY_TO_FILE: {
                saveAsMessageBody(SendToItem.MessageType.RESPONSE, messageInfo);
                break;
            }
            case PASTE_FROM_JTRANSCODER: {
                byte[] text = BurpExtender.getInstance().receiveFromJTransCoder();
                if (text != null) {
                    BurpUtil.pasteSelectionData(this.contextMenu, StringUtil.getStringRaw(text), true);
                }
                break;
            }
            case PASTE_FROM_CLIPBOARD: {
                try {
                    // menuItemCaption にエンコーディングが入ってくる                    
                    byte[] text = BurpExtender.getInstance().receiveFromClipbord(menuItemCaption);
                    if (text != null) {
                        BurpUtil.pasteSelectionData(this.contextMenu, StringUtil.getStringRaw(text), true);
                    }
                    break;
                } catch (UnsupportedEncodingException ex) {
                    Logger.getLogger(SendToExtend.class.getName()).log(Level.SEVERE, null, ex);
                }
            }

            case MESSAGE_INFO_COPY: {
                BurpExtender.getInstance().sendToTableInfoCopy(this.contextMenu, messageInfo);
                break;
            }
            case ADD_HOST_TO_INCLUDE_SCOPE: {
                BurpExtender.getInstance().sendToAddHostIncludeToScope(this.contextMenu, messageInfo);
                break;
            }
            case ADD_HOST_TO_EXCLUDE_SCOPE: {
                BurpExtender.getInstance().sendToAddHostToExcludeScope(this.contextMenu, messageInfo);
                break;
            }
            case ADD_TO_EXCLUDE_SCOPE: {
                BurpExtender.getInstance().sendToAddToExcludeScope(this.contextMenu, messageInfo);
                break;
            }    
            default:
                // ここには現状こない
                break;
        }
    }

    private void saveAsMessage(SendToItem.MessageType messageType, IHttpRequestResponse[] messageInfo) {
        IHttpRequestResponse messageItem = messageInfo[0];
        try {
            JFileChooser filechooser = new JFileChooser(this.currentDirectory.getParentFile());
            filechooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
            filechooser.setSelectedFile(new File(HttpUtil.getBaseName(BurpExtender.getHelpers().getURL(messageItem))));
            int selected = filechooser.showSaveDialog(null);
            if (selected == JFileChooser.APPROVE_OPTION) {
                try {
                    File file = filechooser.getSelectedFile();
                    if (SwingUtil.isFileOverwriteConfirmed(file, String.format(BUNDLE.getString("extend.exists.overwrite.message"), file.getName()), BUNDLE.getString("extend.exists.overwrite.confirm"))) {
                        try (BufferedOutputStream  fstm = new BufferedOutputStream(new FileOutputStream(file))) {
                            if (messageType == SendToItem.MessageType.REQUEST || messageType == SendToItem.MessageType.REQUEST_AND_RESPONSE) {
                                fstm.write(messageItem.getRequest());
                                fstm.write(StringUtil.getBytesRaw(HttpUtil.LINE_TERMINATE));
                            }
                            if (messageType == SendToItem.MessageType.RESPONSE || messageType == SendToItem.MessageType.REQUEST_AND_RESPONSE) {
                                fstm.write(messageItem.getResponse());
                                fstm.write(StringUtil.getBytesRaw(HttpUtil.LINE_TERMINATE));
                            }
                            fstm.flush();
                        }
                    }
                    this.currentDirectory = file;
                } catch (IOException ex) {
                    logger.log(Level.SEVERE, null, ex);
                }
            }
        } catch (Exception ex) {
            logger.log(Level.SEVERE, null, ex);
        }
    }

    private void saveAsMessageBody(SendToItem.MessageType messageType, IHttpRequestResponse[] messageInfo) {
        IHttpRequestResponse messageItem = messageInfo[0];
        try {
            JFileChooser filechooser = new JFileChooser(this.currentDirectory.getParentFile());
            filechooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
            filechooser.setSelectedFile(new File(HttpUtil.getBaseName(BurpExtender.getHelpers().getURL(messageItem))));
            int selected = filechooser.showSaveDialog(null);
            if (selected == JFileChooser.APPROVE_OPTION) {
                try {
                    File file = filechooser.getSelectedFile();
                    if (SwingUtil.isFileOverwriteConfirmed(file, String.format(BUNDLE.getString("extend.exists.overwrite.message"), file.getName()), BUNDLE.getString("extend.exists.overwrite.confirm"))) {
                        try (BufferedOutputStream  fstm = new BufferedOutputStream(new FileOutputStream(file))) {
                            if (messageType == SendToItem.MessageType.REQUEST || messageType == SendToItem.MessageType.REQUEST_AND_RESPONSE) {
                                IRequestInfo reqInfo = BurpExtender.getHelpers().analyzeRequest(messageItem.getRequest());
                                byte reqMessage[] = Arrays.copyOfRange(messageItem.getRequest(), reqInfo.getBodyOffset(), messageItem.getRequest().length);
                                fstm.write(reqMessage);
                            }
                            if (messageType == SendToItem.MessageType.RESPONSE || messageType == SendToItem.MessageType.REQUEST_AND_RESPONSE) {
                                IResponseInfo resInfo = BurpExtender.getHelpers().analyzeResponse(messageItem.getResponse());
                                byte resMessage[] = Arrays.copyOfRange(messageItem.getResponse(), resInfo.getBodyOffset(), messageItem.getResponse().length);
                                fstm.write(resMessage);
                            }
                            fstm.flush();
                        }
                    }
                    this.currentDirectory = file;
                } catch (IOException ex) {
                    logger.log(Level.SEVERE, null, ex);
                }
            }
        } catch (Exception ex) {
            logger.log(Level.SEVERE, null, ex);
        }
    }
    
    @Override
    public void actionPerformed(ActionEvent e) {
        javax.swing.JMenuItem item = (javax.swing.JMenuItem)e.getSource();
        IHttpRequestResponse[] messageInfo = this.contextMenu.getSelectedMessages();
        sendToEvent(item.getText(), messageInfo);
    }

    @Override
    public boolean isEnabled() {
        boolean enabled = false;
        switch (this.getExtend()) {
            case SEND_TO_JTRANSCODER: {
                enabled = (this.contextMenu.getSelectionBounds() != null);
                break;
            }
            case REQUEST_AND_RESPONSE_TO_FILE: {
                enabled = true;
                break;
            }
            case RESPONSE_BODY_TO_FILE: {
                enabled = true;
                break;
            }
            case PASTE_FROM_JTRANSCODER: {
                enabled = (this.contextMenu.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST)
                        || (this.contextMenu.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE)
                        || (this.contextMenu.getInvocationContext() == IContextMenuInvocation.CONTEXT_INTRUDER_PAYLOAD_POSITIONS);
                break;
            }
            case PASTE_FROM_CLIPBOARD: {
                enabled = (this.contextMenu.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST)
                        || (this.contextMenu.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE)
                        || (this.contextMenu.getInvocationContext() == IContextMenuInvocation.CONTEXT_INTRUDER_PAYLOAD_POSITIONS);
                break;
            }
            case MESSAGE_INFO_COPY:
            case ADD_HOST_TO_INCLUDE_SCOPE:
            case ADD_HOST_TO_EXCLUDE_SCOPE: {
                enabled = (this.contextMenu.getInvocationContext() == IContextMenuInvocation.CONTEXT_PROXY_HISTORY)
                        || (this.contextMenu.getInvocationContext() == IContextMenuInvocation.CONTEXT_SEARCH_RESULTS)
                        || (this.contextMenu.getInvocationContext() == IContextMenuInvocation.CONTEXT_INTRUDER_ATTACK_RESULTS)
                        || (this.contextMenu.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST)
                        || (this.contextMenu.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE)
                        || (this.contextMenu.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST)
                        || (this.contextMenu.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE);
                break;
            }
            default:
                // ここには現状こない
                break;
        }
        return enabled;
    }
}
