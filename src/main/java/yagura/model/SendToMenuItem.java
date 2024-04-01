package yagura.model;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import extension.helpers.HttpRequestWapper;
import extension.helpers.HttpResponseWapper;
import extension.helpers.HttpUtil;
import extension.helpers.StringUtil;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URL;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author isayan
 */
public abstract class SendToMenuItem
        extends SendToItem implements java.awt.event.ActionListener {

    private final static Logger logger = Logger.getLogger(SendToMenuItem.class.getName());

    protected ContextMenuEvent contextMenu = null;

    public SendToMenuItem(SendToItem item) {
        super(item);
    }

    public SendToMenuItem(SendToItem item, ContextMenuEvent contextMenu) {
        super(item);
        this.contextMenu = contextMenu;
    }

    /**
     * @return the contextMenu
     */
    protected ContextMenuEvent getContextMenu() {
        return contextMenu;
    }

    /**
     * @param contextMenu the contextMenu to set
     */
    protected void setContextMenu(ContextMenuEvent contextMenu) {
        this.contextMenu = contextMenu;
    }

    protected File tempMessageFile(HttpRequestResponse messageInfo, int index) {
        File file = null;
        try {
            file = File.createTempFile(HttpUtil.getBaseName(new URL(messageInfo.request().url())) + "." + index + ".", ".tmp");
            file.deleteOnExit();
            try (BufferedOutputStream fostm = new BufferedOutputStream(new FileOutputStream(file, true))) {
                if ((this.isRequestHeader() || this.isRequestBody()) && messageInfo.request() != null) {
                    HttpRequestWapper wrapRequest = new HttpRequestWapper(messageInfo.request());
                    byte[] reqMessage = wrapRequest.getMessageByte();
                    if (!(this.isRequestHeader() && this.isRequestBody())) {
                        if (this.isRequestHeader()) {
                            reqMessage = Arrays.copyOfRange(reqMessage, 0, wrapRequest.bodyOffset());
                        } else if (this.isRequestBody()) {
                            reqMessage = Arrays.copyOfRange(reqMessage, wrapRequest.bodyOffset(), reqMessage.length);
                        }
                    }
                    fostm.write(reqMessage);
                    fostm.write(StringUtil.getBytesRaw(HttpUtil.LINE_TERMINATE));
                }
                if ((this.isResponseHeader() || this.isResponseBody()) && messageInfo.response() != null) {
                    HttpResponseWapper wrapResponse = new HttpResponseWapper(messageInfo.response());
                    byte resMessage[] = wrapResponse.getHeaderBytes();
                    if (!(this.isResponseHeader() && this.isResponseBody())) {
                        if (this.isResponseHeader()) {
                            resMessage = Arrays.copyOfRange(resMessage, 0, wrapResponse.bodyOffset());
                        } else if (this.isResponseBody()) {
                            resMessage = Arrays.copyOfRange(resMessage, wrapResponse.bodyOffset(), resMessage.length);
                        }
                    }
                    fostm.write(resMessage);
                    fostm.write(StringUtil.getBytesRaw(HttpUtil.LINE_TERMINATE));
                }
            }
        } catch (IOException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return file;
    }

    public abstract void menuItemClicked(String menuItemCaption, SendToMessage sendToMessage);

    public abstract boolean isEnabled();

}
