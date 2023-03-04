package yagura.model;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import extension.helpers.HttpUtil;
import extension.helpers.StringUtil;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URL;
import java.util.Arrays;
import java.util.List;
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
                    HttpRequest httpRequest = messageInfo.request();
                    byte[] reqMessage = httpRequest.toByteArray().getBytes();
                    if (!(this.isRequestHeader() && this.isRequestBody())) {
                        if (this.isRequestHeader()) {
                            reqMessage = Arrays.copyOfRange(reqMessage, 0, httpRequest.bodyOffset());
                        } else if (this.isRequestBody()) {
                            reqMessage = Arrays.copyOfRange(reqMessage, httpRequest.bodyOffset(), reqMessage.length);
                        }
                    }
                    fostm.write(reqMessage);
                    fostm.write(StringUtil.getBytesRaw(HttpUtil.LINE_TERMINATE));
                }
                if ((this.isResponseHeader() || this.isResponseBody()) && messageInfo.response() != null) {
                    HttpResponse httpResponse = messageInfo.response();
                    byte resMessage[] = httpResponse.toByteArray().getBytes();
                    if (!(this.isResponseHeader() && this.isResponseBody())) {
                        if (this.isResponseHeader()) {
                            resMessage = Arrays.copyOfRange(resMessage, 0, httpResponse.bodyOffset());
                        } else if (this.isResponseBody()) {
                            resMessage = Arrays.copyOfRange(resMessage, httpResponse.bodyOffset(), resMessage.length);
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

    public abstract void menuItemClicked(String menuItemCaption, List<HttpRequestResponse> messageInfo);

    public abstract boolean isEnabled();

}
