package yagura.model;

import burp.BurpExtender;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;
import extension.helpers.HttpUtil;
import extension.helpers.StringUtil;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author isayan
 */
public abstract class SendToMenuItem
        extends SendToItem implements java.awt.event.ActionListener  {
    private final static Logger logger = Logger.getLogger(SendToMenuItem.class.getName());

    protected IContextMenuInvocation contextMenu = null;

    public SendToMenuItem(SendToItem item) {
        super(item);

    }

    public SendToMenuItem(SendToItem item, IContextMenuInvocation contextMenu) {
        super(item);
        this.contextMenu = contextMenu;
    }

    /**
     * @return the contextMenu
     */
    protected IContextMenuInvocation getContextMenu() {
        return contextMenu;
    }

    /**
     * @param contextMenu the contextMenu to set
     */
    protected void setContextMenu(IContextMenuInvocation contextMenu) {
        this.contextMenu = contextMenu;
    }

    protected File tempMessageFile(IHttpRequestResponse messageInfo, int index) {
        File file = null;
        try {
            file = File.createTempFile(HttpUtil.getBaseName(BurpExtender.getHelpers().getURL(messageInfo)) + "." + index + ".", ".tmp");
            file.deleteOnExit();
            try (BufferedOutputStream fostm = new BufferedOutputStream(new FileOutputStream(file, true))) {
                if ((this.isRequestHeader() || this.isRequestBody()) && messageInfo.getRequest() != null) {
                    byte reqMessage[] = messageInfo.getRequest();
                    if (!(this.isRequestHeader() && this.isRequestBody())) {
                        IRequestInfo reqInfo = BurpExtender.getHelpers().analyzeRequest(messageInfo.getRequest());
                        if (this.isRequestHeader()) {
                            reqMessage = Arrays.copyOfRange(messageInfo.getRequest(), 0, reqInfo.getBodyOffset());
                        } else if (this.isRequestBody()) {
                            reqMessage = Arrays.copyOfRange(messageInfo.getRequest(), reqInfo.getBodyOffset(), messageInfo.getRequest().length);
                        }
                    }
                    fostm.write(reqMessage);
                    fostm.write(StringUtil.getBytesRaw(HttpUtil.LINE_TERMINATE));
                }
                if ((this.isResponseHeader() || this.isResponseBody()) && messageInfo.getResponse() != null) {
                    byte resMessage[] = messageInfo.getResponse();
                    if (!(this.isResponseHeader() && this.isResponseBody())) {
                        IResponseInfo resInfo = BurpExtender.getHelpers().analyzeResponse(resMessage);
                        if (this.isResponseHeader()) {
                            resMessage = Arrays.copyOfRange(messageInfo.getResponse(), 0, resInfo.getBodyOffset());
                        } else if (this.isResponseBody()) {
                            resMessage = Arrays.copyOfRange(messageInfo.getResponse(), resInfo.getBodyOffset(), messageInfo.getResponse().length);
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

    public abstract void menuItemClicked(String menuItemCaption, IHttpRequestResponse[] messageInfo);

    public abstract boolean isEnabled();

}
