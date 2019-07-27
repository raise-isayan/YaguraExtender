package yagura.model;

import burp.BurpExtender;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;
import extend.util.BurpWrap;
import extend.util.HttpUtil;
import extend.util.Util;
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
        extends SendToItem implements java.awt.event.ActionListener {
    
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
            file = File.createTempFile(HttpUtil.getBaseName(BurpWrap.getURL(messageInfo)) + "." + index + ".", ".tmp");
            file.deleteOnExit();
            try (FileOutputStream fostm = new FileOutputStream(file, true)) {
                if ((this.isRequestHeader() || this.isRequestBody()) && messageInfo.getRequest() != null) {
                    byte reqMessage[] = messageInfo.getRequest();
                    if (!(this.isRequestHeader() && this.isRequestBody())) {
                        IRequestInfo reqInfo = BurpExtender.getHelpers().analyzeRequest(messageInfo.getRequest());
                        if (this.isRequestHeader()) {
                            reqMessage = Arrays.copyOfRange(messageInfo.getRequest(), 0, reqInfo.getBodyOffset());
                        }
                        else if (this.isRequestBody()) {
                            reqMessage = Arrays.copyOfRange(messageInfo.getRequest(), reqInfo.getBodyOffset(), messageInfo.getRequest().length);                            
                        }                                                    
                    }
                    fostm.write(reqMessage);
                    fostm.write(Util.getRawByte(Util.NEW_LINE));
                }
                if ((this.isResponseHeader() || this.isResponseBody()) && messageInfo.getResponse() != null) {
                    byte resMessage[] = messageInfo.getResponse();
                    if (!(this.isResponseHeader() && this.isResponseBody())) {
                        IResponseInfo resInfo = BurpExtender.getHelpers().analyzeResponse(resMessage);
                        if (this.isResponseHeader()) {
                            resMessage = Arrays.copyOfRange(messageInfo.getResponse(), 0, resInfo.getBodyOffset());
                        }
                        else if (this.isResponseBody()) {
                            resMessage = Arrays.copyOfRange(messageInfo.getResponse(), resInfo.getBodyOffset(), messageInfo.getResponse().length);                            
                        }                                                    
                    }
                    fostm.write(resMessage);
                    fostm.write(Util.getRawByte(Util.NEW_LINE));
                }
            }
        } catch (IOException ex) {
            Logger.getLogger(SendToMenuItem.class.getName()).log(Level.SEVERE, null, ex);
        } catch (Exception ex) {
            Logger.getLogger(SendToMenuItem.class.getName()).log(Level.SEVERE, null, ex);
        }
        return file;
    }

    public abstract void menuItemClicked(String menuItemCaption, IHttpRequestResponse[] messageInfo);
    
    public abstract boolean isEnabled();
    
}
