/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package yagura.model;

import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;
import extend.util.BurpWrap;
import extend.util.HttpUtil;
import extend.util.Util;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
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
     
    public static File tempMessageFile(IHttpRequestResponse messageInfo, int index) {
        File file = null;
        try {            
            file = File.createTempFile(HttpUtil.getBaseName(BurpWrap.getURL(messageInfo)) + "." + index + ".", ".tmp");
            file.deleteOnExit();
            try (FileOutputStream fostm = new FileOutputStream(file, true)) {
                if (messageInfo.getRequest() != null) {
                    fostm.write(messageInfo.getRequest());
                    fostm.write(Util.getRawByte(Util.NEW_LINE));
                }
                if (messageInfo.getResponse() != null) {
                    fostm.write(messageInfo.getResponse());
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
