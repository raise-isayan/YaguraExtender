package yagura.model;

import burp.IHttpRequestResponse;

/**
 *
 * @author isayan
 */
public interface SendToMessage {

    public IHttpRequestResponse[] getSelectedMessages();
    
    public String getSelectedText();
    
    public boolean isExtendVisible();
    
}
