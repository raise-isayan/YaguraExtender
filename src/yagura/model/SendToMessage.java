/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
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
