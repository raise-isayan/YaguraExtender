package yagura.signature;

import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.IScannerCheck;

/**
 *
 * @author isayan
 */
public interface Signature<M> {

    public IScanIssue makeScanIssue(final IHttpRequestResponse messageInfo, final M item);
        
    public IScannerCheck passiveScanCheck();
    
}
