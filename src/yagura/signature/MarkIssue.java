package yagura.signature;

import yagura.model.StartEndPosion;

/**
 *
 * @author isayan
 */
public class MarkIssue extends StartEndPosion {
    private boolean messageIsRequest = false;

    public MarkIssue(boolean messageIsRequest, int s, int e) {
        super(s, e);
        this.messageIsRequest = messageIsRequest;
    }

    /**
     * @return the messageIsRequest
     */
    public boolean isMessageIsRequest() {
        return messageIsRequest;
    }

    /**
     * @param messageIsRequest the messageIsRequest to set
     */
    public void setMessageIsRequest(boolean messageIsRequest) {
        this.messageIsRequest = messageIsRequest;
    }
    
}
