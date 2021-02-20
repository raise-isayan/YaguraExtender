package passive;

import extension.burp.Confidence;
import extension.burp.Severity;
import extension.view.base.CaptureItem;

/**
 *
 * @author raise.isayan
 */
public class IssueItem extends CaptureItem {

    private boolean messageIsRequest = false;

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

    private String type = "";

    /**
     * @return the type
     */
    public String getType() {
        return type;
    }

    /**
     * @param type the type to set
     */
    public void setType(String type) {
        this.type = type;
    }

    private Severity serverity = Severity.INFORMATION;

    /**
     * @return the serverity
     */
    public Severity getServerity() {
        return serverity;
    }

    /**
     * @param serverity the serverity to set
     */
    public void setServerity(Severity serverity) {
        this.serverity = serverity;
    }

    private Confidence confidence = Confidence.CERTAIN;

    /**
     * @return the confidence
     */
    public Confidence getConfidence() {
        return confidence;
    }

    /**
     * @param confidence the confidence to set
     */
    public void setConfidence(Confidence confidence) {
        this.confidence = confidence;
    }

}
