package passive;

import extend.view.base.CaptureItem;
import extend.view.base.MatchItem;

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

    private MatchItem.Severity serverity = MatchItem.Severity.INFORMATION;

    /**
     * @return the serverity
     */
    public MatchItem.Severity getServerity() {
        return serverity;
    }

    /**
     * @param serverity the serverity to set
     */
    public void setServerity(MatchItem.Severity serverity) {
        this.serverity = serverity;
    }

    private MatchItem.Confidence confidence = MatchItem.Confidence.CERTAIN;

    /**
     * @return the confidence
     */
    public MatchItem.Confidence getConfidence() {
        return confidence;
    }

    /**
     * @param confidence the confidence to set
     */
    public void setConfidence(MatchItem.Confidence confidence) {
        this.confidence = confidence;
    }

}
