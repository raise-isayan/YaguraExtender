package extension.burp;

import java.util.EventObject;

/**
 *
 * @author isayan
 */
public class IssueAlertEvent extends EventObject {

    private String message;

    public IssueAlertEvent(Object source) {
        super(source);
    }

    public IssueAlertEvent(Object source, String message) {
        super(source);
        this.message = message;
    }

    /**
     * @return the message
     */
    public String getMessage() {
        return this.message;
    }

    /**
     * @param message the message to set
     */
    public void setMessage(String message) {
        this.message = message;
    }

}
