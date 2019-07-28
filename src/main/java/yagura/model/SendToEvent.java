package yagura.model;

import java.util.EventObject;

/**
 *
 * @author isayan
 */
public class SendToEvent extends EventObject {

    private String message;

    public SendToEvent(Object source) {
        super(source);
    }

    public SendToEvent(Object source, String message) {
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
