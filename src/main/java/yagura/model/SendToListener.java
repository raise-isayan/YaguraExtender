package yagura.model;

import java.util.EventListener;

/**
 *
 * @author isayan
 */
public interface SendToListener extends EventListener {

    public void complete(SendToEvent evt);

    public void warning(SendToEvent evt);

    public void error(SendToEvent evt);

}
