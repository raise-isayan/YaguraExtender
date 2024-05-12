package extension.burp;

import burp.api.montoya.MontoyaApi;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author isayan
 */
public class IssueAlert implements IssueAlertListener {
    private final static Logger logger = Logger.getLogger(IssueAlert.class.getName());

    private final MontoyaApi api;

    public IssueAlert(MontoyaApi api) {
        this.api = api;
    }

    @Override
    public void debug(IssueAlertEvent evt) {
        this.api.logging().raiseDebugEvent(evt.getMessage());
        logger.log(Level.FINE, evt.getMessage());
    }

    @Override
    public void info(IssueAlertEvent evt) {
        this.api.logging().raiseInfoEvent(evt.getMessage());
        logger.log(Level.INFO, evt.getMessage());
    }

    @Override
    public void error(IssueAlertEvent evt) {
        this.api.logging().raiseErrorEvent(evt.getMessage());
        logger.log(Level.WARNING, evt.getMessage());
    }

    @Override
    public void critical(IssueAlertEvent evt) {
        this.api.logging().raiseCriticalEvent(evt.getMessage());
        logger.log(Level.SEVERE, evt.getMessage());
    }

}
