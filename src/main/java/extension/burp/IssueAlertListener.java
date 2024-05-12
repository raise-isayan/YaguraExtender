package extension.burp;

import java.util.EventListener;

/**
 *
 * @author isayan
 */
public interface IssueAlertListener extends EventListener {

    public void debug(IssueAlertEvent evt);

    public void info(IssueAlertEvent evt);

    public void error(IssueAlertEvent evt);

    public void critical(IssueAlertEvent evt);

}
