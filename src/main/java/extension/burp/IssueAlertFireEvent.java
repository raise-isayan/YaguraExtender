package extension.burp;

import javax.swing.event.EventListenerList;

/**
 *
 * @author isayan
 */
public class IssueAlertFireEvent {

    private final EventListenerList issueAlertEventList = new EventListenerList();

    protected void fireIssueAlertDebugEvent(IssueAlertEvent evt) {
        Object[] listeners = this.issueAlertEventList.getListenerList();
        for (int i = listeners.length - 2; i >= 0; i -= 2) {
            if (listeners[i] == IssueAlertListener.class) {
                ((IssueAlertListener) listeners[i + 1]).debug(evt);
            }
        }
    }

    protected void fireIssueAlertInfoEvent(IssueAlertEvent evt) {
        Object[] listeners = this.issueAlertEventList.getListenerList();
        for (int i = listeners.length - 2; i >= 0; i -= 2) {
            if (listeners[i] == IssueAlertListener.class) {
                ((IssueAlertListener) listeners[i + 1]).info(evt);
            }
        }
    }

    protected void fireIssueAlertErrorEvent(IssueAlertEvent evt) {
        Object[] listeners = this.issueAlertEventList.getListenerList();
        for (int i = listeners.length - 2; i >= 0; i -= 2) {
            if (listeners[i] == IssueAlertListener.class) {
                ((IssueAlertListener) listeners[i + 1]).error(evt);
            }
        }
    }

    protected void fireIssueAlertCriticalEvent(IssueAlertEvent evt) {
        Object[] listeners = this.issueAlertEventList.getListenerList();
        for (int i = listeners.length - 2; i >= 0; i -= 2) {
            if (listeners[i] == IssueAlertListener.class) {
                ((IssueAlertListener) listeners[i + 1]).critical(evt);
            }
        }
    }

    public void addIssueAlertListener(IssueAlertListener l) {
        this.issueAlertEventList.add(IssueAlertListener.class, l);
    }

    public void removeIssueAlertListener(IssueAlertListener l) {
        this.issueAlertEventList.remove(IssueAlertListener.class, l);
    }

}
