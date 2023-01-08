package extension.view.base;

import java.awt.AWTEvent;
import java.awt.EventQueue;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.InputEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import javax.swing.JOptionPane;
import javax.swing.event.EventListenerList;

/**
 *
 * @author isayan
 */
public class CustomDialog extends javax.swing.JDialog {

    public static String OK_OPTION = "OK_OPTION";
    public static String CANCEL_OPTION = "CANCEL_OPTION";

    /**
     * Creates new form CustomDialog
     *
     * @param parent
     * @param modal
     */
    public CustomDialog(java.awt.Frame parent, boolean modal) {
        super(parent, modal);
        this.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                modalResult = JOptionPane.CANCEL_OPTION;                                
            }            
        });        
    }

    protected EventListenerList listenerList = new EventListenerList();

    public void addActionListener(ActionListener l) {
        listenerList.add(ActionListener.class, l);
    }

    public void removeActionListener(ActionListener l) {
        listenerList.remove(ActionListener.class, l);
    }

    public ActionListener[] getActionListeners() {
        return listenerList.getListeners(ActionListener.class);
    }

    protected void fireActionPerformed(String command) {
        // Guaranteed to return a non-null array
        Object[] listeners = listenerList.getListenerList();
        long mostRecentEventTime = EventQueue.getMostRecentEventTime();
        int modifiers = 0;
        AWTEvent currentEvent = EventQueue.getCurrentEvent();
        if (currentEvent instanceof InputEvent) {
            modifiers = ((InputEvent) currentEvent).getModifiersEx();
        } else if (currentEvent instanceof ActionEvent) {
            modifiers = ((ActionEvent) currentEvent).getModifiers();
        }
        ActionEvent e = null;
        // Process the listeners last to first, notifying
        // those that are interested in this event
        for (int i = listeners.length - 2; i >= 0; i -= 2) {
            if (listeners[i] == ActionListener.class) {
                // Lazily create the event:
                if (e == null) {
                    e = new ActionEvent(this, ActionEvent.ACTION_PERFORMED,
                            command, mostRecentEventTime,
                            modifiers);
                }
                ((ActionListener) listeners[i + 1]).actionPerformed(e);
            }
        }
    }

    /**
     * Closes the dialog
     *
     * @param evt
     */
    protected void closeDialog(java.awt.event.WindowEvent evt) {
        setVisible(false);
        dispose();
    }

    private int modalResult = JOptionPane.CANCEL_OPTION;

    public void setModalResult(int modalResult) {
        this.modalResult = modalResult;
    }

    public int getModalResult() {
        return this.modalResult;
    }

}
