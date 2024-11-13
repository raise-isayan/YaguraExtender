package extend.util.external;

import extension.view.base.NamedColor;
import java.awt.Color;
import java.beans.PropertyChangeListener;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;
import javax.swing.JFrame;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.RSyntaxUtilities;
import org.fife.ui.rtextarea.Gutter;

/**
 *
 * @author isayan
 */
public class ThemeUI {

    private final static Logger logger = Logger.getLogger(ThemeUI.class.getName());

    private final static List<PropertyChangeListener> listeners = new ArrayList<>();

    public static void addPropertyChangeListener(PropertyChangeListener listener) {
        UIManager.addPropertyChangeListener(listener);
        listeners.add(listener);
    }

    public static void removePropertyChangeListener(PropertyChangeListener listener) {
        UIManager.removePropertyChangeListener(listener);
        listeners.remove(listener);
    }

    public static void removePropertyChangeListener() {
        for (PropertyChangeListener l : listeners) {
            UIManager.removePropertyChangeListener(l);
        }
    }

    public static void changeStyleTheme(RSyntaxTextArea textArea) {
        if (textArea == null) {
            return;
        }
        SwingUtilities.invokeLater(() -> {
//                    BurpExtender.getMontoyaApi().userInterface().applyThemeToComponent(textArea);
//                    Gutter gutter = RSyntaxUtilities.getGutter(textArea);
//                    if (gutter != null) {
//                        BurpExtender.getMontoyaApi().userInterface().applyThemeToComponent(gutter);
//                    }

            textArea.setForeground(UIManager.getColor("EditorPane.foreground"));
            textArea.setBackground(UIManager.getColor("TextField.background"));
            textArea.setSelectedTextColor(UIManager.getColor("TextArea.selectedForeground"));
            textArea.setSelectionColor(UIManager.getColor("TextArea.selectedBackground"));
            Gutter gutter = RSyntaxUtilities.getGutter(textArea);
            if (gutter != null) {
                gutter.setBackground(UIManager.getColor("TextField.background"));
                gutter.setLineNumberColor(UIManager.getColor("TextField.foreground"));
            }
        });
    }

    public static void changeStyleTheme(JTable table) {
        table.setGridColor(UIManager.getColor("Table.gridColor"));
        table.setForeground(UIManager.getColor("Button.default.foreground"));
        table.setBackground(UIManager.getColor("Burp.actionPanelBackground"));
    }

    public static void changeTitleBarBackgroundColor(JFrame frame, Color backColor) {
        changeTitleBarColor(frame, NamedColor.getTextColor(backColor), backColor);
    }

    public static void changeTitleBarColor(JFrame frame, Color foreColor, Color backColor) {
        if (backColor != null) {
            frame.getRootPane().putClientProperty("JRootPane.titleBarBackground", backColor);
        }
        else {
            frame.getRootPane().putClientProperty("JRootPane.titleBarBackground", UIManager.getColor("InternalFrame.activeTitleBackground"));
        }

        if (foreColor != null) {
            frame.getRootPane().putClientProperty("JRootPane.titleBarForeground", foreColor);
        }
        else {
            frame.getRootPane().putClientProperty("JRootPane.titleBarForeground", UIManager.getColor("InternalFrame.activeTitleForeground"));
        }
        SwingUtilities.updateComponentTreeUI(frame);
    }

}
