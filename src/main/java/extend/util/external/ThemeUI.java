package extend.util.external;

import burp.BurpExtension;
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
import javax.swing.text.JTextComponent;
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

    public static Color getDefaultColor(Object key, Color defaultColor) {
        Color color = UIManager.getColor(key);
        return color != null ? color : defaultColor;
    }

    public static void applyStyleTheme(JTextComponent textArea) {
        if (textArea == null) {
            return;
        }

        SwingUtilities.invokeLater(() -> {
//                    BurpExtender.getMontoyaApi().userInterface().applyThemeToComponent(textArea);
//                    Gutter gutter = RSyntaxUtilities.getGutter(textArea);
//                    if (gutter != null) {
//                        BurpExtender.getMontoyaApi().userInterface().applyThemeToComponent(gutter);
//                    }

            textArea.setForeground(getDefaultColor("TextArea.foreground", java.awt.SystemColor.textText));
            textArea.setBackground(getDefaultColor("TextArea.background", java.awt.SystemColor.control));
            textArea.setSelectedTextColor(getDefaultColor("TextArea.selectionForeground", java.awt.SystemColor.textHighlightText));
            textArea.setSelectionColor(getDefaultColor("TextArea.selectedBackground", java.awt.SystemColor.textHighlight));
            if (textArea instanceof RSyntaxTextArea rtextArea) {
                Gutter gutter = RSyntaxUtilities.getGutter(rtextArea);
                if (gutter != null) {
                    gutter.setBackground(getDefaultColor("TextField.background", java.awt.SystemColor.control));
                    gutter.setLineNumberColor(getDefaultColor("TextField.foreground", java.awt.SystemColor.text));
                }
            }
        });
    }

//    public static void applyStyleTheme(RSyntaxTextArea textArea) {
//        if (textArea == null) {
//            return;
//        }
//
//        SwingUtilities.invokeLater(() -> {
//
//            textArea.setForeground(getDefaultColor("TextArea.foreground", java.awt.SystemColor.textText));
//            textArea.setBackground(getDefaultColor("TextArea.background", java.awt.SystemColor.control));
//            textArea.setSelectedTextColor(getDefaultColor("TextArea.selectionForeground", java.awt.SystemColor.textHighlightText));
//            textArea.setSelectionColor(getDefaultColor("TextArea.selectedBackground", java.awt.SystemColor.textHighlight));
//            Gutter gutter = RSyntaxUtilities.getGutter(textArea);
//            if (gutter != null) {
//                gutter.setBackground(getDefaultColor("TextField.background", java.awt.SystemColor.control));
//                gutter.setLineNumberColor(getDefaultColor("TextField.foreground", java.awt.SystemColor.text));
//            }
//        });
//    }

    public static void applyStyleTheme(JTable table) {
        table.setGridColor(UIManager.getColor("Table.gridColor"));
        table.setForeground(UIManager.getColor("Button.default.foreground"));
        table.setBackground(UIManager.getColor("Burp.actionPanelBackground"));
    }

    public static void applyTitleBarBackgroundColor(JFrame frame, Color backColor) {
        applyTitleBarColor(frame, NamedColor.getTextColor(backColor), backColor);
    }

    public static void applyTitleBarColor(JFrame frame, Color foreColor, Color backColor) {
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
