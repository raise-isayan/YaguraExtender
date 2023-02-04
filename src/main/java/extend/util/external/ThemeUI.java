package extend.util.external;

import burp.BurpExtension;
import java.beans.PropertyChangeListener;
import java.util.ArrayList;
import java.util.List;
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
        if (textArea == null) return;
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
            if (gutter!=null) {
                gutter.setBackground(UIManager.getColor("TextField.background"));
                gutter.setLineNumberColor(UIManager.getColor("TextField.foreground"));
            }
        });
    }

}
