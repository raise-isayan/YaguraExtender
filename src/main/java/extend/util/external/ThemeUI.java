package extend.util.external;

import burp.BurpExtender;
import java.beans.PropertyChangeListener;
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



   public static void changeStyleTheme(RSyntaxTextArea textArea) {
       try {
            SwingUtilities.invokeLater(() -> {
//                ExtensionHelper.applyThemeToComponent(textArea);
//                Gutter gutter = RSyntaxUtilities.getGutter(textArea);
//                if (gutter!=null) {
//                    BurpExtender.getMontoyaApi().userInterface().applyThemeToComponent(gutter);
//                }

//                textArea.setForeground(UIManager.getColor("EditorPane.foreground"));
//                textArea.setBackground(UIManager.getColor("TextField.background"));
//                textArea.setSelectedTextColor(UIManager.getColor("TextArea.selectedForeground"));
//                textArea.setSelectionColor(UIManager.getColor("TextArea.selectedBackground"));
//                Gutter gutter = RSyntaxUtilities.getGutter(textArea);
//                if (gutter!=null) {
//                    gutter.setBackground(UIManager.getColor("TextField.background"));
//                    gutter.setLineNumberColor(UIManager.getColor("TextField.foreground"));
//                }


            });
        } catch (NullPointerException ex) {
        }
   }

   public static void removeAllUIManagerListener() {
       PropertyChangeListener[] listener = UIManager.getPropertyChangeListeners();
       for (PropertyChangeListener l : listener) {
           UIManager.removePropertyChangeListener(l);
       }
   }

}
