package extend.util.external;

import javax.swing.UIManager;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.RSyntaxUtilities;
import org.fife.ui.rtextarea.Gutter;

/**
 *
 * @author isayan
 */
public class ThemeUI {

    /***
        StringBuilder builder = new StringBuilder();
        BurpExtender.outPrintln("=====================");
        Enumeration<Object> key = UIManager.getDefaults().keys();
        while (key.hasMoreElements()) {
            builder.append(key.nextElement());
            builder.append("\n");
        }
        BurpExtender.outPrintln(builder.toString());
        BurpExtender.outPrintln("=====================");
    **/

   public static void changeStyleTheme(RSyntaxTextArea textArea) {
        try {
            textArea.setForeground(UIManager.getColor("EditorPane.foreground"));
            textArea.setBackground(UIManager.getColor("TextField.background"));
            textArea.setSelectedTextColor(UIManager.getColor("TextArea.selectedForeground"));
            textArea.setSelectionColor(UIManager.getColor("TextArea.selectedBackground"));
            Gutter gutter = RSyntaxUtilities.getGutter(textArea);
            if (gutter!=null) {
                gutter.setBackground(UIManager.getColor("EditorPane.foreground"));
                gutter.setLineNumberColor(UIManager.getColor("TextField.background"));
            }
        } catch (NullPointerException ex) {
        }
   }
   
}
