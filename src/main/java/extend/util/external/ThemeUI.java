package extend.util.external;

import burp.BurpExtender;
import extension.helpers.StringUtil;
import java.io.IOException;
import java.util.Properties;
import javax.swing.UIManager;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.RSyntaxUtilities;
import org.fife.ui.rsyntaxtextarea.Theme;
import org.fife.ui.rtextarea.Gutter;
import org.fife.ui.rtextarea.RTextScrollPane;

/**
 *
 * @author isayan
 */
public class ThemeUI {
      
   public static void changeStyleTheme(RSyntaxTextArea textArea) {
        try {
            textArea.setForeground(UIManager.getColor("Button.default.foreground"));
            textArea.setBackground(UIManager.getColor("Button.default.background"));
            Gutter gutter = RSyntaxUtilities.getGutter(textArea);
            if (gutter!=null) {
                gutter.setBackground(UIManager.getColor("Button.default.background"));
                gutter.setLineNumberColor(UIManager.getColor("Button.default.foreground"));
            }
        } catch (NullPointerException ex) { 
        }
   }
   
}
