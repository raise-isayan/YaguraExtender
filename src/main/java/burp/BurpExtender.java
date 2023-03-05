package burp;

import javax.swing.JOptionPane;
import yagura.Version;

/**
 *
 * @author isayan
 */
public class BurpExtender implements IBurpExtender {

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks ibec) {
        showUnsupporttDlg();
    }

    public static void showUnsupporttDlg() {
        // ここに来るルートは古いBurp
        JOptionPane.showMessageDialog(null, "Burp suite v2023.1.2 or higher version is required.", Version.getInstance().getProjectName(), JOptionPane.INFORMATION_MESSAGE);
    }

}
