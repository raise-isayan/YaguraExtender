package burp;

import extension.burp.BurpUtil;
import extension.burp.BurpVersion;
import yagura.Version;

/**
 *
 * @author isayan
 */
public class BurpExtender extends BurpExtension implements IBurpExtender {

    private final static java.util.ResourceBundle BUNDLE = java.util.ResourceBundle.getBundle("burp/resources/release");

    /**
     * MontoyaAPI に対応している場合にもこのルートは通る模様
     *
     * @param cb
     */
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks cb) {
        BurpVersion burp_version = BurpUtil.suiteVersion();
        BurpVersion.showUnsupporttDlg(burp_version, Version.getInstance().getProjectName());
    }

}
