package burp;

import extension.burp.BurpUtil;
import extension.burp.BurpVersion;

/**
 *
 * @author isayan
 */
public class BurpExtender extends BurpExtension implements IBurpExtender {

    /**
      MontoyaAPI に対応している場合にもこのルートは通る模様
     * @param cb
     */
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks cb) {
        BurpVersion burp_version = BurpUtil.suiteVersion();
        BurpVersion.showUnsupporttDlg(burp_version);
    }

}
