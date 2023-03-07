package extension.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import extend.util.external.ExtensionHelper;
import java.util.logging.Logger;
import javax.swing.JOptionPane;
import yagura.Version;

/**
 *
 * @author isayan
 */
public class BurpExtensionImpl implements BurpExtension {

    private final static Logger logger = Logger.getLogger(BurpExtensionImpl.class.getName());

    private final static BurpVersion SUPPORT_MIN_VERSION = new BurpVersion("Burp Suite Support v2023.1.2");

    private static BurpExtensionImpl extenderImpl;
    private static MontoyaApi montoyaApi;
    private static ExtensionHelper helper = null;
    private BurpVersion burp_version = null;

    @Override
    public void initialize(MontoyaApi api) {
        extenderImpl = this;
        montoyaApi = api;
        try {
            burp_version = new BurpVersion(api);
        } catch (Exception ex) {
            // 取得できない場合Frameのタイトルから取得
            burp_version = BurpUtil.suiteVersion();
        }

        if (!showUnsupporttDlg(burp_version)) {
            helper = new ExtensionHelper(api);
        }
    }

    @SuppressWarnings("unchecked")
    public static <T extends BurpExtensionImpl> T getInstance() {
        return (T) extenderImpl;
    }

    public static MontoyaApi api() {
        return montoyaApi;
    }

    public BurpVersion getBurpVersion() {
        return burp_version;
    }

    public static ExtensionHelper helpers() {
        return helper;
    }

    private static boolean showUnsupport = false;

    /**
     * バージョンが古い場合警告を表示
     * @param version
     * @return 警告が表示された場合はtrue
     */
    public static boolean showUnsupporttDlg(BurpVersion version) {
        if (!showUnsupport && version.compareTo(SUPPORT_MIN_VERSION) < 0) {
            JOptionPane.showMessageDialog(null, "Burp suite v2023.1.2 or higher version is required.", Version.getInstance().getProjectName(), JOptionPane.INFORMATION_MESSAGE);
            showUnsupport = true;
            return true;
        }
        return false;
    }


}

