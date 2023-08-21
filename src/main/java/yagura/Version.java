package yagura;

import extension.helpers.StringUtil;
import extension.view.base.CustomVersion;

/**
 *
 * @author isayan
 */
public final class Version extends CustomVersion {

    private final static java.util.ResourceBundle BUNDLE = java.util.ResourceBundle.getBundle("burp/resources/release");

    private Version() {
        String ver = BUNDLE.getString("version");
        parseVersion(ver);
    }

    private static Version version = null;

    /**
     * Versionインスタンスの取得
     *
     * @return バージョン
     */
    public static synchronized Version getInstance() {
        if (version == null) {
            version = new Version();
        }
        return version;
    }

    public String getProjectName() {
        String projname = BUNDLE.getString("projname");
        return projname;
    }

    public String getTabCaption() {
        String projname = BUNDLE.getString("tabcaption");
        return projname;
    }

    private final static String VERSION_INFO_FMT
            = "Product Version: %s v%s" + StringUtil.NEW_LINE
            + "Log Dir: %s" + StringUtil.NEW_LINE
            + "Config Dir: %s";

    public String getVersionInfo() {
        return String.format(VERSION_INFO_FMT,
                getProjectName(),
                Version.getInstance().getVersion(),
                Config.getUserDirPath(),
                Config.getExtensionHomeDir().getAbsoluteFile());
    }

}
