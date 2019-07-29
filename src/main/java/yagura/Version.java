package yagura;

import burp.BurpExtender;
import extend.util.CustomVersion;

/**
 *
 * @author isayan
 */
public final class Version extends CustomVersion {

    private final java.util.ResourceBundle BUNDLE = java.util.ResourceBundle.getBundle("burp/resources/release");

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

    private String getProjectName() {
        String projname = BUNDLE.getString("projname");
        return projname;
    }
    
    private final static String VERSION_INFO_FMT = 
            "Product Version: %s %s\n" + 
            "Log Dir: %s\n" +
            "User Dir: %s\n";    

    public String getVersionInfo() {
        return String.format(VERSION_INFO_FMT,
            getProjectName(),
            Version.getInstance().getVersion(), 
            Config.getExtensionHomeDir().getAbsoluteFile(),
            Config.getUserDir());    
    }
    
}
