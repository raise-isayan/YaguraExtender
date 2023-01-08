package extension.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Version;
import extension.helpers.ConvertUtil;
import java.io.File;

public final class BurpVersion {
    private final MontoyaApi montoyaApi;
    private String productName = "";
    private String majorVersion = "";
    private String minorVersion = "";
    private String build = "";

    public BurpVersion(MontoyaApi api) {
        this.montoyaApi = api;
        parseVersion(api);
    }

    private void parseVersion(MontoyaApi api) {
        Version version = api.burpSuite().version();
        this.productName = version.name();
        this.majorVersion = version.major();
        this.minorVersion = version.minor();
        this.build = version.build();
    }

    public String getProductName() {
        return this.productName;
    }

    public String getMajor() {
        return this.majorVersion;
    }

    public String getMinor() {
        return this.minorVersion;
    }

    public String getBuild() {
        return this.build;
    }

    public int getMajorVersion() {
        String majorver = this.majorVersion.replaceAll("\\.", "");
        return ConvertUtil.parseIntDefault(majorver, 0);
    }

    public int getMinorVersion() {
        return (int)ConvertUtil.parseFloatDefault(this.minorVersion, 0);
    }

    public boolean isProfessional() {
        return this.productName.contains("Professional");
    }

    /**
     * バージョン番号
     *
     * @return バージョン番号
     */
    public String getVersion() {
        return String.format("%s %s.%s", getProductName(), getMajor(), getMinor());
    }

    public enum OSType {
        WINDOWS,
        LINUX,
        MAC,
        UNKOWN,
    }

    public static OSType getOSType() {
        String os_name = System.getProperty("os.name").toLowerCase();
        if (os_name.startsWith("win")) {
            return OSType.WINDOWS;
        }
        else if (os_name.startsWith("linux")) {
            return OSType.LINUX;
        }
        else if (os_name.startsWith("mac")) {
            return OSType.MAC;
        }
        else {
            return OSType.UNKOWN;
        }
    }

    /*
     * Windows
     *   %APPDATA%\BurpSuite\UserConfigCommunity.json
     *   %APPDATA%\BurpSuite\UserConfigPro.json
     * Linux
     *   %HOME%/.BurpSuite/UserConfigCommunity.json
     *   %HOME%/.BurpSuite/UserConfigPro.json
     * Mac
     *   %HOME%/.BurpSuite/UserConfigCommunity.json
     *   %HOME%/.BurpSuite/UserConfigPro.json     *
     */

    private final String USER_CONFIG_COMMUNITY = "UserConfigCommunity.json";
    private final String USER_CONFIG_PRO = "UserConfigPro.json";

    public File getBurpConfigFile() {
        if (isProfessional()) {
            final File burpConfig = new File(getBurpConfigHome(), USER_CONFIG_PRO);
            return burpConfig;
        }
        else {
            final File burpConfig = new File(getBurpConfigHome(), USER_CONFIG_COMMUNITY);
            return burpConfig;
        }
    }

    public File getBurpConfigHome() {
        if (BurpVersion.getOSType() == BurpVersion.OSType.WINDOWS) {
            String home = System.getenv("APPDATA");
            if (home != null) {
                final File burpHome = new File(home, "BurpSuite");
                return burpHome;
            }
        }
        else {
            String home = System.getenv("HOME");
            if (home != null) {
                final File burpHome = new File(home, ".BurpSuite");
                return burpHome;
            }
        }
        return null;
    }

}
