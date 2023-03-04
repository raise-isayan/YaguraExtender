package extension.view.base;

import extension.helpers.ConvertUtil;

/**
 *
 * @author isayan
 */
public class CustomVersion {

    private static int MAJOR_VERSION = 0;
    private static int MINOR_VERSION = 0;
    private static int REVISION_VERSION = 0;
    private static int RELEASE_NUMBER = 0;

    private static String RELEASE_EXTENSION = null;

    protected static void parseVersion(String version) {
        String[] splitversion = version.split("\\.");
        if (splitversion.length > 0) {
            MAJOR_VERSION = ConvertUtil.parseIntDefault(splitversion[0], -1);
        }
        if (splitversion.length > 1) {
            MINOR_VERSION = ConvertUtil.parseIntDefault(splitversion[1], -1);
        }
        if (splitversion.length > 2) {
            REVISION_VERSION = ConvertUtil.parseIntDefault(splitversion[2], -1);
        }
        if (splitversion.length > 3) {
            RELEASE_NUMBER = ConvertUtil.parseIntDefault(splitversion[3], -1);
        }
        if (splitversion.length > 4) {
            RELEASE_EXTENSION = splitversion[4];
        }
    }

    /**
     * メジャーバージョン
     *
     * @return メジャーバージョン番号
     */
    public int getMajorVersion() {
        return MAJOR_VERSION;
    }

    /**
     * マイナーバージョン
     *
     * @return マイナーバージョン番号
     */
    public int getMinorVersion() {
        return MINOR_VERSION;
    }

    /**
     * リビジョン番号
     *
     * @return リビジョン番号
     */
    public int getRevision() {
        return REVISION_VERSION;
    }

    /**
     * リリース番号
     *
     * @return リリース番号
     */
    public int getReleaseNumber() {
        return RELEASE_NUMBER;
    }

    /**
     * リリース拡張識別子
     *
     * @return リリース番号
     */
    public String getReleaseExtension() {
        return RELEASE_EXTENSION;
    }

    /**
     * バージョン番号
     *
     * @return バージョン番号
     */
    public String getVersion() {
        if (RELEASE_EXTENSION == null) {
            return String.format("%d.%d.%d.%d", MAJOR_VERSION, MINOR_VERSION, REVISION_VERSION, RELEASE_NUMBER);
        } else {
            return String.format("%d.%d.%d.%d%s", MAJOR_VERSION, MINOR_VERSION, REVISION_VERSION, RELEASE_NUMBER, RELEASE_EXTENSION);
        }
    }

}
