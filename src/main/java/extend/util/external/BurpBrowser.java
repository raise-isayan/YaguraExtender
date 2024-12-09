package extend.util.external;

import burp.api.montoya.MontoyaApi;
import extension.burp.BurpConfig;
import extension.burp.BurpVersion;
import static extension.burp.BurpVersion.OSType.LINUX;
import static extension.burp.BurpVersion.OSType.MAC;
import static extension.burp.BurpVersion.OSType.WINDOWS;
import extension.helpers.StringUtil;
import java.io.File;
import java.io.FileFilter;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JOptionPane;

/**
 *
 * @author isayan
 */
public class BurpBrowser {

    private final static Logger logger = Logger.getLogger(BurpBrowser.class.getName());

    public final static String BROWSER_PROFILE_DEFAULT = "Default";

    private final static String CHROMIUM_BROWSER = "burpbrowser";

    private final static String CHROMIUM_BROWSER_EXTENSION = "burp-chromium-extension";

    private final static String BURP_CHROMIUM_EXTENSION = "resources/Browser/ChromiumExtension";

    private final static String BURP_CHROMIUM_PROPERTIES = "/chromium.properties";

    private final static Properties chromium_prop = new Properties();

    static {
        try {
            chromium_prop.load(BurpBrowser.class.getResourceAsStream(BURP_CHROMIUM_PROPERTIES));
        } catch (IOException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }

    private final MontoyaApi api;

    private BurpBrowser(final MontoyaApi api) {
        this.api = api;
    }

    public static BurpBrowser getInstance(final MontoyaApi api) {
        return new BurpBrowser(api);
    }

    public static String getBaseJar(URL url) {
        String path = url.toExternalForm();
        try {
            int fend = path.indexOf('!');
            if (fend >= 0) {
                path = path.substring(0, fend);
            }
            if (path.startsWith("jar:")) {
                path = path.substring("jar:".length());
            }
            File file = new File(new URI(path));
            path = file.getAbsolutePath();
        } catch (URISyntaxException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return path;
    }

    public static Path getBaseDirectory() {
        URL burpJarUrl = BurpBrowser.class.getResource("/");
        File path = new File(getBaseJar(burpJarUrl));
        return path.getParentFile().toPath();
    }

    public static String getOSArc() {
        String os_arc = null;
        BurpVersion.OSType os = BurpVersion.getOSType();
        BurpVersion.ArcType arc = BurpVersion.getArchType();
        switch (os) {
            case WINDOWS:
                os_arc = "win";
                break;
            case LINUX:
                os_arc = "linux";
                break;
            case MAC:
                os_arc = "macos";
                break;
        }
        switch (arc) {
            case AMD64:
                if (os == BurpVersion.OSType.MAC) {
                    os_arc += "x64";
                } else {
                    os_arc += "64";
                }
                break;
            case ARM64:
                os_arc += "arm64";
                break;
        }
        return os_arc;
    }

    public static String getBrowserVersion() {
        String key = getOSArc();
        return chromium_prop.getProperty(key);
    }

    public static Path getBrowseDirectoryPath() {
        Path browserPath = getBaseDirectory().resolve(CHROMIUM_BROWSER);
        File browserDir = browserPath.toFile();
        if (browserDir.exists() && browserDir.list().length > 0) {
            return browserDir.toPath();
        }
        else {
            Path burpPath = getBurpSuiteDirectoryPath();
            return burpPath.resolve(CHROMIUM_BROWSER);
        }
    }

    public static Path getBurpSuiteDirectoryPath() {
        String home = "";
        String burpDir = "";
        BurpVersion.OSType os = BurpVersion.getOSType();
        switch (os) {
            case WINDOWS:
                home = System.getenv("APPDATA");
                burpDir = "BurpSuite";
                break;
            case LINUX:
                home = System.getenv("HOME");
                burpDir = ".BurpSuite";
                break;
            case MAC:
                home = System.getenv("HOME");
                burpDir = ".BurpSuite";
                break;
        }
        return Path.of(home, burpDir);
    }


    public Path getBrowseUserDataDirectory() {
        Path dir = getBurpSuiteDirectoryPath();
        Path path = Path.of("pre-wired-browser");
        BurpConfig.EmbeddedBrowser browserConfig = BurpConfig.getEmbeddedBrowser(api);
        if (browserConfig.isAllowSavingBrowserSettings() && !StringUtil.isNullOrEmpty(browserConfig.getBrowserDataDirectory())) {
            path = Path.of(browserConfig.getBrowserDataDirectory());
        }
        return dir.resolve(path);
    }

    public static Path getBrowseExtensionDirectory() {
        Path dir = getBurpSuiteDirectoryPath();
        Path path = Path.of(CHROMIUM_BROWSER_EXTENSION);
        return dir.resolve(path);
    }

    public static boolean existsBrowseExtensionDirectory() {
        File dir = getBrowseExtensionDirectory().toFile();
        return dir.exists();
    }

    public static Path getBrowsePath() {
        String chromeExec = "";
        BurpVersion.OSType os = BurpVersion.getOSType();
        switch (os) {
            case WINDOWS:
                chromeExec = "chrome.exe";
                break;
            case LINUX:
                chromeExec = "chrome";
                break;
            case MAC:
                chromeExec = "Chromium.app";
                break;
        }
        Path dir = getBrowseDirectoryPath();
        Path path = Path.of(getBrowserVersion(), chromeExec);
        return dir.resolve(path);
    }

    public static void copyBrowserExtension() throws IOException {
        if (!existsBrowseExtensionDirectory()) {
            File browserExtensions = getBrowseExtensionDirectory().toFile();
            browserExtensions.mkdir();
            URL burpJarUrl = BurpBrowser.class.getResource("/");
            String burpJar = getBaseJar(burpJarUrl);
            ZipUtil.decompressZip(new File(burpJar), browserExtensions, BURP_CHROMIUM_EXTENSION);
        }
    }

    public List<String> getBrowserExecAndArgs(String profile, int port) {
        // chrome://version/ から情報取得
        final List<String> CHROME_ARGS = List.of(
                "--disable-ipc-flooding-protection",
                "--disable-xss-auditor",
                "--disable-bundled-ppapi-flash",
                "--disable-plugins-discovery",
                "--disable-default-apps",
                "--disable-prerender-local-predictor",
                "--disable-sync",
                "--disable-breakpad",
                "--disable-crash-reporter",
                "--disable-prerender-local-predictor",
                "--disk-cache-size=0",
                "--disable-settings-window",
                "--disable-notifications",
                "--disable-speech-api",
                "--disable-file-system",
                "--disable-presentation-api",
                "--disable-permissions-api",
                "--disable-new-zip-unpacker",
                "--disable-media-session-api",
                "--no-experiments",
                "--no-events",
                "--no-first-run",
                "--no-default-browser-check",
                "--no-pings",
                "--no-service-autorun",
                "--media-cache-size=0",
                "--use-fake-device-for-media-stream",
                "--dbus-stub",
                "--disable-background-networking",
                "--disable-features=ChromeWhatsNewUI,HttpsUpgrades,ImageServiceObserveSyncDownloadStatus",
                "--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.127 Safari/537.36",
                "--ignore-certificate-errors",
                String.format("--proxy-server=localhost:%d", port),
                "--proxy-bypass-list=<-loopback>",
                String.format("--profile-directory=%s", profile),
                String.format("--user-data-dir=%s", getBrowseUserDataDirectory().toString()),
                String.format("--load-extension=%s", getBrowseExtensionDirectory().toString()),
                "chrome://newtab"
        );
        BurpVersion.OSType os = BurpVersion.getOSType();
        List<String> chromeExecAndArg = new ArrayList<>();
        chromeExecAndArg.add(getBrowsePath().toString());
        if (BurpVersion.OSType.MAC == os) {
            chromeExecAndArg.add("--args");
        }
        chromeExecAndArg.addAll(CHROME_ARGS);
        return chromeExecAndArg;
    }

    public File[] getUserProfile() {
        File file = getBrowseUserDataDirectory().toFile();
        File[] profiles = file.listFiles(new FileFilter() {

            @Override
            public boolean accept(File pathname) {
                return pathname.isDirectory() && pathname.getName().startsWith("Profile ");
            }

        });
        profiles = (profiles == null) ? new File[]{} : profiles;
        Arrays.sort(profiles, new Comparator<File>() {
            @Override
            public int compare(File f1, File f2) {
                int p1 = Integer.parseInt(f1.getName().substring("Profile ".length()));
                int p2 = Integer.parseInt(f2.getName().substring("Profile ".length()));
                return p1 - p2;
            }
        });
        return profiles;
    }

    public void openBrowser(String profile, int port) {
        try {
            List<String> chromeExeAndArg = getBrowserExecAndArgs(profile, port);
            ProcessBuilder process = new ProcessBuilder(chromeExeAndArg);
            process.start();
        } catch (IOException ex) {
            JOptionPane.showMessageDialog(null, ex.getMessage());
        }
    }

}
