package extend.util.external;

import burp.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.annotations.Expose;
import extension.burp.BurpConfig;
import extension.burp.BurpVersion;
import extension.helpers.FileUtil;
import extension.helpers.StringUtil;
import extension.helpers.json.JsonUtil;
import java.io.File;
import java.io.FileFilter;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
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

    public final static String BROWSER_PROFILE_GUEST = "Guest Profile";

    private final static String CHROMIUM_BROWSER = "burpbrowser";

    private final static String CHROMIUM_BROWSER_EXTENSION = "burp-chromium-extension";

    private final static String BURP_CHROMIUM_EXTENSION = "resources/Browser/ChromiumExtension";

    private final static String BURP_CHROMIUM_PROPERTIES = "/chromium.properties";

    private final static String BURP_CHROMIUM_STATE = "Local State";

    private final static Properties chromium_prop = new Properties();

    static {
        try {
            chromium_prop.load(BurpBrowser.class.getResourceAsStream(BURP_CHROMIUM_PROPERTIES));
        } catch (IOException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        } catch (java.lang.NullPointerException ex) {
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
        Path browserPath = ZipUtil.getBaseDirectory().resolve(CHROMIUM_BROWSER);
        File browserDir = browserPath.toFile();
        if (browserDir.exists() && browserDir.list().length > 0) {
            return browserDir.toPath();
        } else {
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
                chromeExec = "Chromium.app/Contents/MacOS/Chromium";
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
            String burpJar = ZipUtil.getBaseJar(burpJarUrl);
            ZipUtil.decompressZip(new File(burpJar), browserExtensions, BURP_CHROMIUM_EXTENSION);
        }
    }

    public List<String> getBrowserExecAndArgs(String profileKey, int port) {
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
            String.format("--proxy-server=localhost:%d", port),
            "--proxy-bypass-list=<-loopback>",
            "--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.86 Safari/537.36",
            String.format("--user-data-dir=%s", getBrowseUserDataDirectory().toString()),
            String.format("--profile-directory=%s", profileKey),
            "--ignore-certificate-errors",
            "--disable-features=TrackingProtection3pcd,LensOverlay",
            String.format("--load-extension=%s", getBrowseExtensionDirectory().toString()),
            "chrome://newtab"
        );
        List<String> chromeExecAndArg = new ArrayList<>();
        chromeExecAndArg.add(getBrowsePath().toString());
        chromeExecAndArg.addAll(CHROME_ARGS);
        return chromeExecAndArg;
    }

    public File[] getBrowserProfileDirectory() {
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
                try {
                    int p1 = Integer.parseInt(f1.getName().substring("Profile ".length()));
                    int p2 = Integer.parseInt(f2.getName().substring("Profile ".length()));
                    return p1 - p2;
                }
                catch (NumberFormatException ex) {
                    return f1.getName().compareTo(f2.getName());
                }
            }
        });
        return profiles;
    }

    public void openBrowser(String profileKey, int port) {
        try {
            List<String> chromeExeAndArg = getBrowserExecAndArgs(profileKey, port);
            ProcessBuilder process = new ProcessBuilder(chromeExeAndArg);
            process.start();
        } catch (IOException ex) {
            JOptionPane.showMessageDialog(null, ex.getMessage());
        }
    }

    private Path getBrowserProfilePath() {
        Path path = getBrowseUserDataDirectory();
        return path.resolve(BURP_CHROMIUM_STATE);
    }

    public Map<String, BrowserProfile> getBrowserProfile() {
        try {
            Path path = getBrowserProfilePath();
            return getBrowserProfile(path);
        }
        catch (IOException ex) {
            File[] profiles = this.getBrowserProfileDirectory();
            Map<String, BrowserProfile> order_profile = new LinkedHashMap<>();
            for (File p : profiles) {
                BrowserProfile profile = new BrowserProfile();
                profile.setName(p.getName());
                order_profile.put(p.getName(), profile);
            }
            return order_profile;
        }
    }

    /**
     *
     * @param path
     * @return
     * @throws java.io.IOException
     */
    protected static Map<String, BrowserProfile> getBrowserProfile(final Path path) throws IOException {
        String config = FileUtil.stringFromFile(path.toFile(), StandardCharsets.UTF_8);
        JsonObject root_json = JsonUtil.parseJsonObject(config);
        JsonObject profile_info = root_json.getAsJsonObject("profile").getAsJsonObject("info_cache");
        JsonArray profiles_order = root_json.getAsJsonObject("profile").getAsJsonArray("profiles_order");
        Map<String, JsonElement> profile_map = profile_info.asMap();
        Map<String, BrowserProfile> browser_profile = new LinkedHashMap<>();
        for (int i = 0; i < profiles_order.size(); i++) {
            JsonElement profile_key_json = profiles_order.get(i);
            String profile_key = profile_key_json.getAsString();
            if (profile_key.startsWith("Profile ")) {
                JsonElement profile_entry = profile_map.get(profile_key);
                BrowserProfile prowserProfile = JsonUtil.jsonFromJsonElement(profile_entry, BrowserProfile.class, true);
                prowserProfile.setProfileKey(profile_key);
                browser_profile.put(profile_key, prowserProfile);
            }
        }
        return browser_profile;
    }

    public static class BrowserProfile {

        public final static BrowserProfile DEFAULT;
        public final static BrowserProfile GUEST;

        static {
            DEFAULT = new BrowserProfile();
            DEFAULT.profileKey = BROWSER_PROFILE_DEFAULT;
            DEFAULT.name = BROWSER_PROFILE_DEFAULT;
            GUEST = new BrowserProfile();
            GUEST.profileKey = BROWSER_PROFILE_GUEST;
            GUEST.name = BROWSER_PROFILE_GUEST;
        }

        private String profileKey;

        /**
         * @return the profile
         */
        public String getProfileKey() {
            return profileKey;
        }

        /**
         * @param profileKey the profile to set
         */
        public void setProfileKey(String profileKey) {
            this.profileKey = profileKey;
        }

        @Expose
        private String name;

        /**
         * @return the name
         */
        public String getName() {
            return name;
        }

        /**
         * @param name the name to set
         */
        public void setName(String name) {
            this.name = name;
        }

        @Override
        public String toString() {
            return name;
        }

    }

}
