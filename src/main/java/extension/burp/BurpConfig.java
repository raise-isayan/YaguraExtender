package extension.burp;

import java.awt.Color;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Scanner;
import java.util.prefs.Preferences;
import javax.swing.UIManager;

/**
 *
 * @author isayan
 */
public class BurpConfig {
    private static final String CA_PASSWORD = "/burp/media/ps.p12";

    public static String getCAPassword() {
        return CA_PASSWORD;
    }

    public static KeyStore loadCACeart() throws KeyStoreException {
        try {
            final KeyStore ks;
            ks = KeyStore.getInstance("PKCS12");
            Preferences prefs = Preferences.userNodeForPackage(burp.BurpExtension.class);
            byte[] caCartByte = Base64.getDecoder().decode(prefs.get("caCert", ""));
            ks.load(new ByteArrayInputStream(caCartByte), CA_PASSWORD.toCharArray());
            return ks;
        } catch (IOException ex) {
            throw new KeyStoreException(ex);
        } catch (NoSuchAlgorithmException ex) {
            throw new KeyStoreException(ex);
        } catch (CertificateException ex) {
            throw new KeyStoreException(ex);
        }
    }

    public static String getUserHomePath() {
        return System.getProperties().getProperty("user.home");
    }

    public static File getUserHomeFile() {
        final File homePath = new File(getUserHomePath());
        return homePath;
    }

    public static String getUserDirPath() {
        return System.getProperties().getProperty("user.dir");
    }

    public static File getUserDirFile() {
        final File userDir = new File(getUserDirPath());
        return userDir;
    }


    public static File getUserConfig() {
        final File userDir = new File(getUserDirPath());
        return userDir;
    }

    /* Burp built in PayloadStrings */

    private static final String BUILT_IN_PASSWORDS_SIGNATURE = "/resources/PayloadStrings/Passwords.pay";
    private static final String BUILT_IN_USERNAMES_SIGNATURE = "/resources/PayloadStrings/Usernames.pay";
    private static final String BUILT_IN_SHORT_WORDS_SIGNATURE = "/resources/PayloadStrings/Short words.pay";
    private static final String BUILT_IN_3_LETTER_WORDS_SIGNATURE = "/resources/PayloadStrings/3 letter words.pay";
    private static final String BUILT_IN_4_LETTER_WORDS_SIGNATURE = "/resources/PayloadStrings/4 letter words.pay";
    private static final String BUILT_IN_5_LETTER_WORDS_SIGNATURE = "/resources/PayloadStrings/5 letter words.pay";
    private static final String BUILT_IN_6_LETTER_WORDS_SIGNATURE = "/resources/PayloadStrings/6 letter words.pay";
    private static final String BUILT_IN_7_LETTER_WORDS_SIGNATURE = "/resources/PayloadStrings/7 letter words.pay";
    private static final String BUILT_IN_8_LETTER_WORDS_SIGNATURE = "/resources/PayloadStrings/8 letter words.pay";
    private static final String BUILT_IN_9_LETTER_WORDS_SIGNATURE = "/resources/PayloadStrings/9 letter words.pay";
    private static final String BUILT_IN_10_LETTER_WORDS_SIGNATURE = "/resources/PayloadStrings/10 letter words.pay";
    private static final String BUILT_IN_11_LETTER_WORDS_SIGNATURE = "/resources/PayloadStrings/11 letter words.pay";
    private static final String BUILT_IN_12_LETTER_WORDS_SIGNATURE = "/resources/PayloadStrings/12 letter words.pay";

    private static final String BUILT_IN_0_9_SIGNATURE = "/resources/PayloadStrings/0-9.pay";
    private static final String BUILT_IN_A_Z_UPPERCASE_SIGNATURE  = "/resources/PayloadStrings/A-Z .pay";
    private static final String BUILT_IN_A_Z_LOWERCASE_SIGNATURE  = "/resources/PayloadStrings/a-z.pay";
    private static final String BUILT_IN_CGI_SCRIPTS_SIGNATURE = "/resources/PayloadStrings/CGI scripts.pay";
    private static final String BUILT_IN_DIRECTORIES_LONG_SIGNATURE = "/resources/PayloadStrings/Directories - long.pay";
    private static final String BUILT_IN_DIRECTORIES_SHORT_SIGNATURE = "/resources/PayloadStrings/Directories - short.pay";
    private static final String BUILT_IN_EXTENSIONS_LONG_SIGNATURE = "/resources/PayloadStrings/Extensions - long.pay";
    private static final String BUILT_IN_EXTENSIONS_SHORT_SIGNATURE = "/resources/PayloadStrings/Extensions - short.pay";
    private static final String BUILT_IN_FILENAMES_LONG_SIGNATURE = "/resources/PayloadStrings/Filenames - long.pay";
    private static final String BUILT_IN_FILENAMES_SHORT_SIGNATURE = "/resources/PayloadStrings/Filenames - short.pay";
    private static final String BUILT_IN_FORM_FIELD_NAMES_LONG_SIGNATURE = "/resources/PayloadStrings/Form field names - long.pay";
    private static final String BUILT_IN_FORM_FIELD_NAMES_SHORT_SIGNATURE = "/resources/PayloadStrings/Form field names - short.pay";
    private static final String BUILT_IN_FORM_FIELD_VALUES_SIGNATURE = "/resources/PayloadStrings/Form field values.pay";
    private static final String BUILT_IN_FORMAT_STRINGS_SIGNATURE = "/resources/PayloadStrings/Format strings.pay";
    private static final String BUILT_IN_FUZZING_FULL_SIGNATURE = "/resources/PayloadStrings/Fuzzing - full.pay";
    private static final String BUILT_IN_FUZZING_JSON_XML_INJECTION_SIGNATURE = "/resources/PayloadStrings/Fuzzing - JSON_XML injection.pay";
    private static final String BUILT_IN_FUZZING_OUT_OF_BAND_SIGNATURE = "/resources/PayloadStrings/Fuzzing - out-of-band.pay";
    private static final String BUILT_IN_FUZZING_PATH_TRAVERSAL_SINGLE_FILE_SIGNATURE = "/resources/PayloadStrings/Fuzzing - path traversal (single file).pay";
    private static final String BUILT_IN_FUZZING_PATH_TRAVERSAL_SIGNATURE = "/resources/PayloadStrings/Fuzzing - path traversal.pay";
    private static final String BUILT_IN_FUZZING_QUICK_SIGNATURE = "/resources/PayloadStrings/Fuzzing - quick.pay";
    private static final String BUILT_IN_FUZZING_SQL_INJECTION_SIGNATURE = "/resources/PayloadStrings/Fuzzing - SQL injection.pay";
    private static final String BUILT_IN_FUZZING_TEMPLATE_INJECTION_SIGNATURE = "/resources/PayloadStrings/Fuzzing - template injection.pay";
    private static final String BUILT_IN_FUZZING_XSS_SIGNATURE = "/resources/PayloadStrings/Fuzzing - XSS.pay";
    private static final String BUILT_IN_HTTP_HEADERS_SIGNATURE = "/resources/PayloadStrings/HTTP headers.pay";
    private static final String BUILT_IN_HTTP_VERBS_SIGNATURE = "/resources/PayloadStrings/HTTP verbs.pay";
    private static final String BUILT_IN_IIS_FILES_AND_DIRECTORIES_SIGNATURE = "/resources/PayloadStrings/IIS files and directories.pay";
    private static final String BUILT_IN_INTERESTING_FILES_AND_DIRECTORIES_SIGNATURE = "/resources/PayloadStrings/Interesting files and directories.pay";
    private static final String BUILT_IN_LOCAL_FILES_JAVA_SIGNATURE = "/resources/PayloadStrings/Local files - Java.pay";
    private static final String BUILT_IN_LOCAL_FILES_LINUX_SIGNATURE = "/resources/PayloadStrings/Local files - Linux.pay";
    private static final String BUILT_IN_LOCAL_FILES_WINDOWS_SIGNATURE = "/resources/PayloadStrings/Local files - Windows.pay";
    private static final String BUILT_IN_SERVER_SIDE_VARIABLE_NAMES_SIGNATURE = "/resources/PayloadStrings/Server-side variable names.pay";
    private static final String BUILT_IN_SSRF_TARGETS_SIGNATURE = "/resources/PayloadStrings/SSRF targets.pay";
    private static final String BUILT_IN_USER_AGENTS_LONG_SIGNATURE = "/resources/PayloadStrings/User agents - long.pay";
    private static final String BUILT_IN_USER_AGENTS_SHORT_SIGNATURE = "/resources/PayloadStrings/User agents - short.pay";

    public enum PayloadType {
        BUILT_IN_PASSWORDS, BUILT_IN_USERNAMES, BUILT_IN_SHORT_WORDS,
        BUILT_IN_LETTER_3_WORDS, BUILT_IN_LETTER_4_WORDS,
        BUILT_IN_LETTER_5_WORDS, BUILT_IN_LETTER_6_WORDS,
        BUILT_IN_LETTER_7_WORDS, BUILT_IN_LETTER_8_WORDS,
        BUILT_IN_LETTER_9_WORDS, BUILT_IN_LETTER_10_WORDS,
        BUILT_IN_LETTER_11_WORDS, BUILT_IN_LETTER_12_WORDS,
        BUILT_IN_0_9,
        BUILT_IN_A_Z_UPPERCASE,
        BUILT_IN_A_Z_LOWERCASE,
        BUILT_IN_CGI_SCRIPTS,
        BUILT_IN_DIRECTORIES_LONG,
        BUILT_IN_DIRECTORIES_SHORT,
        BUILT_IN_EXTENSIONS_LONG,
        BUILT_IN_EXTENSIONS_SHORT,
        BUILT_IN_FILENAMES_LONG,
        BUILT_IN_FILENAMES_SHORT,
        BUILT_IN_FORM_FIELD_NAMES_LONG,
        BUILT_IN_FORM_FIELD_NAMES_SHORT,
        BUILT_IN_FORM_FIELD_VALUES,
        BUILT_IN_FORMAT_STRINGS,
        BUILT_IN_FUZZING_FULL,
        BUILT_IN_FUZZING_JSON_XML_INJECTION,
        BUILT_IN_FUZZING_OUT_OF_BAND,
        BUILT_IN_FUZZING_PATH_TRAVERSAL_SINGLE_FILE,
        BUILT_IN_FUZZING_PATH_TRAVERSAL,
        BUILT_IN_FUZZING_QUICK,
        BUILT_IN_FUZZING_SQL_INJECTION,
        BUILT_IN_FUZZING_TEMPLATE_INJECTION,
        BUILT_IN_FUZZING_XSS,
        BUILT_IN_HTTP_HEADERS,
        BUILT_IN_HTTP_VERBS,
        BUILT_IN_IIS_FILES_AND_DIRECTORIES,
        BUILT_IN_INTERESTING_FILES_AND_DIRECTORIES,
        BUILT_IN_LOCAL_FILES_JAVA,
        BUILT_IN_LOCAL_FILES_LINUX,
        BUILT_IN_LOCAL_FILES_WINDOWS,
        BUILT_IN_SERVER_SIDE_VARIABLE_NAMES,
        BUILT_IN_SSRF_TARGETS,
        BUILT_IN_USER_AGENTS_LONG,
        BUILT_IN_USER_AGENTS_SHORT,
    };

    protected static List<String> loadFromFile(File file) throws IOException {
        return loadFromStream(new FileInputStream(file));
    }

    protected static List<String> loadFromResource(String name) throws IOException {
        return loadFromStream(BurpConfig.class.getResourceAsStream(name));
    }

    protected static List<String> loadFromStream(InputStream stream) throws IOException {
        List<String> signatures = new ArrayList<>();
        try (Scanner scanner = new Scanner(stream, StandardCharsets.UTF_8.name())) {
            while (scanner.hasNextLine()) {
                String line = scanner.nextLine();
                if (line.trim().length() == 0) {
                    continue;
                }
                signatures.add(line);
            }
        }
        return signatures;
    }

    public static List<String> loadFromSignatureTypes(PayloadType payloadType) throws IOException {
        List<String> signatures = new ArrayList<>();
        switch (payloadType) {
            case BUILT_IN_PASSWORDS:
                signatures.addAll(loadFromResource(BUILT_IN_PASSWORDS_SIGNATURE));
                break;
            case BUILT_IN_USERNAMES:
                signatures.addAll(loadFromResource(BUILT_IN_USERNAMES_SIGNATURE));
                break;
            case BUILT_IN_SHORT_WORDS:
                signatures.addAll(loadFromResource(BUILT_IN_SHORT_WORDS_SIGNATURE));
                break;
            case BUILT_IN_LETTER_3_WORDS:
                signatures.addAll(loadFromResource(BUILT_IN_3_LETTER_WORDS_SIGNATURE));
                break;
            case BUILT_IN_LETTER_4_WORDS:
                signatures.addAll(loadFromResource(BUILT_IN_4_LETTER_WORDS_SIGNATURE));
                break;
            case BUILT_IN_LETTER_5_WORDS:
                signatures.addAll(loadFromResource(BUILT_IN_5_LETTER_WORDS_SIGNATURE));
                break;
            case BUILT_IN_LETTER_6_WORDS:
                signatures.addAll(loadFromResource(BUILT_IN_6_LETTER_WORDS_SIGNATURE));
                break;
            case BUILT_IN_LETTER_7_WORDS:
                signatures.addAll(loadFromResource(BUILT_IN_7_LETTER_WORDS_SIGNATURE));
                break;
            case BUILT_IN_LETTER_8_WORDS:
                signatures.addAll(loadFromResource(BUILT_IN_8_LETTER_WORDS_SIGNATURE));
                break;
            case BUILT_IN_LETTER_9_WORDS:
                signatures.addAll(loadFromResource(BUILT_IN_9_LETTER_WORDS_SIGNATURE));
                break;
            case BUILT_IN_LETTER_10_WORDS:
                signatures.addAll(loadFromResource(BUILT_IN_10_LETTER_WORDS_SIGNATURE));
                break;
            case BUILT_IN_LETTER_11_WORDS:
                signatures.addAll(loadFromResource(BUILT_IN_11_LETTER_WORDS_SIGNATURE));
                break;
            case BUILT_IN_LETTER_12_WORDS:
                signatures.addAll(loadFromResource(BUILT_IN_12_LETTER_WORDS_SIGNATURE));
                break;
            case BUILT_IN_0_9:
                signatures.addAll(loadFromResource(BUILT_IN_0_9_SIGNATURE));
                break;
            case BUILT_IN_A_Z_UPPERCASE:
                signatures.addAll(loadFromResource(BUILT_IN_A_Z_UPPERCASE_SIGNATURE));
                break;
            case BUILT_IN_A_Z_LOWERCASE:
                signatures.addAll(loadFromResource(BUILT_IN_A_Z_LOWERCASE_SIGNATURE));
                break;
            case BUILT_IN_CGI_SCRIPTS:
                signatures.addAll(loadFromResource(BUILT_IN_CGI_SCRIPTS_SIGNATURE));
                break;
            case BUILT_IN_DIRECTORIES_LONG:
                signatures.addAll(loadFromResource(BUILT_IN_DIRECTORIES_LONG_SIGNATURE));
                break;
            case BUILT_IN_DIRECTORIES_SHORT:
                signatures.addAll(loadFromResource(BUILT_IN_DIRECTORIES_SHORT_SIGNATURE));
                break;
            case BUILT_IN_EXTENSIONS_LONG:
                signatures.addAll(loadFromResource(BUILT_IN_EXTENSIONS_LONG_SIGNATURE));
                break;
            case BUILT_IN_EXTENSIONS_SHORT:
                signatures.addAll(loadFromResource(BUILT_IN_EXTENSIONS_SHORT_SIGNATURE));
                break;
            case BUILT_IN_FILENAMES_LONG:
                signatures.addAll(loadFromResource(BUILT_IN_FILENAMES_LONG_SIGNATURE));
                break;
            case BUILT_IN_FILENAMES_SHORT:
                signatures.addAll(loadFromResource(BUILT_IN_FILENAMES_SHORT_SIGNATURE));
                break;
            case BUILT_IN_FORM_FIELD_NAMES_LONG:
                signatures.addAll(loadFromResource(BUILT_IN_FORM_FIELD_NAMES_LONG_SIGNATURE));
                break;
            case BUILT_IN_FORM_FIELD_NAMES_SHORT:
                signatures.addAll(loadFromResource(BUILT_IN_FORM_FIELD_NAMES_SHORT_SIGNATURE));
                break;
            case BUILT_IN_FORM_FIELD_VALUES:
                signatures.addAll(loadFromResource(BUILT_IN_FORM_FIELD_VALUES_SIGNATURE));
                break;
            case BUILT_IN_FORMAT_STRINGS:
                signatures.addAll(loadFromResource(BUILT_IN_FORMAT_STRINGS_SIGNATURE));
                break;
            case BUILT_IN_FUZZING_FULL:
                signatures.addAll(loadFromResource(BUILT_IN_FUZZING_FULL_SIGNATURE));
                break;
            case BUILT_IN_FUZZING_JSON_XML_INJECTION:
                signatures.addAll(loadFromResource(BUILT_IN_FUZZING_JSON_XML_INJECTION_SIGNATURE));
                break;
            case BUILT_IN_FUZZING_OUT_OF_BAND:
                signatures.addAll(loadFromResource(BUILT_IN_FUZZING_OUT_OF_BAND_SIGNATURE));
                break;
            case BUILT_IN_FUZZING_PATH_TRAVERSAL_SINGLE_FILE:
                signatures.addAll(loadFromResource(BUILT_IN_FUZZING_PATH_TRAVERSAL_SINGLE_FILE_SIGNATURE));
                break;
            case BUILT_IN_FUZZING_PATH_TRAVERSAL:
                signatures.addAll(loadFromResource(BUILT_IN_FUZZING_PATH_TRAVERSAL_SIGNATURE));
                break;
            case BUILT_IN_FUZZING_QUICK:
                signatures.addAll(loadFromResource(BUILT_IN_FUZZING_QUICK_SIGNATURE));
                break;
            case BUILT_IN_FUZZING_SQL_INJECTION:
                signatures.addAll(loadFromResource(BUILT_IN_FUZZING_SQL_INJECTION_SIGNATURE));
                break;
            case BUILT_IN_FUZZING_TEMPLATE_INJECTION:
                signatures.addAll(loadFromResource(BUILT_IN_FUZZING_TEMPLATE_INJECTION_SIGNATURE));
                break;
            case BUILT_IN_FUZZING_XSS:
                signatures.addAll(loadFromResource(BUILT_IN_FUZZING_XSS_SIGNATURE));
                break;
            case BUILT_IN_HTTP_HEADERS:
                signatures.addAll(loadFromResource(BUILT_IN_HTTP_HEADERS_SIGNATURE));
                break;
            case BUILT_IN_HTTP_VERBS:
                signatures.addAll(loadFromResource(BUILT_IN_HTTP_VERBS_SIGNATURE));
                break;
            case BUILT_IN_IIS_FILES_AND_DIRECTORIES:
                signatures.addAll(loadFromResource(BUILT_IN_IIS_FILES_AND_DIRECTORIES_SIGNATURE));
                break;
            case BUILT_IN_INTERESTING_FILES_AND_DIRECTORIES:
                signatures.addAll(loadFromResource(BUILT_IN_INTERESTING_FILES_AND_DIRECTORIES_SIGNATURE));
                break;
            case BUILT_IN_LOCAL_FILES_JAVA:
                signatures.addAll(loadFromResource(BUILT_IN_LOCAL_FILES_JAVA_SIGNATURE));
                break;
            case BUILT_IN_LOCAL_FILES_LINUX:
                signatures.addAll(loadFromResource(BUILT_IN_LOCAL_FILES_LINUX_SIGNATURE));
                break;
           case BUILT_IN_LOCAL_FILES_WINDOWS:
                signatures.addAll(loadFromResource(BUILT_IN_LOCAL_FILES_WINDOWS_SIGNATURE));
                break;
            case BUILT_IN_SERVER_SIDE_VARIABLE_NAMES:
                signatures.addAll(loadFromResource(BUILT_IN_SERVER_SIDE_VARIABLE_NAMES_SIGNATURE));
                break;
            case BUILT_IN_SSRF_TARGETS:
                signatures.addAll(loadFromResource(BUILT_IN_SSRF_TARGETS_SIGNATURE));
                break;
            case BUILT_IN_USER_AGENTS_LONG:
                signatures.addAll(loadFromResource(BUILT_IN_USER_AGENTS_LONG_SIGNATURE));
                break;
            case BUILT_IN_USER_AGENTS_SHORT:
                signatures.addAll(loadFromResource(BUILT_IN_USER_AGENTS_SHORT_SIGNATURE));
                break;
            default:
                break;
        }
        return signatures;
    }

   public static Color getTabFlashColor() {
         try {
            return UIManager.getColor("Burp.tabFlashColour");
        } catch (NullPointerException ex) {
            return new Color(0xff, 0x66, 0x33);
        }
   }


}
