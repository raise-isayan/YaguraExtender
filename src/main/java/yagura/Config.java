package yagura;

import extension.burp.BurpConfig;
import java.io.File;

/**
 *
 * @author isayan
 */
public class Config extends BurpConfig {

    protected final static java.util.ResourceBundle BUNDLE = java.util.ResourceBundle.getBundle("burp/resources/release");

    public static File getExtensionHomeDir() {
        return new File(getUserHomePath(), getExtensionDir());
    }

    public static String getTabCaption() {
        String tabcaption = BUNDLE.getString("tabcaption");
        return tabcaption;
    }

    public static String getExtensionDir() {
        return ".yaguraextender";
    }

    public static String getExtensionName() {
        return "YaguraExtender.json";
    }

    public static String getLoggingPropertyName() {
        return "logging.properties";
    }

    public static String getProxyLogMessageName() {
        return "proxy-message.log";
    }

    public static String getWebSocketLogMessageName() {
        return "websocket-message.log";
    }

    public static String getWebSocketLogFinalMessageName() {
        return "websocket-final-message.log";
    }

    public static String getToolLogName(String toolName) {
        return String.format("burp_tool_%s.log", toolName);
    }

}
