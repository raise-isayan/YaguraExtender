package yagura;

import extension.burp.BurpConfig;
import extension.helpers.json.JsonUtil;
import java.io.File;
import java.io.IOException;
import yagura.model.OptionProperty;

/**
 *
 * @author isayan
 */
public class Config extends BurpConfig {
        
    public static File getExtensionHomeDir() {
        return new File(getUserHomePath(), getExtensionDir());
    }

    public static String getTabCaption() {
        return "Yagura";
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

    public static String getToolLogName(String toolName) {
        return String.format("burp_tool_%s.log", toolName);
    }
    
    public static void saveToJson(File fo, OptionProperty option) throws IOException {
        JsonUtil.saveToJson(fo, option, true);
    }

    public static void loadFromJson(File fi, OptionProperty option) throws IOException {
        OptionProperty load = JsonUtil.loadFromJson(fi, OptionProperty.class, true);
        option.setProperty(load);
    }

    public static String stringToJson(OptionProperty option) {
        return JsonUtil.jsonToString(option, true);
    }

    public static void stringFromJson(String json, OptionProperty option) {
        OptionProperty load = JsonUtil.jsonFromString(json, OptionProperty.class, true);
        option.setProperty(load);
    }
    
}
