package yagura;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import extension.burp.BurpConfig;
import extension.helpers.FileUtil;
import extension.helpers.StringUtil;
import extension.helpers.json.JsonUtil;
import java.io.File;
import java.io.IOException;
import java.util.Map;

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

//    public static void saveToJson(File fo, OptionProperty option) throws IOException {
//        JsonUtil.saveToJson(fo, option, true);
//    }
//
//    public static void loadFromJson(File fi, OptionProperty option) throws IOException {
//        OptionProperty load = JsonUtil.loadFromJson(fi, OptionProperty.class, true);
//        option.setProperty(load);
//    }
//
//    public static String stringToJson(OptionProperty option) {
//        return JsonUtil.jsonToString(option, true);
//    }
//
//    public static void stringFromJson(String json, OptionProperty option) {
//        OptionProperty load = JsonUtil.jsonFromString(json, OptionProperty.class, true);
//        option.setProperty(load);
//    }

    public static void loadFromJson(File fi, Map<String, String> option) throws IOException {
        GsonBuilder gsonBuilder = new GsonBuilder().serializeNulls();
        gsonBuilder = gsonBuilder.excludeFieldsWithoutExposeAnnotation();
        Gson gson = gsonBuilder.create();
        String jsonString = StringUtil.getStringUTF8(FileUtil.bytesFromFile(fi));
        JsonElement jsonRoot = JsonUtil.parse(jsonString);
        if (jsonRoot.isJsonObject()) {
            JsonObject jsonMap = jsonRoot.getAsJsonObject();
            for (String memberName : jsonMap.keySet()) {
                option.put(memberName, jsonMap.get(memberName).toString());
            }
        }
    }

    public static void saveToJson(File fo, Map<String, String> option) throws IOException {
        GsonBuilder gsonBuilder = new GsonBuilder().serializeNulls();
        gsonBuilder = gsonBuilder.excludeFieldsWithoutExposeAnnotation();
        Gson gson = gsonBuilder.create();
        JsonObject jsonMap = new JsonObject();
        for (String memberName : option.keySet()) {
            jsonMap.add(memberName, JsonUtil.parse(option.get(memberName)));
        }
        String jsonString = gson.toJson(jsonMap);
        FileUtil.bytesToFile(StringUtil.getBytesUTF8(jsonString), fo);
    }

}
