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
        return BUNDLE.getString("projname");
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

//    public static void loadFromJson(File fi, Map<String, String> option) throws IOException {
//        GsonBuilder gsonBuilder = new GsonBuilder().serializeNulls();
//        gsonBuilder = gsonBuilder.excludeFieldsWithoutExposeAnnotation();
//        Gson gson = gsonBuilder.create();
//        String jsonString = StringUtil.getStringUTF8(FileUtil.bytesFromFile(fi));
//        JsonElement jsonRoot = JsonUtil.parseJson(jsonString);
//        if (jsonRoot.isJsonObject()) {
//            JsonObject jsonMap = jsonRoot.getAsJsonObject();
//            for (String memberName : jsonMap.keySet()) {
//                option.put(memberName, jsonMap.get(memberName).toString());
//            }
//        }
//    }
//
//    public static void saveToJson(File fo, Map<String, String> option) throws IOException {
//        GsonBuilder gsonBuilder = new GsonBuilder().serializeNulls();
//        gsonBuilder = gsonBuilder.excludeFieldsWithoutExposeAnnotation();
//        Gson gson = gsonBuilder.create();
//        JsonObject jsonMap = new JsonObject();
//        for (String memberName : option.keySet()) {
//            jsonMap.add(memberName, JsonUtil.parseJson(option.get(memberName)));
//        }
//        String jsonString = gson.toJson(jsonMap);
//        FileUtil.bytesToFile(StringUtil.getBytesUTF8(jsonString), fo);
//    }
}
