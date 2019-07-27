package extend.util.external;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.json.JsonStructure;
import javax.json.JsonValue;
import javax.json.JsonWriter;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;

/**
 *
 * @author isayan
 */
public class JsonUtil {

    public static String stringify(JsonStructure jsonStructure) {
        StringWriter stWriter = new StringWriter();
        try (JsonWriter jsonWriter = Json.createWriter(stWriter)) {
            jsonWriter.write(jsonStructure);
        }
        String jsonString = stWriter.toString();
        return jsonString;
    }

    public static JsonStructure parse(String jsonObjectString) {
        JsonReader jsonReader = Json.createReader(new StringReader(jsonObjectString));
        return jsonReader.read();
    }

    public static String prettyJSON(String plainJson, boolean pretty) throws IOException {
        StringWriter sw = new StringWriter();
        try {
            javax.json.spi.JsonProvider jsonProvider = javax.json.spi.JsonProvider.provider();
            try (javax.json.JsonReader jsonReader = jsonProvider.createReader(new StringReader(plainJson))) {
                javax.json.JsonStructure json = jsonReader.read();
                return prettyJSON(json, pretty);
            }
        } catch (javax.json.stream.JsonParsingException ex) {
            throw new IOException(ex);
        }
    }

    public static String prettyJSON(JsonStructure json, boolean pretty) throws IOException {
        StringWriter sw = new StringWriter();
        try {
            javax.json.spi.JsonProvider jsonProvider = javax.json.spi.JsonProvider.provider();
            final Map<String, Boolean> config = new HashMap<String, Boolean>();
            if (pretty) {
                config.put(javax.json.stream.JsonGenerator.PRETTY_PRINTING, pretty);
            }
            try (javax.json.JsonWriter jsonWriter = jsonProvider.createWriterFactory(config).createWriter(sw)) {
                jsonWriter.write(json);
            }
        } catch (javax.json.stream.JsonParsingException ex) {
            throw new IOException(ex);
        }
        return sw.getBuffer().toString().trim();
    }

    public static DefaultTreeModel toJSONTreeModel(JsonStructure json) {
        DefaultMutableTreeNode rootJSON = new DefaultMutableTreeNode("JSON");
        DefaultTreeModel model = new DefaultTreeModel(rootJSON);
        toJSONTreeNode(json, rootJSON);
        return model;
    }

    private static void toJSONTreeNode(JsonValue json, DefaultMutableTreeNode parentNode) {
        switch (json.getValueType()) {
            case ARRAY: {
                JsonArray jsonArray = (JsonArray) json;
                for (int i = 0; i < jsonArray.size(); i++) {
                    JsonValue value = jsonArray.get(i);
                    toJSONTreeNode(value, parentNode);
                }
                break;
            }
            case OBJECT: {
                DefaultMutableTreeNode node = new DefaultMutableTreeNode("{}");
                parentNode.add(node);
                JsonObject jsonObject = (JsonObject) json;
                Set<Map.Entry<String, JsonValue>> set = jsonObject.entrySet();
                for (Map.Entry<String, JsonValue> s : set) {
                    JsonValue value = s.getValue();
                    switch (value.getValueType()) {
                        case STRING:
                        case NUMBER:
                        case TRUE:
                        case FALSE:
                        case NULL:
                            DefaultMutableTreeNode jsonKeySet = new DefaultMutableTreeNode(s);
                            node.add(jsonKeySet);
                            break;
                        default: {
                            DefaultMutableTreeNode childNode = new DefaultMutableTreeNode(s.getKey());
                            node.add(childNode);
                            toJSONTreeNode(value, childNode);
                            break;
                        }
                    }
                }
                break;
            }
            case STRING:
            case NUMBER:
            case TRUE:
            case FALSE:
            case NULL:
                DefaultMutableTreeNode node = new DefaultMutableTreeNode(json);
                parentNode.add(node);
                break;
        }
    }
}
