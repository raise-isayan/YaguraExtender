/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package yagura.external;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;

import javax.json.Json;
import javax.json.JsonReader;
import javax.json.JsonStructure;
import javax.json.JsonWriter;

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
            javax.json.JsonReader jsonReader = jsonProvider.createReader(new StringReader(plainJson));
            javax.json.JsonStructure json = jsonReader.read();
            jsonReader.close();
            Map<String, Boolean> config = new HashMap<String, Boolean>();
            if (pretty) config.put(javax.json.stream.JsonGenerator.PRETTY_PRINTING, pretty);        
            javax.json.JsonWriter jsonWriter = jsonProvider.createWriterFactory(config).createWriter(sw);
            jsonWriter.write(json);
            jsonWriter.close();        
        }
        catch (javax.json.stream.JsonParsingException ex) {
            throw new IOException(ex);
        }
        return sw.getBuffer().toString().trim();
    }
    
}
