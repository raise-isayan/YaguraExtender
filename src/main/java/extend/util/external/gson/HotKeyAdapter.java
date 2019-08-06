package extend.util.external.gson;

import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;
import extend.view.base.MatchItem;
import java.awt.event.KeyEvent;
import java.lang.reflect.Type;
import yagura.model.HotKey;

/**
 *
 * @author isayan
 */
public class HotKeyAdapter implements JsonSerializer<HotKey>, JsonDeserializer<HotKey>  {

    @Override
    public JsonElement serialize(HotKey t, Type type, JsonSerializationContext jsc) {
        final JsonObject jsonObject = new JsonObject();
        jsonObject.add("map", jsc.serialize(t.toString()));
        return jsonObject;
    }

    @Override
    public HotKey deserialize(JsonElement je, Type type, JsonDeserializationContext jdc) throws JsonParseException {
        final JsonObject jsonObject = je.getAsJsonObject();
        return HotKey.parseHotkey(jdc.deserialize(jsonObject.get("map"), String.class));
    }
    
}
