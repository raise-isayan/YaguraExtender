package extend.util.external.gson;

import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonElement;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.reflect.TypeToken;
import extension.burp.Confidence;
import extension.burp.HighlightColor;
import extension.burp.NotifyType;
import extension.burp.Severity;
import extension.burp.TargetTool;
import extension.view.base.MatchItem;
import java.lang.reflect.Type;
import yagura.model.MatchAlertItem;
import yagura.model.MatchReplaceItem;

/**
 *
 * @author isayan
 */
public class XMatchItemAdapter implements JsonSerializer<MatchItem>, JsonDeserializer<MatchItem> {

    @Override
    public JsonElement serialize(MatchItem t, Type type, JsonSerializationContext jsc) {
        final TypeToken<?> token = TypeToken.get(type);
        final JsonObject jsonObject = new JsonObject();
        jsonObject.add("selected", jsc.serialize(t.isSelected()));
        jsonObject.add("ignoreCase", jsc.serialize(t.isIgnoreCase()));
        jsonObject.add("regexp", jsc.serialize(t.isRegexp()));
        jsonObject.add("match", jsc.serialize(t.getMatch()));
        jsonObject.add("type", jsc.serialize(t.getType()));
        jsonObject.add("replace", jsc.serialize(t.getReplace()));
        final Class cls = token.getRawType();
        if (cls.equals(MatchAlertItem.class)) {
            MatchAlertItem matchItem = (MatchAlertItem) t;
            jsonObject.add("smartMatch", jsc.serialize(matchItem.isSmartMatch()));
            jsonObject.add("issueName", jsc.serialize(matchItem.getIssueName()));
            jsonObject.add("severity", jsc.serialize(matchItem.getSeverity()));
            jsonObject.add("confidence", jsc.serialize(matchItem.getConfidence()));
            jsonObject.add("notifyTypes", jsc.serialize(matchItem.getNotifyTypes()));
            jsonObject.add("targetTools", jsc.serialize(matchItem.getTargetTools()));
            jsonObject.add("highlightColor", jsc.serialize(matchItem.getHighlightColor()));
            jsonObject.add("comment", jsc.serialize(matchItem.getComment()));
        } else if (cls.equals(MatchReplaceItem.class)) {
            MatchReplaceItem matchItem = (MatchReplaceItem) t;
            jsonObject.add("smartMatch", jsc.serialize(matchItem.isSmartMatch()));
            jsonObject.add("metaChar", jsc.serialize(matchItem.isMetaChar()));
        }
        return jsonObject;
    }

    @Override
    public MatchItem deserialize(JsonElement je, Type type, JsonDeserializationContext jdc) throws JsonParseException {
        final MatchItem item = new MatchItem();
        final TypeToken<?> token = TypeToken.get(type);
        final JsonObject jsonObject = je.getAsJsonObject();
        item.setSelected(jdc.deserialize(jsonObject.get("selected"), Boolean.TYPE));
        item.setIgnoreCase(jdc.deserialize(jsonObject.get("ignoreCase"), Boolean.TYPE));
        item.setRegexp(jdc.deserialize(jsonObject.get("regexp"), Boolean.TYPE));
        item.setMatch(jdc.deserialize(jsonObject.get("match"), String.class));
        item.setType(jdc.deserialize(jsonObject.get("type"), String.class));
        item.setReplace(jdc.deserialize(jsonObject.get("replace"), String.class));
        final Class cls = token.getRawType();
        if (cls.equals(MatchAlertItem.class)) {
            final MatchAlertItem matchItem = new MatchAlertItem();
            matchItem.setProperty((MatchItem) item);
            if (jsonObject.has("smartMatch")) matchItem.setSmartMatch(jdc.deserialize(jsonObject.get("smartMatch"), Boolean.TYPE));
            if (jsonObject.has("issueName")) matchItem.setIssueName(jdc.deserialize(jsonObject.get("issueName"), String.class));
            if (jsonObject.has("severity")) matchItem.setSeverity(jdc.deserialize(jsonObject.get("severity"), Severity.class));
            if (jsonObject.has("confidence")) matchItem.setConfidence(jdc.deserialize(jsonObject.get("confidence"), Confidence.class));
            if (jsonObject.has("notifyTypes")) matchItem.setNotifyTypes(NotifyType.parseEnumSet(jsonObject.get("notifyTypes").getAsJsonArray().toString()));
            if (jsonObject.has("targetTools")) matchItem.setTargetTools(TargetTool.parseEnumSet(jsonObject.get("targetTools").getAsJsonArray().toString()));
            if (jsonObject.has("highlightColor")) matchItem.setHighlightColor(jdc.deserialize(jsonObject.get("highlightColor"), HighlightColor.class));
            if (jsonObject.has("comment")) matchItem.setComment(jdc.deserialize(jsonObject.get("comment"), String.class));
            return matchItem;
        } else if (cls.equals(MatchReplaceItem.class)) {
            final MatchReplaceItem matchItem = new MatchReplaceItem();
            matchItem.setProperty((MatchItem) item);
            if (jsonObject.has("smartMatch")) matchItem.setSmartMatch(jdc.deserialize(jsonObject.get("smartMatch"), Boolean.TYPE));
            if (jsonObject.has("metaChar")) matchItem.setMetaChar(jdc.deserialize(jsonObject.get("metaChar"), Boolean.TYPE));
            return matchItem;
        }
        return item;
    }

}
