package extend.util.external;

import java.io.IOException;
import com.google.gson.TypeAdapter;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import extend.view.base.MatchItem;

/**
 *
 * @author isayan
 */
public class MatchItemAdapter extends TypeAdapter<MatchItem> {

    @Override
    public MatchItem read(final JsonReader in) throws IOException {
        final MatchItem item = new MatchItem();
        in.beginObject();
        while (in.hasNext()) {
            switch (in.nextName()) {
                case "selected":
                    item.setSelected(in.nextBoolean());
                    break;
                case "ignoreCase":
                    item.setIgnoreCase(in.nextBoolean());
                    break;
                case "regexp":
                    item.setRegexp(in.nextBoolean());
                    break;
                case "match":
                    item.setMatch(in.nextString());
                    break;
                case "type":
                    item.setType(in.nextString());
                    break;
                case "replace":
                    item.setReplace(in.nextString());
                    break;
            }
        }
        in.endObject();
        return item;
    }

    @Override
    public void write(final JsonWriter out, final MatchItem item) throws IOException {
        out.beginObject();
        out.name("selected").value(item.isSelected());
        out.name("ignoreCase").value(item.isIgnoreCase());
        out.name("regexp").value(item.isRegexp());
        out.name("match").value(item.getMatch());
        out.name("type").value(item.getType());
        out.name("replace").value(item.getReplace());
        out.endObject();
    }

}
