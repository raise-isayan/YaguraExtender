package extend.util.external;

import burp.api.montoya.http.message.params.*;
import java.util.ArrayList;
import java.util.List;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

/**
 *
 * @author isayan
 */
public class HtmlAnalyze {

    private final String source;
    private final Document doc;

    public HtmlAnalyze(String source) {
        this.source = source;
        this.doc = Jsoup.parse(source);
    }

    public List<TypeParameter> getInputList() {
        List<TypeParameter> list = new ArrayList<>();
        Elements inputs = this.doc.select("input");
        for (Element tag : inputs) {
            String name = tag.attr("name");
            String value = tag.attr("value");
            list.add(new TypeParameter(HttpParameterType.BODY, name, value));
        }
        return list;
    }

}
