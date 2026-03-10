package extend.util.external;

import burp.api.montoya.http.message.params.*;
import java.util.ArrayList;
import java.util.List;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Comment;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.nodes.Node;
import org.jsoup.select.Elements;
import org.jsoup.select.NodeVisitor;

/**
 *
 * @author isayan
 */
public class HtmlAnalyze {

    private final String source;
    private final Document doc;

    public HtmlAnalyze(String source) {
        this.source = source;
        this.doc = Jsoup.parse(this.source);
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

    public List<String> getCommentList() {
        List<String> commentList = new ArrayList<>();
        this.doc.traverse(new NodeVisitor() {
            @Override
            public void head(Node node, int depth) {
                if (node instanceof Comment) {
                    commentList.add(((Comment) node).getData().trim());
                }
            }

            @Override
            public void tail(Node node, int depth) {
            }
        });
        return commentList;
    }

}
