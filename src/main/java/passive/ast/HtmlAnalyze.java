package passive.ast;

import burp.api.montoya.http.message.params.HttpParameterType;
import extension.burp.TypeParameter;
import extension.view.base.CaptureItem;
import java.util.ArrayList;
import java.util.List;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Comment;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.nodes.Node;
import org.jsoup.parser.Parser;
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
        this.doc = Jsoup.parse(this.source, Parser.htmlParser().setTrackPosition(true));
    }

    public boolean analyze() {
        this.clearAll();
        // input type
        Elements inputs = this.doc.select("input, textarea");
        for (Element tag : inputs) {
            String name = tag.attr("name");
            String value = tag.attr("value");
            this.inputParameterList.add(new TypeParameter(HttpParameterType.BODY, name, value));
            if (tag.hasAttr("pattern")) {
                String pattern = tag.attr("pattern");
                CaptureItem item = new CaptureItem();
                item.setCaptureValue(pattern);
                item.setStart(tag.sourceRange().startPos());
                item.setEnd(tag.sourceRange().endPos());
                this.inputPatternList.add(item);
            }
        }
        // Script Tag
        Elements scripts = this.doc.select("script");
        for (Element tag : scripts) {
            CaptureItem item = new CaptureItem();
            item.setCaptureValue(tag.data());
            item.setStart(tag.sourceRange().startPos());
            item.setEnd(tag.sourceRange().endPos());
            this.scriptList.add(item);
        }

        // Comment
        this.doc.traverse(new NodeVisitor() {
            @Override
            public void head(Node node, int depth) {
                if (node instanceof Comment comment) {
                    CaptureItem item = new CaptureItem();
                    item.setCaptureValue(comment.getData());
                    item.setStart(comment.sourceRange().startPos());
                    item.setEnd(comment.sourceRange().endPos());
                    commentList.add(item);
                }
            }

            @Override
            public void tail(Node node, int depth) {
            }
        });

        return true;
    }

    public void clearAll() {
        this.inputParameterList.clear();
        this.inputPatternList.clear();
        this.scriptList.clear();
        this.commentList.clear();
    }

    private final List<TypeParameter> inputParameterList = new ArrayList<>();

    public List<TypeParameter> getParameterInputList() {
        return this.inputParameterList;
    }

    private final List<CaptureItem> inputPatternList = new ArrayList<>();

    public List<CaptureItem> getInputPatternList() {
        return this.inputPatternList;
    }

    private final List<CaptureItem> scriptList = new ArrayList<>();

    public List<CaptureItem> getScriptList() {
        return this.scriptList;
    }

    private final List<CaptureItem> commentList = new ArrayList<>();

    public List<CaptureItem> getCommentList() {
        return this.commentList;
    }

}
