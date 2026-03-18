package passive.ast;

import extension.view.base.CaptureItem;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 * @author isayan
 */
public class HtmlAnalyze {

    private final static Pattern COMMENT_TAG = Pattern.compile("<!--(.*?)-->", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
    private final static Pattern SCRIPT_TAG = Pattern.compile("<script>(.*?)</script>", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);

    private final String input;

    public HtmlAnalyze(String input) {
        this.input = input;
    }

    public boolean analyze() {
        Matcher m1 = SCRIPT_TAG.matcher(input);
        while (m1.find()) {
            CaptureItem item = new CaptureItem();
            item.setCaptureValue(m1.group(1));
            item.setStart(m1.start(1));
            item.setEnd(m1.end(1));
            this.scriptList.add(item);
        }
        Matcher m2 = COMMENT_TAG.matcher(input);
        while (m2.find()) {
            CaptureItem item = new CaptureItem();
            item.setCaptureValue(m2.group(1));
            item.setStart(m2.start(1));
            item.setEnd(m2.end(1));
            this.commentList.add(item);
        }
        return true;
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
