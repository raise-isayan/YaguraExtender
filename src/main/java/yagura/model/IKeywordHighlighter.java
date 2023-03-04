package yagura.model;

import java.awt.Color;
import java.util.regex.Pattern;
import javax.swing.text.BadLocationException;
import javax.swing.text.Document;
import javax.swing.text.Highlighter;

/**
 *
 * @author isayan
 */
public interface IKeywordHighlighter extends Highlighter {

    /**
     * Highlight キーワードの取得
     *
     * @return 現在の Highlight キーワード
     */
    public String getHighlightKeyword();

    /**
     * Highlight キーワードの設定
     *
     * @param doc
     * @param keyword Highlightするキーワード
     * @param quote 正規表現
     * @param ignore 大文字小文字
     * @param color
     */
    public void setHighlightKeyword(Document doc, String keyword, boolean quote, boolean ignore, Color color);

    public void setHighlight(Document doc, Pattern pattern, Color color) throws BadLocationException;

    public void clearHighlightKeyword();

    public StartEndPosion[] getHighlightPositions();

    /**
     * @return the position
     */
    public int getPosition();

    /**
     * @param forward the searchPosition to search
     */
    public void searchPosition(boolean forward);

    /**
     * 選択された開始終了位置
     *
     * @return
     */
    public StartEndPosion getSelectPosition();

    public int getPositionCount();

}
