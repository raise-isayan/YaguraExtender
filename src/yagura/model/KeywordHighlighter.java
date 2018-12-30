package yagura.model;

import java.awt.Color;
import java.awt.Graphics;
import java.awt.Rectangle;
import java.awt.Shape;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultHighlighter;
import javax.swing.text.Document;
import javax.swing.text.Highlighter;
import javax.swing.text.JTextComponent;
import javax.swing.text.Position;
import javax.swing.text.View;

/**
 *
 * @author isayan
 */
public class KeywordHighlighter extends DefaultHighlighter {

    private String keyword = "";
    private int position = 0;

    /**
     * Highlight キーワードの取得
     *
     * @return 現在の Highlight キーワード
     */
    public String getHighlightKeyword() {
        return this.keyword;
    }

    /**
     * Highlight キーワードの設定
     *
     * @param doc
     * @param keyword Highlightするキーワード
     * @param regex 正規表現
     * @param ignore 大文字小文字
     * @param color
     */
    public void setHighlightKeyword(Document doc, String keyword, boolean regex, boolean ignore, Color color) {
        try {
            this.keyword = keyword;
            if (!regex) {
                keyword = Pattern.quote(keyword);
            }
            int flags = 0; //Pattern.MULTILINE;
            if (ignore) {
                flags |= Pattern.CASE_INSENSITIVE;
            }
            Pattern p = Pattern.compile(keyword, flags);
            this.setHighlight(doc, p, color);
        } catch (BadLocationException ex) {
            Logger.getLogger(KeywordHighlighter.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public void setHighlight(Document doc, Pattern pattern, Color color) throws BadLocationException {
        final Highlighter.HighlightPainter highlightPainter = new DefaultHighlighter.DefaultHighlightPainter(color);
        this.removeAllHighlights();
        String text = doc.getText(0, doc.getLength());
        Matcher m = pattern.matcher(text);
        int lastPosition = 0;
        while (m.find(lastPosition)) {
            String s = m.group(0);
            lastPosition = m.end();
            this.addHighlight(lastPosition - s.length(), lastPosition, highlightPainter);            
        }
    }

    public void clearHighlightKeyword() {
        this.keyword = "";
        this.removeAllHighlights();
    }

    @Override
    public void removeAllHighlights() {
        this.position = 0;
        super.removeAllHighlights();
    }
        
    public StartEndPosion[] getHighlightPositions() {
        Highlighter.Highlight[] hs = this.getHighlights();
        List<StartEndPosion> list = new ArrayList<StartEndPosion>();
        for (Highlighter.Highlight h : hs) {
            StartEndPosion pos = new StartEndPosion(h.getStartOffset(), h.getEndOffset());
            list.add(pos);
        }
        return list.toArray(new StartEndPosion[0]);
    }

    /**
     * @return the position
     */
    public int getPosition() {
        return this.position;
    }

    /**
     * @param forward the searchPosition to search
     */
    public void searchPosition(boolean forward) {
        if (forward) {
            if (this.getPositionCount() - 1 > this.position) {
                this.position++;
            }
        } else {
            if (this.getPositionCount() > 0 && this.position > 0) {
                this.position--;
            }
        }
    }

    /**
     * 選択された開始終了位置
     * @return 
     */
    public StartEndPosion getSelectPosition() {
        Highlighter.Highlight[] hs = this.getHighlights();
        StartEndPosion pos = new StartEndPosion(hs[this.position].getStartOffset(), hs[this.position].getEndOffset());
        return pos;
    }

    public int getPositionCount() {
        Highlighter.Highlight[] hs = this.getHighlights();
        return hs.length;
    }

    @Override
    public void paintLayeredHighlights(Graphics g, int p0, int p1,
                                       Shape viewBounds,
                                       JTextComponent editor, View view) {
        super.paintLayeredHighlights(g, p0, p1, viewBounds, editor, view);
        paintLayeredSelection(g, p0, p1, viewBounds, editor, view);
    }

    protected void paintLayeredSelection(Graphics g, int p0, int p1,
                                       Shape viewBounds,
                                       JTextComponent editor, View view) {

        Rectangle r;        
        int sel0 = editor.getSelectionStart();
        int sel1 = editor.getSelectionEnd();
        if ((p0 < sel0 && p1 > sel0) || (p0 >= sel0 && p0 < sel1)) {
            if (sel0 == sel1) {
                r = null;
            }
            else {
                int m0 = Math.max(sel0, p0);
                int m1 = Math.min(sel1, p1);
                try {
                    Shape shape = view.modelToView(m0, Position.Bias.Forward,
                                                   m1,Position.Bias.Backward,
                                                   viewBounds);
                    r = (shape instanceof Rectangle) ?
                                  (Rectangle)shape : shape.getBounds();                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     
                } catch (BadLocationException e) {
                    r = null;
                }                
            }
            if (r != null) {
                r.width = Math.max(r.width, 1);
                g.setColor(editor.getSelectionColor());
                g.fillRect(r.x, r.y, r.width, r.height);
            }                    
        }        
    }
}
