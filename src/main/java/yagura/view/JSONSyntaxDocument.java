package yagura.view;

import java.util.HashSet;

/**
 *
 * @author isayan
 */
public class JSONSyntaxDocument extends AbstractSyntaxDocument {

    private final static String KEYWORDS[] = {};

    @Override
    public HashSet<String> getKeywords() {
        final HashSet<String> keywords = new HashSet<String>();
        for (String kw : KEYWORDS) {
            keywords.add(kw);
        }
        return keywords;
    }

    @Override
    protected boolean isDelimiter(String character) {
        String operands = ":{}[](),";
        if (Character.isWhitespace(character.charAt(0))
                || operands.contains(character)) {
            return true;
        } else {
            return false;
        }
    }

    @Override
    protected boolean isQuoteDelimiter(String character) {
        String quoteDelimiters = "\"";
        if (!quoteDelimiters.contains(character)) {
            return false;
        } else {
            return true;
        }
    }

    @Override
    protected String getStartDelimiter() {
        return null;
    }

    @Override
    protected String getEndDelimiter() {
        return null;
    }

    @Override
    protected String getSingleLineDelimiter() {
        return null;
    }

    @Override
    protected String getEscapeString(String quoteDelimiter) {
        return "\\" + quoteDelimiter;
    }
    
}
