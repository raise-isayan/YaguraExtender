package extension.view.base;

import com.google.gson.annotations.Expose;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 *
 * @author isayan
 */
public class RegexItem {

    @Expose
    private String match = "";

    @Expose
    private Pattern regex;

    /**
     * @return the match
     */
    public String getMatch() {
        return this.match;
    }

    /**
     * @param match the match to set
     */
    public void setMatch(String match) {
        this.match = match;
        this.regex = compileRegex(!this.regexp);
    }

    @Expose
    private boolean regexp = false;

    @Expose
    private boolean ignoreCase = false;

    /**
     * @return the regexp
     */
    public boolean isRegexp() {
        return this.regexp;
    }

    /**
     * @param regexp the regexp to set
     */
    public void setRegexp(boolean regexp) {
        this.regexp = regexp;
    }

    /**
     * @return the ignoreCase
     */
    public boolean isIgnoreCase() {
        return this.ignoreCase;
    }

    /**
     * @param ignoreCase the ignoreCase to set
     */
    public void setIgnoreCase(boolean ignoreCase) {
        this.ignoreCase = ignoreCase;
    }

    public boolean isValidRegex() {
        return this.compileRegex(!this.regexp) != null;
    }

    public Pattern compileRegex(boolean quote) {
        int flags = Pattern.MULTILINE;
        Pattern newregex = null;
        try {
            if (this.ignoreCase) {
                flags |= Pattern.CASE_INSENSITIVE;
            }
            if (quote) {
                newregex = Pattern.compile(Pattern.quote(this.match), flags);
            } else {
                newregex = Pattern.compile(this.match, flags);
            }
        } catch (PatternSyntaxException ex) {
        }
        return newregex;
    }

    public void recompileRegex() {
        this.regex = compileRegex(!isRegexp());
    }

    public void recompileRegex(boolean quote) {
        this.regex = compileRegex(quote);
    }

    /**
     * @return the regex
     */
    public Pattern getRegexPattern() {
        return this.regex;
    }

    public static Pattern compileRegex(String text, int flags, boolean quote) {
        Pattern newregex = null;
        try {
            if (quote) {
                newregex = Pattern.compile(Pattern.quote(text), flags);
            } else {
                newregex = Pattern.compile(text, flags);
            }
        } catch (PatternSyntaxException ex) {
        }
        return newregex;
    }

}
