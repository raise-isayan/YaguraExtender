package extension.helpers;

import extension.view.base.RegexItem;
import java.io.UnsupportedEncodingException;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 * @author isayan
 */
public class MatchUtil {

    private final static Logger logger = Logger.getLogger(MatchUtil.class.getName());

    public static String toSmartMatch(String value) {
        try {
            return toSmartMatch(value, null);
        } catch (UnsupportedEncodingException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    public static String toSmartMatch(String value, String charset) throws UnsupportedEncodingException {
        StringBuilder buff = new StringBuilder();
        boolean escape = false;
        int length = value.length();
        for (int i = 0; i < length; i = value.offsetByCodePoints(i, 1)) {
            char ch = value.charAt(i);
            int code = value.codePointAt(i);
            buff.append('(');
            switch (ch) {
                case '<':
                case '>':
                case '&':
                case '"':
                    buff.append(toRegexEscape(ch));
                    buff.append('|');
                    buff.append(HttpUtil.toHtmlEncode(ch));
                    break;
                case '\\': // escape
                    if (i == length - 1) {
                        buff.append(toRegexEscape(ch));
                    } else {
                        escape = true;
                    }
                    break;
                case '.':
                case '+':
                case '[':
                case '^':
                case ']':
                case '$':
                case '(':
                case ')':
                case '{':
                case '}':
                case '=':
                case '!':
//                case '<':
//                case '>':
                case '|':
                case ':':
                case '-':
                    if (escape) {
                        buff.append(toRegexEscape('\\'));
                    }
                    buff.append(toRegexEscape(ch));
                    escape = false;
                    break;
                case '*': // wild card
                    if (escape) {
                        buff.append(toRegexEscape(ch));
                    } else {
                        buff.append("(?:.*?)");
                    }
                    escape = false;
                    break;
                case '?': // wild card
                    if (escape) {
                        buff.append(toRegexEscape(ch));
                    } else {
                        buff.append('.');
                    }
                    escape = false;
                    break;
                default:
                    if (escape) {
                        buff.append(toRegexEscape('\\'));
                    }
                    buff.appendCodePoint(code);
                    escape = false;
                    break;
            }
            buff.append('|');
            buff.append(String.format("([\\\\%%]u)%04x", code)); // unicode hex
            buff.append('|');
            buff.append(String.format("&#(x%04x|0*%d);", code, code)); // unicode hex,decimal
            if (charset != null) {
                buff.append('|');
                String str = value.substring(i, value.offsetByCodePoints(i, 1));
                byte decode[] = StringUtil.getBytesCharset(str, charset);
                for (int k = 0; k < decode.length; k++) {
                    buff.append(String.format("((\\\\x|%%)0*%x)", 0xff & decode[k])); // byte hex
                }
            } else {
                if (ch <= 0xff) {
                    buff.append('|');
                    buff.append(String.format("((\\\\x0*%x|%%%02x))", 0xff & ch, 0xff & ch)); // byte hex
                }
            }
            buff.append(')');
        }
        return buff.toString();
    }

    public static Pattern compileRegex(String text, boolean smartMatch, boolean regexp, boolean ignoreCase, int flags) {
        if (ignoreCase) {
            flags |= Pattern.CASE_INSENSITIVE;
        }
        Pattern p = RegexItem.compileRegex(text, flags, !regexp);
        if (smartMatch) {
            String smartRegex = toSmartMatch(text);
            p = RegexItem.compileRegex(smartRegex, flags, false);
        }
        return p;
    }

    public static Pattern compileRegex(String text, boolean smartMatch, boolean regexp, boolean ignoreCase) {
        return compileRegex(text, smartMatch, regexp, ignoreCase, 0);
    }

    /*  . \ + * ? [ ^ ] $ ( ) { } = ! < > | : - */
    public static String toRegexEscape(char ch) {
        StringBuilder buff = new StringBuilder();
        switch (ch) {
            case '\\':
            case '.':
            case '+':
            case '*':
            case '?':
            case '[':
            case '^':
            case ']':
            case '$':
            case '(':
            case ')':
            case '{':
            case '}':
            case '=':
            case '!':
            case '<':
            case '>':
            case '|':
            case ':':
            case '-':
                buff.append('\\');
                buff.append(ch);
                break;
            default:
                buff.append(ch);
                break;
        }
        return buff.toString();
    }

    public static boolean isUrlencoded(String value) {
        boolean result = true;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '%') {
                if (i + 2 < value.length()) {
                    char cl = value.charAt(i + 1);
                    char ch = value.charAt(i + 2);
                    if (!('0' <= cl && cl <= '9' || 'a' <= cl && cl <= 'z' || 'A' <= cl && cl <= 'Z' && '0' <= ch && ch <= '9' || 'a' <= ch && ch <= 'z' || 'A' <= ch && ch <= 'Z')) {
                        result = false;
                        break;
                    }
                } else {
                    result = false;
                    break;
                }
            } else if (!('0' <= c && c <= '9' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || c == '*' || c == '_' || c == '+' || c == '.' || c == '-')) {
                result = false;
                break;
            }
        }
        return result;
    }

    private final static Pattern PTN_B64 = Pattern.compile("([0-9a-zA-Z+/\r\n])+={0,2}");
    private final static Pattern PTN_B64_URLSAFE = Pattern.compile("([0-9a-zA-Z_\\-])");

    public static boolean isBase64(String value) {
        // base64
        Matcher m64 = PTN_B64.matcher(value);
        return m64.matches();
    }

    public static boolean isBase64URLSafe(String value) {
        // base64 UrlSafe
        Matcher m64_URLSafe = PTN_B64_URLSAFE.matcher(value);
        return m64_URLSafe.matches();
    }

    private final static Pattern PTN_URL = Pattern.compile("%([0-9a-fA-F]{2})");

    public static boolean containsUrlencoded(String value) {
        Matcher m = PTN_URL.matcher(value);
        return m.find();
    }

    /**
     * email
     * https://html.spec.whatwg.org/multipage/input.html#e-mail-state-(type%3Demail)
     */
    public static final Pattern MAIL_ADDRESS = Pattern.compile("[a-zA-Z0-9.!#$%&'*+\\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*", Pattern.CASE_INSENSITIVE);

    public static boolean containsMailAddress(String word) {
        return MAIL_ADDRESS.matcher(word).find();
    }

    public static final Pattern CREDIT_CARD = Pattern.compile("(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6011[0-9]{12}|3(?:0[0-5]|[68][0-9])[0-9]{11}|3[47][0-9]{13}|(?:2131|1800|35[0-9]{3})[0-9]{11})");

    public static boolean containsCreditCard(String word) {
        return CREDIT_CARD.matcher(word).find();
    }

}
