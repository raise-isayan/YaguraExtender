package extend.util.external;

import extend.util.ConvertUtil;
import extend.util.HttpUtil;
import extend.util.UTF7Charset;
import extend.util.Util;
import extend.view.base.RegexItem;
import java.io.*;
import java.math.BigInteger;
import java.net.IDN;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.text.DecimalFormat;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.mozilla.universalchardet.UniversalDetector;

/**
 * @author isayan
 *
 */
public class TransUtil {

    private final static HashMap<String, Character> ENTITY = new HashMap<>();

    static {
        // see https://www.w3.org/TR/REC-html40/sgml/entities.html
        ENTITY.put("nbsp", (char) 160); // no-break space = non-breaking space, U+00A0 ISOnum
        ENTITY.put("iexcl", (char) 161); // inverted exclamation mark, U+00A1 ISOnum
        ENTITY.put("cent", (char) 162); // cent sign, U+00A2 ISOnum
        ENTITY.put("pound", (char) 163); // pound sign, U+00A3 ISOnum
        ENTITY.put("curren", (char) 164); // currency sign, U+00A4 ISOnum
        ENTITY.put("yen", (char) 165); // yen sign = yuan sign, U+00A5 ISOnum
        ENTITY.put("brvbar", (char) 166); // broken bar = broken vertical bar, U+00A6 ISOnum
        ENTITY.put("sect", (char) 167); // section sign, U+00A7 ISOnum
        ENTITY.put("uml", (char) 168); // diaeresis = spacing diaeresis, U+00A8 ISOdia
        ENTITY.put("copy", (char) 169); // copyright sign, U+00A9 ISOnum
        ENTITY.put("ordf", (char) 170); // feminine ordinal indicator, U+00AA ISOnum
        ENTITY.put("laquo", (char) 171); // left-pointing double angle quotation mark = left pointing guillemet, U+00AB ISOnum
        ENTITY.put("not", (char) 172); // not sign, U+00AC ISOnum
        ENTITY.put("shy", (char) 173); // soft hyphen = discretionary hyphen, U+00AD ISOnum
        ENTITY.put("reg", (char) 174); // registered sign = registered trade mark sign, U+00AE ISOnum
        ENTITY.put("macr", (char) 175); // macron = spacing macron = overline = APL overbar, U+00AF ISOdia
        ENTITY.put("deg", (char) 176); // degree sign, U+00B0 ISOnum
        ENTITY.put("plusmn", (char) 177); // plus-minus sign = plus-or-minus sign, U+00B1 ISOnum
        ENTITY.put("sup2", (char) 178); // superscript two = superscript digit two = squared, U+00B2 ISOnum
        ENTITY.put("sup3", (char) 179); // superscript three = superscript digit three = cubed, U+00B3 ISOnum
        ENTITY.put("acute", (char) 180); // acute accent = spacing acute, U+00B4 ISOdia
        ENTITY.put("micro", (char) 181); // micro sign, U+00B5 ISOnum
        ENTITY.put("para", (char) 182); // pilcrow sign = paragraph sign, U+00B6 ISOnum
        ENTITY.put("middot", (char) 183); // middle dot = Georgian comma = Greek middle dot, U+00B7 ISOnum
        ENTITY.put("cedil", (char) 184); // cedilla = spacing cedilla, U+00B8 ISOdia
        ENTITY.put("sup1", (char) 185); // superscript one = superscript digit one, U+00B9 ISOnum
        ENTITY.put("ordm", (char) 186); // masculine ordinal indicator, U+00BA ISOnum
        ENTITY.put("raquo", (char) 187); // right-pointing double angle quotation mark = right pointing guillemet, U+00BB ISOnum
        ENTITY.put("frac14", (char) 188); // vulgar fraction one quarter = fraction one quarter, U+00BC ISOnum
        ENTITY.put("frac12", (char) 189); // vulgar fraction one half = fraction one half, U+00BD ISOnum
        ENTITY.put("frac34", (char) 190); // vulgar fraction three quarters = fraction three quarters, U+00BE ISOnum
        ENTITY.put("iquest", (char) 191); // inverted question mark = turned question mark, U+00BF ISOnum
        ENTITY.put("Agrave", (char) 192); // latin capital letter A with grave = latin capital letter A grave, U+00C0 ISOlat1
        ENTITY.put("Aacute", (char) 193); // latin capital letter A with acute, U+00C1 ISOlat1
        ENTITY.put("Acirc", (char) 194); // latin capital letter A with circumflex, U+00C2 ISOlat1
        ENTITY.put("Atilde", (char) 195); // latin capital letter A with tilde, U+00C3 ISOlat1
        ENTITY.put("Auml", (char) 196); // latin capital letter A with diaeresis, U+00C4 ISOlat1
        ENTITY.put("Aring", (char) 197); // latin capital letter A with ring above = latin capital letter A ring, U+00C5 ISOlat1
        ENTITY.put("AElig", (char) 198); // latin capital letter AE = latin capital ligature AE, U+00C6 ISOlat1
        ENTITY.put("Ccedil", (char) 199); // latin capital letter C with cedilla, U+00C7 ISOlat1
        ENTITY.put("Egrave", (char) 200); // latin capital letter E with grave, U+00C8 ISOlat1
        ENTITY.put("Eacute", (char) 201); // latin capital letter E with acute, U+00C9 ISOlat1
        ENTITY.put("Ecirc", (char) 202); // latin capital letter E with circumflex, U+00CA ISOlat1
        ENTITY.put("Euml", (char) 203); // latin capital letter E with diaeresis, U+00CB ISOlat1
        ENTITY.put("Igrave", (char) 204); // latin capital letter I with grave, U+00CC ISOlat1
        ENTITY.put("Iacute", (char) 205); // latin capital letter I with acute, U+00CD ISOlat1
        ENTITY.put("Icirc", (char) 206); // latin capital letter I with circumflex, U+00CE ISOlat1
        ENTITY.put("Iuml", (char) 207); // latin capital letter I with diaeresis, U+00CF ISOlat1
        ENTITY.put("ETH", (char) 208); // latin capital letter ETH, U+00D0 ISOlat1
        ENTITY.put("Ntilde", (char) 209); // latin capital letter N with tilde, U+00D1 ISOlat1
        ENTITY.put("Ograve", (char) 210); // latin capital letter O with grave, U+00D2 ISOlat1
        ENTITY.put("Oacute", (char) 211); // latin capital letter O with acute, U+00D3 ISOlat1
        ENTITY.put("Ocirc", (char) 212); // latin capital letter O with circumflex, U+00D4 ISOlat1
        ENTITY.put("Otilde", (char) 213); // latin capital letter O with tilde, U+00D5 ISOlat1
        ENTITY.put("Ouml", (char) 214); // latin capital letter O with diaeresis, U+00D6 ISOlat1
        ENTITY.put("times", (char) 215); // multiplication sign, U+00D7 ISOnum
        ENTITY.put("Oslash", (char) 216); // latin capital letter O with stroke = latin capital letter O slash, U+00D8 ISOlat1
        ENTITY.put("Ugrave", (char) 217); // latin capital letter U with grave, U+00D9 ISOlat1
        ENTITY.put("Uacute", (char) 218); // latin capital letter U with acute, U+00DA ISOlat1
        ENTITY.put("Ucirc", (char) 219); // latin capital letter U with circumflex, U+00DB ISOlat1
        ENTITY.put("Uuml2", (char) 220); // latin capital letter U with diaeresis, U+00DC ISOlat1
        ENTITY.put("Yacute", (char) 221); // latin capital letter Y with acute, U+00DD ISOlat1
        ENTITY.put("THORN", (char) 222); // latin capital letter THORN, U+00DE ISOlat1
        ENTITY.put("szlig", (char) 223); // latin small letter sharp s = ess-zed, U+00DF ISOlat1
        ENTITY.put("agrave", (char) 224); // latin small letter a with grave = latin small letter a grave, U+00E0 ISOlat1
        ENTITY.put("aacute", (char) 225); // latin small letter a with acute, U+00E1 ISOlat1
        ENTITY.put("acirc", (char) 226); // latin small letter a with circumflex, U+00E2 ISOlat1
        ENTITY.put("atilde", (char) 227); // latin small letter a with tilde, U+00E3 ISOlat1
        ENTITY.put("auml", (char) 228); // latin small letter a with diaeresis, U+00E4 ISOlat1
        ENTITY.put("aring", (char) 229); // latin small letter a with ring above = latin small letter a ring, U+00E5 ISOlat1
        ENTITY.put("aelig", (char) 230); // latin small letter ae = latin small ligature ae, U+00E6 ISOlat1
        ENTITY.put("ccedil", (char) 231); // latin small letter c with cedilla, U+00E7 ISOlat1
        ENTITY.put("egrave", (char) 232); // latin small letter e with grave, U+00E8 ISOlat1
        ENTITY.put("eacute", (char) 233); // latin small letter e with acute, U+00E9 ISOlat1
        ENTITY.put("ecirc", (char) 234); // latin small letter e with circumflex, U+00EA ISOlat1
        ENTITY.put("euml", (char) 235); // latin small letter e with diaeresis, U+00EB ISOlat1
        ENTITY.put("igrave", (char) 236); // latin small letter i with grave, U+00EC ISOlat1
        ENTITY.put("iacute", (char) 237); // latin small letter i with acute, U+00ED ISOlat1
        ENTITY.put("icirc", (char) 238); // latin small letter i with circumflex, U+00EE ISOlat1
        ENTITY.put("iuml", (char) 239); // latin small letter i with diaeresis, U+00EF ISOlat1
        ENTITY.put("eth", (char) 240); // latin small letter eth, U+00F0 ISOlat1
        ENTITY.put("ntilde", (char) 241); // latin small letter n with tilde, U+00F1 ISOlat1
        ENTITY.put("ograve", (char) 242); // latin small letter o with grave, U+00F2 ISOlat1
        ENTITY.put("oacute", (char) 243); // latin small letter o with acute, U+00F3 ISOlat1
        ENTITY.put("ocirc", (char) 244); // latin small letter o with circumflex, U+00F4 ISOlat1
        ENTITY.put("otilde", (char) 245); // latin small letter o with tilde, U+00F5 ISOlat1
        ENTITY.put("ouml", (char) 246); // latin small letter o with diaeresis, U+00F6 ISOlat1
        ENTITY.put("divide", (char) 247); // division sign, U+00F7 ISOnum
        ENTITY.put("oslash", (char) 248); // latin small letter o with stroke, = latin small letter o slash, U+00F8 ISOlat1
        ENTITY.put("ugrave", (char) 249); // latin small letter u with grave, U+00F9 ISOlat1
        ENTITY.put("uacute", (char) 250); // latin small letter u with acute, U+00FA ISOlat1
        ENTITY.put("ucirc", (char) 251); // latin small letter u with circumflex, U+00FB ISOlat1
        ENTITY.put("uuml", (char) 252); // latin small letter u with diaeresis, U+00FC ISOlat1
        ENTITY.put("yacute", (char) 253); // latin small letter y with acute, U+00FD ISOlat1
        ENTITY.put("thorn", (char) 254); // latin small letter thorn, U+00FE ISOlat1
        ENTITY.put("yuml", (char) 255); // latin small letter y with diaeresis, U+00FF ISOlat1s
    }

    public enum DateUnit {
        DAYS, WEEKS, MONTHS, YEARS
    }

    public enum EncodeType {
        ALL, ALPHANUM, LIGHT, STANDARD
    };

    public enum ConvertCase {
        UPPER, LOWLER
   };

    public static String toEmpty(Object obj) {
        return (obj == null) ? "" : obj.toString();
    }

    // 条件一致時にEncode
    public final static Pattern PTN_ENCODE_ALL = Pattern.compile(".", Pattern.DOTALL);
    public final static Pattern PTN_ENCODE_ALPHANUM = Pattern.compile("[^a-zA-Z0-9_]");
    public final static Pattern PTN_ENCODE_LIGHT = Pattern.compile("[^A-Za-z0-9!\"$'()*,/:<>@\\[\\\\\\]^`{|}~]");
    public final static Pattern PTN_ENCODE_STANDARD = Pattern.compile("[^A-Za-z0-9\"<>\\[\\\\\\]^`{|}]");

    public static Pattern getEncodeTypePattern(EncodeType type) {
        switch (type) {
            case ALL:
                return PTN_ENCODE_ALL;
            case ALPHANUM:
                return PTN_ENCODE_ALPHANUM;
            case LIGHT:
                return PTN_ENCODE_LIGHT;
            case STANDARD:
                return PTN_ENCODE_STANDARD;
            default:
                break;
        }
        return PTN_ENCODE_ALL;
    }

    public enum EncodePattern {
        NONE, BASE64, BASE64_URLSAFE, BASE64_MIME, UUENCODE, QUOTEDPRINTABLE, PUNYCODE, URL_STANDARD, HTML, BYTE_HTML, URL_UNICODE, UNICODE, BYTE_HEX, BYTE_OCT, GZIP, ZLIB, UTF7, UTF8_ILL, C_LANG, SQL_LANG, REGEX,
    };

    private final static Pattern PTN_URLENCODE = Pattern.compile("([0-9a-zA-Z\\*_\\+\\.-]|%([0-9a-fA-F]{2}))+");
        
    private final static Pattern PTN_B64 = Pattern.compile("([0-9a-zA-Z+/\r\n])+={0,2}");
    private final static Pattern PTN_B64_URLSAFE = Pattern.compile("([0-9a-zA-Z_\\-\r\n])");
    private final static Pattern PTN_UUENCODE = Pattern.compile("begin\\s[0-6]{3}\\s\\w+");
    private final static Pattern PTN_QUOTEDPRINTABLE = Pattern.compile("=([0-9a-fA-F]{2})");
    private final static Pattern PTN_PUNYCODE = Pattern.compile("xn--[0-9a-zA-Z_\\.]+");
    private final static Pattern PTN_URL = Pattern.compile("%([0-9a-fA-F]{2})");
    private final static Pattern PTN_HTML = Pattern.compile("(&#(\\d+);)|(&(lt|gt|amp|quot);)|(&#[xX]([0-9a-fA-F]+);)");
    private final static Pattern PTN_URL_UNICODE = Pattern.compile("%[uU]([0-9a-fA-F]{4})");
    private final static Pattern PTN_UNICODE = Pattern.compile("\\\\[uU]([0-9a-fA-F]{4})");
    private final static Pattern PTN_BYTE_HEX = Pattern.compile("\\\\[xX]([0-9a-fA-F]{2})");
    private final static Pattern PTN_BYTE_OCT = Pattern.compile("\\\\([0-9]{1,})");
    private final static Pattern PTN_GZIP = Pattern.compile("\\x1f\\x8b");

    public static EncodePattern getSmartDecode(String value) {
        // 判定の順番は検討の余地あり        
        // % Encode
        Matcher mURL = PTN_URL.matcher(value);
        // base64
        Matcher m64 = PTN_B64.matcher(value);
        // base64 UrlSafe
        Matcher m64_URLSafe = PTN_B64_URLSAFE.matcher(value);
        // uuencode
        Matcher mUUENCODE = PTN_UUENCODE.matcher(value);
        // QuotedPrintable
        Matcher mQUOTEDPRINTABLE = PTN_QUOTEDPRINTABLE.matcher(value);
        // Punycode
        Matcher mPunycode = PTN_PUNYCODE.matcher(value);
        // html
        Matcher mHTML = PTN_HTML.matcher(value);
        // url unicode
        Matcher mURL_UNICODE = PTN_URL_UNICODE.matcher(value);
        // unicode
        Matcher mUNICODE = PTN_UNICODE.matcher(value);
        // byte hex
        Matcher mBYTE_HEX = PTN_BYTE_HEX.matcher(value);
        // byte oct
        Matcher mBYTE_OCT = PTN_BYTE_OCT.matcher(value);
        // gzip
        Matcher mGZIP = PTN_GZIP.matcher(value);

        // URL encode match
        if (mURL.find()) {
            return EncodePattern.URL_STANDARD;
        } // URL Unicode
        else if (mURL_UNICODE.find()) {
            return EncodePattern.URL_UNICODE;
        } // unicode
        else if (mUNICODE.find()) {
            return EncodePattern.UNICODE;
        } // byte hex
        else if (mBYTE_HEX.find()) {
            return EncodePattern.BYTE_HEX;
        } // byte oct
        else if (mBYTE_OCT.find()) {
            return EncodePattern.BYTE_OCT;
        } // pyny code
        else if (mPunycode.lookingAt()) {
            return EncodePattern.PUNYCODE;
        } // uuencode encode match
        else if (mUUENCODE.lookingAt()) {
            return EncodePattern.UUENCODE;
        } // QuotedPrintable
        else if (mQUOTEDPRINTABLE.find()) {
            return EncodePattern.QUOTEDPRINTABLE;
        } // Base64 encode match
        else if (m64.matches()) {
            return EncodePattern.BASE64;
        } // Base64 URLSafe
        else if (m64_URLSafe.matches()) {
            return EncodePattern.BASE64_URLSAFE;
        } // Html decode
        else if (mHTML.find()) {
            return EncodePattern.HTML;
        } // Gzip
        else if (mGZIP.lookingAt()) {
            return EncodePattern.GZIP;
        }

        return null;
    }

    public static boolean isUrlencoded(String value) {
        Matcher m = PTN_URLENCODE.matcher(value);
        return m.matches();
    }
    
    public static String toSmartDecode(String value) {
        return toSmartDecode(value, getSmartDecode(value), (String) null);
    }

    public static String toSmartDecode(String value, TransUtil.EncodePattern encodePattern, String charset) {
        if (charset == null) {
            return toSmartDecode(value, encodePattern, new StringBuffer());
        } else {
            return toSmartDecode(value, encodePattern, new StringBuffer(charset));
        }
    }

    public static String toSmartDecode(String value, TransUtil.EncodePattern encodePattern, StringBuffer selectCharset) {
        if (selectCharset == null) {
            throw new IllegalArgumentException("charset is not null");
        }
        String charset = (selectCharset.length() == 0) ? null : selectCharset.toString();
        String applyCharset = StandardCharsets.ISO_8859_1.name();
        String decode = value;
        try {
            if (encodePattern == null) {
                if (charset != null) {
                    applyCharset = charset;
                }
                decode = Util.getRawByteStr(value, applyCharset);
            } 
            else {
                // URL encode match
                switch (encodePattern) {
                    case NONE: 
                        decode = value;
                        break;
                    case URL_STANDARD: 
                        {
                            String guessCode = (charset == null) ? getUniversalGuessCode(Util.getRawByte(TransUtil.decodeUrl(value, StandardCharsets.ISO_8859_1))) : charset;
                            if (guessCode != null) {
                                applyCharset = guessCode;
                                decode = TransUtil.decodeUrl(value, applyCharset);
                            } else {
                                decode = TransUtil.decodeUrl(value, StandardCharsets.ISO_8859_1);
                            }
                        }
                        break;
                    // URL Unicode
                    case URL_UNICODE:
                        decode = toUnocodeUrlDecode(value);
                        break;
                    // Unicode
                    case UNICODE:
                        decode = toUnocodeDecode(value);
                        break;
                    // Byte Hex
                    case BYTE_HEX: 
                        {
                            String guessCode = (charset == null) ? getUniversalGuessCode(Util.getRawByte(toByteDecode(value, StandardCharsets.ISO_8859_1.name()))) : charset;
                            if (guessCode != null) {
                                applyCharset = guessCode;
                                decode = toByteDecode(value, applyCharset);
                            } else {
                                decode = toByteDecode(value, StandardCharsets.ISO_8859_1.name());
                            }
                        }
                        break;
                    case BYTE_OCT: 
                        {
                            String guessCode = (charset == null) ? getUniversalGuessCode(Util.getRawByte(toByteDecode(value, StandardCharsets.ISO_8859_1.name()))) : charset;
                            if (guessCode != null) {
                                applyCharset = guessCode;
                                decode = toByteDecode(value, applyCharset);
                            } else {
                                decode = toByteDecode(value, StandardCharsets.ISO_8859_1.name());
                            }
                        }
                        break;
                    // uuencode
                    case UUENCODE: 
                        {
                            String guessCode = (charset == null) ? getUniversalGuessCode(Util.getRawByte(toUudecode(value, "8859_1"))) : charset;
                            if (guessCode != null) {
                                applyCharset = guessCode;
                                decode = toUudecode(value, applyCharset);
                            } else {
                                decode = toUudecode(value, StandardCharsets.ISO_8859_1.name());
                            }
                        }
                        break;
                    // QuotedPrintable
                    case QUOTEDPRINTABLE: 
                        {
                            String guessCode = (charset == null) ? getUniversalGuessCode(Util.getRawByte(toUudecode(value, "8859_1"))) : charset;
                            if (guessCode != null) {
                                applyCharset = guessCode;
                                decode = toUnQuotedPrintable(value, applyCharset);
                            } else {
                                decode = toUnQuotedPrintable(value, StandardCharsets.ISO_8859_1.name());
                            }
                        }
                        break;
                    // Punycode
                    case PUNYCODE:
                        decode = toPunycodeDecode(value);
                        break;
                    // Base64 encode match
                    case BASE64: 
                        {
                            value = value.replaceAll("[\r\n]", ""); // 改行削除
                            byte[] bytes = Base64.getDecoder().decode(value);
                            String guessCode = (charset == null) ? getUniversalGuessCode(bytes) : charset;
                            if (guessCode != null) {
                                applyCharset = guessCode;
                                decode = ConvertUtil.toBase64Decode(value, applyCharset);
                            } else {
                                decode = ConvertUtil.toBase64Decode(value, StandardCharsets.ISO_8859_1);
                            }
                        }
                        break;
                    // Base64 URLSafe
                    case BASE64_URLSAFE: 
                        {
                            value = value.replaceAll("[\r\n]", ""); // 改行削除
                            byte[] bytes = Base64.getUrlDecoder().decode(value);
                            String guessCode = (charset == null) ? getUniversalGuessCode(bytes) : charset;
                            if (guessCode != null) {
                                applyCharset = guessCode;
                                decode = ConvertUtil.toBase64URLSafeDecode(value, applyCharset);
                            } else {
                                decode = ConvertUtil.toBase64URLSafeDecode(value, StandardCharsets.ISO_8859_1);
                            }
                        }
                        break;
                    // Html decode
                    case HTML:
                        decode = toHtmlDecode(value);
                        break;
                    case BYTE_HTML:
                        {
                            String guessCode = (charset == null) ? getUniversalGuessCode(Util.getRawByte(toHtmlDecode(value, StandardCharsets.ISO_8859_1.name()))) : charset;
                            if (guessCode != null) {
                                applyCharset = guessCode;
                                decode = toHtmlDecode(value, applyCharset);
                            } else {
                                decode = toHtmlDecode(value, StandardCharsets.ISO_8859_1.name());
                            }
                        }
                        break;
                    // Gzip
                    case GZIP:
                        decode = Util.getRawStr(ConvertUtil.decompressGzip(Util.encodeMessage(value, charset)));
                        break;
                    // ZLIB
                    case ZLIB:
                        decode = Util.getRawStr(ConvertUtil.decompressZlib(Util.encodeMessage(value, charset)));
                        break;
                    // UTF7
                    case UTF7:
                        decode = TransUtil.toUTF7Decode(value);
                        break;
                    // UTF8 ILL
                    case UTF8_ILL:
                        // nothing
                        break;
                    case C_LANG:
                        decode = TransUtil.decodeCLangQuote(value);
                        break;
                    case SQL_LANG:
                        decode = TransUtil.decodeSQLangQuote(value);
                        break;
                    case REGEX:
                        decode = TransUtil.toRegexDecode(value);
                        break;
                    default:
                        break;
                }
            }

        } catch (IOException ex) {
            Logger.getLogger(TransUtil.class.getName()).log(Level.SEVERE, null, ex);
        }
        if (selectCharset != null) {
            selectCharset.replace(0, selectCharset.length(), applyCharset);
        }
        return decode;
    }

    public static String toPunycodeEncode(String value) {
        return IDN.toASCII(value);
    }

    public static String toPunycodeDecode(String value) {
        return IDN.toUnicode(value);
    }

    public static String toUTF7Encode(String str) {
        UTF7Charset utf7cs = new UTF7Charset("UTF-7", new String[]{});
        ByteBuffer bb = utf7cs.encode(str);
        byte[] content = new byte[bb.limit()];
        System.arraycopy(bb.array(), 0, content, 0, content.length);
        return new String(content, StandardCharsets.US_ASCII);
    }

    public static String toUTF7Decode(String str) {
        UTF7Charset utf7cs = new UTF7Charset("UTF-7", new String[]{});
        CharBuffer cb = utf7cs.decode(ByteBuffer.wrap(str.getBytes(StandardCharsets.US_ASCII)));
        return cb.toString();
    }
    private final static String SPECIAL_CHAR = "!\"#$%&'()*+,-./:;<=>?@[\\]{|}~";

    public static String toUSASCII(String str, String enc)
            throws UnsupportedEncodingException {
        char[] chars = toChars(str);
        for (int i = 0; i < chars.length; i++) {
            // 指定された文字のみ
            if (SPECIAL_CHAR.indexOf(chars[i]) > -1) {
                chars[i] = (char) ((int) chars[i] | 0x80);
            }
        }
        String ustr = new String(chars);
        return new String(ustr.getBytes(StandardCharsets.ISO_8859_1), enc);
    }

    public static int getCharCode(String str, String enc)
            throws UnsupportedEncodingException {
        byte caretbyte[] = str.getBytes(enc);
        return ConvertUtil.toInteger(caretbyte);
    }

    public static char[] toChars(String str) {
        char[] chars = new char[str.length()];
        str.getChars(0, chars.length, chars, 0);
        return chars;
    }

    /*
     * 改行
     */
    public enum NewLine {
        NONE, CRLF, LF, CR
    };

    public static String getNewLine(NewLine linemode) {
        String newLine = Util.NEW_LINE;
        switch (linemode) {
            case NONE:
                newLine = Util.NEW_LINE;
                break;
            case CRLF:
                newLine = "\r\n";
                break;
            case LF:
                newLine = "\n";
                break;
            case CR:
                newLine = "\r";
                break;
            default:
                break;
        }
        return newLine;
    }

    public static String replaceNewLine(NewLine mode, String selectText) {
        switch (mode) {
            case CRLF: {
                return selectText.replaceAll("(\r\n|\r|\n)", "\r\n");
            }
            case LF: {
                return selectText.replaceAll("(\r\n|\r|\n)", "\n");
            }
            case CR: {
                return selectText.replaceAll("(\r\n|\r|\n)", "\r");
            }
            default: {
                // nothing
            }
        }
        return selectText;
    }

    public static String newLine(String separator, String value, int length) {
        return ConvertUtil.newLine(separator, value, length);
    }

    public static String join(String separator, String[] lines) {
        StringBuilder buff = new StringBuilder();
        for (int i = 0; i < lines.length; i++) {
            if (i > 0) {
                buff.append(separator);
            }
            buff.append(lines[i]);
        }
        return buff.toString();
    }

    public static byte[] UTF8Encode(String input, int bytes) {
        char[] input_array = input.toCharArray();
        ByteArrayOutputStream byte_array = new ByteArrayOutputStream();
        for (char c : input_array) {
            switch (bytes) {
                case 4:
                    byte_array.write((byte) (0xff & ((byte) 0xf0)));
                    byte_array.write((byte) (0xff & ((byte) 0x80)));
                    byte_array.write((byte) (0xff & ((byte) (0x80 | ((c & 0x7f) >> 6)))));
                    byte_array.write((byte) (0xff & ((byte) (0x80 | (c & 0x3f)))));
                    break;
                case 3:
                    byte_array.write((byte) (0xff & ((byte) 0xe0)));
                    byte_array.write((byte) (0xff & ((byte) (0x80 | ((c & 0x7f) >> 6)))));
                    byte_array.write((byte) (0xff & ((byte) (0x80 | (c & 0x3f)))));
                    break;
                case 2:
                    byte_array.write((byte) (0xff & ((byte) (0xc0 | ((c & 0x7f) >> 6)))));
                    byte_array.write((byte) (0xff & ((byte) (0x80 | (c & 0x3f)))));
                    break;
                default:
                    throw new IllegalArgumentException("UTF-8 byte :" + bytes);
            }
        }
        return byte_array.toByteArray();
    }

    public static String decodeUrl(String pString, Charset charset) {
        return new String(decodeUrl(pString.getBytes(StandardCharsets.US_ASCII)), charset);
    }

    public static String decodeUrl(String pString, String charset) throws UnsupportedEncodingException {
        return new String(decodeUrl(pString.getBytes(StandardCharsets.US_ASCII)), charset);
    }

    public static String encodeUrl(String pString, Charset charset, boolean upperCase) {
        return new String(encodeUrl(pString.getBytes(charset), PTN_ENCODE_ALPHANUM, upperCase), StandardCharsets.US_ASCII);
    }

    public static String encodeUrl(String pString, String charset, boolean upperCase) throws UnsupportedEncodingException {
        return new String(encodeUrl(pString.getBytes(charset), PTN_ENCODE_ALPHANUM, upperCase), StandardCharsets.US_ASCII);
    }

    public static String encodeUrl(String pString, Charset charset, Pattern pattern, boolean upperCase) {
        return new String(encodeUrl(pString.getBytes(charset), pattern, upperCase), StandardCharsets.US_ASCII);
    }

    public static String encodeUrl(String pString, String charset, Pattern pattern, boolean upperCase) throws UnsupportedEncodingException {
        return new String(encodeUrl(pString.getBytes(charset), pattern, upperCase), StandardCharsets.US_ASCII);
    }

    private static byte[] decodeUrl(byte[] bytes) {
        if (bytes == null) {
            throw new NullPointerException();
        }
        ByteBuffer buffer = ByteBuffer.allocate(bytes.length * 2);
        for (int i = 0; i < bytes.length; i++) {
            int b = bytes[i];
            if (b == '+') {
                buffer.put((byte) ' ');
            } else if (b == '%') {
                try {
                    int u = Character.digit((char) bytes[++i], 16);
                    int l = Character.digit((char) bytes[++i], 16);
                    buffer.put((byte) ((u << 4) + l));
                } catch (ArrayIndexOutOfBoundsException e) {
                }
            } else {
                buffer.put((byte) b);
            }
        }
        buffer.flip();
        byte[] value = new byte[buffer.limit()];
        buffer.get(value);
        return value;
    }

    private static byte[] encodeUrl(byte[] bytes, Pattern pattern, boolean upperCase) {
        if (bytes == null) {
            throw new NullPointerException();
        }
        ByteBuffer buffer = ByteBuffer.allocate(bytes.length * 3);

        for (int i = 0; i < bytes.length; i++) {
            int b = bytes[i] & 0xff;
            Matcher m = pattern.matcher(new String(new char[]{(char) b}));
            if (b == ' ') {
                b = '+';
                buffer.put((byte) b);
            } else if (m.matches()) {
                buffer.put((byte) '%');
                char hex1 = Character.toLowerCase(Character.forDigit((b >> 4) & 0xf, 16));
                char hex2 = Character.toLowerCase(Character.forDigit(b & 0xf, 16));
                if (upperCase) {
                    hex1 = Character.toUpperCase(hex1);
                    hex2 = Character.toUpperCase(hex2);
                }
                buffer.put((byte) hex1);
                buffer.put((byte) hex2);
            } else {
                buffer.put((byte) b);
            }
        }
        buffer.flip();
        byte[] value = new byte[buffer.limit()];
        buffer.get(value);
        return value;
    }

    public static String toUnocodeEncode(String input, boolean upperCase) {
        return toUnocodeEncode(input, PTN_ENCODE_ALPHANUM, upperCase);
    }

    public static String toUnocodeEncode(String input, Pattern pattern, boolean upperCase) {
        StringBuilder buff = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            Matcher m = pattern.matcher(new String(new char[]{c}));
            if (m.matches()) {
                if (upperCase) {
                    buff.append(String.format("\\U%04X", (int) c));
                } else {
                    buff.append(String.format("\\u%04x", (int) c));
                }
            } else {
                buff.append(c);
            }
        }
        return buff.toString();
    }

    public static String toByteHexEncode(String input, String charset, boolean upperCase) throws UnsupportedEncodingException {
        return toByteHexEncode(input, charset, PTN_ENCODE_ALPHANUM, upperCase);
    }

    public static String toByteHexEncode(String input, String charset, Pattern pattern, boolean upperCase) throws UnsupportedEncodingException {
        return toByteHexEncode(input.getBytes(charset), pattern, upperCase);
    }

    public static String toByteOctEncode(String input, String charset, boolean upperCase) throws UnsupportedEncodingException {
        return toByteOctEncode(input, charset, PTN_ENCODE_ALPHANUM, upperCase);
    }

    public static String toByteOctEncode(String input, String charset, Pattern pattern, boolean upperCase) throws UnsupportedEncodingException {
        return toByteOctEncode(input.getBytes(charset), pattern, upperCase);
    }

    public static String toByteHexEncode(byte[] bytes, Pattern pattern, boolean upperCase) {
        StringBuilder buff = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            int b = bytes[i] & 0xff;
            Matcher m = pattern.matcher(new String(new char[]{(char) b}));
            if (m.matches()) {
                if (upperCase) {
                    buff.append(String.format("\\X%02X", b));
                } else {
                    buff.append(String.format("\\x%02x", b));
                }
            } else {
                buff.append((char) b);
            }
        }
        return buff.toString();
    }

    public static String toByteOctEncode(byte[] bytes, Pattern pattern, boolean upperCase) {
        StringBuilder buff = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            int b = bytes[i] & 0xff;
            Matcher m = pattern.matcher(new String(new char[]{(char) b}));
            if (m.matches()) {
                if (upperCase) {
                    buff.append(String.format("\\%02o", b));
                } else {
                    buff.append(String.format("\\%02o", b));
                }
            } else {
                buff.append((char) b);
            }
        }
        return buff.toString();
    }

    private final static Pattern PTN_UNICODE_STR_SURROGATE = Pattern.compile("(\\\\[uU][dD][89abAB][0-9a-fA-F]{2}\\\\[uU][dD][c-fC-F][0-9a-fA-F]{2})|(\\\\[uU][0-9a-fA-F]{4})");

    public static String toUnocodeDecode(String input) {
        StringBuffer buff = new StringBuffer();
        // 上位サロゲート(\uD800-\uDBFF)
        // 下位サロゲート(\uDC00-\uDFFF)
        Matcher m = PTN_UNICODE_STR_SURROGATE.matcher(input);
        while (m.find()) {
            String unicode = m.group(1);
            if (unicode != null) {
                int chHigh = Integer.parseInt(unicode.substring(2, 6), 16);
                int chLow = Integer.parseInt(unicode.substring(8, 12), 16);
                m.appendReplacement(buff, Matcher.quoteReplacement(new String(new char[]{(char) chHigh, (char) chLow})));
            } else {
                unicode = m.group(2);
                int ch = Integer.parseInt(unicode.substring(2), 16);
                m.appendReplacement(buff, Matcher.quoteReplacement(new String(new char[]{(char) ch})));
            }
        }
        m.appendTail(buff);
        return buff.toString();
    }

    private final static Pattern PTN_BYTE_GROUP = Pattern.compile("((\\\\[xX][0-9a-fA-F]{2})+)|((\\\\[0-9]{1,3})+)");

    public static String toByteDecode(String input, String charset) {
        StringBuffer buff = new StringBuffer();
        Matcher m = PTN_BYTE_GROUP.matcher(input);
        try {
            while (m.find()) {
                String hex = m.group(1);
                String oct = m.group(3);
                if (hex != null) {
                    Matcher m2 = PTN_BYTE_HEX.matcher(hex);
                    ByteBuffer buf = ByteBuffer.allocate(hex.length());
                    while (m2.find()) {
                        String hexcode = m2.group(1);
                        int u = Character.digit(hexcode.charAt(0), 16);
                        int l = Character.digit(hexcode.charAt(1), 16);
                        buf.put((byte) ((u << 4) + l));
                    }
                    buf.flip();
                    byte[] value = new byte[buf.limit()];
                    buf.get(value);
                    m.appendReplacement(buff, Matcher.quoteReplacement(new String(value, charset)));
                } else if (oct != null) {
                    Matcher m3 = PTN_BYTE_OCT.matcher(oct);
                    ByteBuffer buf = ByteBuffer.allocate(oct.length());
                    while (m3.find()) {
                        String octecode = m3.group(1);
                        buf.put((byte) Integer.parseInt(octecode, 8));
                    }
                    buf.flip();
                    byte[] value = new byte[buf.limit()];
                    buf.get(value);
                    m.appendReplacement(buff, Matcher.quoteReplacement(new String(value, charset)));
                }
            }
            m.appendTail(buff);
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(TransUtil.class.getName()).log(Level.SEVERE, null, ex);
        }
        return buff.toString();
    }

    public static String toUnocodeUrlEncode(String input, boolean upperCase) {
        return toUnocodeUrlEncode(input, PTN_ENCODE_ALPHANUM, upperCase);
    }

    public static String toUnocodeUrlEncode(String input, Pattern pattern, boolean upperCase) {
        StringBuilder buff = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            Matcher m = pattern.matcher(new String(new char[]{c}));
            if (m.matches()) {
                if (upperCase) {
                    buff.append(String.format("%%U%04X", (int) c));
                } else {
                    buff.append(String.format("%%u%04x", (int) c));
                }
            } else {
                buff.append(c);
            }
        }
        return buff.toString();
    }

    private final static Pattern PTN_UNICODE_URL_SURROGATE = Pattern.compile("(%[uU][dD][89abAB][0-9a-fA-F]{2}%[uU][dD][c-fC-F][0-9a-fA-F]{2})|(%[uU][0-9a-fA-F]{4})");

    public static String toUnocodeUrlDecode(String input) {
        StringBuffer buff = new StringBuffer();
        // 上位サロゲート(\uD800-\uDBFF)
        // 下位サロゲート(\uDC00-\uDFFF)
        Matcher m = PTN_UNICODE_URL_SURROGATE.matcher(input);
        while (m.find()) {
            String unicode = m.group(1);
            if (unicode != null) {
                int chHigh = Integer.parseInt(unicode.substring(2, 6), 16);
                int chLow = Integer.parseInt(unicode.substring(8, 12), 16);
                m.appendReplacement(buff, Matcher.quoteReplacement(new String(new char[]{(char) chHigh, (char) chLow})));
            } else {
                unicode = m.group(2);
                int ch = Integer.parseInt(unicode.substring(2), 16);
                m.appendReplacement(buff, Matcher.quoteReplacement(new String(new char[]{(char) ch})));
            }
        }
        m.appendTail(buff);
        return buff.toString();
    }

    public static String toHtmlDecEncode(String input) {
        return toHtmlDecEncode(input, PTN_ENCODE_ALPHANUM);
    }

    public static String toHtmlDecEncode(String input, Pattern pattern) {
        StringBuilder buff = new StringBuilder();
        int length = input.length();
        for (int i = 0; i < length; i = input.offsetByCodePoints(i, 1)) {
            int c = input.codePointAt(i);
            Matcher m = pattern.matcher(new String(new int[]{c}, 0, 1));
            if (m.matches()) {
                buff.append(String.format("&#%d;", c));
            } else {
                buff.appendCodePoint(c);
            }
        }
        return buff.toString();
    }

    public static String toHtmlHexEncode(String input, boolean upperCase) {
        return toHtmlHexEncode(input, PTN_ENCODE_ALPHANUM, upperCase);
    }

    public static String toHtmlHexEncode(String input, Pattern pattern, boolean upperCase) {
        StringBuilder buff = new StringBuilder();
        int length = input.length();
        for (int i = 0; i < length; i = input.offsetByCodePoints(i, 1)) {
            int c = input.codePointAt(i);
            Matcher m = pattern.matcher(new String(new int[]{c}, 0, 1));
            if (m.matches()) {
                if (upperCase) {
                    buff.append(String.format("&#X%X;", c));
                } else {
                    buff.append(String.format("&#x%x;", c));
                }
            } else {
                buff.appendCodePoint(c);
            }
        }
        return buff.toString();
    }

    public static String toHtmlByteHexEncode(String input, String charset, Pattern pattern, boolean upperCase) throws UnsupportedEncodingException {
        return toHtmlByteHexEncode(input.getBytes(charset), pattern, upperCase);
    }

    public static String toHtmlByteHexEncode(byte[] bytes, Pattern pattern, boolean upperCase) {
        StringBuilder buff = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            int b = bytes[i] & 0xff;
            Matcher m = pattern.matcher(new String(new char[]{(char) b}));
            if (m.matches()) {
                if (upperCase) {
                    buff.append(String.format("&#X%X;", b));
                } else {
                    buff.append(String.format("&#x%x;", b));
                }
            } else {
                buff.append(b);
            }
        }
        return buff.toString();
    }

    public static String toRegexEncode(String input) {
        StringBuilder buff = new StringBuilder();
        int length = input.length();
        for (int i = 0; i < length; i++) {
            char c = input.charAt(i);
            buff.append(toRegexEscape(c));
        }
        return buff.toString();
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

    public static String toRegexDecode(String input) {
        return input.replaceAll("\\\\([\\\\\\.\\+\\*\\?\\[\\^\\]\\$\\(\\)\\{\\}\\=\\!\\<\\>\\|\\:\\-])", "$1");
    }

    public static String toHtmlDecode(String input) {
        StringBuffer buff = new StringBuffer();
        Pattern p = Pattern.compile("(&(?:(#\\d+)|(#[xX][0-9a-fA-F]+)|(\\w+));)");
        Matcher m = p.matcher(input);
        while (m.find()) {
            String html = m.group(1);
            if (html != null) {
                if (html.startsWith("&#x") || html.startsWith("&#X")) {
                    String htmlhex = m.group(3);
                    int ch = Integer.parseInt(htmlhex.substring(2), 16);
                    m.appendReplacement(buff, Matcher.quoteReplacement(new String(new int[]{ch}, 0, 1)));
                } else if (html.startsWith("&#")) {
                    String htmldec = m.group(2);
                    int ch = Integer.parseInt(htmldec.substring(1), 10);
                    m.appendReplacement(buff, Matcher.quoteReplacement(new String(new int[]{ch}, 0, 1)));
                } else if (html.startsWith("&")) {
                    String htmlwd = m.group(4);
                    if (htmlwd == null) {
                        continue;
                    }
                    String htmlch = "";
                    if (htmlwd.equals("lt")) {
                        htmlch = "<";
                    } else if (htmlwd.equals("gt")) {
                        htmlch = ">";
                    } else if (htmlwd.equals("amp")) {
                        htmlch = "&";
                    } else if (htmlwd.equals("quot")) {
                        htmlch = "\"";
                    } else {
                        htmlch = fromHTMLEntity(htmlwd);
                        if (htmlch == null) {
                            htmlch = "";
                        }
                    }
                    m.appendReplacement(buff, htmlch);
                }
            }
        }
        m.appendTail(buff);
        return buff.toString();
    }

    /**
     * @param entityName
     * @return
     */
    protected static String fromHTMLEntity(String entityName) {
        Character ch = ENTITY.get(entityName);
        if (ch == null) {
            return null;
        }
        return Character.toString(ch);
    }

    /**
     * @param input
     * @param charset
     * @return
     * @throws UnsupportedEncodingException
     */
    public static String toHtmlDecode(String input, String charset) throws UnsupportedEncodingException {
        String decode = toHtmlDecode(input);
        if (charset == null) {
            return decode;
        } else {
            return new String(decode.getBytes(StandardCharsets.ISO_8859_1), charset);
        }
    }

    public static String toUudecode(String input, String encoding) throws UnsupportedEncodingException {
        return toMimeUtilDecode(input, encoding, "uuencode");
    }

    public static String toUnQuotedPrintable(String input, String encoding) throws UnsupportedEncodingException {
        return toMimeUtilDecode(input, encoding, "quoted-printable");
    }

    protected static String toMimeUtilDecode(String input, String encoding, String translate) throws UnsupportedEncodingException {
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        try (InputStream in = javax.mail.internet.MimeUtility.decode(new ByteArrayInputStream(input.getBytes(encoding)), translate)) {
            byte[] buf = new byte[1024];
            int length = -1;
            while ((length = in.read(buf)) > -1) {
                bout.write(buf, 0, length);
            }
        } catch (javax.mail.MessagingException ex) {
            Logger.getLogger(TransUtil.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(TransUtil.class.getName()).log(Level.SEVERE, null, ex);
        }
        return new String(bout.toByteArray(), encoding);
    }

    public static String toUuencode(String input, String encoding) throws UnsupportedEncodingException {
        return toMimeUtilEncode(input, encoding, "uuencode");
    }

    public static String toQuotedPrintable(String input, String encoding) throws UnsupportedEncodingException {
        return toMimeUtilEncode(input, encoding, "quoted-printable");
    }

    protected static String toMimeUtilEncode(String input, String encoding, String translate) throws UnsupportedEncodingException {
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        try (OutputStream out = javax.mail.internet.MimeUtility.encode(bout, translate)) {
            byte[] buf = new byte[1024];
            ByteArrayInputStream bin = new ByteArrayInputStream(input.getBytes(encoding));
            int length = -1;
            while ((length = bin.read(buf)) > -1) {
                out.write(buf, 0, length);
            }
        } catch (javax.mail.MessagingException ex) {
            Logger.getLogger(TransUtil.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(TransUtil.class.getName()).log(Level.SEVERE, null, ex);
        }
        return new String(bout.toByteArray(), encoding);
    }

    public static String toBigBin(String value) {
        return "0b" + (new BigInteger(toRadixTrim(value), toPrefixRadix(value))).toString(2);
    }

    public static String toBigDec(String value) {
        return (new BigInteger(toRadixTrim(value), toPrefixRadix(value))).toString(10);
    }

    public static String toBigHex(String value) {
        return "0x" + (new BigInteger(toRadixTrim(value), toPrefixRadix(value))).toString(16);
    }

    public static String toBigOct(String value) {
        return "0" + (new BigInteger(toRadixTrim(value), toPrefixRadix(value))).toString(8);
    }

    private static int toPrefixRadix(String value) {
        int x = 10;
        if (value.startsWith("0x") || value.startsWith("0X")) {
            x = 16;
        } else if (value.startsWith("0b") || value.startsWith("0B")) {
            x = 2;
        } else if (value.startsWith("0")) {
            x = 8;
        }
        return x;
    }

    public static String toCamelCase(String value) {
        StringBuilder buff = new StringBuilder();
        int length = value.length();
        for (int i = 0; i < length; i = value.offsetByCodePoints(i, 1)) {
            int c = value.codePointAt(i);
            if (buff.length() == 0) {
                buff.appendCodePoint(Character.toUpperCase(c));
            } else {
                buff.appendCodePoint(Character.toLowerCase(c));
            }
        }
        return buff.toString();
    }

    private static String toRadixTrim(String value) {
        if (value.startsWith("0x") || value.startsWith("0X")) {
            return value.substring(2);
        } else if (value.startsWith("0b") || value.startsWith("0B")) {
            return value.substring(2);
        } else if (value.startsWith("0")) {
            return value.substring(1);
        }
        return value;
    }

    private final static Pattern PTN_JS_META = Pattern.compile("(\\\\[rnbftv\\\\])|(\\\\x[0-9a-fA-F]{2})|((\\\\u[dD][89abAB][0-9a-fA-F]{2}\\\\u[dD][c-fC-F][0-9a-fA-F]{2})|(\\\\u[0-9a-fA-F]{4}))");

    /**
     * JavaScript言語形式のメタ文字デコード(エスケープされたものを戻す)
     *
     * @param value
     * @return デコードされた値
     */
    public static String decodeJsLangMeta(String input) {
        StringBuffer buff = new StringBuffer();
        Matcher m = PTN_JS_META.matcher(input);
        while (m.find()) {
            String p1 = m.group(1);
            String p2 = m.group(2);
            String p3 = m.group(3);
            if (p1 != null) {
                char code = p1.charAt(1);
                switch (code) {
                    case 'r':
                        m.appendReplacement(buff, "\r");
                        break;
                    case 'n':
                        m.appendReplacement(buff, "\n");
                        break;
                    case 'b':
                        m.appendReplacement(buff, Character.toString((char) (0x08)));
                        break;
                    case 'f':
                        m.appendReplacement(buff, Character.toString((char) (0x0c)));
                        break;
                    case 't':
                        m.appendReplacement(buff, "\t");
                        break;
                    case 'v':
                        m.appendReplacement(buff, Character.toString((char) (0x0b)));
                        break;
                    case '\\':
                        m.appendReplacement(buff, "\\\\");
                        break;
                    default:
                        break;
                }
            } else if (p2 != null) {
                String bytecode = p2;
                int ch = Integer.parseInt(bytecode.substring(2), 16);
                m.appendReplacement(buff, Matcher.quoteReplacement(new String(new char[]{(char) ch})));
            } else if (p3 != null) {
                String unicode = m.group(4);
                if (unicode != null) {
                    int chHigh = Integer.parseInt(unicode.substring(2, 6), 16);
                    int chLow = Integer.parseInt(unicode.substring(8, 12), 16);
                    m.appendReplacement(buff, Matcher.quoteReplacement(new String(new char[]{(char) chHigh, (char) chLow})));
                } else {
                    unicode = m.group(5);
                    int ch = Integer.parseInt(unicode.substring(2), 16);
                    m.appendReplacement(buff, Matcher.quoteReplacement(new String(new char[]{(char) ch})));
                }
            }
        }
        m.appendTail(buff);
        return buff.toString();
    }

    /**
     * JavaScript言語形式のリテラルエンコード(エスケープ)
     *
     * @param value
     * @return エンコードされた値
     */
    public static String encodeJsLangQuote(String value) {
        return value.replaceAll("([\\\\\"'])", "\\\\$1");
    }

    /**
     * JavaScript言語形式のリテラルデコード(エスケープされたものを戻す)
     *
     * @param value
     * @return デコードされた値
     */
    public static String decodeJsLangQuote(String value) {
        return value.replaceAll("\\\\([\\\\\"'])", "$1");
    }

    /**
     * C言語形式のエンコード(エスケープ)
     *
     * @param value
     * @return エンコードされた値
     */
    public static String encodeCLangQuote(String value) {
        return value.replaceAll("([\\\\\"])", "\\\\$1");
    }

    /**
     * C言語形式のデコード(エスケープされたものを戻す)
     *
     * @param value
     * @return デコードされた値
     */
    public static String decodeCLangQuote(String value) {
        return value.replaceAll("\\\\([\\\\\"])", "$1");
    }

    /**
     * PL/SQL言語形式のエンコード(エスケープ)
     *
     * @param value
     * @return エンコードされた値
     */
    public static String encodeSQLLangQuote(String value) {
        return value.replaceAll("([\'])", "\'$1");
    }

    /**
     * PL/SQL言語形式のデコード(エスケープされたものを戻す)
     *
     * @param value
     * @return デコードされた値
     */
    public static String decodeSQLangQuote(String value) {
        return value.replaceAll("''", "'");
    }

    public static String toSmartMatch(String value) {
        try {
            return toSmartMatch(value, null);
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(TransUtil.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    public static String toSmartMatch(String value, String charset) throws UnsupportedEncodingException {
        StringBuilder buff = new StringBuilder();
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
//                case '<':
//                case '>':
                case '|':
                case ':':
                case '-':
                    buff.append(toRegexEscape(ch));
                    break;
                default:
                    buff.appendCodePoint(code);
                    break;
            }
            buff.append('|');
            buff.append(String.format("([\\\\%%]u)%04x", code)); // unicode hex
            buff.append('|');
            buff.append(String.format("&#(x%04x|%d);", code, code)); // unicode hex,decimal
            if (charset != null) {
                buff.append('|');
                String s = value.substring(i, value.offsetByCodePoints(i, 1));
                byte decode[] = s.getBytes(charset);
                for (int k = 0; k < decode.length; k++) {
                    buff.append(String.format("((\\\\x|%%)%02x)", 0xff & decode[k])); // byte hex
                }
            } else {
                if (ch <= 0xff) {
                    buff.append('|');
                    buff.append(String.format("((\\\\x|%%)%02x)", 0xff & ch)); // byte hex
                }
            }
            buff.append(')');
        }
        return buff.toString();
    }

    public static Pattern compileRegex(String text, boolean smartMatch, boolean regexp, boolean ignoreCase) {
        int flags = 0;
        if (ignoreCase) {
            flags |= Pattern.CASE_INSENSITIVE;
        }
        Pattern p = RegexItem.compileRegex(text, flags, !regexp);
        if (smartMatch) {
            String smartRegex = TransUtil.toSmartMatch(text);
            p = RegexItem.compileRegex(smartRegex, flags, false);
        }
        return p;
    }
            
    /**
     * リストを作成する
     *
     * @param format prntf形式書式
     * @param startNum 開始
     * @param endNum 終了
     * @param stepNum ステップ
     * @return 作成済みのリスト
     */
    public static String[] generaterList(String format, int startNum, int endNum, int stepNum) {
        if (stepNum == 0) {
            throw new IllegalArgumentException("You can not specify zero for Step");
        }
        int startValue = Math.min(startNum, endNum);
        int endValue = Math.max(startNum, endNum);
        ArrayList<String> list = new ArrayList<>();
        if (0 < stepNum) {
            for (int i = startValue; i <= endValue; i += stepNum) {
                list.add(String.format(format, i));
            }
        }
        if (0 > stepNum) {
            for (int i = endValue; i >= startValue; i += stepNum) {
                list.add(String.format(format, i));
            }
        }
        return list.toArray(new String[0]);
    }

    public static String[] randomList(String range, int length, int count) {
        ArrayList<String> list = new ArrayList<String>();
        for (int i = 0; i < count; i++) {
            list.add(Util.randomCharRange(range, length));
        }
        return list.toArray(new String[0]);
    }

    /**
     * リストを作成する
     *
     * @param format prntf形式書式
     * @param startDate 開始
     * @param endDate 終了
     * @param stepDate ステップ
     * @return 作成済みのリスト
     */
    public static String[] dateList(String format, LocalDate startDate, LocalDate endDate, int stepDate, DateUnit unit) {
        if (stepDate == 0) {
            throw new IllegalArgumentException("You can not specify zero for Step");
        }
        LocalDate startValue = startDate.compareTo(endDate) < 0 ? startDate : endDate;
        LocalDate endValue = startDate.compareTo(endDate) > 0 ? startDate : endDate;
        ChronoUnit dateUnit = ChronoUnit.DAYS;
        switch (unit) {
            case DAYS:
                dateUnit = ChronoUnit.DAYS;
                break;
            case WEEKS:
                dateUnit = ChronoUnit.WEEKS;
                break;
            case MONTHS:
                dateUnit = ChronoUnit.MONTHS;
                break;
            case YEARS:
                dateUnit = ChronoUnit.YEARS;
                break;
            default:
                break;
        }

        ArrayList<String> list = new ArrayList<>();
        final DateTimeFormatter dateFormat = DateTimeFormatter.ofPattern(format);
        if (0 < stepDate) {
            LocalDate currentDate = startValue;
            while (currentDate.compareTo(endValue) <= 0) {
                list.add(currentDate.format(dateFormat));
                currentDate = currentDate.plus(stepDate, dateUnit);
            }
        }
        if (0 > stepDate) {
            LocalDate currentDate = endValue;
            while (currentDate.compareTo(startValue) >= 0) {
                list.add(currentDate.format(dateFormat));
                currentDate = currentDate.plus(stepDate, dateUnit);
            }
        }
        return list.toArray(new String[0]);
    }

    private static final DecimalFormat FMT_HEX_POSITION = new DecimalFormat("000000"); // @jve:decl-index=0:

    public static void hexDump(byte[] output, PrintStream out) {
        try {
            /*
             * HEX文字列に変換
             */
            String[] hexs = new String[output.length];
            for (int i = 0; i < output.length; i++) {
                hexs[i] = ConvertUtil.toHexString(output[i]);
            }
            /*
             * HEX表示の作成
             */
            String[] hexmod = new String[16 + 2];
            byte[] partout = new byte[16];
            int row = 0;
            int j = 1;
            for (int i = 0; i < hexs.length; i++) {
                hexmod[j++] = hexs[i];
                if (i > 0 && (j - 1) % 16 == 0) {
                    System.arraycopy(output, row * 16, partout, 0, partout.length);
                    String hexText = new String(partout, StandardCharsets.ISO_8859_1);
                    hexmod[0] = FMT_HEX_POSITION.format(row);
                    hexmod[17] = hexText;
                    for (int x = 0; x < hexmod.length; x++) {
                        out.print(hexmod[x]);
                        out.print(" ");
                    }
                    out.println();
                    hexmod = new String[16 + 2];
                    partout = new byte[16];
                    j = 1;
                    row++;
                }
            }
            /*
             * 16で割れなかった余り
             */
            if ((j - 1) > 0) {
                System.arraycopy(output, row * 16, partout, 0, j - 1);
                String hexText = new String(partout, StandardCharsets.ISO_8859_1);
                hexmod[0] = FMT_HEX_POSITION.format(row);
                hexmod[17] = hexText;
                for (int x = 0; x < j; x++) {
                    out.print(hexmod[x]);
                    out.print(" ");
                }
                out.println();
            }
            out.flush();
        } catch (Exception e2) {
            Logger.getLogger(TransUtil.class.getName()).log(Level.SEVERE, null, e2);
        }
    }

    public static String getUniversalGuessCode(byte[] bytes) {
        return getUniversalGuessCode(bytes, null);
    }

    /**
     *
     * @param bytes 文字コードを調べるデータ
     * @return 適当と思われるEncoding、判断できなかった時はnull
     */
    public static String getUniversalGuessCode(byte[] bytes, String defaultCharset) {
        String guessCharset = null;
        ByteArrayInputStream fis = new ByteArrayInputStream(bytes);
        byte[] buf = new byte[4096];
        UniversalDetector detector = new UniversalDetector(null);
        int nread = -1;
        try {
            while ((nread = fis.read(buf)) >= 0 && !detector.isDone()) {
                detector.handleData(buf, 0, nread);
            }
        } catch (IOException ex) {
            Logger.getLogger(TransUtil.class.getName()).log(Level.SEVERE, null, ex);
        }
        detector.dataEnd();
        guessCharset = detector.getDetectedCharset();
        detector.reset();
        if (guessCharset == null) {
            guessCharset = defaultCharset;
        }
        return normalizeCharset(guessCharset);
    }

    private final static Map<String, String> CHARSET_ALIAS = new HashMap<>();

    static {
        // universalchardet unknown support
        CHARSET_ALIAS.put("UTF-16BE", "UTF-16");
        CHARSET_ALIAS.put("HZ-GB-23121", "GB2312");
        CHARSET_ALIAS.put("X-ISO-10646-UCS-4-34121", "UTF-32");
        CHARSET_ALIAS.put("X-ISO-10646-UCS-4-21431", "UTF-32");
    }

    public static String normalizeCharset(String charsetName) {
        String charset = charsetName;
        String aliasName = CHARSET_ALIAS.get(charsetName);
        if (aliasName == null) {
            charset = HttpUtil.normalizeCharset(charsetName);
        } else {
            charset = aliasName;
        }
        return charset;
    }

}
