package yagura.external;

import extend.util.ConvertUtil;
import extend.util.HttpUtil;
import extend.util.UTF7Charset;
import extend.util.Util;
import java.io.*;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.text.DecimalFormat;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.xml.bind.DatatypeConverter;
import org.mozilla.universalchardet.UniversalDetector;

/**
 * @author isayan
 *
 */
public class TransUtil {

    public enum EncodeType {
        ALL, ALPHANUM, LIGHT, STANDARD
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
        BASE64, UUENCODE, QUOTEDPRINTABLE, URL_STANDARD, HTML, URL_UNICODE, UNICODE, BYTE_HEX, BYTE_OCT, ZLIB, UTF7, UTF8_ILL, C_LANG, SQL_LANG
    };

    private final static Pattern PTN_B64 = Pattern.compile("([0-9a-zA-Z+/\r\n])+={0,2}");
    private final static Pattern PTN_UUENCODE = Pattern.compile("begin\\s[0-6]{3}\\s\\w+");
    private final static Pattern PTN_QUOTEDPRINTABLE = Pattern.compile("=([0-9a-fA-F]{2})");
    private final static Pattern PTN_URL = Pattern.compile("%([0-9a-fA-F]{2})");
    private final static Pattern PTN_HTML = Pattern.compile("(&#(\\d+);)|(&#[xX]([0-9a-fA-F]+);)");
    private final static Pattern PTN_URL_UNICODE = Pattern.compile("%[uU]([0-9a-fA-F]{4})");
    private final static Pattern PTN_UNICODE = Pattern.compile("\\\\[uU]([0-9a-fA-F]{4})");
    private final static Pattern PTN_BYTE_HEX = Pattern.compile("\\\\[xX]([0-9a-fA-F]{2})");
    private final static Pattern PTN_BYTE_OCT = Pattern.compile("\\\\([0-9]{1,})");

    public static EncodePattern getSmartDecode(String value) {
        // 判定の順番は検討の余地あり        
        // % Encode
        Matcher mURL = PTN_URL.matcher(value);
        // base64
        Matcher m64 = PTN_B64.matcher(value);
        // uuencode
        Matcher mUUENCODE = PTN_UUENCODE.matcher(value);
        // QuotedPrintable
        Matcher mQUOTEDPRINTABLE = PTN_QUOTEDPRINTABLE.matcher(value);
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

        // URL encode match
        if (mURL.find()) {
            return EncodePattern.URL_STANDARD;
        } // URL Unicode
        else if (mURL_UNICODE.find()) {
            return EncodePattern.URL_UNICODE;
        } // unicode
        else if (mUNICODE.find()) {
            return EncodePattern.UNICODE;
        } // byte
        else if (mBYTE_HEX.find()) {
            return EncodePattern.BYTE_HEX;
        }
        else if (mBYTE_OCT.find()) {
            return EncodePattern.BYTE_OCT;
        } // uuencode encode match
        else if (mUUENCODE.lookingAt()) {
            return EncodePattern.UUENCODE;
        } // QuotedPrintable
        else if (mQUOTEDPRINTABLE.find()) {
            return EncodePattern.QUOTEDPRINTABLE;
        } // Base64 encode match
        else if (m64.matches()) {
            return EncodePattern.BASE64;
        } // Html decode
        else if (mHTML.find()) {
            return EncodePattern.HTML;
        }
        return null;
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
        String applyCharset = "8859_1";
        String decode = value;
        try {
            // URL encode match
            switch (encodePattern) {
                case URL_STANDARD: {
                    String guessCode = (charset == null) ? getUniversalGuessCode(Util.getRawByte(TransUtil.decodeUrl(value, "8859_1"))) : charset;
                    if (guessCode != null) {
                        applyCharset = guessCode;
                        decode = TransUtil.decodeUrl(value, guessCode);
                    } else {
                        decode = TransUtil.decodeUrl(value, "8859_1");
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
                case BYTE_HEX: {
                    String guessCode = (charset == null) ? getUniversalGuessCode(Util.getRawByte(toByteDecode(value, "8859_1"))) : charset;
                    if (guessCode != null) {
                        applyCharset = guessCode;
                        decode = toByteDecode(value, applyCharset);
                    } else {
                        decode = toByteDecode(value, "8859_1");
                    }
                    break;
                }
                case BYTE_OCT: {
                    String guessCode = (charset == null) ? getUniversalGuessCode(Util.getRawByte(toByteDecode(value, "8859_1"))) : charset;
                    if (guessCode != null) {
                        applyCharset = guessCode;
                        decode = toByteDecode(value, applyCharset);
                    } else {
                        decode = toByteDecode(value, "8859_1");
                    }
                    break;
                }
                // uuencode
                case UUENCODE: {
                    String guessCode = (charset == null) ? getUniversalGuessCode(Util.getRawByte(toUudecode(value, "8859_1"))) : charset;
                    if (guessCode != null) {
                        applyCharset = guessCode;
                        decode = toUudecode(value, guessCode);
                    } else {
                        decode = toUudecode(value, "8859_1");
                    }
                }
                break;
                // QuotedPrintable
                case QUOTEDPRINTABLE: {
                    String guessCode = (charset == null) ? getUniversalGuessCode(Util.getRawByte(toUudecode(value, "8859_1"))) : charset;
                    if (guessCode != null) {
                        applyCharset = guessCode;
                        decode = toUnQuotedPrintable(value, guessCode);
                    } else {
                        decode = toUnQuotedPrintable(value, "8859_1");
                    }
                }
                break;
                // Base64 encode match
                case BASE64: {
                    value = value.replaceAll("[\r\n]", ""); // 改行削除
                    byte[] bytes = DatatypeConverter.parseBase64Binary(value);
                    String guessCode = (charset == null) ? getUniversalGuessCode(bytes) : charset;
                    if (guessCode != null) {
                        applyCharset = guessCode;
                        decode = ConvertUtil.toBase64Decode(value, guessCode);
                    } else {
                        decode = ConvertUtil.toBase64Decode(value, "8859_1");
                    }
                }
                break;
                // Html decode
                case HTML:
                    decode = toHtmlDecode(value);
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
                default:
                    break;
            }
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(TransUtil.class.getName()).log(Level.SEVERE, null, ex);
        }
        if (selectCharset != null) {
            selectCharset.replace(0, selectCharset.length(), applyCharset);
        }
        return decode;
    }

    public static String toHexString(byte[] input) {
        StringBuilder digestbuff = new StringBuilder();
        for (int i = 0; i < input.length; i++) {
            String tmp = Integer.toHexString(input[i] & 0xff);
            if (tmp.length() == 1) {
                digestbuff.append('0').append(tmp);
            } else {
                digestbuff.append(tmp);
            }
        }
        return digestbuff.toString();
    }

    public static String toOctString(byte[] input) {
        StringBuilder digestbuff = new StringBuilder();
        for (int i = 0; i < input.length; i++) {
            String tmp = Integer.toOctalString(input[i] & 0xff);
            if (tmp.length() == 1) {
                digestbuff.append('0').append(tmp);
            } else {
                digestbuff.append(tmp);
            }
        }
        return digestbuff.toString();
    }

    public static int toInteger(byte[] input) {
        int value = 0;
        for (int i = 0; i < input.length; i++) {
            value = (value << 8) | (input[i] & 0xff);
        }
        return value;
    }

    public static String toHexString(byte input) {
        StringBuilder digestbuff = new StringBuilder();
        String tmp = Integer.toHexString(input & 0xff);
        if (tmp.length() == 1) {
            digestbuff.append('0').append(tmp);
        } else {
            digestbuff.append(tmp);
        }
        return digestbuff.toString();
    }

    public static String toHexString(int input) {
        StringBuilder digestbuff = new StringBuilder();
        String tmp = Integer.toHexString(input & 0xffffffff);
        // 2で割れる数で0詰め
        if ((tmp.length() % 2) != 0) {
            digestbuff.append('0');
        }
        digestbuff.append(tmp);
        return digestbuff.toString();
    }

    public static String toUTF7Encode(String str) {
        UTF7Charset utf7cs = new UTF7Charset("UTF-7", new String[]{});
        ByteBuffer bb = utf7cs.encode(str);
        byte[] content = new byte[bb.limit()];
        System.arraycopy(bb.array(), 0, content, 0, content.length);
        try {
            String value = new String(content, "US-ASCII");
            return value;
        } catch (UnsupportedEncodingException ex) {
            return "";
        }
    }

    public static String toUTF7Decode(String str) {
        UTF7Charset utf7cs = new UTF7Charset("UTF-7", new String[]{});
        try {
            CharBuffer cb = utf7cs.decode(ByteBuffer.wrap(str.getBytes("US-ASCII")));
            return cb.toString();
        } catch (UnsupportedEncodingException ex) {
            return "";
        }
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
        return new String(ustr.getBytes("8859_1"), enc);
    }

    public static int getCharCode(String str, String enc)
            throws UnsupportedEncodingException {
        byte caretbyte[] = str.getBytes(enc);
        return toInteger(caretbyte);
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
                return selectText.replaceAll("\n", "\r\n");
            }
            case LF: {
                return selectText.replaceAll("\r\n", "\n");
            }
            case CR: {
                return selectText.replaceAll("\r\n", "\r");
            }
            default: {
                // nothing
            }
        }
        return selectText;
    }

    public static String newLine(String separator, String value, int length) {
        Pattern p = Pattern.compile(String.format("(.{%d})", length));
        StringBuffer sb = new StringBuffer();
        Matcher m = p.matcher(value);
        while (m.find()) {
            m.appendReplacement(sb, m.group(1) + separator);
        }
        m.appendTail(sb);
        return sb.toString();
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

    public static String decodeUrl(String pString, String charset) throws UnsupportedEncodingException {
        return new String(decodeUrl(pString.getBytes("US-ASCII")), charset);
    }

    public static String encodeUrl(String pString, String charset, boolean upperCase) throws UnsupportedEncodingException {
        return new String(encodeUrl(pString.getBytes(charset), PTN_ENCODE_ALPHANUM, upperCase), "US-ASCII");
    }

    public static String encodeUrl(String pString, String charset, Pattern pattern, boolean upperCase) throws UnsupportedEncodingException {
        return new String(encodeUrl(pString.getBytes(charset), pattern, upperCase), "US-ASCII");
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
            int b = bytes[i];
            if (b < 0) {
                b = 256 + b;
            }
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
    
    public static String toHexEncode(String input, boolean upperCase) {
        return toHexEncode(input, PTN_ENCODE_ALPHANUM, upperCase);
    }

    public static String toHexEncode(String input, Pattern pattern, boolean upperCase) {
        StringBuilder buff = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            Matcher m = pattern.matcher(new String(new char[]{c}));
            if (m.matches()) {
                if (upperCase) {
                    buff.append(String.format("\\X%02X", (int) c));
                } else {
                    buff.append(String.format("\\x%02x", (int) c));
                }
            } else {
                buff.append(c);
            }
        }
        return buff.toString();
    }

    public static String toByteHexEncode(byte[] bytes, Pattern pattern, boolean upperCase) {
        StringBuilder buff = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            int b = bytes[i];
            if (b < 0) {
                b = 256 + b;
            }
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
            int b = bytes[i];
            if (b < 0) {
                b = 256 + b;
            }
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
    
    public static String toByteArrayJsEncode(byte[] input, boolean upperCase) {
        StringBuilder buff = new StringBuilder();
        buff.append("[");
        for (int i = 0; i < input.length; i++) {
            int b = (input[i] & 0xff);
            if (i > 0) {
                buff.append(",");
            }
            if (upperCase) {
                buff.append(String.format("0X%02X", b));
            } else {
                buff.append(String.format("0x%02x", b));
            }
        }
        buff.append("]");
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
            }
                else if(oct != null) {
                    Matcher m3 = PTN_BYTE_OCT.matcher(oct);
                    ByteBuffer buf = ByteBuffer.allocate(oct.length());
                    while (m3.find()) {
                        String octecode = m3.group(1);
                        buf.put((byte)Integer.parseInt(octecode, 8));
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
                buff.append((char) c);
            }
        }
        return buff.toString();
    }

    public static String toHtmlEncode(String input) {
        StringBuilder buff = new StringBuilder();
        int length = input.length();
        for (int i = 0; i < length; i++) {
            char c = input.charAt(i);
            switch (c) {
                case '<':
                    buff.append("&lt;");
                    break;
                case '>':
                    buff.append("&gt;");
                    break;
                case '&':
                    buff.append("&amp;");
                    break;
                case '"':
                    buff.append("&quot;");
                    break;
                case '\'':
                    buff.append("&#39;");
                    break;
                default:
                    buff.append(c);
                    break;
            }
        }
        return buff.toString();
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
                    } else if (htmlwd.equals("nbsp")) {
                        htmlch = " ";
                    }
                    m.appendReplacement(buff, htmlch);
                }
            }
        }
        m.appendTail(buff);
        return buff.toString();
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

    public enum ConvertCase {
        UPPER, LOWLER
    };

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
    public static String[] dateList(String format, LocalDate startDate, LocalDate endDate, int stepDate) {
        if (stepDate == 0) {
            throw new IllegalArgumentException("You can not specify zero for Step");
        }
        LocalDate startValue = startDate.compareTo(endDate) < 0 ? startDate : endDate;
        LocalDate endValue = startDate.compareTo(endDate) > 0 ? startDate : endDate;

        ArrayList<String> list = new ArrayList<String>();
        final DateTimeFormatter dateFormat = DateTimeFormatter.ofPattern(format);
        if (0 < stepDate) {
            LocalDate currentDate = startValue;
            while (currentDate.compareTo(endValue) <= 0) {
                list.add(currentDate.format(dateFormat));
                currentDate = currentDate.plus(stepDate, ChronoUnit.DAYS);
            }
        }
        if (0 > stepDate) {
            LocalDate currentDate = endValue;
            while (currentDate.compareTo(startValue) >= 0) {
                list.add(currentDate.format(dateFormat));
                currentDate = currentDate.plus(stepDate, ChronoUnit.DAYS);
            }
        }
        return list.toArray(new String[0]);
    }

    private static final DecimalFormat fmtPosition = new DecimalFormat("000000"); // @jve:decl-index=0:

    public static void hexDump(byte[] output, PrintStream out) {
        try {
            /*
             * HEX文字列に変換
             */
            String[] hexs = new String[output.length];
            for (int i = 0; i < output.length; i++) {
                hexs[i] = TransUtil.toHexString(output[i]);
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
                    String hexText = new String(partout, "8859_1");
                    hexmod[0] = fmtPosition.format(row);
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
                String hexText = new String(partout, "8859_1");
                hexmod[0] = fmtPosition.format(row);
                hexmod[17] = hexText;
                for (int x = 0; x < j; x++) {
                    out.print(hexmod[x]);
                    out.print(" ");
                }
                out.println();
            }
            out.flush();
        } catch (UnsupportedEncodingException e1) {
            Logger.getLogger(TransUtil.class.getName()).log(Level.SEVERE, null, e1);
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
            while ((nread = fis.read(buf)) > 0 && !detector.isDone()) {
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

    private final static Map<String, String> CHARSET_ALIAS = new HashMap();

    static {
        // universalchardet unknown support
        CHARSET_ALIAS.put("HZ-GB-23121", "GB2312");
        CHARSET_ALIAS.put("X-ISO-10646-UCS-4-34121", "UTF-32");
        CHARSET_ALIAS.put("X-ISO-10646-UCS-4-21431", "UTF-32");
    }
    
    public static String normalizeCharset(String charsetName) {
        // alias
        String aliasName = CHARSET_ALIAS.get(charsetName);        
        String charset = HttpUtil.normalizeCharset(aliasName);
        return charset;
    }
    
}
