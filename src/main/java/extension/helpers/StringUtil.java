package extension.helpers;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.charset.UnsupportedCharsetException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.SortedMap;

/**
 *
 * @author isayan
 */
public class StringUtil {
    public static final String DEFAULT_ENCODING = System.getProperty("file.encoding");
    public static final String NEW_LINE = System.getProperty("line.separator");

    private static final SecureRandom RANDOM = new SecureRandom();

    public static String repeat(String str, int n) {
      return String.join("", Collections.nCopies(n, str));
    }

    /**
     * 生のバイト文字列取得
     *
     * @param message 対象文字列
     * @return バイト列
     */
    public static byte[] getBytesRaw(String message) {
        return message.getBytes(StandardCharsets.ISO_8859_1);
    }

    public static String getStringRaw(byte[] message) {
        return new String(message, StandardCharsets.ISO_8859_1);
    }

    /**
     * UTF-8のバイト文字列取得
     *
     * @param message 対象文字列
     * @return バイト列
     */
    public static byte[] getBytesUTF8(String message) {
        return message.getBytes(StandardCharsets.UTF_8);
    }

    public static String getStringUTF8(byte[] message) {
        return new String(message, StandardCharsets.UTF_8);
    }

    /**
     * 指定した文字コードのバイト文字列取得
     *
     * @param message 対象文字列
     * @param charset
     * @return バイト列
     */
    public static byte[] getBytesCharset(String message, Charset charset) {
        return message.getBytes(charset);
    }

    public static String getStringCharset(byte[] message, Charset charset) {
        return new String(message, charset);
    }

    public static String getStringCharset(byte[] message, int offset, int length, Charset charset) {
        return new String(message, offset, length, charset);
    }

    public static String getStringCharset(byte[] message, int offset, int length, String encoding) {
        String decodeStr = null;
        try {
            decodeStr = new String(message, offset, length, encoding);
        } catch (UnsupportedEncodingException ex) {
        }
        return decodeStr;
    }

    /**
     * 指定した文字コードのバイト文字列取得
     *
     * @param message 対象文字列
     * @param charset
     * @return バイト列
     */
    public static byte[] getBytesCharset(String message, String charset) throws UnsupportedEncodingException {
        return message.getBytes(charset);
    }

    public static String getStringCharset(byte[] message, String charset) throws UnsupportedEncodingException {
        return new String(message, charset);
    }

    public static String getBytesRawString(byte[] message) {
        return new String(message, StandardCharsets.ISO_8859_1);
    }

    public static String getBytesCharsetString(String message, String encoding) throws UnsupportedEncodingException {
        byte[] encodeByte = message.getBytes(encoding);
        return new String(encodeByte, StandardCharsets.ISO_8859_1);
    }

    public static String getBytesCharsetString(String message, Charset charset) throws UnsupportedEncodingException {
        byte[] encodeByte = message.getBytes(charset);
        return new String(encodeByte, StandardCharsets.ISO_8859_1);
    }

    public static String toString(String value) {
        if (value == null) {
            return "";
        }
        else {
            return String.valueOf(value);
        }
    }

    public static String toString(Boolean value) {
        if (value == null) {
            return "";
        }
        else {
            return String.valueOf(value);
        }
    }

    public static String toString(Integer value) {
        if (value == null) {
            return "";
        }
        else {
            return String.valueOf(value);
        }
    }

    public static String toString(Float value) {
        if (value == null) {
            return "";
        }
        else {
            return String.valueOf(value);
        }
    }

    public static String toString(Object value) {
        if (value == null) {
            return "";
        }
        else {
            return String.valueOf(value);
        }
    }

    private final static char[] NUM_CHARS = "1234567890".toCharArray();
    private final static char[] IDENT_CHARS
            = "_1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".toCharArray();

    public static String randomNumeric(int length) {
        StringBuilder buff = new StringBuilder();
        for (int i = 0; i < length; i++) {
            buff.append(NUM_CHARS[RANDOM.nextInt(NUM_CHARS.length)]);
        }
        return buff.toString();
    }

    public static String randomIdent(int length) {
        StringBuilder buff = new StringBuilder();
        for (int i = 0; i < length; i++) {
            buff.append(IDENT_CHARS[RANDOM.nextInt(IDENT_CHARS.length)]);
        }
        return buff.toString();
    }

    public static String randomCharRange(String range, int length) {
        char[] chars = range.toCharArray();
        StringBuilder buff = new StringBuilder();
        for (int i = 0; i < length; i++) {
            buff.append(chars[RANDOM.nextInt(chars.length)]);
        }
        return buff.toString();
    }

    public static boolean isNullOrEmpty(String value) {
        return !(value != null && !"".equals(value));
    }

    public static boolean equalsString(String a1, String a2) {
        if (a1 == null || a2 == null) {
            return false;
        }
        return Arrays.equals(a1.toCharArray(), a2.toCharArray());
    }

    public static int compareToString(String a1, String a2) {
        int len1 = a1.length();
        int len2 = a2.length();
        int lim = Math.min(len1, len2);
        char v1[] = a1.toCharArray();
        char v2[] = a2.toCharArray();
        int k = 0;
        while (k < lim) {
            char c1 = v1[k];
            char c2 = v2[k];
            if (c1 != c2) {
                return c1 - c2;
            }
            k++;
        }
        return len1 - len2;
    }

    /**
     * 文字列置換
     *
     * @param str 置換元文字列
     * @param startPos 開始位置
     * @param endPos 終了位置
     * @param repstr 置換文字列
     * @return 置換後文字列
     */
    public static String stringReplace(String str, int startPos, int endPos, String repstr) {
        StringBuilder buff = new StringBuilder(str);
        buff.delete(startPos, endPos);
        buff.insert(startPos, repstr);
        return buff.toString();
    }

    public static String toPascalCase(String s) {
        char ch[] = s.toLowerCase().toCharArray();
        if (ch.length > 0) {
            ch[0] = Character.toUpperCase(ch[0]);
        }
        return  new String(ch);
    }

    public static String toCamelCase(String s) {
        char ch[] = s.toCharArray();
        if (ch.length > 0) {
            ch[0] = Character.toLowerCase(ch[0]);
        }
        return  new String(ch);
    }
    
    public static String getStackTraceMessage(Exception ex) {
        return String.format("%s: %s", ex.getClass().getName(), ex.getMessage());
    }

    public static String getStackTrace(Throwable ex) {
        final Writer result = new StringWriter();
        final PrintWriter printWriter = new PrintWriter(result);
        ex.printStackTrace(printWriter);
        return result.toString();
    }

    public static String getStackTrace(String message, Throwable ex) {
        final Writer result = new StringWriter();
        final PrintWriter printWriter = new PrintWriter(result);
        printWriter.append(message);
        printWriter.append(':');
        ex.printStackTrace(printWriter);
        return result.toString();
    }

    public static Charset lookupCharset(String csn) {
        if (Charset.isSupported(csn)) {
            try {
                return Charset.forName(csn);
            } catch (UnsupportedCharsetException x) {
                return null;
            }
        }
        return null;
    }

    /**
     * 有効な文字列エンコーディングリストの取得
     *
     * @return エンコーディングリスト
     */
    public static String[] getAvailableEncodingList() {
        java.util.List<String> list = new ArrayList<String>();
        SortedMap<String, Charset> map = Charset.availableCharsets();
        Charset charsets[] = (Charset[]) map.values().toArray(
                new Charset[]{});
        for (int i = 0; i < charsets.length; i++) {
            String charname = charsets[i].displayName();
            list.add(charname);
        }
        return list.toArray(new String[0]);
    }


}
