package extend.util.external;

import extension.helpers.ConvertUtil;
import extension.helpers.HttpUtil;
import extension.helpers.MatchUtil;
import extension.helpers.SmartCodec;
import extension.helpers.StringUtil;
import extension.helpers.charset.UTF7Charset;
import java.io.*;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.text.DecimalFormat;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.TimeZone;

import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.codec.binary.Base16;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.codec.digest.MessageDigestAlgorithms;
import org.apache.commons.codec.digest.MurmurHash2;

/**
 * @author isayan
 *
 */
public class TransUtil {

    private final static Logger logger = Logger.getLogger(TransUtil.class.getName());

    private final static Pattern PRINTERBLE_MATCH = Pattern.compile("\\p{Print}*");

    public static boolean isPrinterble(String value) {
        Matcher m = PRINTERBLE_MATCH.matcher(value);
        return m.matches();
    }

    public enum DateUnit {
        DAYS, WEEKS, MONTHS, YEARS;

        public static ChronoUnit toChronoUnit(DateUnit unit) {
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
            return dateUnit;
        }
    }

    public enum EncodeType {
        ALL("All"), ALPHANUM("Alphanum"), STANDARD("Standard"), LIGHT("Light"), BURP_LIKE("BurpLike");

        private final String ident;

        EncodeType(final String ident) {
            this.ident = ident;
        }

        public String toIdent() {
            return this.ident;
        }

    };

    public enum ConvertCase {
        UPPER, LOWLER;
    };

    public static Pattern getEncodeTypePattern(EncodeType type) {
        switch (type) {
            case ALL:
                return SmartCodec.ENCODE_PATTERN_ALL;
            case ALPHANUM:
                return SmartCodec.ENCODE_PATTERN_ALPHANUM;
            case STANDARD:
                return SmartCodec.ENCODE_PATTERN_STANDARD;
            case LIGHT:
                return SmartCodec.ENCODE_PATTERN_LIGHT;
            case BURP_LIKE:
                return SmartCodec.ENCODE_PATTERN_BURP;
            default:
                break;
        }
        return SmartCodec.ENCODE_PATTERN_ALL;
    }

    public enum EncodePattern {
        NONE, BASE64, BASE64_URLSAFE, BASE64_MIME, BASE32, BASE16, UUENCODE, QUOTEDPRINTABLE, PUNYCODE, URL_STANDARD, HTML, HTML_UNICODE, HTML_BYTE, URL_UNICODE, UNICODE, UNICODE2, BYTE_HEX, BYTE_HEX1, BYTE_HEX2, BYTE_OCT, GZIP, ZLIB, ZLIB_NOWRAP, UTF7, UTF8_ILL, C_LANG, JSON, SQL_LANG, REGEX,
    };

//    private final static Pattern PTN_URLENCODE = Pattern.compile("(%[0-9a-fA-F][0-9a-fA-F]|[0-9a-zA-Z\\*_\\+\\.-])+");
    private final static Pattern PTN_UUENCODE = Pattern.compile("begin\\s[0-6]{3}\\s\\w+");
    private final static Pattern PTN_QUOTEDPRINTABLE = Pattern.compile("=([0-9a-fA-F]{2})");
    private final static Pattern PTN_PUNYCODE = Pattern.compile("xn--[0-9a-zA-Z_\\.]+");
    private final static Pattern PTN_URL = Pattern.compile("%([0-9a-fA-F]{2})");
    private final static Pattern PTN_HTML = Pattern.compile("(&#(\\d+);)|(&(lt|gt|amp|quot);)|(&#[xX]([0-9a-fA-F]+);)");
    private final static Pattern PTN_URL_UNICODE = Pattern.compile("%[uU]([0-9a-fA-F]{4})");
    private final static Pattern PTN_UNICODE = Pattern.compile("\\\\[uU]([0-9a-fA-F]{4})");
    private final static Pattern PTN_BYTE_HEX_GROUP = Pattern.compile("\\A((?:[0-9a-fA-F]{2})+)\\z");
    private final static Pattern PTN_BYTE_HEX1 = Pattern.compile("\\\\[xX]([0-9a-fA-F]{2})");
    private final static Pattern PTN_BYTE_HEX2 = Pattern.compile("\\\\([0-9a-fA-F]{2})");
    private final static Pattern PTN_BYTE_OCT_SMART = Pattern.compile("\\\\(0[0-9]{1,})");
    private final static Pattern PTN_BYTE_OCT = Pattern.compile("\\\\([0-9]{1,})");
    private final static Pattern PTN_GZIP = Pattern.compile("\\x1f\\x8b");

    public static EncodePattern getSmartDecode(String value) {
        // 判定の順番は検討の余地あり
        // % Encode
        Matcher mURL = PTN_URL.matcher(value);
//        // uuencode
//        Matcher mUUENCODE = PTN_UUENCODE.matcher(value);
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
        Matcher mBYTE_HEX1 = PTN_BYTE_HEX1.matcher(value);
        // byte hex2
        Matcher mBYTE_HEX2 = PTN_BYTE_HEX2.matcher(value);
        // byte hex
        Matcher mBYTE_HEX = PTN_BYTE_HEX_GROUP.matcher(value);
        // byte oct
        Matcher mBYTE_OCT = PTN_BYTE_OCT_SMART.matcher(value);
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
        else if (mBYTE_HEX1.find()) {
            return EncodePattern.BYTE_HEX1;
        } // byte oct
        else if (mBYTE_OCT.find()) {
            return EncodePattern.BYTE_OCT;
        } // byte hex2
        else if (mBYTE_HEX2.find()) {
            return EncodePattern.BYTE_HEX2;
        } // pyny code
        else if (mPunycode.lookingAt()) {
            return EncodePattern.PUNYCODE;
        } // uuencode encode match
        //        else if (mUUENCODE.lookingAt()) {
        //            return EncodePattern.UUENCODE;
        //        } // QuotedPrintable
        else if (mQUOTEDPRINTABLE.find()) {
            return EncodePattern.QUOTEDPRINTABLE;
        } // Base64 encode match
        else if (MatchUtil.isBase64(value)) {
            return EncodePattern.BASE64;
        } // Base64 URLSafe
        else if (MatchUtil.isBase64URLSafe(value)) {
            return EncodePattern.BASE64_URLSAFE;
        } // byte hex
        else if (mBYTE_HEX.find()) {
            return EncodePattern.BYTE_HEX;
        } // Html decode
        else if (mHTML.find()) {
            return EncodePattern.HTML;
        } // Gzip
        else if (mGZIP.lookingAt()) {
            return EncodePattern.GZIP;
        }

        return null;
    }

    public static boolean isBase64Encoded(String value) {
        return Base64.isBase64(value);
    }

    public static String toSmartDecode(String value) {
        return toSmartDecode(value, getSmartDecode(value), false, (String) null);
    }

    public static String toSmartDecode(String value, TransUtil.EncodePattern encodePattern, boolean metaChar, String charset) {
        if (charset == null) {
            return toSmartDecode(value, encodePattern, metaChar, new StringBuffer());
        } else {
            return toSmartDecode(value, encodePattern, metaChar, new StringBuffer(charset));
        }
    }

    public static String toSmartDecode(String value, TransUtil.EncodePattern encodePattern, boolean metaChar, StringBuffer selectCharset) {
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
                decode = StringUtil.getBytesCharsetString(value, applyCharset);
            } else {
                // URL encode match
                switch (encodePattern) {
                    case NONE:
                        decode = value;
                        break;
                    case URL_STANDARD: {
                        String guessCode = (charset == null) ? HttpUtil.getUniversalGuessCode(StringUtil.getBytesRaw(SmartCodec.toUrlDecode(value, StandardCharsets.ISO_8859_1))) : charset;
                        if (guessCode != null) {
                            applyCharset = guessCode;
                            decode = SmartCodec.toUrlDecode(value, applyCharset);
                        } else {
                            decode = SmartCodec.toUrlDecode(value, StandardCharsets.ISO_8859_1);
                        }
                    }
                    break;
                    // URL Unicode
                    case URL_UNICODE:
                        decode = SmartCodec.toUnicodeUrlDecode(value);
                        break;
                    // Unicode
                    case UNICODE:
                        decode = SmartCodec.toUnicodeDecode(value);
                        break;
                    // Unicode2
                    case UNICODE2:
                        decode = SmartCodec.toUnocodeDecode(value, Pattern.quote("$"));
                        break;
                    // Byte Hex
                    case BYTE_HEX: {
                        String guessCode = (charset == null) ? HttpUtil.getUniversalGuessCode(StringUtil.getBytesRaw(toByteDecode(value, StandardCharsets.ISO_8859_1.name()))) : charset;
                        if (guessCode != null) {
                            applyCharset = guessCode;
                            decode = toByteHexDecode(value, applyCharset);
                        } else {
                            decode = toByteHexDecode(value, StandardCharsets.ISO_8859_1.name());
                        }
                        break;
                    }
                    // Byte Hex
                    case BYTE_HEX1: {
                        String guessCode = (charset == null) ? HttpUtil.getUniversalGuessCode(StringUtil.getBytesRaw(toByteDecode(value, StandardCharsets.ISO_8859_1.name()))) : charset;
                        if (guessCode != null) {
                            applyCharset = guessCode;
                            decode = toByteDecode(value, applyCharset);
                        } else {
                            decode = toByteDecode(value, StandardCharsets.ISO_8859_1.name());
                        }
                        break;
                    }
                    // Byte Hex2
                    case BYTE_HEX2: {
                        String guessCode = (charset == null) ? HttpUtil.getUniversalGuessCode(StringUtil.getBytesRaw(toByteDecode(value, StandardCharsets.ISO_8859_1.name()))) : charset;
                        if (guessCode != null) {
                            applyCharset = guessCode;
                            decode = toByteHex2Decode(value, applyCharset);
                        } else {
                            decode = toByteHex2Decode(value, StandardCharsets.ISO_8859_1.name());
                        }
                        break;
                    }
//                    // Byte Dec
//                    case BYTE_DEC:
//                        {
//                            String guessCode = (charset == null) ? getUniversalGuessCode(StringUtil.getBytesRaw(toByteDecode(value, StandardCharsets.ISO_8859_1.name()))) : charset;
//                            if (guessCode != null) {
//                                applyCharset = guessCode;
//                                decode = toByteDecode(value, applyCharset);
//                            } else {
//                                decode = toByteDecode(value, StandardCharsets.ISO_8859_1.name());
//                            }
//                        }
//                        break;
                    case BYTE_OCT: {
                        String guessCode = (charset == null) ? HttpUtil.getUniversalGuessCode(StringUtil.getBytesRaw(toByteDecode(value, StandardCharsets.ISO_8859_1.name()))) : charset;
                        if (guessCode != null) {
                            applyCharset = guessCode;
                            decode = toByteDecode(value, applyCharset);
                        } else {
                            decode = toByteDecode(value, StandardCharsets.ISO_8859_1.name());
                        }
                    }
                    break;
                    // uuencode
//                    case UUENCODE:
//                        {
//                            String guessCode = (charset == null) ? getUniversalGuessCode(StringUtil.getBytesRaw(toUudecode(value, "8859_1"))) : charset;
//                            if (guessCode != null) {
//                                applyCharset = guessCode;
//                                decode = toUudecode(value, applyCharset);
//                            } else {
//                                decode = toUudecode(value, StandardCharsets.ISO_8859_1.name());
//                            }
//                        }
//                        break;
                    // QuotedPrintable
                    case QUOTEDPRINTABLE: {
                        String guessCode = (charset == null) ? HttpUtil.getUniversalGuessCode(StringUtil.getBytesRaw(toUnQuotedPrintable(value, StandardCharsets.ISO_8859_1))) : charset;
                        if (guessCode != null) {
                            applyCharset = guessCode;
                            decode = toUnQuotedPrintable(value, applyCharset);
                        } else {
                            decode = toUnQuotedPrintable(value, StandardCharsets.ISO_8859_1);
                        }
                    }
                    break;
                    // Punycode
                    case PUNYCODE:
                        decode = ConvertUtil.toPunycodeDecode(value);
                        break;
                    // Base64 encode match
                    case BASE64: {
                        value = value.replaceAll("[\r\n]", ""); // 改行削除
                        byte[] bytes = TransUtil.toBase64Decode(value);
                        String guessCode = (charset == null) ? HttpUtil.getUniversalGuessCode(bytes) : charset;
                        if (guessCode != null) {
                            applyCharset = guessCode;
                            decode = TransUtil.toBase64Decode(value, applyCharset);
                        } else {
                            decode = TransUtil.toBase64Decode(value, StandardCharsets.ISO_8859_1);
                        }
                    }
                    break;
                    // Base64 URLSafe
                    case BASE64_URLSAFE: {
                        value = value.replaceAll("[\r\n]", ""); // 改行削除
                        byte[] bytes = TransUtil.toBase64URLSafeDecode(value);
                        String guessCode = (charset == null) ? HttpUtil.getUniversalGuessCode(bytes) : charset;
                        if (guessCode != null) {
                            applyCharset = guessCode;
                            decode = TransUtil.toBase64URLSafeDecode(value, applyCharset);
                        } else {
                            decode = TransUtil.toBase64URLSafeDecode(value, StandardCharsets.ISO_8859_1);
                        }
                    }
                    break;
                    // Base32 encode
                    case BASE32: {
                        value = value.replaceAll("[\r\n]", ""); // 改行削除
                        byte[] bytes = TransUtil.toBase32Decode(value);
                        String guessCode = (charset == null) ? HttpUtil.getUniversalGuessCode(bytes) : charset;
                        if (guessCode != null) {
                            applyCharset = guessCode;
                            decode = TransUtil.toBase32Decode(value, applyCharset);
                        } else {
                            decode = TransUtil.toBase32Decode(value, StandardCharsets.ISO_8859_1);
                        }
                    }
                    break;
                    // Base16 encode
                    case BASE16: {
                        value = value.replaceAll("[\r\n]", ""); // 改行削除
                        byte[] bytes = TransUtil.toBase16Decode(value);
                        String guessCode = (charset == null) ? HttpUtil.getUniversalGuessCode(bytes) : charset;
                        if (guessCode != null) {
                            applyCharset = guessCode;
                            decode = TransUtil.toBase16Decode(value, applyCharset);
                        } else {
                            decode = TransUtil.toBase16Decode(value, StandardCharsets.ISO_8859_1);
                        }
                    }
                    break;
                    // Html decode
                    case HTML:
                        decode = SmartCodec.toHtmlDecode(value, SmartCodec.ENCODE_PATTERN_ALL);
                        break;
                    case HTML_UNICODE:
                        decode = SmartCodec.toHtmlUnicodeDecode(value, SmartCodec.ENCODE_PATTERN_ALL);
                        break;
                    case HTML_BYTE: {
                        String guessCode = (charset == null) ? HttpUtil.getUniversalGuessCode(StringUtil.getBytesRaw(SmartCodec.toHtmlDecode(value, StandardCharsets.ISO_8859_1.name()))) : charset;
                        if (guessCode != null) {
                            applyCharset = guessCode;
                            decode = SmartCodec.toHtmlDecode(value, applyCharset);
                        } else {
                            decode = SmartCodec.toHtmlDecode(value, StandardCharsets.ISO_8859_1.name());
                        }
                    }
                    break;
                    // Gzip
                    case GZIP:
                        decode = StringUtil.getBytesRawString(ConvertUtil.decompressGzip(StringUtil.getBytesCharset(value, charset)));
                        break;
                    // ZLIB
                    case ZLIB:
                        decode = StringUtil.getBytesRawString(ConvertUtil.decompressZlib(StringUtil.getBytesCharset(value, charset)));
                        break;
                    // ZLIB_NOWRAP
                    case ZLIB_NOWRAP:
                        decode = StringUtil.getBytesRawString(ConvertUtil.decompressZlib(StringUtil.getBytesCharset(value, charset), true));
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
                        decode = ConvertUtil.decodeCLangQuote(value, metaChar);
                        break;
                    case JSON:
                        decode = ConvertUtil.decodeJsonLiteral(value, metaChar);
                        break;
                    case SQL_LANG:
                        decode = ConvertUtil.decodeSQLangQuote(value, metaChar);
                        break;
                    case REGEX:
                        decode = ConvertUtil.toRegexDecode(value, metaChar);
                        break;
                    default:
                        break;
                }
            }

        } catch (IOException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        if (selectCharset != null) {
            selectCharset.replace(0, selectCharset.length(), applyCharset);
        }
        return decode;
    }

    public static String toBase64Encode(String src, Charset charset) {
        return toBase64Encode(src, charset, true);
    }

    public static String toBase64Encode(String src, Charset charset, boolean padding) {
        if (padding) {
            byte bytes[] = Base64.encodeBase64(StringUtil.getBytesCharset(src, charset));
            return StringUtil.getBytesRawString(bytes);
        } else {
            byte bytes[] = removePadding(Base64.encodeBase64(StringUtil.getBytesCharset(src, charset)));
            return StringUtil.getBytesRawString(bytes);
        }
    }

    public static String toBase64Encode(String src, String charset)
            throws UnsupportedEncodingException {
        return toBase64Encode(src, charset, true);
    }

    public static String toBase64Encode(String src, String charset, boolean padding)
            throws UnsupportedEncodingException {
        if (padding) {
            byte bytes[] = Base64.encodeBase64(StringUtil.getBytesCharset(src, charset));
            return StringUtil.getBytesRawString(bytes);
        } else {
            byte bytes[] = removePadding(Base64.encodeBase64(StringUtil.getBytesCharset(src, charset)));
            return StringUtil.getBytesRawString(bytes);
        }
    }

    public static String toBase64Encode(byte[] src, String charset)
            throws UnsupportedEncodingException {
        return toBase64Encode(src, true);
    }

    public static String toBase64Encode(byte[] src, boolean padding) {
        if (padding) {
            byte bytes[] = Base64.encodeBase64(src);
            return StringUtil.getBytesRawString(bytes);
        } else {
            byte bytes[] = removePadding(Base64.encodeBase64(src));
            return StringUtil.getBytesRawString(bytes);
        }
    }

    public static String toBase64Decode(String str, Charset charset) {
        byte bytes[] = Base64.decodeBase64(str);
        return StringUtil.getStringCharset(bytes, charset);
    }

    public static String toBase64Decode(String str, String charset)
            throws UnsupportedEncodingException {
        byte bytes[] = Base64.decodeBase64(str);
        return StringUtil.getStringCharset(bytes, charset);
    }

    public static byte[] toBase64Decode(String str) {
        byte bytes[] = Base64.decodeBase64(str);
        return bytes;
    }

    public static String toBase64URLSafeEncode(String src, Charset charset) {
        byte bytes[] = Base64.encodeBase64(StringUtil.getBytesCharset(src, charset), false, true);
        return StringUtil.getBytesRawString(bytes);
    }

    public static String toBase64URLSafeEncode(String src, String charset)
            throws UnsupportedEncodingException {
        byte bytes[] = Base64.encodeBase64(StringUtil.getBytesCharset(src, charset), false, true);
        return StringUtil.getBytesRawString(bytes);
    }

    public static String toBase64URLSafeEncode(byte[] src) {
        byte bytes[] = Base64.encodeBase64(src, false, true);
        return StringUtil.getBytesRawString(bytes);
    }

    public static String toBase64URLSafeDecode(String str, Charset charset) {
        byte bytes[] = Base64.decodeBase64(str);
        return StringUtil.getStringCharset(bytes, charset);
    }

    public static String toBase64URLSafeDecode(String str, String charset)
            throws UnsupportedEncodingException {
        byte bytes[] = Base64.decodeBase64(str);
        return StringUtil.getStringCharset(bytes, charset);
    }

    public static byte[] toBase64URLSafeDecode(String str) {
        byte bytes[] = Base64.decodeBase64(str);
        return bytes;
    }

    public static String toBase32Encode(String src, Charset charset) {
        return toBase32Encode(src, charset, true);
    }

    public static String toBase32Encode(String src, Charset charset, boolean padding) {
        if (padding) {
            byte bytes[] = toBase32Encode(StringUtil.getBytesCharset(src, charset));
            return StringUtil.getBytesRawString(bytes);
        } else {
            byte bytes[] = removePadding(toBase32Encode(StringUtil.getBytesCharset(src, charset)));
            return StringUtil.getBytesRawString(bytes);
        }
    }

    public static String toBase32Encode(String src, String charset)
            throws UnsupportedEncodingException {
        return toBase32Encode(src, charset, true);
    }

    public static String toBase32Encode(String src, String charset, boolean padding)
            throws UnsupportedEncodingException {
        if (padding) {
            byte bytes[] = toBase32Encode(StringUtil.getBytesCharset(src, charset));
            return StringUtil.getBytesRawString(bytes);
        } else {
            byte bytes[] = removePadding(toBase32Encode(StringUtil.getBytesCharset(src, charset)));
            return StringUtil.getBytesRawString(bytes);
        }
    }

    public static String toBase32Encode(byte[] src, String charset)
            throws UnsupportedEncodingException {
        return toBase32Encode(src, true);
    }

    public static String toBase32Encode(byte[] src, boolean padding) {
        if (padding) {
            byte bytes[] = toBase32Encode(src);
            return StringUtil.getBytesRawString(bytes);
        } else {
            byte bytes[] = removePadding(toBase32Encode(src));
            return StringUtil.getBytesRawString(bytes);
        }
    }

    public static String toBase32Decode(String str, Charset charset) {
        byte bytes[] = toBase32Decode(str);
        return StringUtil.getStringCharset(bytes, charset);
    }

    public static String toBase32Decode(String str, String charset)
            throws UnsupportedEncodingException {
        byte bytes[] = toBase32Decode(str);
        return StringUtil.getStringCharset(bytes, charset);
    }

    public static byte[] toBase32Decode(String str) {
        final Base32 b32 = new Base32();
        return b32.decode(str);
    }

    private static byte[] toBase32Encode(byte[] bytes) {
        final Base32 b32 = new Base32();
        return b32.encode(bytes);
    }

    public static String toBase16Encode(String src, Charset charset) {
        return toBase16Encode(src, charset, true);
    }

    public static String toBase16Encode(String src, Charset charset, boolean padding) {
        if (padding) {
            byte bytes[] = toBase16encode(StringUtil.getBytesCharset(src, charset));
            return StringUtil.getStringRaw(bytes);
        } else {
            byte bytes[] = removePadding(toBase16encode(StringUtil.getBytesCharset(src, charset)));
            return StringUtil.getStringRaw(bytes);
        }
    }

    public static String toBase16Encode(String src, String charset)
            throws UnsupportedEncodingException {
        return toBase16Encode(src, charset, true);
    }

    public static String toBase16Encode(String src, String charset, boolean padding)
            throws UnsupportedEncodingException {
        if (padding) {
            byte bytes[] = toBase16encode(StringUtil.getBytesCharset(src, charset));
            return StringUtil.getStringRaw(bytes);
        } else {
            byte bytes[] = removePadding(toBase16encode(StringUtil.getBytesCharset(src, charset)));
            return StringUtil.getStringRaw(bytes);
        }
    }

    public static String toBase16Encode(byte[] src, String charset)
            throws UnsupportedEncodingException {
        return toBase32Encode(src, true);
    }

    public static String toBase16Encode(byte[] src, boolean padding) {
        if (padding) {
            byte bytes[] = toBase16encode(src);
            return StringUtil.getStringRaw(bytes);
        } else {
            byte bytes[] = toBase16encode(src);
            return StringUtil.getStringRaw(bytes);
        }
    }

    public static String toBase16Decode(String str, Charset charset) {
        byte bytes[] = toBase16encode(str);
        return StringUtil.getStringCharset(bytes, charset);
    }

    public static String toBase16Decode(String str, String charset)
            throws UnsupportedEncodingException {
        byte bytes[] = toBase16encode(str);
        return StringUtil.getStringCharset(bytes, charset);
    }

    public static byte[] toBase16Decode(String str) {
        byte bytes[] = toBase16encode(str);
        return bytes;
    }

    private static byte[] toBase16encode(byte[] bytes) {
        final Base16 b16 = new Base16();
        return b16.encode(bytes);
    }

    private static byte[] toBase16encode(String str) {
        final Base16 b16 = new Base16();
        return b16.decode(str);
    }

    private static byte[] removePadding(byte[] vaule) {
        int len = vaule.length;
        while (len > 0 && vaule[len - 1] == (byte) '=') {
            len--;
        }
        return Arrays.copyOf(vaule, len);
    }

    public static String toUTF7Encode(String str) {
        UTF7Charset utf7cs = new UTF7Charset("UTF-7", new String[]{});
        ByteBuffer bb = utf7cs.encode(str);
        byte[] content = Arrays.copyOfRange(bb.array(), 0, bb.limit());
        return StringUtil.getStringCharset(content, StandardCharsets.US_ASCII);
    }

    public static String toUTF7Decode(String str) {
        UTF7Charset utf7cs = new UTF7Charset("UTF-7", new String[]{});
        CharBuffer cb = utf7cs.decode(ByteBuffer.wrap(StringUtil.getBytesCharset(str, StandardCharsets.US_ASCII)));
        return cb.toString();
    }
    private final static String SPECIAL_CHAR = "!\"#$%&'()*+,-./:;<=>?@[\\]{|}~";

    public static String toUSASCII(String str, String charset)
            throws UnsupportedEncodingException {
        char[] chars = StringUtil.toChars(str);
        for (int i = 0; i < chars.length; i++) {
            // 指定された文字のみ
            if (SPECIAL_CHAR.indexOf(chars[i]) > -1) {
                chars[i] = (char) ((int) chars[i] | 0x80);
            }
        }
        return StringUtil.getStringCharset(StringUtil.getBytesRaw(String.valueOf(chars)), charset);
    }

    public static int getCharCode(String str, String enc)
            throws UnsupportedEncodingException {
        byte caretbyte[] = StringUtil.getBytesCharset(str, enc);
        return ConvertUtil.toInteger(caretbyte);
    }

    /*
     * 改行
     */
    public enum NewLine {
        NONE, CRLF, LF, CR
    };

    public static String getNewLine(NewLine linemode) {
        String newLine = HttpUtil.LINE_TERMINATE;
        switch (linemode) {
            case NONE:
                newLine = HttpUtil.LINE_TERMINATE;
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

    public static String join(String separator, List lines) {
        StringBuilder buff = new StringBuilder();
        for (int i = 0; i < lines.size(); i++) {
            if (i > 0) {
                buff.append(separator);
            }
            buff.append(lines.get(i));
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

    public static String toByteHexEncode(String input, Charset charset, boolean upperCase) {
        return toByteHexEncode(StringUtil.getBytesCharset(input, charset), upperCase);
    }

    public static String toByteHexEncode(String input, String charset, boolean upperCase) throws UnsupportedEncodingException {
        return toByteHexEncode(StringUtil.getBytesCharset(input, charset), upperCase);
    }

    public static String toByteHex1Encode(String input, Charset charset, Pattern pattern, boolean upperCase) throws UnsupportedEncodingException {
        return toByteHex1Encode(StringUtil.getBytesCharset(input, charset), pattern, upperCase);
    }

    public static String toByteHex1Encode(String input, String charset, Pattern pattern, boolean upperCase) throws UnsupportedEncodingException {
        return toByteHex1Encode(StringUtil.getBytesCharset(input, charset), pattern, upperCase);
    }

    public static String toByteHex1Encode(String input, String charset, boolean upperCase) throws UnsupportedEncodingException {
        return toByteHex1Encode(input, charset, SmartCodec.ENCODE_PATTERN_ALPHANUM, upperCase);
    }

    public static String toByteHex1Encode(String input, Charset charset, boolean upperCase) throws UnsupportedEncodingException {
        return toByteHex1Encode(input, charset, SmartCodec.ENCODE_PATTERN_ALPHANUM, upperCase);
    }

    public static String toByteHex2Encode(String input, String charset, boolean upperCase) throws UnsupportedEncodingException {
        return toByteHex2Encode(input, charset, SmartCodec.ENCODE_PATTERN_ALPHANUM, upperCase);
    }

    public static String toByteHex2Encode(String input, Charset charset, boolean upperCase) throws UnsupportedEncodingException {
        return toByteHex2Encode(input, charset, SmartCodec.ENCODE_PATTERN_ALPHANUM, upperCase);
    }

    public static String toByteHex2Encode(String input, String charset, Pattern pattern, boolean upperCase) throws UnsupportedEncodingException {
        return toByteHex2Encode(StringUtil.getBytesCharset(input, charset), pattern, upperCase);
    }

    public static String toByteHex2Encode(String input, Charset charset, Pattern pattern, boolean upperCase) throws UnsupportedEncodingException {
        return toByteHex2Encode(StringUtil.getBytesCharset(input, charset), pattern, upperCase);
    }

    public static String toByteDecEncode(String input, String charset) throws UnsupportedEncodingException {
        return toByteDecEncode(input, charset, SmartCodec.ENCODE_PATTERN_ALPHANUM);
    }

    public static String toByteDecEncode(String input, Charset charset) throws UnsupportedEncodingException {
        return toByteDecEncode(input, charset, SmartCodec.ENCODE_PATTERN_ALPHANUM);
    }

    public static String toByteDecEncode(String input, String charset, Pattern pattern) throws UnsupportedEncodingException {
        return toByteDecEncode(StringUtil.getBytesCharset(input, charset), pattern);
    }

    public static String toByteDecEncode(String input, Charset charset, Pattern pattern) throws UnsupportedEncodingException {
        return toByteDecEncode(StringUtil.getBytesCharset(input, charset), pattern);
    }

    public static String toByteOctEncode(String input, String charset) throws UnsupportedEncodingException {
        return toByteOctEncode(input, charset, SmartCodec.ENCODE_PATTERN_ALPHANUM);
    }

    public static String toByteOctEncode(String input, Charset charset) throws UnsupportedEncodingException {
        return toByteOctEncode(input, charset, SmartCodec.ENCODE_PATTERN_ALPHANUM);
    }

    public static String toByteOctEncode(String input, String charset, Pattern pattern) throws UnsupportedEncodingException {
        return toByteOctEncode(StringUtil.getBytesCharset(input, charset), pattern);
    }

    public static String toByteOctEncode(String input, Charset charset, Pattern pattern) throws UnsupportedEncodingException {
        return toByteOctEncode(StringUtil.getBytesCharset(input, charset), pattern);
    }

    public static String toByteHexEncode(byte[] bytes, boolean upperCase) {
        return ConvertUtil.toHexString(bytes, upperCase);
    }

    public static String toByteHex1Encode(byte[] bytes, Pattern pattern, boolean upperCase) {
        StringBuilder buff = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            int b = bytes[i] & 0xff;
            Matcher m = pattern.matcher(String.valueOf(new char[]{(char) b}));
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

    public static String toByteHex2Encode(byte[] bytes, Pattern pattern, boolean upperCase) {
        StringBuilder buff = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            int b = bytes[i] & 0xff;
            Matcher m = pattern.matcher(String.valueOf(new char[]{(char) b}));
            if (m.matches()) {
                if (upperCase) {
                    buff.append(String.format("\\%02X", b));
                } else {
                    buff.append(String.format("\\%02x", b));
                }
            } else {
                buff.append((char) b);
            }
        }
        return buff.toString();
    }

    private static String toByteDecEncode(byte[] bytes, Pattern pattern) {
        StringBuilder buff = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            int b = bytes[i] & 0xff;
            Matcher m = pattern.matcher(String.valueOf(new char[]{(char) b}));
            if (m.matches()) {
                buff.append(String.format("\\%d", b));
            } else {
                buff.append((char) b);
            }
        }
        return buff.toString();
    }

    public static String toByteOctEncode(byte[] bytes, Pattern pattern) {
        StringBuilder buff = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            int b = bytes[i] & 0xff;
            Matcher m = pattern.matcher(String.valueOf(new char[]{(char) b}));
            if (m.matches()) {
                buff.append(String.format("\\%02o", b));
            } else {
                buff.append((char) b);
            }
        }
        return buff.toString();
    }

    private final static Pattern PTN_BYTE_GROUP = Pattern.compile("((?:\\\\[xX][0-9a-fA-F]{2})+)|((?:\\\\[0-9]{1,3})+)");

    public static String toByteDecode(String input, String charset) throws UnsupportedEncodingException {
        StringBuffer buff = new StringBuffer();
        Matcher m = PTN_BYTE_GROUP.matcher(input);
        while (m.find()) {
            String hex = m.group(1);
            String oct = m.group(2);
            if (hex != null) {
                Matcher m2 = PTN_BYTE_HEX1.matcher(hex);
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
                m.appendReplacement(buff, Matcher.quoteReplacement(StringUtil.getStringCharset(value, charset)));
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
        return buff.toString();
    }
    private final static Pattern PTN_BYTE_HEX = Pattern.compile("((?:[0-9a-fA-F]{2}))");

    public static String toByteHexDecode(String input, String charset) throws UnsupportedEncodingException {
        StringBuffer buff = new StringBuffer();
        Matcher m = PTN_BYTE_HEX_GROUP.matcher(input);
        while (m.find()) {
            String hex = m.group(1);
            if (hex != null) {
                Matcher m0 = PTN_BYTE_HEX.matcher(hex);
                ByteBuffer buf = ByteBuffer.allocate(hex.length());
                while (m0.find()) {
                    String hexcode = m0.group(1);
                    int u = Character.digit(hexcode.charAt(0), 16);
                    int l = Character.digit(hexcode.charAt(1), 16);
                    buf.put((byte) ((u << 4) + l));
                }
                buf.flip();
                byte[] value = new byte[buf.limit()];
                buf.get(value);
                m.appendReplacement(buff, Matcher.quoteReplacement(StringUtil.getStringCharset(value, charset)));
            }
        }
        m.appendTail(buff);
        return buff.toString();
    }

    private final static Pattern PTN_BYTE_HEX2_GROUP = Pattern.compile("((?:\\\\[xX][0-9a-fA-F]{2})+)|((?:\\\\[0-9a-fA-F]{2})+)");

    public static String toByteHex2Decode(String input, String charset) throws UnsupportedEncodingException {
        StringBuffer buff = new StringBuffer();
        Matcher m = PTN_BYTE_HEX2_GROUP.matcher(input);
        while (m.find()) {
            String hex1 = m.group(1);
            String hex2 = m.group(2);
            if (hex1 != null) {
                Matcher m2 = PTN_BYTE_HEX1.matcher(hex1);
                ByteBuffer buf = ByteBuffer.allocate(hex1.length());
                while (m2.find()) {
                    String hexcode = m2.group(1);
                    int u = Character.digit(hexcode.charAt(0), 16);
                    int l = Character.digit(hexcode.charAt(1), 16);
                    buf.put((byte) ((u << 4) + l));
                }
                buf.flip();
                byte[] value = new byte[buf.limit()];
                buf.get(value);
                m.appendReplacement(buff, Matcher.quoteReplacement(StringUtil.getStringCharset(value, charset)));
            } else if (hex2 != null) {
                Matcher m3 = PTN_BYTE_HEX2.matcher(hex2);
                ByteBuffer buf = ByteBuffer.allocate(hex2.length());
                while (m3.find()) {
                    String hexcode = m3.group(1);
                    int u = Character.digit(hexcode.charAt(0), 16);
                    int l = Character.digit(hexcode.charAt(1), 16);
                    buf.put((byte) ((u << 4) + l));
                }
                buf.flip();
                byte[] value = new byte[buf.limit()];
                buf.get(value);
                m.appendReplacement(buff, Matcher.quoteReplacement(StringUtil.getStringCharset(value, charset)));
            }
        }
        m.appendTail(buff);
        return buff.toString();
    }

//    public static String toUudecode(String input, String encoding) throws UnsupportedEncodingException {
//        return toMimeUtilDecode(input, encoding, "uuencode");
//    }
    public static String toUnQuotedPrintable(String input, String charset) throws UnsupportedEncodingException {
        try {
            org.apache.commons.codec.net.QuotedPrintableCodec codec = new org.apache.commons.codec.net.QuotedPrintableCodec();
            return codec.decode(input, charset);
        } catch (org.apache.commons.codec.DecoderException ex) {
            return input;
        }
    }

    public static String toUnQuotedPrintable(String input, Charset charset) {
        try {
            org.apache.commons.codec.net.QuotedPrintableCodec codec = new org.apache.commons.codec.net.QuotedPrintableCodec();
            return codec.decode(input, charset);
        } catch (org.apache.commons.codec.DecoderException ex) {
            return input;
        }
    }

//    protected static String toMimeUtilDecode(String input, String encoding, String translate) throws UnsupportedEncodingException {
//        ByteArrayOutputStream bout = new ByteArrayOutputStream();
//        try (InputStream in = javax.mail.internet.MimeUtility.decode(new ByteArrayInputStream(input.getBytes(encoding)), translate)) {
//            byte[] buf = new byte[1024];
//            int length = -1;
//            while ((length = in.read(buf)) > -1) {
//                bout.write(buf, 0, length);
//            }
//        } catch (javax.mail.MessagingException ex) {
//            logger.log(Level.SEVERE, ex.getMessage(), ex);
//        } catch (IOException ex) {
//            logger.log(Level.SEVERE, ex.getMessage(), ex);
//        }
//        return new String(bout.toByteArray(), encoding);
//    }
//    public static String toUuencode(String input, String encoding) throws UnsupportedEncodingException {
//        return toMimeUtilEncode(input, encoding, "uuencode");
//    }
//
//    public static String toQuotedPrintable(String input, String encoding) throws UnsupportedEncodingException {
//        return toMimeUtilEncode(input, encoding, "quoted-printable");
//    }
    public static String toQuotedPrintable(String input, String charset) throws UnsupportedEncodingException, org.apache.commons.codec.DecoderException {
        org.apache.commons.codec.net.QuotedPrintableCodec codec = new org.apache.commons.codec.net.QuotedPrintableCodec();
        return codec.encode(input, charset);
    }

    public static String toQuotedPrintable(String input, Charset charset) throws org.apache.commons.codec.DecoderException {
        org.apache.commons.codec.net.QuotedPrintableCodec codec = new org.apache.commons.codec.net.QuotedPrintableCodec();
        return codec.encode(input, charset);
    }

//
//    protected static String toMimeUtilEncode(String input, String encoding, String translate) throws UnsupportedEncodingException {
//        ByteArrayOutputStream bout = new ByteArrayOutputStream();
//        try (OutputStream out = javax.mail.internet.MimeUtility.encode(bout, translate)) {
//            byte[] buf = new byte[1024];
//            ByteArrayInputStream bin = new ByteArrayInputStream(input.getBytes(encoding));
//            int length = -1;
//            while ((length = bin.read(buf)) > -1) {
//                out.write(buf, 0, length);
//            }
//        } catch (javax.mail.MessagingException ex) {
//            logger.log(Level.SEVERE, ex.getMessage(), ex);
//        } catch (IOException ex) {
//            logger.log(Level.SEVERE, ex.getMessage(), ex);
//        }
//        return new String(bout.toByteArray(), encoding);
//    }
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
        return list.toArray(String[]::new);
    }

    public static String[] randomList(String range, int length, int count) {
        ArrayList<String> list = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            list.add(StringUtil.randomCharRange(range, length));
        }
        return list.toArray(String[]::new);
    }

    /**
     * リストを作成する
     *
     * @param format prntf形式書式
     * @param startDate 開始
     * @param endDate 終了
     * @param stepDate ステップ
     * @param unit
     * @return 作成済みのリスト
     */
    public static String[] dateList(String format, LocalDate startDate, LocalDate endDate, int stepDate, DateUnit unit) {
        if (stepDate == 0) {
            throw new IllegalArgumentException("You can not specify zero for Step");
        }
        LocalDate startValue = startDate.compareTo(endDate) < 0 ? startDate : endDate;
        LocalDate endValue = startDate.compareTo(endDate) > 0 ? startDate : endDate;
        ChronoUnit dateUnit = DateUnit.toChronoUnit(unit);

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
        return list.toArray(String[]::new);
    }

    private static final DecimalFormat FMT_HEX_POSITION = new DecimalFormat("000000"); // @jve:decl-index=0:

    public static void hexDump(byte[] output, PrintStream out) {
        try {
            /*
             * HEX文字列に変換
             */
            String[] hexs = new String[output.length];
            for (int i = 0; i < output.length; i++) {
                hexs[i] = ConvertUtil.toHexString(output[i], true);
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
                    String hexText = StringUtil.getStringRaw(partout);
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
                String hexText = StringUtil.getStringRaw(partout);
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
            logger.log(Level.SEVERE, e2.getMessage(), e2);
        }
    }

    /**
     * HashUtil
     *
     */
    /**
     * MD2値の取得
     *
     * @param binary 対象バイト
     * @param upperCase
     * @return ハッシュ値
     */
    public static String toMd2Sum(byte[] binary, boolean upperCase) {
        if (upperCase) {
            return DigestUtils.md2Hex(binary).toUpperCase();
        } else {
            return DigestUtils.md2Hex(binary);
        }
    }

    /**
     * MD2値の取得
     *
     * @param str 対象文字列
     * @param upperCase
     * @return ハッシュ値
     */
    public static String toMd2Sum(String str, boolean upperCase) {
        if (upperCase) {
            return DigestUtils.md2Hex(str).toUpperCase();
        } else {
            return DigestUtils.md2Hex(str);
        }
    }

    /**
     * MD2値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toMd2Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        if (upperCase) {
            return DigestUtils.md2Hex(StringUtil.getBytesCharset(str, charset)).toUpperCase();
        } else {
            return DigestUtils.md2Hex(StringUtil.getBytesCharset(str, charset));
        }
    }

    /**
     * MD5値の取得
     *
     * @param binary 対象バイト
     * @param upperCase
     * @return ハッシュ値
     */
    public static String toMd5Sum(byte[] binary, boolean upperCase) {
        if (upperCase) {
            return DigestUtils.md5Hex(binary).toUpperCase();
        } else {
            return DigestUtils.md5Hex(binary);
        }
    }

    /**
     * MD5値の取得
     *
     * @param str 対象文字列
     * @param upperCase
     * @return ハッシュ値
     */
    public static String toMd5Sum(String str, boolean upperCase) {
        if (upperCase) {
            return DigestUtils.md5Hex(str).toUpperCase();
        } else {
            return DigestUtils.md5Hex(str);
        }
    }

    /**
     * MD5値の取得
     *
     * @param str 対象文字列
     * @param charset
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toMd5Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        if (upperCase) {
            return DigestUtils.md5Hex(StringUtil.getBytesCharset(str, charset)).toUpperCase();
        } else {
            return DigestUtils.md5Hex(StringUtil.getBytesCharset(str, charset));
        }
    }

    /**
     * SHA-1値の取得
     *
     * @param binary 対象バイト
     * @param upperCase
     * @return ハッシュ値
     */
    public static String toSHA1Sum(byte[] binary, boolean upperCase) {
        if (upperCase) {
            return DigestUtils.sha1Hex(binary).toUpperCase();
        } else {
            return DigestUtils.sha1Hex(binary);
        }
    }

    /**
     * SHA-1値の取得
     *
     * @param str 対象文字列
     * @param upperCase
     * @return ハッシュ値
     */
    public static String toSHA1Sum(String str, boolean upperCase) {
        if (upperCase) {
            return DigestUtils.sha1Hex(str).toUpperCase();
        } else {
            return DigestUtils.sha1Hex(str);
        }
    }

    /**
     * SHA-1値の取得
     *
     * @param str 対象文字列
     * @param charset
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toSHA1Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        if (upperCase) {
            return DigestUtils.sha1Hex(StringUtil.getBytesCharset(str, charset)).toUpperCase();
        } else {
            return DigestUtils.sha1Hex(StringUtil.getBytesCharset(str, charset));
        }
    }

    private final static DigestUtils SHA_224_HASH = new DigestUtils(MessageDigestAlgorithms.SHA_224);

    /**
     * SHA-224値の取得
     *
     * @param binary 対象バイト
     * @param upperCase
     * @return ハッシュ値
     */
    public static String toSHA224Sum(byte[] binary, boolean upperCase) {
        if (upperCase) {
            return SHA_224_HASH.digestAsHex(binary).toUpperCase();
        } else {
            return SHA_224_HASH.digestAsHex(binary);
        }
    }

    /**
     * SHA-224値の取得
     *
     * @param str 対象文字列
     * @param upperCase
     * @return ハッシュ値
     */
    public static String toSHA224Sum(String str, boolean upperCase) {
        if (upperCase) {
            return SHA_224_HASH.digestAsHex(str).toUpperCase();
        } else {
            return SHA_224_HASH.digestAsHex(str);
        }
    }

    /**
     * SHA-224値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toSHA224Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        if (upperCase) {
            return SHA_224_HASH.digestAsHex(StringUtil.getBytesCharset(str, charset)).toUpperCase();
        } else {
            return SHA_224_HASH.digestAsHex(StringUtil.getBytesCharset(str, charset));
        }
    }

    /**
     * SHA-256値の取得
     *
     * @param binary 対象バイト
     * @param upperCase
     * @return ハッシュ値
     */
    public static String toSHA256Sum(byte[] binary, boolean upperCase) {
        if (upperCase) {
            return DigestUtils.sha256Hex(binary).toUpperCase();
        } else {
            return DigestUtils.sha256Hex(binary);
        }
    }

    /**
     * SHA-256値の取得
     *
     * @param str 対象文字列
     * @param upperCase
     * @return ハッシュ値
     */
    public static String toSHA256Sum(String str, boolean upperCase) {
        if (upperCase) {
            return DigestUtils.sha256Hex(str).toUpperCase();
        } else {
            return DigestUtils.sha256Hex(str);
        }
    }

    /**
     * SHA-256値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toSHA256Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        if (upperCase) {
            return DigestUtils.sha256Hex(StringUtil.getBytesCharset(str, charset)).toUpperCase();
        } else {
            return DigestUtils.sha256Hex(StringUtil.getBytesCharset(str, charset));
        }
    }

    /**
     * SHA-384値の取得
     *
     * @param binary 対象バイト
     * @param upperCase
     * @return ハッシュ値
     */
    public static String toSHA384Sum(byte[] binary, boolean upperCase) {
        if (upperCase) {
            return DigestUtils.sha384Hex(binary).toUpperCase();
        } else {
            return DigestUtils.sha384Hex(binary);
        }
    }

    /**
     * SHA-384値の取得
     *
     * @param str 対象文字列
     * @param upperCase
     * @return ハッシュ値
     */
    public static String toSHA384Sum(String str, boolean upperCase) {
        if (upperCase) {
            return DigestUtils.sha384Hex(str).toUpperCase();
        } else {
            return DigestUtils.sha384Hex(str);
        }
    }

    /**
     * SHA-384値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toSHA384Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        if (upperCase) {
            return DigestUtils.sha384Hex(StringUtil.getBytesCharset(str, charset)).toUpperCase();
        } else {
            return DigestUtils.sha384Hex(StringUtil.getBytesCharset(str, charset));
        }
    }

    /**
     * SHA-512値の取得
     *
     * @param binary 対象バイト
     * @param upperCase
     * @return ハッシュ値
     */
    public static String toSHA512Sum(byte[] binary, boolean upperCase) {
        if (upperCase) {
            return DigestUtils.sha512Hex(binary).toUpperCase();
        } else {
            return DigestUtils.sha512Hex(binary);
        }
    }

    /**
     * SHA-512値の取得
     *
     * @param str 対象文字列
     * @param upperCase
     * @return ハッシュ値
     */
    public static String toSHA512Sum(String str, boolean upperCase) {
        if (upperCase) {
            return DigestUtils.sha512Hex(str).toUpperCase();
        } else {
            return DigestUtils.sha512Hex(str);
        }
    }

    /**
     * SHA-512値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toSHA512Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        if (upperCase) {
            return DigestUtils.sha512Hex(StringUtil.getBytesCharset(str, charset)).toUpperCase();
        } else {
            return DigestUtils.sha512Hex(StringUtil.getBytesCharset(str, charset));
        }
    }

    private final static DigestUtils SHA_512_224_HASH = new DigestUtils(MessageDigestAlgorithms.SHA_512_224);

    /**
     * SHA-512/224値の取得
     *
     * @param binary 対象バイト
     * @param upperCase
     * @return ハッシュ値
     */
    public static String toSHA512_224Sum(byte[] binary, boolean upperCase) {
        if (upperCase) {
            return SHA_512_224_HASH.digestAsHex(binary).toUpperCase();
        } else {
            return SHA_512_224_HASH.digestAsHex(binary);
        }
    }

    /**
     * SHA-512/224値の取得
     *
     * @param str 対象文字列
     * @param upperCase
     * @return ハッシュ値
     */
    public static String toSHA512_224Sum(String str, boolean upperCase) {
        if (upperCase) {
            return SHA_512_224_HASH.digestAsHex(str).toUpperCase();
        } else {
            return SHA_512_224_HASH.digestAsHex(str);
        }
    }

    /**
     * SHA-512/224値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toSHA512_224Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        if (upperCase) {
            return SHA_512_224_HASH.digestAsHex(StringUtil.getBytesCharset(str, charset)).toUpperCase();
        } else {
            return SHA_512_224_HASH.digestAsHex(StringUtil.getBytesCharset(str, charset));
        }
    }

    private final static DigestUtils SHA_512_256_HASH = new DigestUtils(MessageDigestAlgorithms.SHA_512_256);

    /**
     * SHA-512/256値の取得
     *
     * @param binary 対象バイト
     * @param upperCase
     * @return ハッシュ値
     */
    public static String toSHA512_256Sum(byte[] binary, boolean upperCase) {
        if (upperCase) {
            return SHA_512_256_HASH.digestAsHex(binary).toUpperCase();
        } else {
            return SHA_512_256_HASH.digestAsHex(binary);
        }
    }

    /**
     * SHA-512/256値の取得
     *
     * @param str 対象文字列
     * @param upperCase
     * @return ハッシュ値
     */
    public static String toSHA512_256Sum(String str, boolean upperCase) {
        if (upperCase) {
            return SHA_512_256_HASH.digestAsHex(str).toUpperCase();
        } else {
            return SHA_512_256_HASH.digestAsHex(str);
        }
    }

    /**
     * SHA-512/256値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toSHA512_256Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        if (upperCase) {
            return SHA_512_256_HASH.digestAsHex(StringUtil.getBytesCharset(str, charset)).toUpperCase();
        } else {
            return SHA_512_256_HASH.digestAsHex(StringUtil.getBytesCharset(str, charset));
        }
    }

    private final static DigestUtils SHA3_224_HASH = new DigestUtils(MessageDigestAlgorithms.SHA3_224);

    /**
     * SHA3-224値の取得
     *
     * @param binary 対象バイト
     * @param upperCase
     * @return ハッシュ値
     */
    public static String toSHA3_224Sum(byte[] binary, boolean upperCase) {
        if (upperCase) {
            return SHA3_224_HASH.digestAsHex(binary).toUpperCase();
        } else {
            return SHA3_224_HASH.digestAsHex(binary);
        }
    }

    /**
     * SHA3-224値の取得
     *
     * @param str 対象文字列
     * @param upperCase
     * @return ハッシュ値
     */
    public static String toSHA3_224um(String str, boolean upperCase) {
        if (upperCase) {
            return SHA3_224_HASH.digestAsHex(str).toUpperCase();
        } else {
            return SHA3_224_HASH.digestAsHex(str);
        }
    }

    /**
     * SHA3-224値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toSHA3_224Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        if (upperCase) {
            return SHA3_224_HASH.digestAsHex(StringUtil.getBytesCharset(str, charset)).toUpperCase();
        } else {
            return SHA3_224_HASH.digestAsHex(StringUtil.getBytesCharset(str, charset));
        }
    }

    private final static DigestUtils SHA3_256_HASH = new DigestUtils(MessageDigestAlgorithms.SHA3_256);

    /**
     * SHA3-256値の取得
     *
     * @param binary 対象バイト
     * @param upperCase
     * @return ハッシュ値
     */
    public static String toSHA3_256Sum(byte[] binary, boolean upperCase) {
        if (upperCase) {
            return SHA3_256_HASH.digestAsHex(binary).toUpperCase();
        } else {
            return SHA3_256_HASH.digestAsHex(binary);
        }
    }

    /**
     * SHA3-256値の取得
     *
     * @param str 対象文字列
     * @param upperCase
     * @return ハッシュ値
     */
    public static String toSHA3_256um(String str, boolean upperCase) {
        if (upperCase) {
            return SHA3_256_HASH.digestAsHex(str).toUpperCase();
        } else {
            return SHA3_256_HASH.digestAsHex(str);
        }
    }

    /**
     * SHA3-256値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toSHA3_256Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        if (upperCase) {
            return SHA3_256_HASH.digestAsHex(StringUtil.getBytesCharset(str, charset)).toUpperCase();
        } else {
            return SHA3_256_HASH.digestAsHex(StringUtil.getBytesCharset(str, charset));
        }
    }

    private final static DigestUtils SHA3_512_HASH = new DigestUtils(MessageDigestAlgorithms.SHA3_512);

    /**
     * SHA3-256値の取得
     *
     * @param binary 対象バイト
     * @param upperCase
     * @return ハッシュ値
     */
    public static String toSHA3_512um(byte[] binary, boolean upperCase) {
        if (upperCase) {
            return SHA3_512_HASH.digestAsHex(binary).toUpperCase();
        } else {
            return SHA3_512_HASH.digestAsHex(binary);
        }
    }

    /**
     * SHA3-512値の取得
     *
     * @param str 対象文字列
     * @param upperCase
     * @return ハッシュ値
     */
    public static String toSHA3_512um(String str, boolean upperCase) {
        if (upperCase) {
            return SHA3_512_HASH.digestAsHex(str).toUpperCase();
        } else {
            return SHA3_512_HASH.digestAsHex(str);
        }
    }

    /**
     * SHA3-512値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toSHA3_512Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        if (upperCase) {
            return SHA3_512_HASH.digestAsHex(StringUtil.getBytesCharset(str, charset)).toUpperCase();
        } else {
            return SHA3_512_HASH.digestAsHex(StringUtil.getBytesCharset(str, charset));
        }
    }

    private final static DigestUtils SHA3_384_HASH = new DigestUtils(MessageDigestAlgorithms.SHA3_384);

    /**
     * SHA3-384値の取得
     *
     * @param binary 対象バイト
     * @param upperCase
     * @return ハッシュ値
     */
    public static String toSHA3_384um(byte[] binary, boolean upperCase) {
        if (upperCase) {
            return SHA3_384_HASH.digestAsHex(binary).toUpperCase();
        } else {
            return SHA3_384_HASH.digestAsHex(binary);
        }
    }

    /**
     * SHA3-384値の取得
     *
     * @param str 対象文字列
     * @param upperCase
     * @return ハッシュ値
     */
    public static String toSHA3_384um(String str, boolean upperCase) {
        if (upperCase) {
            return SHA3_384_HASH.digestAsHex(str).toUpperCase();
        } else {
            return SHA3_384_HASH.digestAsHex(str);
        }
    }

    /**
     * SHA3-384値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toSHA3_384Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        if (upperCase) {
            return SHA3_384_HASH.digestAsHex(StringUtil.getBytesCharset(str, charset)).toUpperCase();
        } else {
            return SHA3_384_HASH.digestAsHex(StringUtil.getBytesCharset(str, charset));
        }
    }

    /**
     * MurmurHash値の取得
     *
     * @param binary 対象バイト
     * @return ハッシュ値
     */
    public static int toMurmurHash2_32(byte[] binary) {
        return MurmurHash2.hash32(binary, binary.length);
    }

    /**
     * MurmurHash値の取得
     *
     * @param str 対象文字列
     * @return ハッシュ値
     */
    public static int toMurmurHash2_32(String str) {
        return MurmurHash2.hash32(str);
    }

    /**
     * MurmurHash値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static int toMurmurHash2_32(String str, String charset)
            throws UnsupportedEncodingException {
        byte[] body = StringUtil.getBytesCharset(str, charset);
        return MurmurHash2.hash32(body, body.length);
    }

    /**
     * MurmurHash値の取得
     *
     * @param binary 対象バイト
     * @return ハッシュ値
     */
    public static long toMurmurHash2_64(byte[] binary) {
        return MurmurHash2.hash64(binary, binary.length);
    }

    /**
     * MurmurHash値の取得
     *
     * @param str 対象文字列
     * @return ハッシュ値
     */
    public static long toMurmurHash2_64(String str) {
        return MurmurHash2.hash64(str);
    }

    /**
     * MurmurHash値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static long toMurmurHash2_64(String str, String charset)
            throws UnsupportedEncodingException {
        byte[] binary = StringUtil.getBytesCharset(str, charset);
        return MurmurHash2.hash64(binary, binary.length);
    }

    public static long toEpochSecond(BigDecimal excel_serial) {
        // Unixtime = (Excelserial - 25569) * (60 * 60 * 24) - (60 * 60 * 0)
        final TimeZone tz = TimeZone.getDefault();
        final long tz_offset = tz.getRawOffset() / 1000L;
        excel_serial = excel_serial.subtract(BigDecimal.valueOf(25569L)).multiply(BigDecimal.valueOf(60 * 60 * 24)).subtract(BigDecimal.valueOf(tz_offset));
        return excel_serial.longValue();
    }

    public static long toEpochMilli(BigDecimal excel_serial) {
        return toEpochSecond(excel_serial) * 1000L;
    }

    public static BigDecimal toExcelSerial(long epoch_milli) {
        // Excel Serial = 25569 + ((Unixtime + (60 * 60 * 0)) / (60 * 60 * 24))
        final TimeZone tz = TimeZone.getDefault();
        final long tz_offset = tz.getRawOffset() / 1000L;
        BigDecimal excel_serial = new BigDecimal(epoch_milli);
        return excel_serial.add(BigDecimal.valueOf(tz_offset)).divide(BigDecimal.valueOf(60 * 60 * 24), 6, RoundingMode.HALF_EVEN).add(BigDecimal.valueOf(25569L));
    }

    private final static String ORDERD_CHAR = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    public static char getOrderdChar(int ord) {
        return ORDERD_CHAR.charAt(ord % ORDERD_CHAR.length());
    }

    /*
     * DateへはZoneがデフォルトのZoneになるため強制的に変更
     */
    public static Date toZoneWithDate(LocalDateTime ldtm, ZoneId zoneId) {
        GregorianCalendar cal = new GregorianCalendar(ldtm.getYear(), ldtm.getMonthValue() - 1, ldtm.getDayOfMonth(), ldtm.getHour(), ldtm.getMinute(), ldtm.getSecond());
        cal.setTimeZone(TimeZone.getTimeZone(zoneId));
        return cal.getTime();
    }

    /*
     * DateへはZoneがデフォルトのZoneになるため強制的に変更
     */
    public static ZonedDateTime toZoneWithZoneDate(Date date, ZoneId zoneId) {
        Calendar cal = GregorianCalendar.getInstance();
        //cal.setTimeZone(TimeZone.getTimeZone(zoneId));
        cal.setTime(date);
        ZonedDateTime zdtm = ZonedDateTime.of(cal.get(Calendar.YEAR), cal.get(Calendar.MONTH) + 1, cal.get(Calendar.DAY_OF_MONTH), cal.get(Calendar.HOUR_OF_DAY), cal.get(Calendar.MINUTE), cal.get(Calendar.SECOND), 0, zoneId);
        return zdtm;
    }

    private final static CharSequence[] HALF_WIDTH_STR = {
        " ", "!", "\"", "#", "$", "%", "&", "'", "(", ")", "*", "+", ",", "-", ".", "/", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", ":", ";", "<", "=", ">", "?", "@", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "[", "\\", "]", "^", "_", "`",
        "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "{", "|", "}", "~",
        "ｳﾞ", "ｶﾞ", "ｷﾞ", "ｸﾞ", "ｹﾞ", "ｺﾞ", "ｻﾞ", "ｼﾞ", "ｽﾞ", "ｾﾞ", "ｿﾞ", "ﾀﾞ", "ﾁﾞ", "ﾂﾞ", "ﾃﾞ", "ﾄﾞ", "ﾊﾞ", "ﾋﾞ", "ﾌﾞ", "ﾍﾞ", "ﾎﾞ", "ﾊﾟ", "ﾋﾟ", "ﾌﾟ", "ﾍﾟ", "ﾎﾟ",
        "ｦ", "ｧ", "ｨ", "ｩ", "ｪ", "ｫ", "ｬ", "ｭ", "ｮ", "ｯ", "ｰ", "ｱ", "ｲ", "ｳ", "ｴ", "ｵ", "ｶ", "ｷ", "ｸ", "ｹ", "ｺ", "ｻ", "ｼ", "ｽ", "ｾ", "ｿ", "ﾀ", "ﾁ", "ﾂ", "ﾃ", "ﾄ", "ﾅ", "ﾆ", "ﾇ", "ﾈ", "ﾉ", "ﾊ", "ﾋ", "ﾌ", "ﾍ", "ﾎ", "ﾏ", "ﾐ", "ﾑ", "ﾒ", "ﾓ", "ﾔ", "ﾕ", "ﾖ", "ﾗ", "ﾘ", "ﾙ", "ﾚ", "ﾛ", "ﾜ", "ﾝ", "ﾞ", "ﾟ",
        "｡", "｢", "｣", "､", "･",};

    private final static CharSequence[] FULL_WIDTH_STR = {
        "　", "！", "”", "＃", "＄", "％", "＆", "’", "（", "）", "＊", "＋", "，", "－", "．", "／", "０", "１", "２", "３", "４", "５", "６", "７", "８", "９", "：", "；", "＜", "＝", "＞", "？", "＠", "Ａ", "Ｂ", "Ｃ", "Ｄ", "Ｅ", "Ｆ", "Ｇ", "Ｈ", "Ｉ", "Ｊ", "Ｋ", "Ｌ", "Ｍ", "Ｎ", "Ｏ", "Ｐ", "Ｑ", "Ｒ", "Ｓ", "Ｔ", "Ｕ", "Ｖ", "Ｗ", "Ｘ", "Ｙ", "Ｚ", "［", "￥", "］", "＾", "＿", "‘", "ａ", "ｂ", "ｃ", "ｄ", "ｅ", "ｆ", "ｇ", "ｈ", "ｉ", "ｊ", "ｋ", "ｌ", "ｍ", "ｎ", "ｏ", "ｐ", "ｑ", "ｒ", "ｓ", "ｔ", "ｕ", "ｖ", "ｗ", "ｘ", "ｙ", "ｚ", "｛", "｜", "｝", "￣",
        "ヴ", "ガ", "ギ", "グ", "ゲ", "ゴ", "ザ", "ジ", "ズ", "ゼ", "ゾ", "ダ", "ヂ", "ヅ", "デ", "ド", "バ", "ビ", "ブ", "ベ", "ボ", "パ", "ピ", "プ", "ペ", "ポ",
        "ヲ", "ァ", "ィ", "ゥ", "ェ", "ォ", "ャ", "ュ", "ョ", "ッ", "ー", "ア", "イ", "ウ", "エ", "オ", "カ", "キ", "ク", "ケ", "コ", "サ", "シ", "ス", "セ", "ソ", "タ", "チ", "ツ", "テ", "ト", "ナ", "ニ", "ヌ", "ネ", "ノ", "ハ", "ヒ", "フ", "ヘ", "ホ", "マ", "ミ", "ム", "メ", "モ", "ヤ", "ユ", "ヨ", "ラ", "リ", "ル", "レ", "ロ", "ワ", "ン", "゛", "゜",
        "。", "「", "」", "、", "・",};

    private static String translate(String target, CharSequence[] search, CharSequence[] translate) {
        String result = target;
        int len = Math.min(search.length, translate.length);
        for (int i = 0; i < len; i++) {
            result = result.replace(search[i], translate[i]);
        }
        return result;
    }

    public static String translateFullWidth2HalfWidth(String target) {
        return translate(target, FULL_WIDTH_STR, HALF_WIDTH_STR);
    }

    public static String translateHalfWidth2FullWidth(String target) {
        return translate(target, HALF_WIDTH_STR, FULL_WIDTH_STR);
    }

}
