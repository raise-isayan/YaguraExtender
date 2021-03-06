package passive;

import extension.helpers.ConvertUtil;
import extension.helpers.StringUtil;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 *
 * @author isayan
 */
public abstract class JsonToken {

    public abstract JsonToken parseToken(String value, boolean matches);

    public abstract boolean isValidFormat(String value);

    public abstract boolean isSignFormat();

    public abstract String getToken();

    public abstract String getData();

    public abstract String getPayload();

    public abstract String getSignature();

    public abstract boolean signatureEqual(final String secret);

    public static long bytesToLong(final byte[] bytes) {
        long result = 0;
        for (int i = 0; i < bytes.length; i++) {
            result <<= Byte.SIZE;
            result |= (bytes[i] & 0xFF);
        }
        return result;
    }

    public static byte []longToBytes(final long value) {
        int mag = Long.SIZE - Long.numberOfLeadingZeros(value);
        int bsize = Math.max(((mag + (Byte.SIZE - 1)) / Byte.SIZE), 1);
        byte [] bytes = new byte [bsize];
        long val = value;
        for (int i = bytes.length - 1; i >= 0; i--) {
            bytes[i] = (byte)(val & 0xFF);
            val >>= Byte.SIZE;
        }
        return bytes;
    }

    public static String decodeUrl(String value) {
        return URLDecoder.decode(value, StandardCharsets.ISO_8859_1);
    }

    public static String encodeUrl(String value) {
        return URLEncoder.encode(value, StandardCharsets.ISO_8859_1);
    }

    public static String decompressZlibBase64(String content) {
        byte [] decode = decodeBase64UrlSafeByte(content);
        return StringUtil.getStringUTF8(ConvertUtil.decompressZlib(decode));
    }

    public static byte[] decodeBase64UrlSafeByte(String value) {
        return Base64.getUrlDecoder().decode(value);
    }

    protected static String decodeBase64UrlSafe(byte [] value) {
        return StringUtil.getStringUTF8(Base64.getUrlDecoder().decode(value));
    }

    protected static String decodeBase64UrlSafe(String value) {
        return StringUtil.getStringUTF8(decodeBase64UrlSafeByte(value));
    }

    public static byte[] encodeBase64UrlSafeByte(byte [] value) {
        return Base64.getUrlEncoder().withoutPadding().encode(value);
    }

    public static byte[] encodeBase64UrlSafeByte(String value) {
        return JsonToken.encodeBase64UrlSafeByte(StringUtil.getBytesUTF8(value));
    }

    public static String encodeBase64UrlSafe(byte [] value) {
        return StringUtil.getStringUTF8(JsonToken.encodeBase64UrlSafeByte(value));
    }

    protected static String encodeBase64UrlSafe(String value) {
        return StringUtil.getStringUTF8(encodeBase64UrlSafeByte(value));
    }

}
