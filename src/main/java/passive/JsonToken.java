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
public interface JsonToken {

    public JsonToken parseToken(String value, boolean matches);

    public boolean isValidFormat(String value);

    public boolean isSignFormat();

    public String getToken();

    public String getData();

    public String getPayload();

    public String getSignature();

    public boolean signatureEqual(final String secret);

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

    static String decodeBase64UrlSafe(byte [] value) {
        return StringUtil.getStringUTF8(Base64.getUrlDecoder().decode(value));
    }

    static String decodeBase64UrlSafe(String value) {
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

    static String encodeBase64UrlSafe(String value) {
        return StringUtil.getStringUTF8(encodeBase64UrlSafeByte(value));
    }

}
