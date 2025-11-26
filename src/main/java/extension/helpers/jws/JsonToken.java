package extension.helpers.jws;

import com.google.gson.JsonSyntaxException;
import extension.helpers.ConvertUtil;
import extension.helpers.StringUtil;
import extension.helpers.json.JsonUtil;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SignatureException;
import java.util.Base64;

/**
 *
 * @author isayan
 */
public interface JsonToken {

    public JsonToken parseToken(String value, boolean matches);

    public boolean isValid();

    public boolean isSignFormat();

    public String getToken();

    public String getData();

    public Payload getPayload();

    public Signature getSignature();

    public String getPayloadPart();

    public String getSignaturePart();

    public boolean signatureEqual(final String secret) throws SignatureException;

    public static class Payload implements JsonSegment {

        private String tokenPart;

        public Payload(String tokenPart) {
            this.tokenPart = tokenPart;
        }

        public boolean isValid() {
            try {
                toJSON(false);
                return true;
            } catch (JsonSyntaxException | IllegalArgumentException ex) {
                return false;
            }
        }

        @Override
        public String getPart() {
            return this.tokenPart;
        }

        public String toJSON(boolean pretty) {
            return JsonUtil.prettyJson(JsonToken.decodeBase64UrlSafe(this.tokenPart), pretty);
        }

        public String getsDecodeBase64Url() {
            return JsonToken.decodeBase64UrlSafe(this.tokenPart);
        }

        public void setEncodeBase64Url(String value) {
            this.tokenPart = JsonToken.encodeBase64UrlSafe(value);
        }

    }

    public static class Signature implements JsonSegment {

        private String tokenPart;

        public Signature(String tokenPart) {
            this.tokenPart = tokenPart;
        }

        public boolean isValid() {
            try {
                getsDecodeBase64Url();
                return true;
            } catch (IllegalArgumentException ex) {
                return false;
            }
        }

        @Override
        public String getPart() {
            return this.tokenPart;
        }

        public byte[] getsDecodeBase64Url() {
            return JsonToken.decodeBase64UrlSafeByte(this.tokenPart);
        }

        public void setEncodeBase64Url(byte[] value) {
            this.tokenPart = JsonToken.encodeBase64UrlSafe(value);
        }

        public boolean isEmpty() {
            return this.tokenPart.isEmpty();
        }

        public static Signature valueOf(byte[] tokenBytes) {
            return new Signature(JsonToken.encodeBase64UrlSafe(tokenBytes));
        }

    }

    public static String decodeUrl(String value) {
        return URLDecoder.decode(value, StandardCharsets.ISO_8859_1);
    }

    public static String encodeUrl(String value) {
        return URLEncoder.encode(value, StandardCharsets.ISO_8859_1);
    }

    public static String decompressZlibBase64(String content) {
        byte[] decode = decodeBase64UrlSafeByte(content);
        return StringUtil.getStringUTF8(ConvertUtil.decompressZlib(decode));
    }

    public static byte[] decodeBase64UrlSafeByte(String value) {
        return Base64.getUrlDecoder().decode(value);
    }

    static String decodeBase64UrlSafe(byte[] value) {
        return StringUtil.getStringUTF8(Base64.getUrlDecoder().decode(value));
    }

    static String decodeBase64UrlSafe(String value) {
        return StringUtil.getStringUTF8(decodeBase64UrlSafeByte(value));
    }

    public static byte[] encodeBase64UrlSafeByte(byte[] value) {
        return Base64.getUrlEncoder().withoutPadding().encode(value);
    }

    public static byte[] encodeBase64UrlSafeByte(String value) {
        return JsonToken.encodeBase64UrlSafeByte(StringUtil.getBytesUTF8(value));
    }

    public static String encodeBase64UrlSafe(byte[] value) {
        return StringUtil.getStringUTF8(JsonToken.encodeBase64UrlSafeByte(value));
    }

    static String encodeBase64UrlSafe(String value) {
        return StringUtil.getStringUTF8(encodeBase64UrlSafeByte(value));
    }

}
