package passive;

import extend.util.ConvertUtil;
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

    public static String decompressZlibBase64(String content) {
        byte [] decode = decodeUrlSafeByte(content);
        return new String(ConvertUtil.decompressZlib(decode), StandardCharsets.UTF_8);
    }
    
    public static byte[] decodeUrlSafeByte(String value) {
        return Base64.getUrlDecoder().decode(value);
    }
    
    protected static String decodeUrlSafe(byte [] value) {
        return new String(Base64.getUrlDecoder().decode(value), StandardCharsets.UTF_8);
    }
    
    protected static String decodeUrlSafe(String value) {
        return new String(decodeUrlSafeByte(value), StandardCharsets.UTF_8);
    }

    public static byte[] encodeUrlSafeByte(byte [] value) {
        return Base64.getUrlEncoder().withoutPadding().encode(value);
    }
    
    public static byte[] encodeUrlSafeByte(String value) {
        return encodeUrlSafeByte(value.getBytes(StandardCharsets.UTF_8));
    }

    public static String encodeUrlSafe(byte [] value) {
        return new String(encodeUrlSafeByte(value), StandardCharsets.UTF_8);
    }

    protected static String encodeUrlSafe(String value) {
        return new String(encodeUrlSafeByte(value), StandardCharsets.UTF_8);
    }
    
}
