package yagura.model;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import yagura.external.JsonUtil;

/**
 *
 * @author isayan
 */
public class JWTObject {

private final static Pattern PTN_JWT = Pattern.compile("(e(?:[0-9a-zA-Z_-]){10,})\\.(e(?:[0-9a-zA-Z_-]){2,})\\.((?:[0-9a-zA-Z_-]){20,})");

public static boolean isJWTFormat(String value) {
    Matcher m = PTN_JWT.matcher(value);
    if (m.matches()) {
        return true;    
    }
    return false;
}

public static boolean containsJWTFormat(String value) {
    Matcher m = PTN_JWT.matcher(value);
    if (m.find()) {
        return true;    
    }
    return false;
}

public static JWTObject parseJWTObject(String value, boolean matches) {
    JWTObject jwt = new JWTObject();
    Matcher m = PTN_JWT.matcher(value);
    boolean find = false;
    if (matches)
        find = m.matches();
     else 
        find = m.find();
           
    if (find) {
        String header = m.group(1);
        String payload = m.group(2);
        String signature = m.group(3);    
        JsonUtil.parse(decodeB64(header));
        JsonUtil.parse(decodeB64(payload));
        decodeB64(signature);
        jwt.header = header;
        jwt.payload = payload;
        jwt.signature = signature;    
    }
    return jwt;
}

    private String header;
    private String payload;
    private String signature;

    private static byte [] decodeB64Byte(String value) {
      value = value.replace('-', '+');
      value = value.replace('_', '/');
      return Base64.getDecoder().decode(value);
    }
    
    private static String decodeB64(String value) {
      return new String(decodeB64Byte(value), StandardCharsets.UTF_8);
    }
       
    /**
     * @return the header
     */
    public String getHeader() {
        return header;
    }

    /**
     * @return the header
     */
    public String getHeaderJSON(boolean pretty) {
        try {
            return JsonUtil.prettyJSON(decodeB64(header), pretty);
        } catch (IOException ex) {
            return null;
        }
    }
    
    /**
     * @return the payload
     */
    public String getPayload() {
        return payload;
    }

    /**
     * @return the payload
     */
    public String getPayloadJSON(boolean pretty) {
        try {
            return JsonUtil.prettyJSON(decodeB64(payload), pretty);
        } catch (IOException ex) {
            return null;
        }
    }
    
    /**
     * @return the signature
     */
    public String getSignature() {
        return signature;
    }

    /**
     * @return the signature
     */
    public byte [] getSignatureByte() {
        return decodeB64Byte(signature);
    }
    
}
