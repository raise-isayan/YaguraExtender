package yagura.model;

import extend.util.Util;
import extend.view.base.CaptureItem;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author isayan
 */
public class JWTToken {

    public JWTToken() {
    }
    
    public JWTToken(JWTToken token) {
        this.algorithm = token.algorithm;
        this.header = token.header;
        this.payload = token.payload;
        this.signature = token.signature;
        this.signatureByte = decodeB64Byte(token.signature);
    }
    
    public enum Algorithm {
        HS256("HmacSHA256"),
        HS384("HmacSHA384"),
        HS512("HmacSHA512"),
        RS256("SHA256withRSA"),
        RS384("SHA384withRSA"),
        RS512("SHA512withRSA"),
        ES256("SHA256withECDSA"),
        ES384("SHA384withECDSA"),
        ES512("SHA512withECDSA"),
        PS256(""),
        PS384(""),
        PS512("");

        private String signAlgorithm;

        Algorithm(String signAlgorithm) {
            this.signAlgorithm = signAlgorithm;
        }

        public String getSignAlgorithm() {
            return signAlgorithm;
        }

    };

    private final static Pattern PTN_JWT_HEADER_ALGORITHM = Pattern.compile("\"alg\"\\s*?:\\s*?\"(\\w+?)\"");

    private static Algorithm findAlgorithm(String header) {
        String decodeHeader = decodeB64(header);
        Matcher m = PTN_JWT_HEADER_ALGORITHM.matcher(decodeHeader);
        try {
            if (m.find()) {
                return Enum.valueOf(Algorithm.class, m.group(1));
            }
        } catch (java.lang.IllegalArgumentException ex) {

        }
        return null;
    }

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

    public static CaptureItem[] findJWT(String value) {
        List<CaptureItem> tokens = new ArrayList<>();
        Matcher m = PTN_JWT.matcher(value);
        while (m.find()) {
            CaptureItem item = new CaptureItem();
            item.setCaptureValue(m.group(0));
            item.setStart(m.start());
            item.setEnd(m.end());
            tokens.add(item);
        }
        return tokens.toArray(new CaptureItem[0]);
    }

    private Algorithm algorithm;
    private String header;
    private String payload;
    private String signature;
    private byte[] signatureByte;

    public static JWTToken parseJWTToken(String value, boolean matches) {
        JWTToken jwt = new JWTToken();
        Matcher m = PTN_JWT.matcher(value);
        boolean find = false;
        if (matches) {
            find = m.matches();
        } else {
            find = m.find();
        }

        if (find) {
            String header = m.group(1);
            String payload = m.group(2);
            String signature = m.group(3);
            jwt.algorithm = findAlgorithm(header);
            jwt.header = header;
            jwt.payload = payload;
            jwt.signature = signature;
            jwt.signatureByte = decodeB64Byte(signature);
        }
        return jwt;
    }

    public static byte[] decodeB64Byte(String value) {
        value = value.replace('-', '+');
        value = value.replace('_', '/');
        return Base64.getDecoder().decode(value);
    }

    protected static String decodeB64(String value) {
        return new String(decodeB64Byte(value), StandardCharsets.UTF_8);
    }

    /**
     * @return the token
     */
    public String getToken() {
        StringBuilder buff = new StringBuilder();
        buff.append(header);
        buff.append(".");
        buff.append(payload);
        buff.append(".");
        buff.append(signature);
        return buff.toString();
    }

    /**
     * @return the data
     */
    public String getData() {
        StringBuilder buff = new StringBuilder();
        buff.append(header);
        buff.append(".");
        buff.append(payload);
        return buff.toString();
    }

    /**
     * @return the signAlgorithm
     */
    public Algorithm getAlgorithm() {
        return algorithm;
    }

    /**
     * @return the header
     */
    public String getHeader() {
        return header;
    }

    /**
     * @return the payload
     */
    public String getPayload() {
        return payload;
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
    public byte[] getSignatureByte() {
        return this.signatureByte;
    }

    public static boolean signatureEqual(final JWTToken token, final String secret) throws NoSuchAlgorithmException {
        return signatureEqual(token.getAlgorithm(), token.getData(), token.getSignatureByte(), secret);
    }

    public static Mac mac256 = null;
    public static Mac mac384 = null;
    public static Mac mac512 = null;

    static {
        try {
            mac256 = Mac.getInstance(Algorithm.HS256.getSignAlgorithm());
            mac384 = Mac.getInstance(Algorithm.HS384.getSignAlgorithm());
            mac512 = Mac.getInstance(Algorithm.HS512.getSignAlgorithm());
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(JWTToken.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public static boolean signatureEqual(Algorithm algo, final String encrypt, final byte[] signature, final String secret) throws NoSuchAlgorithmException {
        try {
            Mac mac = mac256;
            switch (algo) {
                case HS256:
                    mac = mac256;
                    break;
                case HS384:
                    mac = mac384;
                    break;
                case HS512:
                    mac = mac512;
                    break;
                default:
                    throw new NoSuchAlgorithmException(algo.name());
            }
            final SecretKeySpec sk = new SecretKeySpec(Util.getRawByte(secret), algo.getSignAlgorithm());
            mac.init(sk);
            mac.reset();
            final byte[] mac_bytes = mac.doFinal(Util.getRawByte(encrypt));
            return Arrays.equals(mac_bytes, signature);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(JWTToken.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;
    }

}
