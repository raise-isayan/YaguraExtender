package passive;

import extend.util.CertUtil;
import extend.util.Util;
import extend.view.base.CaptureItem;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
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
import java.security.Signature;
import java.security.SignatureException;

/**
 *
 * @author isayan
 */
public class JWTToken {
    private final static Logger logger = Logger.getLogger(JWTToken.class.getName());

    public JWTToken() {
    }

    public JWTToken(JWTToken token) {
        this.algorithm = token.algorithm;
        this.header = token.header;
        this.payload = token.payload;
        this.signature = token.signature;
        this.signatureByte = decodeUrlSafeByte(token.signature);
    }

    public enum Algorithm {
        NONE(""),
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

        public static Algorithm parseValue(String s) {
            return Algorithm.valueOf(s.toUpperCase());
        }

    };

    private final static Pattern PTN_JWT_HEADER_ALGORITHM = Pattern.compile("\"alg\"\\s*?:\\s*?\"(\\w+?)\"");

    private static Algorithm findAlgorithm(String header) {
        String decodeHeader = decodeUrlSafe(header);
        Matcher m = PTN_JWT_HEADER_ALGORITHM.matcher(decodeHeader);
        try {
            if (m.find()) {
//                return Enum.valueOf(Algorithm.class, m.group(1));
                return Algorithm.parseValue(m.group(1));
            }
        } catch (java.lang.IllegalArgumentException ex) {

        }
        return null;
    }

    private final static Pattern PTN_JWT = Pattern.compile("(e(?:[0-9a-zA-Z_-]){10,})\\.(e(?:[0-9a-zA-Z_-]){2,})\\.((?:[0-9a-zA-Z_-]){30,})?");

    public static boolean isJWTFormat(String value) {
        Matcher m = PTN_JWT.matcher(value);
        if (m.matches()) {
            return (JWTToken.parseJWTToken(value, true) != null);
        }
        return false;
    }

    public static boolean containsJWTFormat(String value) {
        Matcher m = PTN_JWT.matcher(value);
        if (m.find()) {
            return (JWTToken.parseJWTToken(m.group(0), true) != null);
        }
        return false;
    }

    public static CaptureItem[] findJWT(String value) {
        List<CaptureItem> tokens = new ArrayList<>();
        Matcher m = PTN_JWT.matcher(value);
        while (m.find()) {
            String capture = m.group(0);
            if (isJWTFormat(capture)) {
                CaptureItem item = new CaptureItem();
                item.setCaptureValue(capture);
                item.setStart(m.start());
                item.setEnd(m.end());
                tokens.add(item);
            }
        }
        return tokens.toArray(new CaptureItem[0]);
    }

    private Algorithm algorithm;
    private String header;
    private String payload;
    private String signature;
    private byte[] signatureByte;

    public static JWTToken parseJWTToken(String value, boolean matches) {
        JWTToken jwt = null;
        Matcher m = PTN_JWT.matcher(value);
        boolean find = false;
        if (matches) {
            find = m.matches();
        } else {
            find = m.find();
        }

        if (find) {
            jwt = new JWTToken();
            String header = m.group(1);
            String payload = m.group(2);
            String signature = (m.group(3) != null) ? m.group(3) : "";
            jwt.algorithm = findAlgorithm(header);
            jwt.header = header;
            jwt.payload = payload;
            jwt.signature = signature;
            jwt.signatureByte = decodeUrlSafeByte(signature);
        }
        return jwt;
    }

    public static byte[] decodeUrlSafeByte(String value) {
        return Base64.getUrlDecoder().decode(value);
    }

    protected static String decodeUrlSafe(byte[] value) {
        return new String(Base64.getUrlDecoder().decode(value), StandardCharsets.UTF_8);
    }

    protected static String decodeUrlSafe(String value) {
        return new String(decodeUrlSafeByte(value), StandardCharsets.UTF_8);
    }

    public static byte[] encodeUrlSafeByte(byte[] value) {
        return Base64.getUrlEncoder().withoutPadding().encode(value);
    }

    public static byte[] encodeUrlSafeByte(String value) {
        return encodeUrlSafeByte(value.getBytes(StandardCharsets.UTF_8));
    }

    public static String encodeUrlSafe(byte[] value) {
        return new String(encodeUrlSafeByte(value), StandardCharsets.UTF_8);
    }

    protected static String encodeUrlSafe(String value) {
        return new String(encodeUrlSafeByte(value), StandardCharsets.UTF_8);
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

    public static boolean signatureEqual(Algorithm algo, final String encrypt, final byte[] signature, final String secret) throws NoSuchAlgorithmException {
        try {
            switch (algo) {
                case HS256:
                case HS384:
                case HS512:
                    Mac mac = Mac.getInstance(algo.getSignAlgorithm());
                    final SecretKeySpec sk = new SecretKeySpec(Util.getRawByte(secret), algo.getSignAlgorithm());
                    mac.init(sk);
                    mac.reset();
                    final byte[] mac_bytes = mac.doFinal(Util.getRawByte(encrypt));
                    return Arrays.equals(mac_bytes, signature);
                default:
                    throw new NoSuchAlgorithmException(algo.name());
            }
        } catch (InvalidKeyException ex) {
            logger.log(Level.SEVERE, null, ex);
        }
        return false;
    }

    public static byte[] sign(Algorithm algo, final String encrypt, final String secret) throws NoSuchAlgorithmException {
        try {
            switch (algo) {
                case NONE:
                    return new byte[]{};
                case HS256:
                case HS384:
                case HS512: {
                    Mac mac = Mac.getInstance(algo.getSignAlgorithm());
                    final SecretKeySpec sk = new SecretKeySpec(Util.getRawByte(secret), algo.getSignAlgorithm());
                    mac.init(sk);
                    mac.reset();
                    final byte[] mac_bytes = mac.doFinal(Util.getRawByte(encrypt));
                    return mac_bytes;
                }
                case RS256:
                case RS384:
                case RS512: {
                    Signature rsaSignature = Signature.getInstance(algo.getSignAlgorithm());
                    PrivateKey privateKey = CertUtil.loadPrivateKey(secret);
                    rsaSignature.initSign(privateKey);
                    rsaSignature.update(Util.getRawByte(encrypt));
                    byte[] mac_bytes = rsaSignature.sign();
                    return mac_bytes;
                }
                case ES256:
                case ES384:
                case ES512: {
                    Signature rsaSignature = Signature.getInstance(algo.getSignAlgorithm());
                    PrivateKey privateKey = CertUtil.loadPrivateKey(secret);
                    rsaSignature.initSign(privateKey);
                    rsaSignature.update(Util.getRawByte(encrypt));
                    byte[] mac_bytes = rsaSignature.sign();
                    return mac_bytes;
                }
                default:
                    throw new NoSuchAlgorithmException(algo.name());
            }
        } catch (InvalidKeyException ex) {
            logger.log(Level.SEVERE, null, ex);
        } catch (SignatureException ex) {
            logger.log(Level.SEVERE, null, ex);
        } catch (GeneralSecurityException ex) {
            logger.log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            logger.log(Level.SEVERE, null, ex);
        }
        throw new NoSuchAlgorithmException(algo.name());
    }

}
