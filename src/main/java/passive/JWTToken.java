package passive;

import extension.helpers.MatchUtil;
import extension.helpers.json.JsonUtil;
import extension.helpers.StringUtil;
import extension.view.base.CaptureItem;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
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
public class JWTToken implements JsonToken {

    private final static Logger logger = Logger.getLogger(JWTToken.class.getName());

    private final static JWTToken jwtInstance = new JWTToken();

    public JWTToken getInstance() {
        return jwtInstance;
    }

    public JWTToken() {
    }

    public JWTToken(JWTToken token) {
        this.algorithm = token.algorithm;
        this.header = token.header;
        this.payload = token.payload;
        this.signature = token.signature;
        this.signatureByte = JsonToken.decodeBase64UrlSafeByte(token.signature);
    }

    public enum Algorithm {
        NONE(""),
        // JWT
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

        private final String signAlgorithm;

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
        String decodeHeader = JsonToken.decodeBase64UrlSafe(header);
        Matcher m = PTN_JWT_HEADER_ALGORITHM.matcher(decodeHeader);
        try {
            if (m.find()) {
                return Algorithm.parseValue(m.group(1));
            }
        } catch (java.lang.IllegalArgumentException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

//    private final static Pattern PTN_JWT = Pattern.compile("(ey(?:[0-9a-zA-Z_-]){10,})(?:\\.)(ey(?:[0-9a-zA-Z_-]){2,})(?:\\.)((?:[0-9a-zA-Z_-]){30,})?");
//    private final static Pattern PTN_JWT = Pattern.compile("(ey(?:[0-9a-zA-Z_-]|%2[dD]|%5[fF]){10,})(?:\\.|%2[eE])(ey(?:[0-9a-zA-Z_-]|%2[dD]|%5[fF]){2,})(?:\\.|%2[eE])((?:[0-9a-zA-Z_-]|%2[dD]|%5[fF]){30,})?");
    private final static Pattern PTN_JWT = Pattern.compile("(ey(?:[0-9a-zA-Z_-]|%2[dD]|%5[fF]){10,}?)(?:\\.|%2[eE])(ey(?:[0-9a-zA-Z_-]|%2[dD]|%5[fF]){2,}?)(?:\\.|%2[eE])((?:[0-9a-zA-Z_-]|%2[dD]|%5[fF]){30,}?)?");

    protected static boolean isTokenFormat(String value) {
        Matcher m = PTN_JWT.matcher(value);
        if (m.matches()) {
            if (jwtInstance.parseToken(value, true) != null) {
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean isSignFormat() {
        switch (this.algorithm) {
            case HS256:
            case HS384:
            case HS512:
                return true;
            default:
                return false;
        }
    }

    public static boolean containsTokenFormat(String value) {
        if (MatchUtil.isUrlencoded(value)) {
            value = JsonToken.decodeUrl(value);
        }
        Matcher m = PTN_JWT.matcher(value);
        if (m.find()) {
            return isTokenFormat(m.group(0));
        }
        return false;
    }

    public static CaptureItem[] findToken(String value) {
        List<CaptureItem> tokens = new ArrayList<>();
        Matcher m = PTN_JWT.matcher(value);
        while (m.find()) {
            String capture = m.group(0);
            if (isTokenFormat(capture)) {
                CaptureItem item = new CaptureItem();
                item.setCaptureValue(capture);
                item.setStart(m.start());
                item.setEnd(m.end());
                tokens.add(item);
            }
        }
        return tokens.toArray(CaptureItem[]::new);
    }

    @Override
    public boolean isValidFormat(String value) {
        return isTokenFormat(value);
    }

    private Algorithm algorithm;
    private String header;
    private String payload;
    private String signature;
    private byte[] signatureByte;

    @Override
    public JWTToken parseToken(String value, boolean matches) {
        JWTToken token = null;
        if (MatchUtil.isUrlencoded(value)) {
            value = JsonToken.decodeUrl(value);
        }
        Matcher m = PTN_JWT.matcher(value);
        boolean find = false;
        if (matches) {
            find = m.matches();
        } else {
            find = m.find();
        }

        if (find) {
            token = new JWTToken();
            String header = m.group(1);
            String payload = m.group(2);
            String signature = (m.group(3) != null) ? m.group(3) : "";
            token.algorithm = findAlgorithm(header);
            token.header = header;
            token.payload = payload;
            token.signature = signature;
            token.signatureByte = JsonToken.decodeBase64UrlSafeByte(signature);
        }
        return token;
    }

    /**
     * @return the token
     */
    @Override
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
    @Override
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
    @Override
    public String getPayload() {
        return payload;
    }

    /**
     * @return the signature
     */
    @Override
    public String getSignature() {
        return signature;
    }

    /**
     * @return the signature
     */
    public byte[] getSignatureByte() {
        return this.signatureByte;
    }

    /**
     * @param pretty
     * @return the header
     */
    public String getHeaderJSON(boolean pretty) {
        return JsonUtil.prettyJson(JsonToken.decodeBase64UrlSafe(this.getHeader()), pretty);
    }

    /**
     * @param pretty
     * @return the payload
     */
    public String getPayloadJSON(boolean pretty) {
        return JsonUtil.prettyJson(JsonToken.decodeBase64UrlSafe(this.getPayload()), pretty);
    }

    @Override
    public boolean signatureEqual(final String secret) {
        return signatureEqual(this.algorithm, StringUtil.getBytesRaw(this.getData()), this.signatureByte, StringUtil.getBytesRaw(secret));
    }

    public static boolean signatureEqual(Algorithm algo, String encrypt, final byte[] signature, String secret) {
        return signatureEqual(algo, StringUtil.getBytesRaw(encrypt), signature, StringUtil.getBytesRaw(secret));
    }

    protected static boolean signatureEqual(Algorithm algo, byte[] encrypt, final byte[] signature, final byte[] secret) {
        try {
            switch (algo) {
                case HS256:
                case HS384:
                case HS512:
                    Mac mac = Mac.getInstance(algo.getSignAlgorithm());
                    final SecretKeySpec sk = new SecretKeySpec(secret, algo.getSignAlgorithm());
                    mac.init(sk);
                    mac.reset();
                    final byte[] mac_bytes = mac.doFinal(encrypt);
                    return Arrays.equals(mac_bytes, signature);
                default:
                    break;
            }
        } catch (InvalidKeyException | NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return false;
    }

    public static String jwtHeader(Algorithm algo) {
        return String.format("{\"alg\":\"%s\",\"typ\":\"JWT\"}", algo.toString());
    }

    public static byte[] sign(Algorithm algo, String payload, String secret) throws NoSuchAlgorithmException {
        return sign(algo, payload, StringUtil.getBytesRaw(secret));
    }

    public static byte[] sign(Algorithm algo, final String payload, final byte[] secret) throws NoSuchAlgorithmException {
        try {
            switch (algo) {
                case NONE:
                    return new byte[]{};
                case HS256:
                case HS384:
                case HS512: {
                    Mac mac = Mac.getInstance(algo.getSignAlgorithm());
                    final SecretKeySpec sk = new SecretKeySpec(secret, algo.getSignAlgorithm());
                    mac.init(sk);
                    mac.reset();
                    String data = JsonToken.encodeBase64UrlSafe(jwtHeader(algo)) + "." + payload;
                    final byte[] mac_bytes = mac.doFinal(StringUtil.getBytesRaw(data));
                    return mac_bytes;
                }
//                case RS256:
//                case RS384:
//                case RS512: {
//                    Signature rsaSignature = Signature.getInstance(algo.getSignAlgorithm());
//                    PrivateKey privateKey = CertUtil.loadPrivateKey(Util.getRawStr(secret));
//                    rsaSignature.initSign(privateKey);
//                    String data = encodeBase64UrlSafe(jwtHeader(algo)) + "." + payload;
//                    rsaSignature.update(StringUtil.getBytesRaw(data));
//                    byte[] mac_bytes = rsaSignature.sign();
//                    return mac_bytes;
//                }
//                case ES256:
//                case ES384:
//                case ES512: {
//                    Signature rsaSignature = Signature.getInstance(algo.getSignAlgorithm());
//                    PrivateKey privateKey = CertUtil.loadPrivateKey(Util.getRawStr(secret));
//                    String data = encodeBase64UrlSafe(jwtHeader(algo)) + "." + payload;
//                    rsaSignature.update(StringUtil.getBytesRaw(data));
//                    byte[] mac_bytes = rsaSignature.sign();
//                    return mac_bytes;
//                }
                default:
                    throw new NoSuchAlgorithmException(algo.name());
            }
        } catch (InvalidKeyException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        } catch (GeneralSecurityException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        throw new NoSuchAlgorithmException(algo.name());
    }

    private final static String[] algNone = {"none", "NONE", "None"};

    public static String[] generateNoneToken(String baseJWT) {
        final List<String> tokens = new ArrayList<>();
        JWTToken jwt = jwtInstance.parseToken(baseJWT, true);
        if (jwt != null) {
            for (String alg : algNone) {
                String decodeHeader = JsonToken.decodeBase64UrlSafe(jwt.getHeader());
                Matcher m = PTN_JWT_HEADER_ALGORITHM.matcher(decodeHeader);
                StringBuffer header = new StringBuffer();
                if (m.find()) {
                    m.appendReplacement(header, String.format("\"alg\":\"%s\"", alg));
                }
                m.appendTail(header);
                String token = JsonToken.encodeBase64UrlSafe(header.toString()) + "." + jwt.getPayload() + ".";
                tokens.add(token);
            }
        }
        return tokens.toArray(String[]::new);
    }

    private final static Algorithm[] algHS = {Algorithm.HS256, Algorithm.HS384, Algorithm.HS512};

    public static String[] generatePublicToHashToken(String baseToken, byte[] publicKey) {
        final List<String> tokens = new ArrayList<>();
        JWTToken jwt = jwtInstance.parseToken(baseToken, true);
        if (jwt != null) {
            for (Algorithm alg : algHS) {
                byte[] sign;
                try {
                    sign = JWTToken.sign(alg, jwt.getPayload(), publicKey);
                    String signature = JsonToken.encodeBase64UrlSafe(sign);
                    String result = JsonToken.encodeBase64UrlSafe(JWTToken.jwtHeader(alg)) + "." + jwt.getPayload() + "." + signature;
                    tokens.add(result);
                } catch (NoSuchAlgorithmException ex) {
                    logger.log(Level.SEVERE, ex.getMessage(), ex);
                }
            }
        }
        return tokens.toArray(String[]::new);
    }

}
