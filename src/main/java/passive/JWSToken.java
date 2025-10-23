package passive;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.SignedJWT;
import extend.util.external.jws.JWSUtil;
import extend.util.external.jws.WeakMACProvider;
import extend.util.external.jws.WeakMACSigner;
import extend.util.external.jws.WeakMACVerifier;
import extension.helpers.MatchUtil;
import extension.helpers.StringUtil;
import extension.helpers.json.JsonUtil;
import extension.view.base.CaptureItem;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author isayan
 */
public class JWSToken implements JsonToken {

    private final static Logger logger = Logger.getLogger(JWSToken.class.getName());

    private final static JWSToken jwsInstance = new JWSToken();

    public JWSToken getInstance() {
        return jwsInstance;
    }

    public JWSToken() {
    }

    public JWSToken(JWSToken token) {
        this.algorithm = token.algorithm;
        this.header = token.header;
        this.payload = token.payload;
        this.signature = token.signature;
        this.signatureByte = JsonToken.decodeBase64UrlSafeByte(token.signature);
    }

    private JWSAlgorithm algorithm;
    private String header;
    private String payload;
    private String signature;
    private byte[] signatureByte;

    /**
     * @return the signAlgorithm
     */
    public JWSAlgorithm getAlgorithm() {
        return algorithm;
    }

    @Override
    public JWSToken parseToken(String value, boolean matches) {
        JWSToken token = null;
        if (MatchUtil.isUrlencoded(value)) {
            value = JsonToken.decodeUrl(value);
        }
        CaptureItem[] items = null;
        boolean find = false;
        if (matches) {
            find = JWSUtil.isValidJWT(value);
            if (find) {
                items = JWSUtil.findToken(value);
            }
        } else {
            items = JWSUtil.findToken(value);
            find = items.length > 0;
        }
        if (items != null) {
            for (int i = 0; i < items.length; i++) {
                try {
                    SignedJWT jwt = SignedJWT.parse(items[i].getCaptureValue());
                    token = new JWSToken();
                    String header = jwt.getHeader().toBase64URL().toString();
                    String payload = jwt.getPayload().toBase64URL().toString();
                    String signature = jwt.getSignature().toString();
                    token.algorithm = jwt.getHeader().getAlgorithm();
                    token.header = header;
                    token.payload = payload;
                    token.signature = signature;
                } catch (ParseException ex) {
                    //
                }
                break;
            }
        }
        return token;
    }

    public static boolean containsTokenFormat(String value) {
        if (MatchUtil.isUrlencoded(value)) {
            value = JsonToken.decodeUrl(value);
        }
        CaptureItem[] tokens = JWSUtil.findToken(value);
        for (CaptureItem token : tokens) {
            if (JWSUtil.isValidJWT(token.getCaptureValue())) {
                return true;
            }
        }
        return false;
    }

    public static CaptureItem[] findToken(String value) {
        return JWSUtil.findToken(value);
    }

    @Override
    public boolean isValidFormat(String value) {
        try {
            JWSObject.parse(value);
            return true;
        } catch (ParseException ex) {
            return false;
        }
    }

    @Override
    public boolean isSignFormat() {
        return (this.algorithm.equals(JWSAlgorithm.ES256)
                || this.algorithm.equals(JWSAlgorithm.HS384)
                || this.algorithm.equals(JWSAlgorithm.ES256));
    }

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

    @Override
    public String getData() {
        StringBuilder buff = new StringBuilder();
        buff.append(header);
        buff.append(".");
        buff.append(payload);
        return buff.toString();
    }

    /**
     * @return the header
     */
    public String getHeader() {
        return header;
    }

    @Override
    public String getPayload() {
        return payload;
    }

    @Override
    public String getSignature() {
        return signature;
    }

    @Override
    public boolean signatureEqual(final String secret) {
        return signatureEqual(this.algorithm, this.header, this.payload, this.signature, secret);
    }

    public static boolean signatureEqual(JWSAlgorithm algo, String header, String payload, String signature, String secret) {
        return signatureEqual(algo, Base64URL.from(header), Base64URL.from(payload), Base64URL.from(signature), toSecretKey(secret));
    }

    protected static boolean signatureEqual(JWSAlgorithm algo, Base64URL header, Base64URL payload, final Base64URL signature, final byte[] secret) {
        return signatureEqual(algo, header, payload, signature, toSecretKey(secret));
    }

    protected static boolean signatureEqual(JWSAlgorithm algo, Base64URL header, Base64URL payload, final Base64URL signature, final SecretKey secretKey) {
        if (algo.equals(JWSAlgorithm.HS256)
                || algo.equals(JWSAlgorithm.HS384)
                || algo.equals(JWSAlgorithm.HS512)) {
            try {
                JWSObject token = new JWSObject(header, payload, signature);
                JWSVerifier verifier = new WeakMACVerifier(secretKey);
                return token.verify(verifier);
            } catch (ParseException | JOSEException ex) {
                return false;
            }
        }
        return false;
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

    public static SecretKey toSecretKey(String secret) {
        return new SecretKeySpec(StringUtil.getBytesRaw(secret), "MAC");
    }

    public static SecretKey toSecretKey(byte[] secret) {
        return new SecretKeySpec(secret, "MAC");
    }

    public static Base64URL sign(JWSAlgorithm algo, String header, String payload, SecretKey secretKey) throws ParseException, JOSEException {
        return sign(algo, Base64URL.from(header), Base64URL.from(payload), secretKey);
    }

    public static Base64URL sign(JWSAlgorithm algo, Base64URL header, Base64URL payload, SecretKey secretKey) throws ParseException, JOSEException {
        if (algo.equals(JWSAlgorithm.HS256)
                || algo.equals(JWSAlgorithm.HS384)
                || algo.equals(JWSAlgorithm.HS512)) {
            WeakMACSigner signer = new WeakMACSigner(secretKey);
            JWSObject token = new JWSObject(JWSHeader.parse(header), new Payload(payload));
            token.sign(signer);
            return token.getSignature();
        }
        throw new IllegalArgumentException("Not support:" + algo.getName());
    }

    private final static JWSAlgorithm[] algHS = {JWSAlgorithm.HS256, JWSAlgorithm.HS384, JWSAlgorithm.HS512};

    public static Base64URL forceSign(JWSAlgorithm algo, String header, final String payload, SecretKey secretKey) throws NoSuchAlgorithmException {
        try {
            if (algo.equals(JWSAlgorithm.HS256)
                    || algo.equals(JWSAlgorithm.HS384)
                    || algo.equals(JWSAlgorithm.HS512)) {
                Mac mac = Mac.getInstance(WeakMACProvider.getJCAAlgorithmName(algo));
                mac.init(secretKey);
                mac.reset();
                String data = JsonToken.encodeBase64UrlSafe(JWSUtil.toHeaderJSON(algo)) + "." + payload;
                final byte[] mac_bytes = mac.doFinal(StringUtil.getBytesRaw(data));
                return Base64URL.encode(mac_bytes);
            }
        } catch (JOSEException | InvalidKeyException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        throw new NoSuchAlgorithmException(algo.getName());
    }

    public static String[] generatePublicToHashToken(String baseToken, byte[] publicKey) {
        final List<String> tokens = new ArrayList<>();
        JWSToken jws = jwsInstance.parseToken(baseToken, true);
        if (jws != null) {
            for (JWSAlgorithm alg : algHS) {
                try {
                    Base64URL signURL = JWSToken.forceSign(alg, jws.header, jws.payload, JWSToken.toSecretKey(publicKey));
                    String result = JsonToken.encodeBase64UrlSafe(JWSUtil.toHeaderJSON(alg)) + "." + jws.getPayload() + "." + signURL.toString();
                    tokens.add(result);
                } catch (NoSuchAlgorithmException ex) {
                    logger.log(Level.SEVERE, ex.getMessage(), ex);
                }
            }
        }
        return tokens.toArray(String[]::new);
    }

    private final static Pattern PTN_JWT_HEADER_ALGORITHM = Pattern.compile("\"alg\"\\s*?:\\s*?\"(\\w+?)\"");

    private final static String[] algNone = {"none", "NONE", "None"};

    public static String[] generateNoneToken(String baseJWT) {
        final List<String> tokens = new ArrayList<>();
        JWSToken jwt = jwsInstance.parseToken(baseJWT, true);
        if (jwt != null) {
            for (String alg : algNone) {
                String decodeHeader = jwt.getHeaderJSON(false);
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

}
