package passive;

import com.google.gson.JsonSyntaxException;
import extend.util.external.jws.JWSUtil;
import extension.helpers.BouncyUtil;
import extension.helpers.MatchUtil;
import extension.helpers.StringUtil;
import extension.helpers.json.JsonUtil;
import extension.view.base.CaptureItem;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.SecretKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMException;

/**
 *
 * @author isayan
 */
public class JWSToken implements JsonToken {

    private final static Logger logger = Logger.getLogger(JWSToken.class.getName());

    private final static JWSToken jwsInstance = new JWSToken();

    public JWSToken() {
    }

    private Header header;
    private Payload payload;
    private Signature signature;

    public JWSToken(JWSToken token) {
        this.header = token.header;
        this.payload = token.payload;
        this.signature = token.signature;
    }

    public JWSToken(Header header, Payload payload, Signature signature) {
        this.header = header;
        this.payload = payload;
        this.signature = signature;
    }

    public JWSToken(Header header, Payload payload) {
        this.header = header;
        this.payload = payload;
        this.signature = new Signature("");
    }

    public JWSToken(String headerPart, String payloadPart, String signaturePart) {
        this.header = new Header(headerPart);
        this.payload = new Payload(payloadPart);
        this.signature = new Signature(signaturePart);
    }

    public JWSToken getInstance() {
        return jwsInstance;
    }

    public boolean isValidFormat(String value) {
        JWSToken token = parseToken(value, true);
        return token != null;
    }

    public enum Algorithm {
        NONE("", null),
        HS256("HmacSHA256", null),
        HS384("HmacSHA384", null),
        HS512("HmacSHA512", null),
        RS256("SHA256withRSA", null),
        RS384("SHA384withRSA", null),
        RS512("SHA512withRSA", null),
        PS256("RSASSA-PSS", new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1)),
        PS384("RSASSA-PSS", new PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 48, 1)),
        PS512("RSASSA-PSS", new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1)),
        ES256("SHA256withECDSA", null),
        ES384("SHA384withECDSA", null),
        ES512("SHA512withECDSA", null);

        private final String signAlgorithm;
        private final AlgorithmParameterSpec signParams;

        Algorithm(String signAlgorithm, AlgorithmParameterSpec params) {
            this.signAlgorithm = signAlgorithm;
            this.signParams = params;
        }

        public String getSignAlgorithm() {
            return this.signAlgorithm;
        }

        public AlgorithmParameterSpec getSignAlgorithmParameter() {
            return this.signParams;
        }

        public static Algorithm parseValue(String s) {
            return Algorithm.valueOf(s.toUpperCase());
        }

    };

    public static Set<Algorithm> getSupportAlgorithm() {
        final Set<Algorithm> algos = new LinkedHashSet<>();
        algos.add(Algorithm.NONE);
        algos.add(Algorithm.HS256);
        algos.add(Algorithm.HS384);
        algos.add(Algorithm.HS512);
        algos.add(Algorithm.RS256);
        algos.add(Algorithm.RS384);
        algos.add(Algorithm.RS512);
        algos.add(Algorithm.PS256);
        algos.add(Algorithm.PS384);
        algos.add(Algorithm.PS512);
        algos.add(Algorithm.ES256);
        algos.add(Algorithm.ES384);
        algos.add(Algorithm.ES512);
        return algos;
    }

    private final static Pattern PTN_JWT_HEADER_ALGORITHM = Pattern.compile("\"alg\"\\s*?:\\s*?\"(\\w+?)\"");

    private static Algorithm findAlgorithmJSON(String header) {
        Matcher m = PTN_JWT_HEADER_ALGORITHM.matcher(header);
        try {
            if (m.find()) {
                return Algorithm.parseValue(m.group(1));
            }
        } catch (java.lang.IllegalArgumentException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    public static class Header implements JsonSegment {

        private String tokenPart;

        public Header(String tokenPart) {
            this.tokenPart = tokenPart;
        }

        public Algorithm getAlgorithm() {
            String header = toJSON(false);
            return findAlgorithmJSON(header);
        }

        public static Header generateAlgorithm(Algorithm algo) {
            String token = String.format("{\"alg\":\"%s\",\"typ\":\"JWT\"}", algo.name());
            return new JWSToken.Header(JsonToken.encodeBase64UrlSafe(token));
        }

        public Header withAlgorithm(Algorithm algo) {
            return withAlgorithm(algo.name());
        }

        public Header withAlgorithm(String algo) {
            String headerJSON = getsDecodeBase64Url();
            Matcher m = PTN_JWT_HEADER_ALGORITHM.matcher(headerJSON);
            StringBuffer headerSecment = new StringBuffer();
            if (m.find()) {
                headerSecment.append(headerJSON.substring(0, m.start(1)));
                headerSecment.append(algo);
                headerSecment.append(headerJSON.substring(m.end(1)));
            }
            return new Header(JsonToken.encodeBase64UrlSafe(headerSecment.toString()));
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

    /**
     * @return the signAlgorithm
     */
    public Algorithm getAlgorithm() {
        return this.header.getAlgorithm();
    }

    @Override
    public JWSToken parseToken(String value, boolean matches) {
        JWSToken token = null;
        if (MatchUtil.isUrlencoded(value)) {
            value = JsonToken.decodeUrl(value);
        }
        CaptureItem[] items = JWSUtil.findToken(value);
        boolean find = items.length > 0;
        if (find) {
            for (int i = 0; i < items.length; i++) {
                String jws_token = items[i].getCaptureValue();
                if (matches && !(items[i].start() == 0 && items[i].end() == jws_token.length())) {
                    break;
                }
                String[] segment = JWSUtil.splitSegment(jws_token);
                JWSToken jws = new JWSToken();
                jws.header = new JWSToken.Header(segment[0]);
                jws.payload = new JsonToken.Payload(segment[1]);
                jws.signature = new JsonToken.Signature(segment[2]);
                if (jws.isValid()) {
                    token = jws;
                }
                break;
            }
        }
        return token;
    }

    public static CaptureItem[] findToken(String value) {
        return JWSUtil.findToken(value);
    }

    public static boolean containsTokenFormat(String value) {
        return JWSUtil.containsTokenFormat(value);
    }

    @Override
    public boolean isValid() {
        try {
            this.header.toJSON(false);
            this.payload.toJSON(false);
        } catch (JsonSyntaxException | IllegalArgumentException ex) {
            return false;
        }
        return true;
    }

    @Override
    public boolean isSignFormat() {
        Algorithm alg = this.header.getAlgorithm();
        return (alg.equals(Algorithm.HS256) || alg.equals(Algorithm.HS384) || alg.equals(Algorithm.ES512));
    }

    @Override
    public String getToken() {
        StringBuilder buff = new StringBuilder();
        buff.append(this.header.getPart());
        buff.append(".");
        buff.append(this.payload.getPart());
        buff.append(".");
        buff.append(this.signature.getPart());
        return buff.toString();
    }

    @Override
    public String getData() {
        StringBuilder buff = new StringBuilder();
        buff.append(this.header.getPart());
        buff.append(".");
        buff.append(this.payload.getPart());
        return buff.toString();
    }

    public static String getData(String header, String payload) {
        StringBuilder buff = new StringBuilder();
        buff.append(header);
        buff.append(".");
        buff.append(payload);
        return buff.toString();
    }

    public static String getData(Header header, Payload payload) {
        StringBuilder buff = new StringBuilder();
        buff.append(header.getPart());
        buff.append(".");
        buff.append(payload.getPart());
        return buff.toString();
    }

    /**
     * @return the header
     */
    public String getHeaderPart() {
        return this.header.getPart();
    }

    public JWSToken.Header getHeader() {
        return this.header;
    }

    @Override
    public String getPayloadPart() {
        return this.payload.getPart();
    }

    @Override
    public JsonToken.Payload getPayload() {
        return this.payload;
    }

    @Override
    public JsonToken.Signature getSignature() {
        return this.signature;
    }

    @Override
    public String getSignaturePart() {
        return this.signature.getPart();
    }

    public byte[] getSignatureBytes() {
        return this.signature.getsDecodeBase64Url();
    }

    public boolean isSigned() {
        return !this.signature.isEmpty();
    }

    public byte[] sign(String secretKey) throws SignatureException {
        return sign(this.header.getAlgorithm(), secretKey, this.getData());
    }

    public byte[] sign(Algorithm algo, String secretKey) throws SignatureException {
        return sign(algo, secretKey, this.getData());
    }

    public static byte[] sign(Algorithm algo, String secretKey, String headerPart, String payloadPart) throws SignatureException {
        return sign(algo, secretKey, JWSToken.getData(headerPart, payloadPart));
    }

    public static byte[] sign(Algorithm algo, String secretKey, Header header, Payload payload) throws SignatureException {
        return sign(algo, secretKey, JWSToken.getData(header, payload));
    }

    public static byte[] sign(Algorithm algo, String secretKey, String data) throws SignatureException {
        try {
            byte[] signatureByte = new byte[]{};
            switch (algo) {
                case HS256:
                case HS384:
                case HS512:
                    signatureByte = sign(algo, JWSUtil.toSecretKey(secretKey), data);
                    break;
                case RS256:
                case RS384:
                case RS512:
                    signatureByte = sign(algo, JWSUtil.toPrivateKey(secretKey), data);
                    break;
                case PS256:
                case PS384:
                case PS512:
                    signatureByte = sign(algo, JWSUtil.toPrivateKey(secretKey), data);
                    break;
                case ES256:
                case ES384:
                case ES512:
                    signatureByte = sign(algo, JWSUtil.toECPrivateKey(secretKey), data);
                    break;
            }
            return signatureByte;
        } catch (PEMException ex) {
            throw new SignatureException(ex.getMessage(), ex);
        }
    }

    public static byte[] sign(Algorithm algo, SecretKey secretKey, String message) throws SignatureException {
        byte[] signatureByte = new byte[]{};
        switch (algo) {
            case HS256:
                signatureByte = BouncyUtil.hmacSHA256(secretKey.getEncoded(), StringUtil.getBytesUTF8(message));
                break;
            case HS384:
                signatureByte = BouncyUtil.hmacSHA384(secretKey.getEncoded(), StringUtil.getBytesUTF8(message));
                break;
            case HS512:
                signatureByte = BouncyUtil.hmacSHA512(secretKey.getEncoded(), StringUtil.getBytesUTF8(message));
                break;
        }
        return signatureByte;
    }

    private static byte[] sign(Algorithm algo, PrivateKey secretKey, String message) throws SignatureException {
        try {
            java.security.Signature signature = java.security.Signature.getInstance(algo.getSignAlgorithm(), BouncyCastleProvider.PROVIDER_NAME);
            if (algo.getSignAlgorithmParameter() != null) {
                signature.setParameter(algo.getSignAlgorithmParameter());
            }
            signature.initSign(secretKey);
            signature.update(StringUtil.getBytesUTF8(message));
            return signature.sign();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException | InvalidAlgorithmParameterException ex) {
            throw new SignatureException(ex.getMessage(), ex);
        }
    }

    @Override
    public boolean signatureEqual(final String secret) throws SignatureException {
        return signatureEqual(this.header.getPart(), this.payload.getPart(), this.signature.getPart(), secret);
    }

    protected static boolean signatureEqual(String header, String payload, final String signature, final String secretKey) throws SignatureException {
        JWSToken token = new JWSToken(header, payload, signature);
        byte[] signatureByte = token.sign(secretKey);
        return signature.equals(JsonToken.encodeBase64UrlSafe(signatureByte));
    }

    protected static boolean signatureEqual(Algorithm algo, String header, String payload, final String signature, final String secretKey) throws SignatureException {
        JWSToken token = new JWSToken(header, payload, signature);
        byte[] signatureByte = token.sign(algo, secretKey);
        return signature.equals(JsonToken.encodeBase64UrlSafe(signatureByte));
    }

    private final static Algorithm[] algHS = {Algorithm.HS256, Algorithm.HS384, Algorithm.HS512};

    public static String[] generatePublicToHashToken(String baseToken, String secretKey) throws SignatureException {
        final List<String> tokens = new ArrayList<>();
        JWSToken jws = jwsInstance.parseToken(baseToken, true);
        if (jws != null) {
            for (Algorithm alg : algHS) {
                byte[] sign = JWSToken.sign(alg, secretKey, jws.getHeader().withAlgorithm(alg), jws.getPayload());
                JWSToken token = new JWSToken(jws.header.getPart(), jws.payload.getPart(), JsonToken.encodeBase64UrlSafe(sign));
                tokens.add(token.getToken());
            }
        }
        return tokens.toArray(String[]::new);
    }

    private final static String[] algNone = {"none", "NONE", "None"};

    public static String[] generateNoneToken(String baseJWT) {
        final List<String> tokens = new ArrayList<>();
        JWSToken jwt = jwsInstance.parseToken(baseJWT, true);
        if (jwt != null) {
            for (String alg : algNone) {
                JWSToken token = new JWSToken(jwt.header.withAlgorithm(alg), jwt.payload, jwt.signature);
                tokens.add(token.getData() + ".");
            }
        }
        return tokens.toArray(String[]::new);
    }

}
