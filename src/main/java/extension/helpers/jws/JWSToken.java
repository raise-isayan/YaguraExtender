package extension.helpers.jws;

import com.google.gson.JsonSyntaxException;
import extension.helpers.BouncyUtil;
import extension.helpers.MatchUtil;
import extension.helpers.StringUtil;
import extension.helpers.json.JsonUtil;
import extension.view.base.CaptureItem;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.SecretKey;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
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

    public boolean isValidToken(String value) {
        return parseToken(value, true) != null;
    }

    public enum Algorithm {
        NONE("none", "", null),
        HS256("HS256", "HmacSHA256", null),
        HS384("HS384", "HmacSHA384", null),
        HS512("HS512", "HmacSHA512", null),
        RS256("RS256", "SHA256withRSA", null),
        RS384("RS384", "SHA384withRSA", null),
        RS512("RS512", "SHA512withRSA", null),
        PS256("PS256", "SHA256withRSA/PSS", new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1)),
        PS384("PS384", "SHA384withRSA/PSS", new PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 48, 1)),
        PS512("PS512", "SHA512withRSA/PSS", new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1)),
        ES256("ES256", "SHA256withECDSA", null),
        ES384("ES384", "SHA384withECDSA", null),
        ES512("ES512", "SHA512withECDSA", null),
        EDDSA("EdDSA", "Ed25519", null);

        private final String algorithmName;
        private final String signAlgorithm;
        private final AlgorithmParameterSpec algorithmParameter;

        Algorithm(String algorithmName, String signAlgorithm, AlgorithmParameterSpec algorithmParameter) {
            this.algorithmName = algorithmName;
            this.algorithmParameter = algorithmParameter;
            this.signAlgorithm = signAlgorithm;
        }

        public String getAlgorithmName() {
            return this.algorithmName;
        }

        public String getSignAlgorithm() {
            return this.signAlgorithm;
        }

        public AlgorithmParameterSpec getAlgorithmParameter() {
            return this.algorithmParameter;
        }

        public static Algorithm parseValue(String s) {
            return Algorithm.valueOf(s.toUpperCase());
        }

    };

    public final static EnumSet<Algorithm> SYMMETRIC_KEY = EnumSet.of(Algorithm.HS256, Algorithm.HS384, Algorithm.HS512);

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
        algos.add(Algorithm.EDDSA);
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
            String token = String.format("{\"alg\":\"%s\",\"typ\":\"JWT\"}", algo.getAlgorithmName());
            return new JWSToken.Header(JsonToken.encodeBase64UrlSafe(token));
        }

        public Header withAlgorithm(Algorithm algo) {
            return withAlgorithm(algo.getAlgorithmName());
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

        public boolean isValid() {
            if (StringUtil.isPrintable(getsDecodeBase64Url())) {
                try {
                    Algorithm algo = getAlgorithm();
                    return algo != null;
                } catch (JsonSyntaxException | IllegalArgumentException ex) {
                    // nothing
                }
            }
            return false;
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
        CaptureItem[] items = JWSUtil.findTokenFormat(value);
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
                    break;
                }
            }
        }
        return token;
    }

    public static boolean containsTokenFormat(String value) {
        CaptureItem[] tokens = JWSUtil.findTokenFormat(value, JWSUtil.INCLUDE_SIGNATURE);
        return tokens.length > 0;
    }

    public static boolean containsValidToken(String value) {
        CaptureItem[] tokens = JWSUtil.findTokenFormat(value);
        final JWSToken jws = new JWSToken();
        for (int i = 0; i < tokens.length; i++) {
            if (jws.parseToken(tokens[i].getCaptureValue(), true) != null)
                return true;
        }
        return false;
    }

    @Override
    public boolean isValid() {
        if (this.header.isValid() && this.payload.isValid()) {
            try {
                this.header.toJSON(false);
                this.payload.toJSON(false);
                if (!this.signature.isEmpty()) {
                    return this.signature.isValid();
                }
                return true;
            } catch (JsonSyntaxException | IllegalArgumentException ex) {
                // nothong
            }
        }
        return false;
    }

    @Override
    public boolean isSignFormat() {
        Algorithm alg = this.header.getAlgorithm();
        Set<Algorithm> algoAll = getSupportAlgorithm();
        return (algoAll.contains(alg));
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

    public byte[] sign(Key secretKey) throws SignatureException {
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

    public static byte[] sign(Algorithm algo, String secretKey, String message) throws SignatureException {
        return sign(algo, secretKey, StringUtil.getBytesUTF8(message));
    }

    public static byte[] sign(Algorithm algo, String secretKey, byte[] messageBytes) throws SignatureException {
        try {
            byte[] signatureByte = new byte[]{};
            switch (algo) {
                case HS256:
                case HS384:
                case HS512:
                        signatureByte = sign(algo, JWSUtil.toSecretKey(secretKey), messageBytes);
                    break;
                case RS256:
                case RS384:
                case RS512:
                    // JWK
                    if (JsonUtil.isJson(secretKey)) {
                       signatureByte = sign(algo, JWKToken.parseJWK(secretKey).getPrivate(), messageBytes);
                    }
                    else {
                        signatureByte = sign(algo, JWSUtil.toPrivateKey(secretKey), messageBytes);
                    }
                    break;
                case PS256:
                case PS384:
                case PS512:
                    // JWK
                    if (JsonUtil.isJson(secretKey)) {
                       signatureByte = sign(algo, JWKToken.parseJWK(secretKey).getPrivate(), messageBytes);
                    }
                    else {
                        signatureByte = sign(algo, JWSUtil.toPrivateKey(secretKey), messageBytes);
                    }
                    break;
                case ES256:
                case ES384:
                case ES512:
                    // JWK
                    if (JsonUtil.isJson(secretKey)) {
                        signatureByte = sign(algo, (ECPrivateKey)JWKToken.parseJWK(secretKey).getPrivate(), messageBytes);
                    }
                    else {
                        signatureByte = sign(algo, JWSUtil.toECPrivateKey(secretKey), messageBytes);
                   }
                    break;
                case EDDSA:
                    // JWK
                    if (JsonUtil.isJson(secretKey)) {
                        signatureByte = sign(algo, (EdECPrivateKey)JWKToken.parseJWK(secretKey).getPrivate(), messageBytes);
                    }
                    else {
                        signatureByte = sign(algo, JWSUtil.toEdECPrivateKey(secretKey), messageBytes);
                    }
                    break;
            }
            return signatureByte;
        } catch (PEMException ex) {
            throw new SignatureException(ex.getMessage(), ex);
        } catch (InvalidKeySpecException ex) {
            throw new SignatureException(ex.getMessage(), ex);
        } catch (ClassCastException ex) {
            throw new SignatureException(ex.getMessage(), ex);
        } catch (NullPointerException ex) {
            throw new SignatureException(ex.getMessage(), ex);
        }
    }

    protected static byte[] sign(Algorithm algo, Key privateKey, String message) throws SignatureException {
        return sign(algo, privateKey, StringUtil.getBytesUTF8(message));
    }

    protected static byte[] sign(Algorithm algo, Key privateKey, byte[] messageBytes) throws SignatureException {
        if (privateKey instanceof SecretKey secretKey) {
            return sign(algo, secretKey, messageBytes);
        } else if (privateKey instanceof RSAPrivateKey rsaPrivateKey) {
            return sign(algo, rsaPrivateKey, messageBytes);
        }
        else if (privateKey instanceof ECPrivateKey ecPrivateKey) {
            return sign(algo, ecPrivateKey, messageBytes);
        }
        else if (privateKey instanceof EdECPrivateKey edPrivateKey) {
            return sign(algo, edPrivateKey, messageBytes);
        }
        throw new SignatureException("Unsupport algorithm:" + privateKey.getAlgorithm());
    }

    public static byte[] sign(Algorithm algo, SecretKey secretKey, String message) throws SignatureException {
        return sign(algo, secretKey, StringUtil.getBytesUTF8(message));
    }

    public static byte[] sign(Algorithm algo, SecretKey secretKey, byte[] messageBytes) throws SignatureException {
        byte[] signatureByte = new byte[]{};
        switch (algo) {
            case HS256:
                signatureByte = BouncyUtil.hmacSHA256(secretKey.getEncoded(), messageBytes);
                break;
            case HS384:
                signatureByte = BouncyUtil.hmacSHA384(secretKey.getEncoded(), messageBytes);
                break;
            case HS512:
                signatureByte = BouncyUtil.hmacSHA512(secretKey.getEncoded(), messageBytes);
                break;
        }
        return signatureByte;
    }

    private static byte[] sign(Algorithm algo, RSAPrivateKey secretKey, byte[] messageBytes) throws SignatureException {
        try {
            java.security.Signature signature = java.security.Signature.getInstance(algo.getSignAlgorithm(), BouncyCastleProvider.PROVIDER_NAME);
            if (algo.getAlgorithmParameter() != null) {
                signature.setParameter(algo.getAlgorithmParameter());
            }
            signature.initSign(secretKey);
            signature.update(messageBytes);
            return signature.sign();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException | InvalidAlgorithmParameterException ex) {
            throw new SignatureException(ex.getMessage(), ex);
        }
    }

    final static Map<Algorithm, Integer> EC_SIG_SIZE = new HashMap<>();

    static {
        EC_SIG_SIZE.put(Algorithm.ES256, 64);
        EC_SIG_SIZE.put(Algorithm.ES384, 96);
        EC_SIG_SIZE.put(Algorithm.ES512, 132);
    }

    private static byte[] sign(Algorithm algo, ECPrivateKey secretKey, byte[] messageBytes) throws SignatureException {
        try {
            java.security.Signature signature = java.security.Signature.getInstance(algo.getSignAlgorithm(), BouncyCastleProvider.PROVIDER_NAME);
            signature.initSign(secretKey);
            signature.update(messageBytes);
            return derToJose(signature.sign(), EC_SIG_SIZE.get(algo));
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException | IOException ex) {
            throw new SignatureException(ex.getMessage(), ex);
        }
    }

    private static byte[] sign(Algorithm algo, EdECPrivateKey secretKey, byte[] messageBytes) throws SignatureException {
        try {
            java.security.Signature signature = java.security.Signature.getInstance(algo.getSignAlgorithm(), BouncyCastleProvider.PROVIDER_NAME);
            signature.initSign(secretKey);
            signature.update(messageBytes);
            return signature.sign();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException ex) {
            throw new SignatureException(ex.getMessage(), ex);
        }
    }

    @Override
    public boolean signatureEqual(final String secret) throws SignatureException {
        return signatureEqual(this.header.getPart(), this.payload.getPart(), this.signature.getPart(), secret);
    }

    protected static boolean signatureEqual(String header, String payload, final String signature, final String secretKey) throws SignatureException {
        JWSToken token = new JWSToken(header, payload, signature);
        byte[] signatureBytes = token.sign(secretKey);
        return signature.equals(JsonToken.encodeBase64UrlSafe(signatureBytes));
    }

    public static boolean signatureEqual(Algorithm algo, String header, String payload, final String signature, final String secretKey) throws SignatureException {
        JWSToken token = new JWSToken(header, payload, signature);
        byte[] signatureByte = token.sign(algo, secretKey);
        return signature.equals(JsonToken.encodeBase64UrlSafe(signatureByte));
    }

    public boolean verify(String secretKey) throws SignatureException {
        return verify(this.header.getAlgorithm(), secretKey, StringUtil.getBytesUTF8(this.getData()), this.getSignatureBytes());
    }

    public boolean verify(Algorithm algo, String secretKey) throws SignatureException {
        return verify(algo, secretKey, StringUtil.getBytesUTF8(this.getData()), this.getSignatureBytes());
    }

    public static boolean verify(Algorithm algo, String secretKey, byte[] messageBytes, byte[] signatureBytes) throws SignatureException {
        try {
            boolean result = false;
            switch (algo) {
                case HS256:
                case HS384:
                case HS512:
                    result = verify(algo, JWSUtil.toSecretKey(secretKey), messageBytes, signatureBytes);
                    break;
                case RS256:
                case RS384:
                case RS512:
                    result = verify(algo, JWSUtil.toPublicKey(secretKey), messageBytes, signatureBytes);
                    break;
                case PS256:
                case PS384:
                case PS512:
                    result = verify(algo, JWSUtil.toPublicKey(secretKey), messageBytes, signatureBytes);
                    break;
                case ES256:
                case ES384:
                case ES512:
                    result = verify(algo, JWSUtil.toECPublicKey(secretKey), messageBytes, signatureBytes);
                    break;
                case EDDSA:
                    result = verify(algo, JWSUtil.toEdECPublicKey(secretKey), messageBytes, signatureBytes);
                    break;
            }
            return result;
        } catch (PEMException ex) {
            throw new SignatureException(ex.getMessage(), ex);
        }
    }

    protected static boolean verify(Algorithm algo, Key publicKey, String message, String signature) throws SignatureException {
        return verify(algo, publicKey, StringUtil.getBytesUTF8(message), JsonToken.decodeBase64UrlSafeByte(signature));
    }

    protected static boolean verify(Algorithm algo, Key publicKey, byte[] messageBytes, byte[] signatureBytes) throws SignatureException {
        if (publicKey instanceof SecretKey secretKey) {
            return verify(algo, secretKey, messageBytes, signatureBytes);
        }
        else if (publicKey instanceof RSAPublicKey rsaPublicKey) {
            return verify(algo, rsaPublicKey, messageBytes, signatureBytes);
        }
        else if (publicKey instanceof ECPublicKey ecPublicKey) {
            return verify(algo, ecPublicKey, messageBytes, signatureBytes);
        }
        else if (publicKey instanceof EdECPublicKey edPublicKey) {
            return verify(algo, edPublicKey, messageBytes, signatureBytes);
        }
        throw new SignatureException("Unsupport algorithm:" + publicKey.getAlgorithm());
    }

    protected static boolean verify(Algorithm algo, PublicKey publicKey, String message, String signature) throws SignatureException {
        return verify(algo, publicKey, StringUtil.getBytesUTF8(message), JsonToken.decodeBase64UrlSafeByte(signature));
    }

    protected static boolean verify(Algorithm algo, SecretKey secretKey, byte [] messageBytes, byte[] signatureBytes) throws SignatureException {
        byte[] signatureByte = JWSToken.sign(algo, secretKey, messageBytes);
        String sign = JsonToken.encodeBase64UrlSafe(signatureByte);
        return sign.equals(JsonToken.encodeBase64UrlSafe(signatureByte));
    }

    private static boolean verify(Algorithm algo, RSAPublicKey publicKey, byte[] messageBytes, byte[] signatureBytes) throws SignatureException {
        try {
            java.security.Signature verifier = java.security.Signature.getInstance(algo.getSignAlgorithm(), BouncyCastleProvider.PROVIDER_NAME);
            if (algo.getAlgorithmParameter() != null) {
                verifier.setParameter(algo.getAlgorithmParameter());
            }
            verifier.initVerify(publicKey);
            verifier.update(messageBytes);
            return verifier.verify(signatureBytes);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException | InvalidAlgorithmParameterException ex) {
            throw new SignatureException(ex.getMessage(), ex);
        }
    }

    private static boolean verify(Algorithm algo, ECPublicKey publicKey, byte[] messageBytes, byte[] signatureBytes) throws SignatureException {
        try {
            java.security.Signature verifier = java.security.Signature.getInstance(algo.getSignAlgorithm(), BouncyCastleProvider.PROVIDER_NAME);
            verifier.initVerify(publicKey);
            verifier.update(messageBytes);
            return verifier.verify(joseToDer(signatureBytes));
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException | IOException ex) {
            throw new SignatureException(ex.getMessage(), ex);
        }
    }

    private static boolean verify(Algorithm algo, EdECPublicKey publicKey, byte[] messageBytes, byte[] signatureBytes) throws SignatureException {
        try {
            java.security.Signature verifier = java.security.Signature.getInstance(algo.getSignAlgorithm(), BouncyCastleProvider.PROVIDER_NAME);
            verifier.initVerify(publicKey);
            verifier.update(messageBytes);
            return verifier.verify(signatureBytes);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException ex) {
            throw new SignatureException(ex.getMessage(), ex);
        }
    }

    private static byte[] toFixedLength(byte[] src, int size) {
        if (src.length == size) {
            return src;
        }
        byte[] dst = new byte[size];
        if (src.length > size) {
            System.arraycopy(src, src.length - size, dst, 0, size);
        } else {
            System.arraycopy(src, 0, dst, size - src.length, src.length);
        }
        return dst;
    }

    // DER → JOSE  変換
    public static byte[] derToJose(byte[] derSignature, int keylen) throws IOException {
        int size = keylen / 2;
        ASN1Sequence seq = (ASN1Sequence) ASN1Primitive.fromByteArray(derSignature);
        BigInteger r = ((ASN1Integer) seq.getObjectAt(0)).getValue();
        BigInteger s = ((ASN1Integer) seq.getObjectAt(1)).getValue();

        byte[] rBytes = toFixedLength(r.toByteArray(), size);
        byte[] sBytes = toFixedLength(s.toByteArray(), size);

        byte[] concat = new byte[size * 2];
        System.arraycopy(rBytes, 0, concat, 0, size);
        System.arraycopy(sBytes, 0, concat, size, size);
        return concat;
    }

    // JOSE → DER 変換
    public static byte[] joseToDer(byte[] joseSignature) throws IOException {
        int size = joseSignature.length / 2;
        byte[] rBytes = new byte[size];
        byte[] sBytes = new byte[size];
        System.arraycopy(joseSignature, 0, rBytes, 0, size);
        System.arraycopy(joseSignature, size, sBytes, 0, size);

        BigInteger r = new BigInteger(1, rBytes);
        BigInteger s = new BigInteger(1, sBytes);

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(r));
        v.add(new ASN1Integer(s));
        DERSequence seq = new DERSequence(v);
        return seq.getEncoded(ASN1Encoding.DER);
    }

    private final static Algorithm[] algHS = {Algorithm.HS256, Algorithm.HS384, Algorithm.HS512};

    public static String[] generatePublicToHashToken(String baseToken, String secretKey) throws SignatureException {
        final List<String> tokens = new ArrayList<>();
        JWSToken jws = jwsInstance.parseToken(baseToken, true);
        if (jws != null) {
            for (Algorithm alg : algHS) {
                Header hs_hader = jws.getHeader().withAlgorithm(alg);
                byte[] sign = JWSToken.sign(alg, secretKey, hs_hader, jws.getPayload());
                JWSToken token = new JWSToken(hs_hader, jws.payload, new JWSToken.Signature(JsonToken.encodeBase64UrlSafe(sign)));
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
