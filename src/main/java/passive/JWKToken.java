package passive;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonSyntaxException;
import extension.helpers.ConvertUtil;
import extension.helpers.json.JsonUtil;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed448PrivateKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;

/**
 *
 * @author isayan
 */
public class JWKToken {

    private final static BouncyCastleProvider BC_PROVIDER_INSTANCE = new BouncyCastleProvider();

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BC_PROVIDER_INSTANCE);
        }
    }

    private static byte[] normalize(byte[] bytes, int fieldSize) {
        int sizeBytes = (fieldSize + 7) / 8;
        if (bytes.length < sizeBytes) {
            byte[] padded = new byte[sizeBytes];
            System.arraycopy(bytes, 0, padded, sizeBytes - bytes.length, bytes.length);
            bytes = padded;
        }
        else if (bytes.length > sizeBytes) {
            byte[] padded = new byte[sizeBytes];
            System.arraycopy(bytes, bytes.length - sizeBytes, padded, 0, sizeBytes);
            bytes = padded;
        }
        return bytes;
    }

    private static byte[] normalize(byte[] bytes) {
        if (bytes.length > 1 && bytes[0] == 0x00) {
            bytes = Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        return bytes;
    }

    private static JsonObject jsonJWKSet(List<JsonObject> jwks) {
        JsonArray jsonArray = new JsonArray();
        for  (JsonObject jwk : jwks) {
            jsonArray.add(jwk);
        }
        JsonObject jsonKeys = new JsonObject();
        jsonKeys.add("keys", jsonArray);
        return jsonKeys;
    }

    public static interface JWKKey {
        public final static String KTY = "kty";

        public String getKeyType();

        public boolean isPrivate();

        public KeyPair toKeyPair() throws InvalidKeySpecException;

        public String toJWK(boolean pretty) throws InvalidKeySpecException;

    }

    public static class RSAKey implements JWKKey {
        public final static String KEY_TYPE = "RSA";
        public final static String N = "n";
        public final static String E = "e";
        public final static String D = "d";
        public final static String P = "p";
        public final static String Q = "q";
        public final static String DP = "dp";
        public final static String DQ = "dq";
        public final static String QI = "qi";

        private final JsonObject tokenJWK;
        private final KeyPair keyPair;

        private RSAKey(JsonObject tokenJWK) {
            this.tokenJWK = tokenJWK;
            this.keyPair = null;
        }

        private RSAKey(KeyPair keyPair) {
            this.keyPair = keyPair;
            this.tokenJWK = null;
        }

        @Override
        public String getKeyType() {
            return KEY_TYPE;
        }

        @Override
        public boolean isPrivate() {
            if (this.tokenJWK != null) {
                return this.tokenJWK.has(RSAKey.D);
            } else {
                return this.keyPair.getPrivate() instanceof RSAPrivateKey;
            }
        }

        private static boolean hasKeyType(JsonObject tokenJWK) {
            return tokenJWK.has(KTY) && KEY_TYPE.equals(tokenJWK.get(KTY).getAsString());
        }

        public static RSAKey parse(String jsonJWK) throws InvalidKeySpecException {
            try {
                JsonObject jwkObject = JsonUtil.parseJsonObject(jsonJWK);
                if (!hasKeyType(jwkObject)) throw new InvalidKeySpecException("Invalid key spec:" + jsonJWK);
                RSAKey rsaKey = new RSAKey(jwkObject);
                return rsaKey;
            } catch (JsonSyntaxException ex) {
                throw new InvalidKeySpecException(ex);
            }
        }

        public RSAPrivateCrtKeySpec toRSAPrivateCrtKeySpec() throws InvalidKeySpecException {
            if (this.tokenJWK != null && this.tokenJWK.has(RSAKey.D)
                    && this.tokenJWK.has(RSAKey.N)
                    && this.tokenJWK.has(RSAKey.E)
                    && this.tokenJWK.has(RSAKey.P)
                    && this.tokenJWK.has(RSAKey.DP)
                    && this.tokenJWK.has(RSAKey.DQ)
                    && this.tokenJWK.has(RSAKey.QI)) {
                // public
                byte[] n = ConvertUtil.toBase64URLSafeDecode(this.tokenJWK.get(RSAKey.N).getAsString());
                byte[] e = ConvertUtil.toBase64URLSafeDecode(this.tokenJWK.get(RSAKey.E).getAsString());
                // private
                byte[] d = ConvertUtil.toBase64URLSafeDecode(this.tokenJWK.get(RSAKey.D).getAsString());
                // private CRT
                byte[] p = ConvertUtil.toBase64URLSafeDecode(this.tokenJWK.get(RSAKey.P).getAsString());
                byte[] q = ConvertUtil.toBase64URLSafeDecode(this.tokenJWK.get(RSAKey.Q).getAsString());
                byte[] dp = ConvertUtil.toBase64URLSafeDecode(this.tokenJWK.get(RSAKey.DP).getAsString());
                byte[] dq = ConvertUtil.toBase64URLSafeDecode(this.tokenJWK.get(RSAKey.DQ).getAsString());
                byte[] qi = ConvertUtil.toBase64URLSafeDecode(this.tokenJWK.get(RSAKey.QI).getAsString());
                RSAPrivateCrtKeySpec privSpec = new RSAPrivateCrtKeySpec(
                        new BigInteger(1, n), // modulus
                        new BigInteger(1, e), // publicExponent
                        new BigInteger(1, d), // privateExponent
                        new BigInteger(1, p), // primeP
                        new BigInteger(1, q), // primeQ
                        new BigInteger(1, dp), // primeExponentP
                        new BigInteger(1, dq), // primeExponentQ
                        new BigInteger(1, qi) // crtCoefficient
                );
                return privSpec;
            }
            return null;
        }

        @Override
        public KeyPair toKeyPair() throws InvalidKeySpecException {
            try {
//                String kty = this.tokenJWK.get(KTY).getAsString();
                PublicKey pubKey = null;
                PrivateKey priKey = null;
                KeyFactory kf = KeyFactory.getInstance(KEY_TYPE, BouncyCastleProvider.PROVIDER_NAME);
                // public
                byte[] n = ConvertUtil.toBase64URLSafeDecode(this.tokenJWK.get(RSAKey.N).getAsString());
                byte[] e = ConvertUtil.toBase64URLSafeDecode(this.tokenJWK.get(RSAKey.E).getAsString());

                RSAPublicKeySpec pubSpec = new RSAPublicKeySpec(new BigInteger(1, n), new BigInteger(1, e));
                pubKey = kf.generatePublic(pubSpec);

                // private
                if (this.tokenJWK.has(RSAKey.D)) {
                    byte[] d = ConvertUtil.toBase64URLSafeDecode(this.tokenJWK.get(RSAKey.D).getAsString());
                    if (toRSAPrivateCrtKeySpec() != null) {
                        RSAPrivateCrtKeySpec priSpec = toRSAPrivateCrtKeySpec();
                        priKey = kf.generatePrivate(priSpec);
                    } else {
                        RSAPrivateKeySpec priSpec = new RSAPrivateKeySpec(new BigInteger(1, n), new BigInteger(1, d));
                        priKey = kf.generatePrivate(priSpec);
                    }
                }
                return new KeyPair(pubKey, priKey);
            } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
                throw new InvalidKeySpecException(ex.getMessage(), ex);
            }
        }

        public static RSAKey build(KeyPair keyPair) {
            RSAKey rsaKey = new RSAKey(keyPair);
            return rsaKey;
        }

        private JsonObject toJsonObject() throws InvalidKeySpecException {
            LinkedHashMap<String, String> jwk = new LinkedHashMap<>();
            try {
                KeyFactory kf = KeyFactory.getInstance(KEY_TYPE, BouncyCastleProvider.PROVIDER_NAME);
                RSAPublicKeySpec pubSpec = kf.getKeySpec(this.keyPair.getPublic(), RSAPublicKeySpec.class);

                jwk.put(KTY, RSAKey.KEY_TYPE);

                // public
                String n = ConvertUtil.toBase64URLSafeEncode(normalize(pubSpec.getModulus().toByteArray()));
                String e = ConvertUtil.toBase64URLSafeEncode(normalize(pubSpec.getPublicExponent().toByteArray()));
                jwk.put(RSAKey.N, n);
                jwk.put(RSAKey.E, e);

                // private
                if (this.keyPair.getPrivate() != null) {
                    RSAPrivateKeySpec priSpec = kf.getKeySpec(this.keyPair.getPrivate(), RSAPrivateKeySpec.class);
                    String d = ConvertUtil.toBase64URLSafeEncode(normalize(priSpec.getPrivateExponent().toByteArray()));
                    jwk.put(RSAKey.D, d);

                    if (this.keyPair.getPrivate() instanceof RSAPrivateCrtKey rsaPrivateCrtKey) {
                        String p = ConvertUtil.toBase64URLSafeEncode(normalize(rsaPrivateCrtKey.getPrimeP().toByteArray()));
                        jwk.put(RSAKey.P, p);
                        String q = ConvertUtil.toBase64URLSafeEncode(normalize(rsaPrivateCrtKey.getPrimeQ().toByteArray()));
                        jwk.put(RSAKey.Q, q);
                        String dp = ConvertUtil.toBase64URLSafeEncode(normalize(rsaPrivateCrtKey.getPrimeExponentP().toByteArray()));
                        jwk.put(RSAKey.DP, dp);
                        String dq = ConvertUtil.toBase64URLSafeEncode(normalize(rsaPrivateCrtKey.getPrimeExponentQ().toByteArray()));
                        jwk.put(RSAKey.DQ, dq);
                        String qi = ConvertUtil.toBase64URLSafeEncode(normalize(rsaPrivateCrtKey.getCrtCoefficient().toByteArray()));
                        jwk.put(RSAKey.QI, qi);
                    }

                }
            } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
                throw new InvalidKeySpecException(ex.getMessage(), ex);
            }
            Gson gson = new Gson();
            JsonElement jsonElement = gson.toJsonTree(jwk);
            return jsonElement.getAsJsonObject();
        }

        @Override
        public String toJWK(boolean pretty) throws InvalidKeySpecException {
            return JsonUtil.prettyJson(toJsonObject(), pretty);
        }

        public String toJWKSet(boolean pretty) throws InvalidKeySpecException {
            List<JsonObject> jwks = List.of(toJsonObject());
            return JsonUtil.prettyJson(jsonJWKSet(jwks), pretty);
        }

    }

    public static class ECKey implements JWKKey {
        public final static String KEY_TYPE = "EC";
        public final static String CRV = "crv";
        public final static String X = "x";
        public final static String Y = "y";
        public final static String D = "d";

        private final JsonObject tokenJWK;
        private final KeyPair keyPair;

        private ECKey(JsonObject tokenJWK) {
            this.tokenJWK = tokenJWK;
            this.keyPair = null;
        }

        private ECKey(KeyPair keyPair) {
            this.keyPair = keyPair;
            this.tokenJWK = null;
        }

        @Override
        public String getKeyType() {
            return KEY_TYPE;
        }

        @Override
        public boolean isPrivate() {
            if (tokenJWK != null) {
                return this.tokenJWK.has(ECKey.D);
            } else {
                return this.keyPair.getPrivate() instanceof ECPrivateKey;
            }
        }

        private static boolean hasKeyType(JsonObject tokenJWK) {
            return tokenJWK.has(KTY) && KEY_TYPE.equals(tokenJWK.get(KTY).getAsString());
        }

        public static ECKey parse(String jsonJWK) throws InvalidKeySpecException {
            try {
                JsonObject jwkObject = JsonUtil.parseJsonObject(jsonJWK);
                if (!hasKeyType(jwkObject)) throw new InvalidKeySpecException("Invalid key spec:" + jsonJWK);
                ECKey ecKey = new ECKey(jwkObject);
                return ecKey;
            } catch (JsonSyntaxException ex) {
                throw new InvalidKeySpecException(ex);
            }
        }

        @Override
        public KeyPair toKeyPair() throws InvalidKeySpecException {
            try {
  //              String kty = this.tokenJWK.get(KTY).getAsString();
                PublicKey pubKey = null;
                PrivateKey priKey = null;
                KeyFactory kf = KeyFactory.getInstance(KEY_TYPE, BouncyCastleProvider.PROVIDER_NAME);
                String curve = this.tokenJWK.get(CRV).getAsString();
                byte[] x = ConvertUtil.toBase64URLSafeDecode(this.tokenJWK.get(X).getAsString());
                byte[] y = ConvertUtil.toBase64URLSafeDecode(this.tokenJWK.get(Y).getAsString());
                ECParameterSpec params = jwkToECParameterSpec(curve);
                ECPoint pubPoint = new ECPoint(new BigInteger(1, x), new BigInteger(1, y));
                ECPublicKeySpec pubSpec = new ECPublicKeySpec(pubPoint, params);
                pubKey = kf.generatePublic(pubSpec);
                // private
                if (this.tokenJWK.has(D)) {
                    byte[] s = ConvertUtil.toBase64URLSafeDecode(this.tokenJWK.get(D).getAsString());
                    ECPrivateKeySpec priSpec = new ECPrivateKeySpec(new BigInteger(1, s), params);
                    priKey = kf.generatePrivate(priSpec);
                }
                return new KeyPair(pubKey, priKey);
            } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
                throw new InvalidKeySpecException(ex.getMessage(), ex);
            }
        }

        static ECParameterSpec jwkToECParameterSpec(String crv) {
            String curveName = switch (crv) {
                case "P-256" ->
                    "secp256r1";
                case "P-384" ->
                    "secp384r1";
                case "P-521" ->
                    "secp521r1";
                case "secp256k1" ->
                    "secp256k1";
                default ->
                    throw new IllegalArgumentException("Unsupported curve: " + crv);
            };

            ECNamedCurveParameterSpec params = ECNamedCurveTable.getParameterSpec(curveName);
            return new ECNamedCurveSpec(
                    curveName,
                    params.getCurve(),
                    params.getG(),
                    params.getN(),
                    params.getH(),
                    params.getSeed());
        }

        public static ECKey build(KeyPair keyPair) {
            ECKey ecKey = new ECKey(keyPair);
            return ecKey;
        }

        private JsonObject toJsonObject() throws InvalidKeySpecException {
            LinkedHashMap<String, String> jwk = new LinkedHashMap<>();
            try {
                KeyFactory kf = KeyFactory.getInstance(KEY_TYPE, BouncyCastleProvider.PROVIDER_NAME);
                ECPublicKeySpec pubSpec = kf.getKeySpec(this.keyPair.getPublic(), ECPublicKeySpec.class);

                jwk.put(KTY, KEY_TYPE);
                ECPoint w = pubSpec.getW();

                byte[] xBytes = w.getAffineX().toByteArray();
                byte[] yBytes = w.getAffineY().toByteArray();

                int fieldSize = pubSpec.getParams().getCurve().getField().getFieldSize();
                String x = ConvertUtil.toBase64URLSafeEncode(normalize(xBytes, fieldSize));
                String y = ConvertUtil.toBase64URLSafeEncode(normalize(yBytes, fieldSize));

                String curveName = mapCurveName(fieldSize);
                // public
                jwk.put(CRV, curveName);
                jwk.put(X, x);
                jwk.put(Y, y);

                // private
                if (this.keyPair.getPrivate() != null) {
                    ECPrivateKeySpec priSpec = kf.getKeySpec(this.keyPair.getPrivate(), ECPrivateKeySpec.class);
                    byte[] sBytes = priSpec.getS().toByteArray();
                    BigInteger a = new BigInteger(1, sBytes);
                    a.toByteArray();
                    String s = ConvertUtil.toBase64URLSafeEncode(normalize(sBytes, fieldSize));
                    jwk.put(D, s);
                }
            } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
                throw new InvalidKeySpecException(ex.getMessage(), ex);
            }
            Gson gson = new Gson();
            JsonElement jsonElement = gson.toJsonTree(jwk);
            return jsonElement.getAsJsonObject();
        }

        @Override
        public String toJWK(boolean pretty) throws InvalidKeySpecException {
            return JsonUtil.prettyJson(toJsonObject(), pretty);
        }

        public String toJWKSet(boolean pretty) throws InvalidKeySpecException {
            List<JsonObject> jwks = List.of(toJsonObject());
            return JsonUtil.prettyJson(jsonJWKSet(jwks), pretty);
        }

        private static String mapCurveName(int fieldSize) {
            switch (fieldSize) {
                case 256:
                    return "P-256";
                case 384:
                    return "P-384";
                case 521:
                    return "P-521";
                default:
                    throw new IllegalArgumentException("Unsupported curve size: " + fieldSize);
            }
        }

    }

    public static class EDKey implements JWKKey {
        public final static String KEY_TYPE = "OKP";
        public final static String CRV = "crv";
        public final static String X = "x";
        public final static String D = "d";

        private final JsonObject tokenJWK;
        private final KeyPair keyPair;

        private EDKey(JsonObject tokenJWK) {
            this.tokenJWK = tokenJWK;
            this.keyPair = null;
        }

        private EDKey(KeyPair keyPair) {
            this.keyPair = keyPair;
            this.tokenJWK = null;
        }

        @Override
        public String getKeyType() {
            return KEY_TYPE;
        }

        @Override
        public boolean isPrivate() {
            if (tokenJWK != null) {
                return this.tokenJWK.has(EDKey.D);
            } else {
                return this.keyPair.getPrivate() instanceof EdECPrivateKey;
            }
        }

        private static boolean hasKeyType(JsonObject tokenJWK) {
            return tokenJWK.has(KTY) && KEY_TYPE.equals(tokenJWK.get(KTY).getAsString());
        }

        public static EDKey parse(String jsonJWK) throws InvalidKeySpecException {
            try {
                JsonObject jwkObject = JsonUtil.parseJsonObject(jsonJWK);
                if (!hasKeyType(jwkObject)) throw new InvalidKeySpecException("Invalid key spec:" + jsonJWK);
                EDKey edKey = new EDKey(jwkObject);
                return edKey;
            } catch (JsonSyntaxException ex) {
                throw new InvalidKeySpecException(ex);
            }
        }

        @Override
        public KeyPair toKeyPair() throws InvalidKeySpecException {
            try {
                PublicKey pubKey = null;
                PrivateKey priKey = null;
//                String kty = this.tokenJWK.get(KTY).getAsString();
                String curve = this.tokenJWK.get(CRV).getAsString();
                KeyFactory kf = KeyFactory.getInstance(curve, BouncyCastleProvider.PROVIDER_NAME);
                byte[] x = ConvertUtil.toBase64URLSafeDecode(this.tokenJWK.get(X).getAsString());
                SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(mapCurveIdentifier(curve), x);
                pubKey = kf.generatePublic(new X509EncodedKeySpec(spki.getEncoded()));
                // private
                if (this.tokenJWK.has(D)) {
                    byte[] d = ConvertUtil.toBase64URLSafeDecode(this.tokenJWK.get(D).getAsString());
                    org.bouncycastle.asn1.pkcs.PrivateKeyInfo pki = new org.bouncycastle.asn1.pkcs.PrivateKeyInfo(
                                    mapCurveIdentifier(curve),
                                    new org.bouncycastle.asn1.DEROctetString(d)
                    );
                    PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(pki.getEncoded());
                    priKey = kf.generatePrivate(privateSpec);
                }
                return new KeyPair(pubKey, priKey);
            } catch (NoSuchAlgorithmException | NoSuchProviderException | IOException ex) {
                throw new InvalidKeySpecException(ex.getMessage(), ex);
            }
        }

        static org.bouncycastle.asn1.x509.AlgorithmIdentifier mapCurveIdentifier(String crv) {
            org.bouncycastle.asn1.x509.AlgorithmIdentifier algo = switch (crv) {
                case "Ed25519" ->
                    new org.bouncycastle.asn1.x509.AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519);
                case "Ed448" ->
                    new org.bouncycastle.asn1.x509.AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed448);
                default ->
                    throw new IllegalArgumentException("Unsupported curve: " + crv);
            };
            return algo;
        }

        public static EDKey build(KeyPair keyPair) {
            EDKey edKey = new EDKey(keyPair);
            return edKey;
        }

        private JsonObject toJsonObject() throws InvalidKeySpecException {
            LinkedHashMap<String, String> jwk = new LinkedHashMap<>();
            try {
                EdECPublicKey edPub = (EdECPublicKey)this.keyPair.getPublic();
                String curve = edPub.getAlgorithm();
                //KeyFactory kf = KeyFactory.getInstance(curve, BouncyCastleProvider.PROVIDER_NAME);
                //EdECPublicKeySpec pubSpec = kf.getKeySpec(this.keyPair.getPublic(), EdECPublicKeySpec.class);
                SubjectPublicKeyInfo pubKeyInfo = SubjectPublicKeyInfo.getInstance(edPub.getEncoded());
                jwk.put(KTY, KEY_TYPE);
                byte[] pubKeyBytes = pubKeyInfo.getPublicKeyData().getBytes();
                String x = ConvertUtil.toBase64URLSafeEncode(pubKeyBytes);
                jwk.put(CRV, curve);
                jwk.put(X, x);
                if (this.keyPair.getPrivate() instanceof EdECPrivateKey edPrivKey) {
//                    PrivateKeyInfo priKeyInfo = PrivateKeyInfo.getInstance(edPrivKey.getEncoded());
//                    byte[] privKeyBytes = priKeyInfo.parsePrivateKey().toASN1Primitive().getEncoded();
//                    // (Ed25519 32バイト/Ed448 57バイト)
//                    String d = ConvertUtil.toBase64URLSafeEncode(privKeyBytes);
                    AsymmetricKeyParameter privateKeyParam = PrivateKeyFactory.createKey(edPrivKey.getEncoded());
                    if (privateKeyParam instanceof Ed25519PrivateKeyParameters edPrivate) {
                        String d = ConvertUtil.toBase64URLSafeEncode(edPrivate.getEncoded());
                        jwk.put(D, d);
                    }
                    else if (privateKeyParam instanceof Ed448PrivateKeyParameters edPrivate) {
                        String d = ConvertUtil.toBase64URLSafeEncode(edPrivate.getEncoded());
                        jwk.put(D, d);
                    }
                    else {
                        throw new IllegalArgumentException("Unsupported curve: " + curve);
                    }
                }
            } catch (IOException ex) {
                throw new InvalidKeySpecException(ex.getMessage(), ex);
            }
            Gson gson = new Gson();
            JsonElement jsonElement = gson.toJsonTree(jwk);
            return jsonElement.getAsJsonObject();
        }

        @Override
        public String toJWK(boolean pretty) throws InvalidKeySpecException {
            return JsonUtil.prettyJson(toJsonObject(), pretty);
        }

        public String toJWKSet(boolean pretty) throws InvalidKeySpecException {
            List<JsonObject> jwks = List.of(toJsonObject());
            return JsonUtil.prettyJson(jsonJWKSet(jwks), pretty);
        }

    }

}
