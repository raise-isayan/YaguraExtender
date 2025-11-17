package passive;

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
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.LinkedHashMap;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
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

    private static byte[] padding(byte[] bytes, int fieldSize) {
        int sizeBytes = (fieldSize + 7) / 8;
        if (bytes.length < sizeBytes) {
            byte[] padded = new byte[sizeBytes];
            System.arraycopy(bytes, 0, padded, sizeBytes - bytes.length, bytes.length);
            bytes = padded;
        }
        return bytes;
    }

    public static interface JWKKey {
        public final static String KTY = "kty";

        public String getAlgorithm();

        public boolean isPrivate();

        public KeyPair toKeyPair() throws InvalidKeySpecException;

        public String toJWK(boolean pretty) throws InvalidKeySpecException;

    }

    public static class RSAKey implements JWKKey {
        public final static String ALGORITHM = "RSA";
        public final static String N = "n";
        public final static String E = "e";
        public final static String D = "d";

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
        public String getAlgorithm() {
            return ALGORITHM;
        }

        @Override
        public boolean isPrivate() {
            if (tokenJWK != null) {
                return this.tokenJWK.has(RSAKey.D);
            }
            else {
                return this.keyPair.getPrivate() instanceof RSAPrivateKey;
            }
        }

        public static RSAKey parse(String jsonJWK) throws InvalidKeySpecException {
            try {
                JsonObject jwkObject = JsonUtil.parseJsonObject(jsonJWK);
                RSAKey rsaKey = new RSAKey(jwkObject);
                return rsaKey;
            } catch (JsonSyntaxException ex) {
                throw new InvalidKeySpecException(ex);
            }
        }

        @Override
        public KeyPair toKeyPair() throws InvalidKeySpecException {
            try {
                String kty = this.tokenJWK.get(KTY).getAsString();
                PublicKey pubKey = null;
                PrivateKey priKey = null;
                KeyFactory kf = KeyFactory.getInstance(kty, BouncyCastleProvider.PROVIDER_NAME);
                // public
                byte[] n = ConvertUtil.toBase64URLSafeDecode(this.tokenJWK.get(RSAKey.N).getAsString());
                byte[] e = ConvertUtil.toBase64URLSafeDecode(this.tokenJWK.get(RSAKey.E).getAsString());

                RSAPublicKeySpec pubSpec = new RSAPublicKeySpec(new BigInteger(1, n), new BigInteger(1, e));
                pubKey = kf.generatePublic(pubSpec);

                // private
                if (this.tokenJWK.has(RSAKey.D)) {
                    byte[] d = ConvertUtil.toBase64URLSafeDecode(this.tokenJWK.get(RSAKey.D).getAsString());
                    RSAPrivateKeySpec priSpec = new RSAPrivateKeySpec(new BigInteger(1, n), new BigInteger(1, d));
                    priKey = kf.generatePrivate(priSpec);
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

        @Override
        public String toJWK(boolean pretty) throws InvalidKeySpecException {
            LinkedHashMap<String, String> jwk = new LinkedHashMap<>();
            try {
                KeyFactory kf = KeyFactory.getInstance(this.keyPair.getPublic().getAlgorithm(), BouncyCastleProvider.PROVIDER_NAME);
                RSAPublicKeySpec pubSpec = kf.getKeySpec(this.keyPair.getPublic(), RSAPublicKeySpec.class);

                jwk.put(KTY, RSAKey.ALGORITHM);

                // public
                String n = ConvertUtil.toBase64URLSafeEncode(pubSpec.getModulus().toByteArray());
                String e = ConvertUtil.toBase64URLSafeEncode(pubSpec.getPublicExponent().toByteArray());
                jwk.put(RSAKey.N, n);
                jwk.put(RSAKey.E, e);

                // private
                if (keyPair.getPrivate() != null) {
                    RSAPrivateKeySpec priSpec = kf.getKeySpec(this.keyPair.getPrivate(), RSAPrivateKeySpec.class);
                    String d = ConvertUtil.toBase64URLSafeEncode(priSpec.getPrivateExponent().toByteArray());
                    jwk.put(RSAKey.D, d);
                }
            } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
                throw new InvalidKeySpecException(ex.getMessage(), ex);
            }
            return JsonUtil.prettyJson(jwk, pretty);
        }

    }

    public static class ECKey implements JWKKey {
        public final static String ALGORITHM = "EC";
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
        public String getAlgorithm() {
            return ALGORITHM;
        }

        @Override
        public boolean isPrivate() {
            if (tokenJWK != null) {
                return this.tokenJWK.has(ECKey.D);
            }
            else {
                return this.keyPair.getPrivate() instanceof ECPrivateKey;
            }
        }

        public static ECKey parse(String jsonJWK) throws InvalidKeySpecException {
            try {
                JsonObject jwkObject = JsonUtil.parseJsonObject(jsonJWK);
                ECKey ecKey = new ECKey(jwkObject);
                return ecKey;
            } catch (JsonSyntaxException ex) {
                throw new InvalidKeySpecException(ex);
            }
        }

        @Override
        public KeyPair toKeyPair() throws InvalidKeySpecException {
            try {
                String kty = this.tokenJWK.get(KTY).getAsString();
                PublicKey pubKey = null;
                PrivateKey priKey = null;
                KeyFactory kf = KeyFactory.getInstance(kty, BouncyCastleProvider.PROVIDER_NAME);
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

        @Override
        public String toJWK(boolean pretty) throws InvalidKeySpecException {
            LinkedHashMap<String, String> jwk = new LinkedHashMap<>();
            try {
                KeyFactory kf = KeyFactory.getInstance(keyPair.getPublic().getAlgorithm(), BouncyCastleProvider.PROVIDER_NAME);
                ECPublicKeySpec pubSpec = kf.getKeySpec(keyPair.getPublic(), ECPublicKeySpec.class);

                jwk.put(KTY, ALGORITHM);
                ECPoint w = pubSpec.getW();

                byte[] xBytes = w.getAffineX().toByteArray();
                byte[] yBytes = w.getAffineY().toByteArray();

                int fieldSize = pubSpec.getParams().getCurve().getField().getFieldSize();
                String x = ConvertUtil.toBase64URLSafeEncode(padding(xBytes, fieldSize));
                String y = ConvertUtil.toBase64URLSafeEncode(padding(yBytes, fieldSize));

                String curveName = mapCurveName(fieldSize);
                // public
                jwk.put(CRV, curveName);
                jwk.put(X, x);
                jwk.put(Y, y);

                // private
                if (keyPair.getPrivate() != null) {
                    ECPrivateKeySpec priSpec = kf.getKeySpec(keyPair.getPrivate(), ECPrivateKeySpec.class);
                    byte[] sBytes = priSpec.getS().toByteArray();
                    String s = ConvertUtil.toBase64URLSafeEncode(padding(sBytes, fieldSize));
                    jwk.put(D, s);
                }
            } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
                throw new InvalidKeySpecException(ex.getMessage(), ex);
            }
            return JsonUtil.prettyJson(jwk, pretty);
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
        public final static String ALGORITHM = "OKP";
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
        public String getAlgorithm() {
            return ALGORITHM;
        }

        @Override
        public boolean isPrivate() {
            if (tokenJWK != null) {
                return this.tokenJWK.has(EDKey.D);
            }
            else {
                return this.keyPair.getPrivate() instanceof EdECPrivateKey;
            }
        }

        public static EDKey parse(String jsonJWK) throws InvalidKeySpecException {
            try {
                JsonObject jwkObject = JsonUtil.parseJsonObject(jsonJWK);
                EDKey edKey = new EDKey(jwkObject);
                return edKey;
            } catch (JsonSyntaxException ex) {
                throw new InvalidKeySpecException(ex);
            }
        }

        @Override
        public KeyPair toKeyPair() throws InvalidKeySpecException {
            try {
                String kty = this.tokenJWK.get(KTY).getAsString();
                String curve = this.tokenJWK.get(CRV).getAsString();
                PublicKey pubKey = null;
                PrivateKey priKey = null;
                KeyFactory kf = KeyFactory.getInstance(curve, BouncyCastleProvider.PROVIDER_NAME);
                byte[] x = ConvertUtil.toBase64URLSafeDecode(this.tokenJWK.get(X).getAsString());
                Ed25519PublicKeyParameters pubParam = new Ed25519PublicKeyParameters(x, 0);
                pubKey = kf.generatePublic(new X509EncodedKeySpec(pubParam.getEncoded()));
                // private
                if (this.tokenJWK.has(D)) {
                    byte[] d = ConvertUtil.toBase64URLSafeDecode(this.tokenJWK.get(D).getAsString());
                    Ed25519PrivateKeyParameters priParam = new Ed25519PrivateKeyParameters(d, 0);
                    priKey = kf.generatePrivate(new PKCS8EncodedKeySpec(priParam.getEncoded()));
                }
                return new KeyPair(pubKey, priKey);
            } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
                throw new InvalidKeySpecException(ex.getMessage(), ex);
            }
        }

        public static EDKey build(KeyPair keyPair) {
            EDKey edKey = new EDKey(keyPair);
            return edKey;
        }

        @Override
        public String toJWK(boolean pretty) throws InvalidKeySpecException {
            LinkedHashMap<String, String> jwk = new LinkedHashMap<>();
            try {
                EdECPublicKey edPub = (EdECPublicKey) this.keyPair.getPublic();
                KeyFactory kf = KeyFactory.getInstance(this.keyPair.getPublic().getAlgorithm(), BouncyCastleProvider.PROVIDER_NAME);
                String curve = edPub.getAlgorithm();
                SubjectPublicKeyInfo pubKeyInfo = SubjectPublicKeyInfo.getInstance(edPub.getEncoded());
                jwk.put(KTY, ALGORITHM);
                byte[] pubKeyBytes = pubKeyInfo.getPublicKeyData().getBytes();
                String x = ConvertUtil.toBase64URLSafeEncode(pubKeyBytes);
                jwk.put(CRV, curve);
                jwk.put(X, x);
                if (this.keyPair.getPrivate() instanceof EdECPrivateKey edPrivKey) {
                    PrivateKeyInfo priKeyInfo = PrivateKeyInfo.getInstance(edPrivKey.getEncoded());
                    byte[] privKeyBytes = priKeyInfo.parsePrivateKey().toASN1Primitive().getEncoded();
                    // (Ed25519 32バイト/Ed448 57バイト)
                    String d = ConvertUtil.toBase64URLSafeEncode(privKeyBytes);
                    jwk.put(D, d);
                }
            } catch (NoSuchAlgorithmException | NoSuchProviderException | IOException ex) {
                throw new InvalidKeySpecException(ex.getMessage(), ex);
            }
            return JsonUtil.prettyJson(jwk, pretty);
        }
    }

}
