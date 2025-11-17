package extend.util.external.jws;

import com.google.gson.JsonObject;
import extension.helpers.ConvertUtil;
import extension.helpers.json.JsonUtil;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.LinkedHashMap;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.interfaces.EdDSAPrivateKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import java.security.KeyFactory;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import passive.JWKToken;

/**
 *
 * @author isayan
 */
public class JWKUtil {

    private JWKUtil() {
    }

    public static String toJWK(KeyPair keyPair, boolean pretty) throws InvalidKeySpecException {
        String jwk = null;
        if (keyPair.getPublic() instanceof RSAPublicKey) {
            JWKToken.RSAKey jwkKey = JWKToken.RSAKey.build(keyPair);
            jwk = jwkKey.toJWK(pretty);
        } else if (keyPair.getPublic() instanceof ECPublicKey) {
            JWKToken.ECKey jwkKey = JWKToken.ECKey.build(keyPair);
            jwk = jwkKey.toJWK(pretty);
        } else if (keyPair.getPublic() instanceof EdECPublicKey) {
            JWKToken.EDKey jwkKey = JWKToken.EDKey.build(keyPair);
            jwk = jwkKey.toJWK(pretty);
        }
        return jwk;
    }

    public static KeyPair parseJWK(String jsonJWK) throws InvalidKeySpecException {
        JsonObject jwk = JsonUtil.parseJsonObject(jsonJWK);
        String kty = jwk.get(JWKToken.JWKKey.KTY).getAsString();
        KeyPair keyPair = null;
        if (JWKToken.RSAKey.ALGORITHM.equals(kty)) {
            JWKToken.RSAKey jwkKey = JWKToken.RSAKey.parse(jsonJWK);
            keyPair = jwkKey.toKeyPair();
        } else if (JWKToken.ECKey.ALGORITHM.equals(kty)) {
            JWKToken.ECKey jwkKey = JWKToken.ECKey.parse(jsonJWK);
            keyPair = jwkKey.toKeyPair();
        } else if (JWKToken.EDKey.ALGORITHM.equals(kty)) {
            JWKToken.EDKey jwkKey = JWKToken.EDKey.parse(jsonJWK);
            keyPair = jwkKey.toKeyPair();
        }
        if (keyPair == null) {
            throw new InvalidKeySpecException();
        }
        if (keyPair.getPublic() == null) {
            throw new InvalidKeySpecException();
        }
        return keyPair;
    }

}
