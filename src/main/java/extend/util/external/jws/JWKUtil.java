package extend.util.external.jws;

import com.google.gson.JsonObject;
import extension.helpers.json.JsonUtil;
import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.interfaces.EdECPublicKey;
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
        if (JWKToken.RSAKey.KEY_TYPE.equals(kty)) {
            JWKToken.RSAKey jwkKey = JWKToken.RSAKey.parse(jsonJWK);
            keyPair = jwkKey.toKeyPair();
        } else if (JWKToken.ECKey.KEY_TYPE.equals(kty)) {
            JWKToken.ECKey jwkKey = JWKToken.ECKey.parse(jsonJWK);
            keyPair = jwkKey.toKeyPair();
        } else if (JWKToken.EDKey.KEY_TYPE.equals(kty)) {
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
