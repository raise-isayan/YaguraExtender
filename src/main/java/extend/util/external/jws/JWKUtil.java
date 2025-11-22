package extend.util.external.jws;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import extension.helpers.json.JsonUtil;
import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.interfaces.EdECPublicKey;
import java.util.ArrayList;
import java.util.List;
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
        if (jwk == null) {
            throw new InvalidKeySpecException("Invalid KeyPair");
        }
        return jwk;
    }

    public static String toJWKS(KeyPair keyPair, boolean pretty) throws InvalidKeySpecException {
        String jwk = null;
        if (keyPair.getPublic() instanceof RSAPublicKey) {
            JWKToken.RSAKey jwkKey = JWKToken.RSAKey.build(keyPair);
            jwk = jwkKey.toJWKS(pretty);
        } else if (keyPair.getPublic() instanceof ECPublicKey) {
            JWKToken.ECKey jwkKey = JWKToken.ECKey.build(keyPair);
            jwk = jwkKey.toJWKS(pretty);
        } else if (keyPair.getPublic() instanceof EdECPublicKey) {
            JWKToken.EDKey jwkKey = JWKToken.EDKey.build(keyPair);
            jwk = jwkKey.toJWKS(pretty);
        }
        if (jwk == null) {
            throw new InvalidKeySpecException("Invalid KeyPair");
        }
        return jwk;
    }

    public static KeyPair parseJWK(String jsonJWK) throws InvalidKeySpecException {
        JsonObject jwkObject = JsonUtil.parseJsonObject(jsonJWK);
        return parseJWK(jwkObject);
    }

    private static KeyPair parseJWK(JsonObject jwkObject) throws InvalidKeySpecException {
        String kty = jwkObject.get(JWKToken.JWKKey.KTY).getAsString();
        KeyPair keyPair = null;
        if (JWKToken.RSAKey.KEY_TYPE.equals(kty)) {
            JWKToken.RSAKey jwkKey = JWKToken.RSAKey.parse(jwkObject);
            keyPair = jwkKey.toKeyPair();
        } else if (JWKToken.ECKey.KEY_TYPE.equals(kty)) {
            JWKToken.ECKey jwkKey = JWKToken.ECKey.parse(jwkObject);
            keyPair = jwkKey.toKeyPair();
        } else if (JWKToken.EDKey.KEY_TYPE.equals(kty)) {
            JWKToken.EDKey jwkKey = JWKToken.EDKey.parse(jwkObject);
            keyPair = jwkKey.toKeyPair();
        }
        if (keyPair == null) {
            throw new InvalidKeySpecException("Invalid KeyPair");
        }
        if (keyPair.getPublic() == null) {
            throw new InvalidKeySpecException("not include Public key");
        }
        return keyPair;
    }

    public static List<KeyPair> parseJWKS(String jsonJWK) throws InvalidKeySpecException {
        JsonObject jwkObject = JsonUtil.parseJsonObject(jsonJWK);
        return parseJWKS(jwkObject);
    }

    private static List<KeyPair> parseJWKS(JsonObject jwkObject) throws InvalidKeySpecException {
        List<KeyPair> keyList = new ArrayList<>();
        if (jwkObject.has(JWKToken.JWKKey.KEYS)) {
            JsonElement jsonKeySet = jwkObject.get(JWKToken.JWKKey.KEYS);
            if (jsonKeySet.isJsonArray()) {
                JsonArray keys = jsonKeySet.getAsJsonArray();
                for (int i = 0; i < keys.size(); i++) {
                    JsonElement key = keys.get(i);
                    keyList.add(parseJWK(key.getAsJsonObject()));
                }
            }
        }
        return keyList;
    }

}
