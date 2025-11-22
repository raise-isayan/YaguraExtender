package extend.util.external.jws;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;

/**
 *
 * @author isayan
 */
public class JWKJoseUtil {

    public static KeyPair parseRSAJWK(String jsonJWK) throws InvalidKeySpecException
    {
        try {
            JWK jwk = JWK.parse(jsonJWK);
            return jwk.toRSAKey().toKeyPair();
        } catch (ParseException | JOSEException ex) {
            throw new InvalidKeySpecException(ex);
        }
    }

    public static String toRSAJWK(KeyPair keyPair) {
       if (keyPair.getPublic() instanceof RSAPublicKey) {
            RSAKey.Builder key = new RSAKey.Builder((RSAPublicKey)keyPair.getPublic());
            return key.build().toJSONString();
       }
       return null;
    }
}
