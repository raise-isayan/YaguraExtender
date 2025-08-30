package extend.util.external;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.text.ParseException;

/**
 */
public class JWSUtil {

    public JWSAlgorithm[] ALG_NAMES = new JWSAlgorithm[]{
        JWSAlgorithm.HS256,
        JWSAlgorithm.HS384,
        JWSAlgorithm.HS512,
        JWSAlgorithm.RS256,
        JWSAlgorithm.RS384,
        JWSAlgorithm.RS512,
        JWSAlgorithm.ES256,
        //JWSAlgorithm.ES256K,
        JWSAlgorithm.ES384,
        JWSAlgorithm.ES512,
        JWSAlgorithm.PS256,
        JWSAlgorithm.PS384,
        JWSAlgorithm.PS512,
        //JWSAlgorithm.EdDSA,
        //JWSAlgorithm.Ed25519,
        // JWSAlgorithm.Ed448;
    };

    private JWSUtil() {
    }

    private static Payload algNoneHeader() {
        JWTClaimsSet header = new JWTClaimsSet.Builder()
                .claim("alg", JWSAlgorithm.NONE.getName())
                .build();
        return header.toPayload();
    }

    public static String jwtAlgNone(Payload payload) {
        return serialize(algNoneHeader().toBase64URL(), payload.toBase64URL());
    }

    public static String serialize(Base64URL header, Base64URL payload) {
        StringBuilder token = new StringBuilder();
        return token.append(header.toString()).append('.').append(payload.toString()).append('.').toString();
    }

    public static boolean isValidJWT(String token) {
        try {
            SignedJWT.parse(token);
            return true;
        } catch (ParseException ex) {
            return false;
        }
    }

}
