package extend.util.external.jws;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.impl.HMAC;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.StandardCharset;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import passive.JWSToken;
import passive.JsonToken;

/**
 * https://github.com/felx/nimbus-jose-jwt
 *
 * Apache license
 * https://github.com/felx/nimbus-jose-jwt?tab=Apache-2.0-1-ov-file#readme
 */
public class WeakMACSigner extends WeakMACProvider implements JWSSigner, JWSVerifier {

    /**
     * The secret.
     */
    private final byte[] secret;

    /**
     * Creates a new Message Authentication (MAC) provider.
     *
     * @param secret The secret. Must be at least 256 bits long and not
     * {@code null}.
     */
    protected WeakMACSigner(final byte[] secret) {
        this.secret = secret;
    }

    /**
     * Gets the secret key.
     *
     * @return The secret key.
     */
    public SecretKey getSecretKey() {
        return new SecretKeySpec(secret, "MAC");
    }

    /**
     * Gets the secret bytes.
     *
     * @return The secret bytes.
     */
    public byte[] getSecret() {
        return secret;
    }

    /**
     * Gets the secret as a UTF-8 encoded string.
     *
     * @return The secret as a UTF-8 encoded string.
     */
    public String getSecretString() {
        return new String(secret, StandardCharset.UTF_8);
    }

    /**
     * Creates a new Message Authentication (MAC) signer.
     *
     * @param secretString The secret as a UTF-8 encoded string. Must be at
     * least 256 bits long and not {@code null}.
     */
    public WeakMACSigner(final String secretString) {
        this(secretString.getBytes(StandardCharset.UTF_8));
    }

    /**
     * Creates a new Message Authentication (MAC) signer.
     *
     * @param secretKey The secret key. Must be at least 256 bits long and not
     * {@code null}.
     */
    public WeakMACSigner(final SecretKey secretKey) {
        this(secretKey.getEncoded());
    }

    /**
     * Creates a new Message Authentication (MAC) signer.
     *
     * @param jwk The secret as a JWK. Must be at least 256 bits long and not
     * {@code null}.
     */
    public WeakMACSigner(final OctetSequenceKey jwk) {
        this(jwk.toByteArray());
    }

    @Override
    public Base64URL sign(final JWSHeader header, final byte[] signingInput)
            throws JOSEException {
        String jcaAlg = getJCAAlgorithmName(header.getAlgorithm());
        byte[] hmac = HMAC.compute(jcaAlg, getSecretKey(), signingInput, getJCAContext().getProvider());
        return Base64URL.encode(hmac);
    }

    @Override
    public boolean verify(final JWSHeader header,
            final byte[] signedContent,
            final Base64URL signature)
            throws JOSEException {
        String jcaAlg = getJCAAlgorithmName(header.getAlgorithm());
        byte[] hmac = HMAC.compute(jcaAlg, getSecretKey(), signedContent, getJCAContext().getProvider());
        Base64URL expectedSignature = Base64URL.encode(hmac);
        return (expectedSignature.equals(signature));
    }

}
