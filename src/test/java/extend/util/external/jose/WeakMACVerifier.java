package extend.util.external.jose;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.impl.HMAC;
import com.nimbusds.jose.util.Base64URL;
import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author isayan
 */
public class WeakMACVerifier extends WeakMACProvider implements JWSVerifier {

    private final SecretKey secretKey;

    public WeakMACVerifier(final String secretString) {
        this(secretString.getBytes(StandardCharsets.ISO_8859_1));
    }

    public WeakMACVerifier(final byte [] secretByte) {
        this.secretKey = new SecretKeySpec(secretByte, "MAC");
    }

    public WeakMACVerifier(SecretKey secretKey) {
        this.secretKey = secretKey;
    }

    @Override
    public boolean verify(final JWSHeader header,
            final byte[] signedContent,
            final Base64URL signature)
            throws JOSEException {
        String jcaAlg = getJCAAlgorithmName(header.getAlgorithm());
        byte[] hmac = HMAC.compute(jcaAlg, this.secretKey, signedContent, getJCAContext().getProvider());
        Base64URL expectedSignature = Base64URL.encode(hmac);
        return (expectedSignature.equals(signature));
    }

}
