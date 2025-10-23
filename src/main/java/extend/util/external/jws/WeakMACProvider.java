package extend.util.external.jws;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.impl.AlgorithmSupportMessage;
import com.nimbusds.jose.crypto.impl.BaseJWSProvider;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

public class WeakMACProvider extends BaseJWSProvider {

    /**
     * The supported JWS algorithms by the MAC provider class.
     */
    public static final Set<JWSAlgorithm> SUPPORTED_ALGORITHMS;

    static {
        Set<JWSAlgorithm> algs = new LinkedHashSet<>();
        algs.add(JWSAlgorithm.HS256);
        algs.add(JWSAlgorithm.HS384);
        algs.add(JWSAlgorithm.HS512);
        SUPPORTED_ALGORITHMS = Collections.unmodifiableSet(algs);
    }

    /**
     * Gets the matching Java Cryptography Architecture (JCA) algorithm name for
     * the specified HMAC-based JSON Web Algorithm (JWA).
     *
     * @param alg The JSON Web Algorithm (JWA). Must be supported and not
     * {@code null}.
     *
     * @return The matching JCA algorithm name.
     *
     * @throws JOSEException If the algorithm is not supported.
     */
    public static String getJCAAlgorithmName(final JWSAlgorithm alg)
            throws JOSEException {
        if (alg.equals(JWSAlgorithm.HS256)) {
            return "HMACSHA256";
        } else if (alg.equals(JWSAlgorithm.HS384)) {
            return "HMACSHA384";
        } else if (alg.equals(JWSAlgorithm.HS512)) {
            return "HMACSHA512";
        } else {
            throw new JOSEException(AlgorithmSupportMessage.unsupportedJWSAlgorithm(alg, SUPPORTED_ALGORITHMS));
        }
    }

    public WeakMACProvider() {
        super(SUPPORTED_ALGORITHMS);
    }

}
