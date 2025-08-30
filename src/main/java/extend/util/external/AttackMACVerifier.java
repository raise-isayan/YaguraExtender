package extend.util.external;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.impl.HMAC;
import com.nimbusds.jose.util.Base64URL;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.ListIterator;
import java.util.Scanner;
import java.util.stream.Collectors;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author isayan
 */
public class AttackMACVerifier extends WeakMACProvider implements JWSVerifier {
    private final List<SecretKey> attackList;
    private final ListIterator<SecretKey> ite;

    protected AttackMACVerifier(final List<SecretKey> attackList) {
        this.attackList = attackList;
        this.ite = attackList.listIterator();
    }

    public int current() {
        return this.ite.nextIndex() - 1;
    }

    public boolean hasCurrentSecretKey() {
        return this.ite.hasPrevious();
    }

    public boolean hasNextSecretKey() {
        return this.ite.hasNext();
    }

    public SecretKey currentSecretKey() {
        return this.ite.previous();
    }

    public SecretKey nextSecretKey() {
        return this.ite.next();
    }

    @Override
    public boolean verify(final JWSHeader header,
            final byte[] signedContent,
            final Base64URL signature)
            throws JOSEException {
        String jcaAlg = getJCAAlgorithmName(header.getAlgorithm());
        byte[] hmac = HMAC.compute(jcaAlg, nextSecretKey(), signedContent, getJCAContext().getProvider());
        Base64URL expectedSignature = Base64URL.encode(hmac);
        return (expectedSignature.equals(signature));
    }

    public List<SecretKey> toSecretKeyList(List<String> list) {
        return list.stream().map(key -> {
            return new SecretKeySpec(key.getBytes(StandardCharsets.ISO_8859_1), "MAC");
        }).collect(Collectors.toList());
    }

    public static List<SecretKey> loadFromStream(InputStream stream) throws IOException {
        List<SecretKey> signatures = new ArrayList<>();
        try (Scanner scanner = new Scanner(stream, StandardCharsets.UTF_8.name())) {
            while (scanner.hasNextLine()) {
                String line = scanner.nextLine();
                if (line.trim().length() == 0) {
                    continue;
                }
                signatures.add(new SecretKeySpec(line.getBytes(StandardCharsets.ISO_8859_1), "MAC"));
            }
        }
        return signatures;
    }

}
