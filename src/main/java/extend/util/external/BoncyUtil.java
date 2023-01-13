package extend.util.external;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.Key;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.Certificate;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

/**
 *
 * @author isayan
 */
public class BoncyUtil {
    private final static BouncyCastleProvider BC_PROVIDER = new BouncyCastleProvider();

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BC_PROVIDER);
        }
    }

    public static void storeCertificatePem(Certificate cert, File to) throws IOException {
        try (JcaPEMWriter pw = new JcaPEMWriter(new FileWriter(to))) {
            pw.writeObject(cert);
        }
    }

    public static void storeCertificatePem(KeyPair pair, File to) throws IOException {
        try (JcaPEMWriter pw = new JcaPEMWriter(new FileWriter(to))) {
            pw.writeObject(pair);
        }
    }

    public static void storeCertificatePem(KeyPair pair, Certificate cert, File to) throws IOException {
        try (JcaPEMWriter pw = new JcaPEMWriter(new FileWriter(to))) {
            pw.writeObject(pair);
            pw.writeObject(cert);
        }
    }

    public static void storeCertificatePem(Key key, Certificate cert, File to) throws IOException {
        try (JcaPEMWriter pw = new JcaPEMWriter(new FileWriter(to))) {
            pw.writeObject(key);
            pw.writeObject(cert);
        }
    }

}
