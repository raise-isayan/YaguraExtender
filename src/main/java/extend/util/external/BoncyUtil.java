package extend.util.external;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.Key;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.AbstractMap;
import java.util.Map;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.io.pem.PemObject;

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

    public static Map.Entry<Key, X509Certificate> loadFromPem(File storeFile, String password) {
        try {
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            PemReader pemParser = new PemReader(new FileReader(storeFile));
            PemObject pemObject = pemParser.readPemObject();
            PrivateKey privateKey = null;
            X509Certificate x509Certificate = null;
            while (pemObject != null) {
                if ("TYPE_CERTIFICATE".equals(pemObject.getType())) {
                    byte cert[] = pemObject.getContent();
                    try (ByteArrayInputStream inStream = new ByteArrayInputStream(cert)) {
                        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509",  BouncyCastleProvider.PROVIDER_NAME);
                        Certificate certificate = certificateFactory.generateCertificate(inStream);
                        x509Certificate = (X509Certificate)certificate;
                    }
                } else {
                    PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(pemObject);
                    privateKey = converter.getPrivateKey(privateKeyInfo);
                }
                pemObject = pemParser.readPemObject();
            }
            return new AbstractMap.SimpleEntry(privateKey, x509Certificate);
        } catch (IOException ex) {
        } catch (CertificateException ex) {
        } catch (NoSuchProviderException ex) {
        }
        return null;
    }

    public static void storeCertificatePem(Key key, File to) throws IOException {
        try (JcaPEMWriter pw = new JcaPEMWriter(new FileWriter(to))) {
            pw.writeObject(key);
        }
    }

    public static void storeCertificatePem(Certificate cert, File to) throws IOException {
        try (JcaPEMWriter pw = new JcaPEMWriter(new FileWriter(to))) {
            pw.writeObject(cert);
        }
    }

    public static void storeCertificatePem(Key key, Certificate cert, File to) throws IOException {
        try (JcaPEMWriter pw = new JcaPEMWriter(new FileWriter(to))) {
            pw.writeObject(key);
            pw.writeObject(cert);
        }
    }

    public static void storeCertificateDer(Key key, File to) throws IOException {
        byte [] keyBytes = key.getEncoded();
        try (FileOutputStream fos = new FileOutputStream(to)) {
            fos.write(keyBytes);
        }
    }

    public static void storeCertificateDer(Certificate cert, File to) throws IOException {
        try {
            byte [] certBytes = cert.getEncoded();
            try (FileOutputStream fos = new FileOutputStream(to)) {
                fos.write(certBytes);
            }
        }   catch (CertificateEncodingException ex) {
            throw new IOException(ex);
        }
    }

}
