package extend.util.external;

import java.security.Security;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.BeforeAll;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

/**
 *
 * @author isayan
 */
public class BoncyUtilTest {

    private final static BouncyCastleProvider BC_PROVIDER = new BouncyCastleProvider();

    public BoncyUtilTest() {
    }

    @BeforeAll
    public static void setUpClass() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BC_PROVIDER);
        }
    }

    @AfterAll
    public static void tearDownClass() {
    }

    @BeforeEach
    public void setUp() {
    }

    @AfterEach
    public void tearDown() {
    }

    @Test
    public void testLoadFromPem() {
    }

//    /**
//     * Test of loadFromPem method, of class BoncyUtil.
//     */
//    @Test
//    public void testLoadFromPem() {
//        System.out.println("loadFromPem");
//        String storeFileName = BoncyUtilTest.class.getResource("/resources/burpca.p12").getPath();
//        HashMap<String, Map.Entry<Key, X509Certificate>> certMap = CertUtil.loadFromPKCS12(new File(storeFileName), "testca");
//        try {
//            for (String alias : certMap.keySet()) {
//                {
//                    File priFile = File.createTempFile("pri", "pem");
//                    Map.Entry<Key, X509Certificate> cert = certMap.get(alias);
//                    BoncyUtil.storeCertificatePem(cert.getKey(), priFile);
//                    File privatekeyPath = new File(BoncyUtilTest.class.getResource("/resources/burpca_privatekey.pem").getPath());
//                    String s1 = StringUtil.getStringRaw(Files.readAllBytes(priFile.toPath()));
//                    String s2 = StringUtil.getStringRaw(Files.readAllBytes(privatekeyPath.toPath()));
//                    assertEquals(s1, s2);
//                }
//                {
//                    File certFile = File.createTempFile("cert", "pem");
//                    Map.Entry<Key, X509Certificate> cert = certMap.get(alias);
//                    BoncyUtil.storeCertificatePem(cert.getValue(), certFile);
//                    File certificatePath = new File(BoncyUtilTest.class.getResource("/resources/burpca_certificate.pem").getPath());
//                    String s1 = StringUtil.getStringRaw(Files.readAllBytes(certFile.toPath()));
//                    String s2 = StringUtil.getStringRaw(Files.readAllBytes(certificatePath.toPath()));
//                    assertEquals(s1, s2);
//                }
//            }
//        }
//        catch (IOException ex) {
//            Logger.getLogger(BoncyUtilTest.class.getName()).log(Level.SEVERE, null, ex);
//        }
//    }
}
