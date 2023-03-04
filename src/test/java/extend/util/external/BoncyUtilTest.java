package extend.util.external;

import extension.helpers.CertUtil;
import java.io.File;
import java.security.Key;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
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
    public void testBouncyUtil() {
        System.out.println("testBouncyUtil");
        String storeFileName = BoncyUtilTest.class.getResource("/resources/burpca.p12").getPath();
        HashMap<String, Map.Entry<Key, X509Certificate>> certMap = CertUtil.loadFromPKCS12(new File(storeFileName), "testca");
        for (String key : certMap.keySet()) {
            Map.Entry<Key, X509Certificate> cert = certMap.get(key);
            System.out.println(cert.getValue().getType());
            System.out.println(cert.getValue().getSubjectX500Principal().getName());
        }
    }
}
