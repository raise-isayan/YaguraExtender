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
import static org.junit.jupiter.api.Assertions.assertEquals;
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

    @Test
    public void testHashUtil() {
        System.out.println("testHashUtil");
        {
            String hash = BouncyUtil.toRIPEMD128Sum("hello world", true);
            assertEquals("C52AC4D06245286B33953957BE6C6F81", hash);
        }
        {
            String hash = BouncyUtil.toRIPEMD160Sum("hello world", true);
            assertEquals("98C615784CCB5FE5936FBC0CBE9DFDB408D92F0F", hash);
        }
        {
            String hash = BouncyUtil.toRIPEMD256Sum("hello world", true);
            assertEquals("0D375CF9D9EE95A3BB15F757C81E93BB0AD963EDF69DC4D12264031814608E37", hash);
        }
        {
            String hash = BouncyUtil.toRIPEMD320Sum("hello world", true);
            assertEquals("0E12FE7D075F8E319E07C106917EDDB0135E9A10AEFB50A8A07CCB0582FF1FA27B95ED5AF57FD5C6", hash);
        }
        {
            String hash = BouncyUtil.toTigerSum("hello world", true);
            assertEquals("4C8FBDDAE0B6F25832AF45E7C62811BB64EC3E43691E9CC3", hash);
        }
        {
            String hash = BouncyUtil.toGOST3411Sum("hello world", true);
            assertEquals("C5AA1455AFE9F0C440EEC3C96CCCCB5C8495097572CC0F625278BD0DA5EA5E07", hash);
        }
        {
            String hash = BouncyUtil.toWHIRLPOOLSum("hello world", true);
            assertEquals("8D8309CA6AF848095BCABAF9A53B1B6CE7F594C1434FD6E5177E7E5C20E76CD30936D8606E7F36ACBEF8978FEA008E6400A975D51ABE6BA4923178C7CF90C802", hash);
        }
    }


}
