package extend.util.external.jws;

import extension.helpers.FileUtil;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import extension.view.base.CaptureItem;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import org.bouncycastle.jcajce.interfaces.EdDSAPrivateKey;
import org.bouncycastle.jcajce.interfaces.EdDSAPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import passive.JWSTokenTest;

/**
 *
 * @author isayan
 */
public class JWSUtilTest {

    public JWSUtilTest() {
    }


    @BeforeAll
    public static void setUpClass() {
        Security.addProvider(new BouncyCastleProvider());
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

    private final String JWT_TOKEN00 = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ5b3VyLWFwcCIsInN1YiI6InVzZXIxMjMiLCJyb2xlIjoiYWRtaW4iLCJleHAiOjE3NTU3ODMxNzV9.dqBgwLri4YJt1FIqjjT1Ljn1LWaoDvACfpX1bgSx8bc";

    private final String JWT_COOKIE00 = "Cookie: sessionid=1234567890; token=eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ5b3VyLWFwcCIsInN1YiI6InVzZXIxMjMiLCJyb2xlIjoiYWRtaW4iLCJleHAiOjE3NTU3ODMxNzV9.dqBgwLri4YJt1FIqjjT1Ljn1LWaoDvACfpX1bgSx8bc uid=aabbcceedd";

    private final String JWT_NONE01 = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJtYWluIjoieHh4eHh4Iiwic3ViIjoi44OG44K544OIIn0.";

    /* secret */
    private final String JWT_TOKEN01 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJtYWluIjoieHh4eHh4Iiwic3ViIjoi44OG44K544OIIn0.IjbkfaSdmROAC0MeW40lJo4s_KoX0VgF0vogsXygNNc";

    @Test
    public void testToRSA() {
        System.out.println("testToRSA");
        try {
            String priRSAKeyPath = JWSTokenTest.class.getResource("/resources/private-rsa-key.pem").getPath();
            String pemRSAKeyPrivateData = FileUtil.stringFromFile(new File(priRSAKeyPath), StandardCharsets.UTF_8);
            String pubRSAKeyKeyPath = JWSTokenTest.class.getResource("/resources/public-rsa-key.pem").getPath();
            String pemRSAKeyPublicData = FileUtil.stringFromFile(new File(pubRSAKeyKeyPath), StandardCharsets.UTF_8);
            {
                RSAPrivateKey rsaPrivateKey = (RSAPrivateKey)JWSUtil.toRSAPrivateKey(pemRSAKeyPrivateData);
                assertNotNull(rsaPrivateKey);

                RSAPublicKey rsaPublicKey = (RSAPublicKey)JWSUtil.toRSAPublicKey(pemRSAKeyPublicData);
                assertNotNull(rsaPublicKey);

                PrivateKey privateKey = (PrivateKey)JWSUtil.toPrivateKey(pemRSAKeyPrivateData);
                assertNotNull(privateKey);

                PublicKey publicKey = (PublicKey)JWSUtil.toPublicKey(pemRSAKeyPublicData);
                assertNotNull(publicKey);
            }

        } catch (IOException ex) {
            fail(ex.getMessage(), ex);
        }
    }

    @Test
    public void testToEC() {
        System.out.println("testToEC");
        try {
            String priECKey256Path = JWSTokenTest.class.getResource("/resources/private-ec256-key.pem").getPath();
            String pemECKey256PrivateData = FileUtil.stringFromFile(new File(priECKey256Path), StandardCharsets.UTF_8);
            String pubECKey256KeyPath = JWSTokenTest.class.getResource("/resources/public-ec256-key.pem").getPath();
            String pemECKey256PublicData = FileUtil.stringFromFile(new File(pubECKey256KeyPath), StandardCharsets.UTF_8);
            {
                ECPrivateKey ecPrivateKey = (ECPrivateKey)JWSUtil.toECPrivateKey(pemECKey256PrivateData);
                assertNotNull(ecPrivateKey);

                ECPublicKey ecPublicKey = (ECPublicKey)JWSUtil.toECPublicKey(pemECKey256PublicData);
                assertNotNull(ecPublicKey);

                PrivateKey privateKey = (PrivateKey)JWSUtil.toPrivateKey(pemECKey256PrivateData);
                assertNotNull(privateKey);

                PublicKey publicKey = (PublicKey)JWSUtil.toPublicKey(pemECKey256PublicData);
                assertNotNull(publicKey);
            }
            String priECKey384Path = JWSTokenTest.class.getResource("/resources/private-ec384-key.pem").getPath();
            String pemECKey384PrivateData = FileUtil.stringFromFile(new File(priECKey384Path), StandardCharsets.UTF_8);
            String pubECKey384KeyPath = JWSTokenTest.class.getResource("/resources/public-ec384-key.pem").getPath();
            String pemECKey384PublicData = FileUtil.stringFromFile(new File(pubECKey384KeyPath), StandardCharsets.UTF_8);
            {
                ECPrivateKey ecPrivateKey = (ECPrivateKey)JWSUtil.toECPrivateKey(pemECKey384PrivateData);
                assertNotNull(ecPrivateKey);

                ECPublicKey ecPublicKey = (ECPublicKey)JWSUtil.toECPublicKey(pemECKey384PublicData);
                assertNotNull(ecPublicKey);

                PrivateKey privateKey = (PrivateKey)JWSUtil.toPrivateKey(pemECKey256PrivateData);
                assertNotNull(privateKey);

                PublicKey publicKey = (PublicKey)JWSUtil.toPublicKey(pemECKey384PublicData);
                assertNotNull(publicKey);
            }
            String priECKey512Path = JWSTokenTest.class.getResource("/resources/private-ec512-key.pem").getPath();
            String pemECKey512PrivateData = FileUtil.stringFromFile(new File(priECKey512Path), StandardCharsets.UTF_8);
            String pubECKey512KeyPath = JWSTokenTest.class.getResource("/resources/public-ec512-key.pem").getPath();
            String pemECKey512PublicData = FileUtil.stringFromFile(new File(pubECKey512KeyPath), StandardCharsets.UTF_8);
            {
                ECPrivateKey ecPrivateKey = (ECPrivateKey)JWSUtil.toECPrivateKey(pemECKey512PrivateData);
                assertNotNull(ecPrivateKey);

                ECPublicKey ecPublicKey = (ECPublicKey)JWSUtil.toECPublicKey(pemECKey512PublicData);
                assertNotNull(ecPublicKey);

                PrivateKey privateKey = (PrivateKey)JWSUtil.toPrivateKey(pemECKey512PrivateData);
                assertNotNull(privateKey);

                PublicKey publicKey = (PublicKey)JWSUtil.toPublicKey(pemECKey512PublicData);
                assertNotNull(publicKey);
            }
        } catch (IOException ex) {
            fail(ex.getMessage(), ex);
        }
    }

    @Test
    public void testToEdDSA() {
        System.out.println("testToEdDSA");
        try {
            String priEdDSAPath = JWSTokenTest.class.getResource("/resources/private-eddsa-key.pem").getPath();
            String pemEdDSAPrivateData = FileUtil.stringFromFile(new File(priEdDSAPath), StandardCharsets.UTF_8);
            String pubEdDSAKeyPath = JWSTokenTest.class.getResource("/resources/public-eddsa-key.pem").getPath();
            String pemEdDSAublicData = FileUtil.stringFromFile(new File(pubEdDSAKeyPath), StandardCharsets.UTF_8);
            {
                EdDSAPrivateKey edsaPrivateKey = JWSUtil.toEdDSAPrivateKey(pemEdDSAPrivateData);
                assertNotNull(edsaPrivateKey);

                EdDSAPublicKey edsaPublicKey = JWSUtil.toEdDSAPublicKey(pemEdDSAublicData);
                assertNotNull(edsaPublicKey);

                PrivateKey privateKey = (PrivateKey)JWSUtil.toPrivateKey(pemEdDSAPrivateData);
                System.out.println("PrivateKey:" + privateKey.getClass().getName());

                assertNotNull(privateKey);

                PublicKey publicKey = (PublicKey)JWSUtil.toPublicKey(pemEdDSAublicData);
                System.out.println("PublicKey:" + privateKey.getClass().getName());
                assertNotNull(publicKey);
            }

        } catch (IOException ex) {
            fail(ex.getMessage(), ex);
        }
    }

    @Test
    public void testFindToken()
    {
        System.out.println("testFindToken");
        final String TOKEN_TOKEN_RESULT = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ5b3VyLWFwcCIsInN1YiI6InVzZXIxMjMiLCJyb2xlIjoiYWRtaW4iLCJleHAiOjE3NTU3ODMxNzV9.dqBgwLri4YJt1FIqjjT1Ljn1LWaoDvACfpX1bgSx8bc";
        {
            CaptureItem[] tokens = JWSUtil.findToken(JWT_TOKEN00);
            for (CaptureItem t : tokens) {
                System.out.println("token:" + t.getCaptureValue());
                System.out.println("start:" + t.start());
                System.out.println("end:" + t.end());
            }
            assertEquals(1, tokens.length);
            assertEquals(TOKEN_TOKEN_RESULT, tokens[0].getCaptureValue());
        }
        {
            CaptureItem[] tokens = JWSUtil.findToken(JWT_COOKIE00);
            for (CaptureItem t : tokens) {
                System.out.println("token:" + t.getCaptureValue());
                System.out.println("start:" + t.start());
                System.out.println("end:" + t.end());
            }
            assertEquals(1, tokens.length);
            assertEquals(TOKEN_TOKEN_RESULT, tokens[0].getCaptureValue());
        }
    }

    @Test
    public void testContainsTokenFormat()
    {
        System.out.println("testContainsTokenFormat");
        {
            String token = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ5b3VyLWFwcCIsInN1YiI6InVzZXIxMjMiLCJyb2xlIjoiYWRtaW4iLCJleHAiOjE3NTU3ODMxNzV9.dqBgwLri4YJt1FIqjjT1Ljn1LWaoDvACfpX1bgSx8bc";
            assertTrue(JWSUtil.containsTokenFormat(token));
        }
        {
            String token = "Cookie: sessionid=1234567890; token=eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ5b3VyLWFwcCIsInN1YiI6InVzZXIxMjMiLCJyb2xlIjoiYWRtaW4iLCJleHAiOjE3NTU3ODMxNzV9.dqBgwLri4YJt1FIqjjT1Ljn1LWaoDvACfpX1bgSx8bc uid=aabbcceedd";
            assertTrue(JWSUtil.containsTokenFormat(token));
        }
    }

    @Test
    public void testSplitSegment()
    {
        System.out.println("testSplitSegment");
        {
            String token = JWT_TOKEN01;
            String [] segment = JWSUtil.splitSegment(token);
            assertEquals(3, segment.length);
        }
        {
            String token = JWT_NONE01;
            String [] segment = JWSUtil.splitSegment(token);
            assertEquals(3, segment.length);
        }
    }

    @Test
    public void testEdDSA()
    {
        System.out.println("testEdDSA");
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Ed25519", "BC");
            KeyPair keyPair = keyGen.generateKeyPair();

            System.out.println("Private key: " + keyPair.getPrivate());
            System.out.println("Private class: " + keyPair.getPrivate().getClass().getName());
            System.out.println("Public key:  " + keyPair.getPublic());
            System.out.println("Public class: " + keyPair.getPublic().getClass().getName());
        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
            fail(ex.getMessage(), ex);
        }
    }
}
