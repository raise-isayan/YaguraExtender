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
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
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
                RSAPrivateKey rsaPrivateKey = JWSUtil.toRSAPrivateKey(pemRSAKeyPrivateData);
                assertNotNull(rsaPrivateKey);

                RSAPublicKey rsaPublicKey = JWSUtil.toRSAPublicKey(pemRSAKeyPublicData);
                assertNotNull(rsaPublicKey);

                PrivateKey privateKey = JWSUtil.toPrivateKey(pemRSAKeyPrivateData);
                assertNotNull(privateKey);

                PublicKey publicKey = JWSUtil.toPublicKey(pemRSAKeyPublicData);
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
                ECPrivateKey ecPrivateKey = JWSUtil.toECPrivateKey(pemECKey256PrivateData);
                assertNotNull(ecPrivateKey);

                ECPublicKey ecPublicKey = JWSUtil.toECPublicKey(pemECKey256PublicData);
                assertNotNull(ecPublicKey);

                PrivateKey privateKey = JWSUtil.toPrivateKey(pemECKey256PrivateData);
                assertNotNull(privateKey);

                PublicKey publicKey = JWSUtil.toPublicKey(pemECKey256PublicData);
                assertNotNull(publicKey);
            }
            String priECKey384Path = JWSTokenTest.class.getResource("/resources/private-ec384-key.pem").getPath();
            String pemECKey384PrivateData = FileUtil.stringFromFile(new File(priECKey384Path), StandardCharsets.UTF_8);
            String pubECKey384KeyPath = JWSTokenTest.class.getResource("/resources/public-ec384-key.pem").getPath();
            String pemECKey384PublicData = FileUtil.stringFromFile(new File(pubECKey384KeyPath), StandardCharsets.UTF_8);
            {
                ECPrivateKey ecPrivateKey = JWSUtil.toECPrivateKey(pemECKey384PrivateData);
                assertNotNull(ecPrivateKey);

                ECPublicKey ecPublicKey = JWSUtil.toECPublicKey(pemECKey384PublicData);
                assertNotNull(ecPublicKey);

                PrivateKey privateKey = JWSUtil.toPrivateKey(pemECKey256PrivateData);
                assertNotNull(privateKey);

                PublicKey publicKey = JWSUtil.toPublicKey(pemECKey384PublicData);
                assertNotNull(publicKey);
            }
            String priECKey521Path = JWSTokenTest.class.getResource("/resources/private-ec521-key.pem").getPath();
            String pemECKey521PrivateData = FileUtil.stringFromFile(new File(priECKey521Path), StandardCharsets.UTF_8);
            String pubECKey521KeyPath = JWSTokenTest.class.getResource("/resources/public-ec521-key.pem").getPath();
            String pemECKey521PublicData = FileUtil.stringFromFile(new File(pubECKey521KeyPath), StandardCharsets.UTF_8);
            {
                ECPrivateKey ecPrivateKey = JWSUtil.toECPrivateKey(pemECKey521PrivateData);
                assertNotNull(ecPrivateKey);

                ECPublicKey ecPublicKey = JWSUtil.toECPublicKey(pemECKey521PublicData);
                assertNotNull(ecPublicKey);

                PrivateKey privateKey = JWSUtil.toPrivateKey(pemECKey521PrivateData);
                assertNotNull(privateKey);

                PublicKey publicKey = JWSUtil.toPublicKey(pemECKey521PublicData);
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
                EdECPrivateKey edPrivateKey = JWSUtil.toEdECPrivateKey(pemEdDSAPrivateData);
                assertNotNull(edPrivateKey);

                EdECPublicKey edPublicKey = JWSUtil.toEdECPublicKey(pemEdDSAublicData);
                assertNotNull(edPublicKey);

                PrivateKey privateKey = JWSUtil.toPrivateKey(pemEdDSAPrivateData);
                System.out.println("PrivateKey:" + privateKey.getClass().getName());

                assertNotNull(privateKey);

                PublicKey publicKey = JWSUtil.toPublicKey(pemEdDSAublicData);
                System.out.println("PublicKey:" + privateKey.getClass().getName());
                assertNotNull(publicKey);
            }

        } catch (IOException ex) {
            fail(ex.getMessage(), ex);
        }
    }

    private final static String REQ_MESSAGE_URLENCODE_TOKEN00 =
            "POST /cgi-bin/multienc.cgi?charset=Shift_JIS&mode=disp HTTP/1.1\r\n"
            + "Host: 192.168.0.1\r\n"
            + "Content-Length: 60\r\n"
            + "Cache-Control: max-age=0\r\n"
            + "Origin: http://192.168.0.1\r\n"
            + "Content-Type: application/x-www-form-urlencoded\r\n"
            + "User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36\r\n"
            + "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8\r\n"
            + "Accept-Encoding: gzip, deflate\r\n"
            + "Accept-Language: ja,en-US;q=0.9,en;q=0.8\r\n"
            + "Connection: close\r\n"
            + "\r\n"
            + "text=%82%A0%82%A2%82%A4%82%A6%82%A8&OS=win&submit=%91%97%90M\r\n";

    @Test
    public void testFindToken()
    {
        System.out.println("testFindToken");
        final String TOKEN_TOKEN_RESULT = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ5b3VyLWFwcCIsInN1YiI6InVzZXIxMjMiLCJyb2xlIjoiYWRtaW4iLCJleHAiOjE3NTU3ODMxNzV9.dqBgwLri4YJt1FIqjjT1Ljn1LWaoDvACfpX1bgSx8bc";
        {
            CaptureItem[] tokens = JWSUtil.findTokenFormat(JWT_TOKEN00);
            for (CaptureItem t : tokens) {
                System.out.println("token:" + t.getCaptureValue());
                System.out.println("start:" + t.start());
                System.out.println("end:" + t.end());
            }
            assertEquals(1, tokens.length);
            assertEquals(TOKEN_TOKEN_RESULT, tokens[0].getCaptureValue());
        }
        {
            CaptureItem[] tokens = JWSUtil.findTokenFormat(JWT_COOKIE00);
            for (CaptureItem t : tokens) {
                System.out.println("token:" + t.getCaptureValue());
                System.out.println("start:" + t.start());
                System.out.println("end:" + t.end());
            }
            assertEquals(1, tokens.length);
            assertEquals(TOKEN_TOKEN_RESULT, tokens[0].getCaptureValue());
        }
        {
            CaptureItem[] token = JWSUtil.findTokenFormat(REQ_MESSAGE_URLENCODE_TOKEN00);
            assertEquals(0, token.length);
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
            {
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Ed25519", "BC");
                keyGen.initialize(255);
                KeyPair keyPair = keyGen.generateKeyPair();

                System.out.println("Private key: " + keyPair.getPrivate());
                System.out.println("Private class: " + keyPair.getPrivate().getClass().getName());
                System.out.println("Public key:  " + keyPair.getPublic());
                System.out.println("Public class: " + keyPair.getPublic().getClass().getName());
                if (keyPair.getPublic() instanceof EdDSAPublicKey pubKey) {
                    System.out.println("Public format:" + pubKey.getFormat());
                }
            }
            {
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Ed448", "BC");
                keyGen.initialize(448);
                KeyPair keyPair = keyGen.generateKeyPair();

                System.out.println("Private key: " + keyPair.getPrivate());
                System.out.println("Private class: " + keyPair.getPrivate().getClass().getName());
                System.out.println("Public key:  " + keyPair.getPublic());
                System.out.println("Public class: " + keyPair.getPublic().getClass().getName());
                if (keyPair.getPublic() instanceof EdDSAPublicKey pubKey) {
                    System.out.println("EdDSA Public format:" + pubKey.getFormat());
                }
                if (keyPair.getPublic() instanceof EdECPublicKey pubKey) {
                    System.out.println("EdEC Public format:" + pubKey.getFormat());
                }
            }
        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
            fail(ex.getMessage(), ex);
        }
    }

    public static PrivateKey jwkToRsaPrivateKey(
            String n, String e, String d, String p, String q, String dp, String dq, String qi
        ) throws InvalidKeySpecException {
        try {
            BigInteger modulus = new BigInteger(1, Base64.getUrlDecoder().decode(n));
            BigInteger pubExp = new BigInteger(1, Base64.getUrlDecoder().decode(e));
            BigInteger privExp = new BigInteger(1, Base64.getUrlDecoder().decode(d));
            BigInteger primeP = new BigInteger(1, Base64.getUrlDecoder().decode(p));
            BigInteger primeQ = new BigInteger(1, Base64.getUrlDecoder().decode(q));
            BigInteger primeExpP = new BigInteger(1, Base64.getUrlDecoder().decode(dp));
            BigInteger primeExpQ = new BigInteger(1, Base64.getUrlDecoder().decode(dq));
            BigInteger crtCoef = new BigInteger(1, Base64.getUrlDecoder().decode(qi));
            RSAPrivateCrtKeySpec keySpec = new RSAPrivateCrtKeySpec(
                    modulus, pubExp, privExp,
                    primeP, primeQ, primeExpP, primeExpQ, crtCoef);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException ex) {
            throw new InvalidKeySpecException(ex);
        }
    }

    public static PublicKey jwkToRsaPublicKey(String n, String e) throws InvalidKeySpecException {
        try {
            BigInteger modulus = new BigInteger(1, Base64.getUrlDecoder().decode(n));
            BigInteger exponent = new BigInteger(1, Base64.getUrlDecoder().decode(e));
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, exponent);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException ex) {
            throw new InvalidKeySpecException(ex);
        }
    }


}
