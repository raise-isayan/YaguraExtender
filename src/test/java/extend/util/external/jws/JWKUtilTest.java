package extend.util.external.jws;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import static org.junit.jupiter.api.Assertions.fail;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 *
 * @author isayan
 */
public class JWKUtilTest {

    public JWKUtilTest() {
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

    @Test
    public void testToJWK() {
        System.out.println("testToJWK");
        {
            try {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
                kpg.initialize(2048);
                KeyPair keyPair = kpg.generateKeyPair();
                String jsonJWK = JWKUtil.toJWK(keyPair, false);
                System.out.println("toRSAJWK:" + jsonJWK);
                KeyPair keyPairPub = new KeyPair(keyPair.getPublic(), null);
                String jsonJWKPub = JWKUtil.toJWK(keyPairPub, false);
                System.out.println("toRSAJWK:" + jsonJWKPub);
            } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException ex) {
                fail(ex.getMessage(), ex);
            }
            try {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
                kpg.initialize(256);
                KeyPair keyPair = kpg.generateKeyPair();
                String jsonJWK = JWKUtil.toJWK(keyPair, false);
                System.out.println("toEC256JWK:" + jsonJWK);
                KeyPair keyPairPub = new KeyPair(keyPair.getPublic(), null);
                String jsonJWKPub = JWKUtil.toJWK(keyPairPub, false);
                System.out.println("toEC256JWK:" + jsonJWKPub);
            } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException ex) {
                fail(ex.getMessage(), ex);
            }
            try {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
                kpg.initialize(384);
                KeyPair keyPair = kpg.generateKeyPair();
                String jsonJWK = JWKUtil.toJWK(keyPair, false);
                System.out.println("toEC384JWK:" + jsonJWK);
                KeyPair keyPairPub = new KeyPair(keyPair.getPublic(), null);
                String jsonJWKPub = JWKUtil.toJWK(keyPairPub, false);
                System.out.println("toEC384JWK:" + jsonJWKPub);
            } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException ex) {
                fail(ex.getMessage(), ex);
            }
            try {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
                kpg.initialize(521);
                KeyPair keyPair = kpg.generateKeyPair();
                String jsonJWK = JWKUtil.toJWK(keyPair, false);
                System.out.println("toEC521JWK:" + jsonJWK);
                KeyPair keyPairPub = new KeyPair(keyPair.getPublic(), null);
                String jsonJWKPub = JWKUtil.toJWK(keyPairPub, false);
                System.out.println("toEC521JWK:" + jsonJWKPub);
            } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException ex) {
                fail(ex.getMessage(), ex);
            }
            try {
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Ed25519", "BC");
                KeyPair keyPair = keyGen.generateKeyPair();
                String jsonJWK = JWKUtil.toJWK(keyPair, false);
                System.out.println("toEd25519JWK:" + jsonJWK);
            } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException ex) {
                fail(ex.getMessage(), ex);
            }
            try {
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Ed448", "BC");
                KeyPair keyPair = keyGen.generateKeyPair();
                String jsonJWK = JWKUtil.toJWK(keyPair, false);
                System.out.println("toEd448JWK:" + jsonJWK);
            } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException ex) {
                fail(ex.getMessage(), ex);
            }
//            try {
//                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Ed25519", "BC");
//                KeyPair keyPair = keyGen.generateKeyPair();
//                String jsonJWK = JWKUtil.toJWK(keyPair);
//                System.out.println("toEd25519JWK:" + jsonJWK);
//            } catch (NoSuchAlgorithmException ex) {
//                fail(ex.getMessage(), ex);
//            } catch (NoSuchProviderException ex) {
//                fail(ex.getMessage(), ex);
//            } catch (InvalidKeySpecException ex) {
//                ex.printStackTrace();
//                fail(ex.getMessage(), ex);
//            }
//
//            try {
//                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Ed448", "BC");
//                KeyPair keyPair = keyGen.generateKeyPair();
//                String jsonJWK = JWKUtil.toJWK(keyPair);
//                System.out.println("toEd448JWK:" + jsonJWK);
//            } catch (NoSuchAlgorithmException ex) {
//                fail(ex.getMessage(), ex);
//            } catch (NoSuchProviderException ex) {
//                fail(ex.getMessage(), ex);
//            } catch (InvalidKeySpecException ex) {
//                fail(ex.getMessage(), ex);
//            }
//
//            try {
//                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Ed448", "BC");
//                KeyPair keyPair = keyGen.generateKeyPair();
//                String jsonJWK = JWKUtil.toJWK(keyPair);
//                System.out.println("toEd448JWK:" + jsonJWK);
//            } catch (NoSuchAlgorithmException ex) {
//                fail(ex.getMessage(), ex);
//            } catch (NoSuchProviderException ex) {
//                fail(ex.getMessage(), ex);
//            } catch (InvalidKeySpecException ex) {
//                fail(ex.getMessage(), ex);
//            }
//            try {
//                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Ed25519", "BC");
//                KeyPair keyPair = keyGen.generateKeyPair();
//                String jsonJWK = JWKUtil.toJWK(keyPair);
//                System.out.println("toEd25519JWK:" + jsonJWK);
//            } catch (NoSuchAlgorithmException ex) {
//                fail(ex.getMessage(), ex);
//            } catch (NoSuchProviderException ex) {
//                fail(ex.getMessage(), ex);
//            } catch (InvalidKeySpecException ex) {
//                ex.printStackTrace();
//                fail(ex.getMessage(), ex);
//            }
//
//            try {
//                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Ed448", "BC");
//                KeyPair keyPair = keyGen.generateKeyPair();
//                String jsonJWK = JWKUtil.toJWK(keyPair);
//                System.out.println("toEd448JWK:" + jsonJWK);
//            } catch (NoSuchAlgorithmException ex) {
//                fail(ex.getMessage(), ex);
//            } catch (NoSuchProviderException ex) {
//                fail(ex.getMessage(), ex);
//            } catch (InvalidKeySpecException ex) {
//                fail(ex.getMessage(), ex);
//            }

//            try {
//                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Ed25519", "BC");
//                KeyPair keyPair = keyGen.generateKeyPair();
//                String jsonJWK = JWKUtil.toJWK(keyPair);
//                System.out.println("toEd25519JWK:" + jsonJWK);
//            } catch (NoSuchAlgorithmException ex) {
//                fail(ex.getMessage(), ex);
//            } catch (NoSuchProviderException ex) {
//                fail(ex.getMessage(), ex);
//            } catch (InvalidKeySpecException ex) {
//                ex.printStackTrace();
//                fail(ex.getMessage(), ex);
//            }
//
//            try {
//                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Ed448", "BC");
//                KeyPair keyPair = keyGen.generateKeyPair();
//                String jsonJWK = JWKUtil.toJWK(keyPair);
//                System.out.println("toEd448JWK:" + jsonJWK);
//            } catch (NoSuchAlgorithmException ex) {
//                fail(ex.getMessage(), ex);
//            } catch (NoSuchProviderException ex) {
//                fail(ex.getMessage(), ex);
//            } catch (InvalidKeySpecException ex) {
//                fail(ex.getMessage(), ex);
//            }

//
//            try {
//                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Ed448", "BC");
//                KeyPair keyPair = keyGen.generateKeyPair();
//                String jsonJWK = JWKUtil.toJWK(keyPair);
//                System.out.println("toEd448JWK:" + jsonJWK);
//            } catch (NoSuchAlgorithmException ex) {
//                fail(ex.getMessage(), ex);
//            } catch (NoSuchProviderException ex) {
//                fail(ex.getMessage(), ex);
//            } catch (InvalidKeySpecException ex) {
//                fail(ex.getMessage(), ex);
//            }


//            try {
//                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Ed25519", "BC");
//                KeyPair keyPair = keyGen.generateKeyPair();
//                String jsonJWK = JWKUtil.toJWK(keyPair);
//                System.out.println("toEd25519JWK:" + jsonJWK);
//            } catch (NoSuchAlgorithmException ex) {
//                fail(ex.getMessage(), ex);
//            } catch (NoSuchProviderException ex) {
//                fail(ex.getMessage(), ex);
//            } catch (InvalidKeySpecException ex) {
//                ex.printStackTrace();
//                fail(ex.getMessage(), ex);
//            }
//
//            try {
//                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Ed448", "BC");
//                KeyPair keyPair = keyGen.generateKeyPair();
//                String jsonJWK = JWKUtil.toJWK(keyPair);
//                System.out.println("toEd448JWK:" + jsonJWK);
//            } catch (NoSuchAlgorithmException ex) {
//                fail(ex.getMessage(), ex);
//            } catch (NoSuchProviderException ex) {
//                fail(ex.getMessage(), ex);
//            } catch (InvalidKeySpecException ex) {
//                fail(ex.getMessage(), ex);
//            }

        }
    }

    @Test
    public void testGenJWK()
    {
        System.out.println("testGenJWK");
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
            kpg.initialize(2048);
            KeyPair keyPair = kpg.generateKeyPair();
            String jwk = toRSA_JWK(keyPair);
            System.out.println("JWK:" + jwk);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException ex) {
            fail(ex.getMessage(), ex);
        }
    }

    public static String toRSA_JWK(KeyPair keyPair) throws InvalidKeySpecException {
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
            RSAPublicKeySpec pubSpec = kf.getKeySpec(keyPair.getPublic(), java.security.spec.RSAPublicKeySpec.class);
            RSAPrivateCrtKeySpec privSpec = kf.getKeySpec(keyPair.getPrivate(), java.security.spec.RSAPrivateCrtKeySpec.class);

            // JWK を構築
            Map<String, String> jwk = new LinkedHashMap<>();
            jwk.put("kty", "RSA");
            jwk.put("n", Base64.getUrlEncoder().encodeToString((pubSpec.getModulus().toByteArray())));
            jwk.put("e", Base64.getUrlEncoder().encodeToString(pubSpec.getPublicExponent().toByteArray()));
            jwk.put("d", Base64.getUrlEncoder().encodeToString(privSpec.getPrivateExponent().toByteArray()));
            jwk.put("p", Base64.getUrlEncoder().encodeToString(privSpec.getPrimeP().toByteArray()));
            jwk.put("q", Base64.getUrlEncoder().encodeToString(privSpec.getPrimeQ().toByteArray()));
            jwk.put("dp", Base64.getUrlEncoder().encodeToString(privSpec.getPrimeExponentP().toByteArray()));
            jwk.put("dq", Base64.getUrlEncoder().encodeToString(privSpec.getPrimeExponentQ().toByteArray()));
            jwk.put("qi", Base64.getUrlEncoder().encodeToString(privSpec.getCrtCoefficient().toByteArray()));

            StringBuilder json = new StringBuilder();
            for (var entry : jwk.entrySet()) {
                if (json.length() > 0) {
                    json.append(",");
                }
                json.append("\"").append(entry.getKey())
                        .append("\":\"").append(entry.getValue()).append("\"");
            }
            return "{" + json.toString() + "}";
        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
            throw new InvalidKeySpecException(ex);
        }
    }

    @Test
    public void testBigInteger() {
        System.out.println("testBigInteger");
        {
            byte [] b = new byte[] {0,0,0,0,0,1,1,1,1,1,1};
            BigInteger x = new BigInteger(1, b);
            byte [] r = x.toByteArray();
        }

    }


}
