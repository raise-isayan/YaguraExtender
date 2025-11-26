package extend.util.external.jws;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import extension.helpers.jws.JWKToken;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 *
 * @author isayan
 */
public class JWKUtilJoseTest {

    public JWKUtilJoseTest() {
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

    private final static String JWK_RSA_KEY = "{\n" +
        "    \"p\": \"48ROPhznQFngYuQi_y_RBcWnWLxQF4eUuTXMBalMceAG42GKWS3DE1BDTVNSHI0BhsaNIwxxiId4-TlebO-mpS2qH4wPKg9xYl4mLbPwh5-LW7_JXf_HJehGRUex1XZmPQ3q4se1C7HEOpZInfEwWSE72NSJTdtDfBg1XzG5yXk\",\n" +
        "    \"kty\": \"RSA\",\n" +
        "    \"q\": \"wey5aHgMXQLzmTbF731k4A5dd4dmndK7pHlGaMfUaV60lRyexqr3VZb1_d82lbbAZkQfX9MomNffk9GDOgWYOpu5RF_4ktnDHXvD--ns6_U5jX4QjdK8u58FScRtLmOwAiE3d9nSssI5KQJwQS5X0EpIQmdpHxUnRmg3OwpBBW8\",\n" +
        "    \"d\": \"HvBuWwrhhKkA-a4Ws5JzkIkRhuT99CZ9eIRSZdbKwPa8i3JqHbdvaXuhfIMhzCICc1edOCKz1GoQi2029I3-MoA_S5Pq69YoooAUhS9j1y8WDCI3lDrroNxvD6blGw6p0xYBIAdpYl9P7QWdoAGIHp-FzT37p7-J3ET5BnD-KVxXZhXp6O-cR49Xav0M0sE4Yd8LManIj5pN-mSxgf1DwrhzLDJ9X0cKb-78ewJnKIrMfbwDZvQLMxnxLRzHETMuRszyalPQPxTkffdHlhuCYyg9UROUXzxaUDxuaT-zotMyy5X0UIpLJWfMkYtKkYT8Fdg2PePPzXkeLVjhs9j6gQ\",\n" +
        "    \"e\": \"AQAB\",\n" +
        "    \"use\": \"sig\",\n" +
        "    \"qi\": \"vL7BlNaVg2ZUkj5-Zru_EO3GmwjUPXQzye3ysM0-xLw4YdtYksEhx0ANlNfG8I1dC8zerbDXyvWvpfbfxNRIKuQgtn2ly7EOpiClV_iq-rjJ5r0QGcGcMvzQbWZLgzdXEcMq662d5gGX27IU5A2pwDZmfId_Ko4g2CsRPZOaSGc\",\n" +
        "    \"dp\": \"rOW2k1XzgZj4SXluy5IrtJr-1tBUaBgmoJWi42VJv2PVNsQzdlDTtZSHEmq-eSfc0cdlGgb3JDHadi3DbSRatya77qiuVjpU0twvVSAz5XAKJMKohG-GaFMzDKJI74aqQ4yOEkqRN2hhUiwEwch18CLXQFjORci9KLVjxniD1Nk\",\n" +
        "    \"alg\": \"RS256\",\n" +
        "    \"dq\": \"Dn8GoROQQQeuc_6PL0bdWo5YWE4L0rJlCndyVvTRIQtOTnM0Pz-ae5BsVQzxhKGDomFnQv-C4mIIuYEI4TZ32bG4WK8f4sJafoK49MTYzA6pvbT1wdRF_XR2rbv8OWKETrRy9AeZY3l3UmR3RbgUImLbIfOe_Q7Uv8OclVI_6As\",\n" +
        "    \"n\": \"rImc6sQmrXOpnxYj73g57A9hakV24DSqEGuWRCovkeUbwZbc-ZX7fTDcGpbhI3WZpZmK4uU_w08NMJJv6zITLiWuWf4M4_diTTdlXVGUcgkAay5DDzc9bL6l0W0FceEWK5A2J5IRSpoaaK6ACQsn6Sm_GgxkgNqRP5UdWfdjCR92sSVGtZKpMdzZppiXMJDvIbrcIVEokwN2Am4udO99UGzUbvLJcrP_zBGoIDYj86MEDoTNhl1bjzUX6eZyzsgDCDHstOxCdqYGn3FXZGyJVepjm0dOWF5ycgHQWO6sxditpMgUt3UtdJOmuBZecZo7x5-ONbfSN4nb6VAtEja4dw\"\n" +
        "}";

    @Test
    public void testParseJoseJWK() {
        System.out.println("testParseJoseJWK");
        try {
            JWK jwk = JWK.parse(JWK_RSA_KEY);
        } catch (ParseException ex) {
            fail(ex.getMessage(), ex);
        }
    }

    @Test
    public void testToJWK() {
        try {
            System.out.println("testToJWK");
            {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA","BC");
                kpg.initialize(2048);
                KeyPair genKeyPair = kpg.generateKeyPair();
                String jsonJWK = JWKToken.toJWK(genKeyPair, false);
                System.out.println("toRSAJWK:" + jsonJWK);
                JWK jwk = JWK.parse(jsonJWK);
                RSAKey rsaKey = jwk.toRSAKey();
                KeyPair rsaKeyPair = rsaKey.toKeyPair();
                assertTrue(rsaKeyPair.getPublic() instanceof RSAPublicKey);
                assertTrue(rsaKeyPair.getPrivate() instanceof RSAPrivateKey);
            }
            {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC","BC");
                kpg.initialize(256);
                KeyPair genKeyPair = kpg.generateKeyPair();
                String jsonJWK = JWKToken.toJWK(genKeyPair, false);
                System.out.println("toEC256JWK:" + jsonJWK);
                JWK jwk = JWK.parse(jsonJWK);
                ECKey ecKey = jwk.toECKey();
                KeyPair ecKeyPair = ecKey.toKeyPair();
                assertTrue(ecKeyPair.getPublic() instanceof ECPublicKey);
                assertTrue(ecKeyPair.getPrivate() instanceof ECPrivateKey);
            }
            {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC","BC");
                kpg.initialize(384);
                KeyPair genKeyPair = kpg.generateKeyPair();
                String jsonJWK = JWKToken.toJWK(genKeyPair, false);
                System.out.println("toEC384JWK:" + jsonJWK);
                JWK jwk = JWK.parse(jsonJWK);
                ECKey ecKey = jwk.toECKey();
                KeyPair ecKeyPair = ecKey.toKeyPair();
                assertTrue(ecKeyPair.getPublic() instanceof ECPublicKey);
                assertTrue(ecKeyPair.getPrivate() instanceof ECPrivateKey);
            }
            {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC","BC");
                kpg.initialize(521);
                KeyPair genKeyPair = kpg.generateKeyPair();
                String jsonJWK = JWKToken.toJWK(genKeyPair, false);
                System.out.println("toEC512JWK:" + jsonJWK);
                JWK jwk = JWK.parse(jsonJWK);
                ECKey ecKey = jwk.toECKey();
                KeyPair ecKeyPair = ecKey.toKeyPair();
                assertTrue(ecKeyPair.getPublic() instanceof ECPublicKey);
                assertTrue(ecKeyPair.getPrivate() instanceof ECPrivateKey);
            }
            if (OctetKeyPairGenerator.SUPPORTED_CURVES.contains(Curve.Ed25519)) {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519","BC");
                KeyPair genKeyPair = kpg.generateKeyPair();
                String jsonJWK = JWKToken.toJWK(genKeyPair, false);
                JWK jwk = JWK.parse(jsonJWK);
                OctetKeyPair edKeyPair = jwk.toOctetKeyPair();
                assertEquals(edKeyPair.getKeyType(),KeyType.OKP);
                assertEquals(edKeyPair.getCurve(),Curve.Ed25519);
            }
            if (OctetKeyPairGenerator.SUPPORTED_CURVES.contains(Curve.Ed448)) {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed448","BC");
                KeyPair genKeyPair = kpg.generateKeyPair();
                String jsonJWK = JWKToken.toJWK(genKeyPair, false);
                JWK jwk = JWK.parse(jsonJWK);
                OctetKeyPair edKeyPair = jwk.toOctetKeyPair();
                assertEquals(edKeyPair.getKeyType(),KeyType.OKP);
                assertEquals(edKeyPair.getCurve(),Curve.Ed448);
            }
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException ex) {
            ex.printStackTrace();
            fail(ex.getMessage(), ex);
        } catch (JOSEException ex) {
            ex.printStackTrace();
            fail(ex.getMessage(), ex);
        } catch (ParseException ex) {
            ex.printStackTrace();
            fail(ex.getMessage(), ex);
        }
    }

    @Test
    public void testJoseJWK() {
        System.out.println("testJoseJWK");
        {
            try {
                {
                    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
                    kpg.initialize(2048);
                    KeyPair keyPair = kpg.generateKeyPair();
                    RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey)keyPair.getPublic()).privateKey((RSAPrivateKey)keyPair.getPrivate()).build();
                    String jsonJWK = rsaKey.toString();
                    System.out.println("toRSAJWK:" + jsonJWK);
                    KeyPair rsaKeyPair = JWKToken.parseJWK(jsonJWK);
                    assertTrue(rsaKeyPair.getPublic() instanceof RSAPublicKey);
                    assertTrue(rsaKeyPair.getPrivate() instanceof RSAPrivateKey);
                }
                {
                    KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
                    kpg.initialize(256);
                    KeyPair keyPair = kpg.generateKeyPair();
                    ECKey ecKey = new ECKey.Builder(Curve.P_256, (ECPublicKey)keyPair.getPublic()).privateKey((ECPrivateKey)keyPair.getPrivate()).build();
                    String jsonJWK = ecKey.toString();
                    System.out.println("toEC256JWK:" + jsonJWK);
                    KeyPair ecKeyPair = JWKToken.parseJWK(jsonJWK);
                    assertTrue(ecKeyPair.getPublic() instanceof ECPublicKey);
                    assertTrue(ecKeyPair.getPrivate() instanceof ECPrivateKey);
                }
                {
                    KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
                    kpg.initialize(384);
                    KeyPair keyPair = kpg.generateKeyPair();
                    ECKey ecKey = new ECKey.Builder(Curve.P_384, (ECPublicKey)keyPair.getPublic()).privateKey((ECPrivateKey)keyPair.getPrivate()).build();
                    String jsonJWK = ecKey.toString();
                    System.out.println("toEC384JWK:" + jsonJWK);
                    KeyPair ecKeyPair = JWKToken.parseJWK(jsonJWK);
                    assertTrue(ecKeyPair.getPublic() instanceof ECPublicKey);
                    assertTrue(ecKeyPair.getPrivate() instanceof ECPrivateKey);
                }
                {
                    KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
                    kpg.initialize(521);
                    KeyPair keyPair = kpg.generateKeyPair();
                    ECKey ecKey = new ECKey.Builder(Curve.P_521, (ECPublicKey)keyPair.getPublic()).privateKey((ECPrivateKey)keyPair.getPrivate()).build();
                    String jsonJWK = ecKey.toString();
                    System.out.println("toEC521JWK:" + jsonJWK);
                    KeyPair ecKeyPair = JWKToken.parseJWK(jsonJWK);
                    assertTrue(ecKeyPair.getPublic() instanceof ECPublicKey);
                    assertTrue(ecKeyPair.getPrivate() instanceof ECPrivateKey);
                }
                if (OctetKeyPairGenerator.SUPPORTED_CURVES.contains(Curve.Ed25519)) {
                    OctetKeyPair jwk = new OctetKeyPairGenerator(Curve.Ed25519).generate();
                    // 秘密鍵・公開鍵を含むJWK (private + public)
                    String jsonJWK = jwk.toJSONString();
                    System.out.println("Ed25519 JWK:" + jsonJWK);
                    KeyPair edKeyPair = JWKToken.parseJWK(jsonJWK);
                    assertTrue(edKeyPair.getPublic() instanceof EdECPublicKey);
                    assertTrue(edKeyPair.getPrivate() instanceof EdECPrivateKey);
                }
                if (OctetKeyPairGenerator.SUPPORTED_CURVES.contains(Curve.Ed448)) {
                    OctetKeyPair jwk = new OctetKeyPairGenerator(Curve.Ed448).generate();
                  // 秘密鍵・公開鍵を含むJWK (private + public)
                    String jsonJWK = jwk.toJSONString();
                    System.out.println("Ed448 JWK:" + jsonJWK);
                    KeyPair edKeyPair = JWKToken.parseJWK(jsonJWK);
                    assertTrue(edKeyPair.getPublic() instanceof EdECPublicKey);
                    assertTrue(edKeyPair.getPrivate() instanceof EdECPrivateKey);
                }
            } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException  ex) {
                ex.printStackTrace();
                fail(ex.getMessage(), ex);
            } catch (JOSEException ex) {
                ex.printStackTrace();
                fail(ex.getMessage(), ex);
            }
        }
    }


}
