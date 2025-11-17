package extend.util.external.jws;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
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
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECPublicKeySpec;
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

    @Test
    public void testParseJWK() {
        try {
            System.out.println("testParseJWK");
            String jsonJWK = "{\"kty\":\"RSA\",\"n\":\"ANBBzCbXZqdj1juvW3A1MShLjccs89r0bPRUr71PwknG-7nr_QuYgb5vQgjr7RZbpj9GcePsdthugvL-a7o_trgZcAFa5dTgRyHcs32719l4KC0cyNfip2WCPO7e5eY3kPrh4fT10LvzZ1WvdlrRw4AVRI6fd-fzx8s5A1bnW3gUg09VVz6lnZXp1riKWxfZgmuQD-qOOZptt9d1HrdJALao1tsEBO3S6RzZYL5GFrr0agRbtt_ux2Owju6C0_l1tGTee1mpUUOg_GIphkYvKW0ZetUZMyWDNu1MHbVTHIejNEo9YOZTcBXzJkdnNazhUxa4ODjX-Dkdj9UBcPlnVps=\",\"e\":\"AQAB\",\"d\":\"CegPW4ukjPLhVn59dYV6PKX3bRGU2gYFhsvefj1kixjlkY8Jvvr2tQXa2MzMPuOGMX1a3pI5hwsevItguX_dY72GB_J4e1td1t0GRsVgO66NDrRPU4GrH9eFqYE942kiQuTq2Dm3P7GQ6VEK6sAOsjGQzM4GKKj-iIrCP2iK_9e3-rwgjj3TcwVowir1SSVRkUI177pAdA4Qe2blS3mWtlPJrDOqKVM0QlnKcLWsQJ0D1MmgVQq91twyBemQEXyKFka4FnehlY835T-WTPGyMxhYKu9kr07wDLL4OvWNHYvv0LoqMBj_o8w3SwM4o8xSp8jiGRDmz6BAX_alJzsWnQ==\",\"p\":\"AO6JcdiuBGTTfP0gYJrz1VzutiB1b7858PCY2D_Jy5CA-ravZAvbRG5125ccMGYqkBlWrc3cdgVVEx3SILzGTsMl1QXGFMaJ8V7-L9h8CD6t0z3AtGbJXfU-FzZsim_Fyl5KBPm9I0_kgNuQBY3_tFRqmJ05Met1cgYYY9hrPJd9\",\"q\":\"AN-A3EkJEG8CpwHIzLc48o5Nxn-pAGiIRY0wyT0q7FJy-wc_rMDdO4iwmE7eOegNOpquoI5sst2ZWVXW0qy7IRChTlNcApMV63DYQShjTPdpDD4Kx_He8q8inuGfw4lQzv5EDPhShMTayKFpx5dAX6o0w1tHqlR9yIZ5usdpz3H3\",\"dp\":\"SP6oZw1BbPVG_1LkHSbWuPyXoTEuxA7gC1BKhKKk95BwqGzdqb8snrzUONa4fNszg32B7Eg1mYYiNnLx77KjsZYnLQAjpWnbAh242H-EKmIZDYGl8vpWFVEt20q1xmR5fAccpKvbXXxobkgRWxXPwjFoiFxTSWGERhc6nqSaQyU=\",\"dq\":\"ZlWDBzHOQ3XMb-W3zgCWFpAH3fXMiRA0AEShL4-SquGYjKYb_CaPlrN82Ueo7dX4ylBAlVWxxALtw37b8Viw-ANTcJmFWEFGDuIFW2-0EugXQeT_zYAOUCAi7R2QkzPbwtH3uk9WGSgvirB7QYapBq6n8AhtNcht4xyjZ6DL6ds=\",\"qi\":\"ANKXemRfZxoWIb347JQFhWjCRu7iDsFBSdlXe2fH1qRxDCwh4Wz3bj5h5P7nVHx2v7jXKkZyM2ffnIHTvulwBC3WE6keGO1TO5NAZAXdYFbQGH7DWpd3mIV8mm7f4tKUrIfD_r3LomxXBEIS04YcV_yV-p8CKEpMQrhC7xqtltgd\"}";
            KeyPair keyPair = JWKJoseUtil.parseRSAJWK(jsonJWK);
            assertTrue(keyPair.getPrivate() instanceof RSAPrivateKey);
            assertTrue(keyPair.getPublic() instanceof RSAPublicKey);
        } catch (InvalidKeySpecException ex) {
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
                KeyPair keyPair = kpg.generateKeyPair();
                String jsonJWK = JWKJoseUtil.toRSAJWK(keyPair);
                System.out.println("toRSAJWK:" + jsonJWK);

                KeyPair keyPairPublic = new KeyPair(keyPair.getPublic(), null);
                String jsonJWKPub = JWKJoseUtil.toRSAJWK(keyPairPublic);
                System.out.println("toRSAJWK:" + jsonJWKPub);
                RSAKey.Builder key = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic());
                System.out.println("buildRSA256JWK:" + key.build());
            }
            {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC","BC");
                kpg.initialize(256);
                KeyPair keyPair = kpg.generateKeyPair();
//                String jsonJWK = JWKUtil.toJWK(keyPair);
                System.out.println("toECJWK:" + keyPair.getPrivate().getAlgorithm());
                System.out.println("toECJWK:" + keyPair.getPublic().getAlgorithm());
                System.out.println("toECJWK.Name:" + keyPair.getPrivate().getClass().getName());
                KeyFactory kf = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
                ECPublicKeySpec pubSpec = kf.getKeySpec(keyPair.getPublic(), java.security.spec.ECPublicKeySpec.class);
                System.out.println("toECJWK:" + pubSpec.getParams().getCurve().getField().getFieldSize());
                ECKey.Builder key = new ECKey.Builder(Curve.P_256, (ECPublicKey) keyPair.getPublic());
                System.out.println("buildEC256JWK:" + key.build());
            }
            {
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Ed25519","BC");
                KeyPair keyPair = keyGen.generateKeyPair();
                System.out.println("toEdJWK.Name:" + keyPair.getPrivate().getClass().getName());
                System.out.println("toEdJWK:" + keyPair.getPrivate().getAlgorithm());
                System.out.println("toEdJWK:" + keyPair.getPublic().getAlgorithm());
                System.out.println("toEdJWK.EdECPublicKey(EC):" + (keyPair.getPublic() instanceof java.security.interfaces.EdECPublicKey));
            }
            {
//                OctetKeyPair jwk = new OctetKeyPairGenerator(Curve.Ed25519).generate();

                // 秘密鍵・公開鍵を含むJWK (private + public)
//                System.out.println("Full JWK:");
//                System.out.println(jwk.toJSONString());
            }
            {
//                OctetKeyPair jwk = new OctetKeyPairGenerator(Curve.Ed448).generate();
                // 秘密鍵・公開鍵を含むJWK (private + public)
//                System.out.println("Full JWK:");
//                System.out.println(jwk.toJSONString());
            }
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException ex) {
            fail(ex.getMessage(), ex);
        }
    }

    @Test
    public void testJoseJWK() {
        System.out.println("testJoseJWK");
        {
            try {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
                kpg.initialize(2048);
                KeyPair keyPair = kpg.generateKeyPair();
                String jsonJWK = JWKUtil.toJWK(keyPair, false);
                System.out.println("toRSAJWK:" + jsonJWK);
                JWK jwk = JWK.parse(jsonJWK);
                KeyPair rsaKey = jwk.toRSAKey().toKeyPair();
                assertTrue(rsaKey.getPublic() instanceof RSAPublicKey);
                assertTrue(rsaKey.getPrivate() instanceof RSAPrivateKey);
            } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException | ParseException | JOSEException ex) {
                fail(ex.getMessage(), ex);
            }
            try {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
                kpg.initialize(256);
                KeyPair keyPair = kpg.generateKeyPair();
                String jsonJWK = JWKUtil.toJWK(keyPair, false);
                System.out.println("toEC256JWK:" + jsonJWK);
                JWK jwk = JWK.parse(jsonJWK);
                KeyPair ecKey = jwk.toECKey().toKeyPair();
                assertTrue(ecKey.getPublic() instanceof ECPublicKey);
                assertTrue(ecKey.getPrivate() instanceof ECPrivateKey);
                KeyPair keyPairPub = new KeyPair(keyPair.getPublic(), null);
                String jsonJWKPub = JWKUtil.toJWK(keyPairPub, false);
                System.out.println("toEC256JWK:" + jsonJWKPub);
            } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException | ParseException | JOSEException ex) {
                fail(ex.getMessage(), ex);
            }
            try {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
                kpg.initialize(384);
                KeyPair keyPair = kpg.generateKeyPair();
                String jsonJWK = JWKUtil.toJWK(keyPair, false);
                System.out.println("toEC384JWK:" + jsonJWK);
                JWK jwk = JWK.parse(jsonJWK);
                KeyPair ecKey = jwk.toECKey().toKeyPair();
                assertTrue(ecKey.getPublic() instanceof ECPublicKey);
                assertTrue(ecKey.getPrivate() instanceof ECPrivateKey);
                KeyPair keyPairPub = new KeyPair(keyPair.getPublic(), null);
                String jsonJWKPub = JWKUtil.toJWK(keyPairPub, false);
                System.out.println("toEC384JWK:" + jsonJWKPub);
            } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException | ParseException | JOSEException ex) {
                fail(ex.getMessage(), ex);
            }
            try {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
                kpg.initialize(521);
                KeyPair keyPair = kpg.generateKeyPair();
                String jsonJWK = JWKUtil.toJWK(keyPair, false);
                System.out.println("toEC521JWK:" + jsonJWK);
                JWK jwk = JWK.parse(jsonJWK);
                KeyPair ecKey = jwk.toECKey().toKeyPair();
                assertTrue(ecKey.getPublic() instanceof ECPublicKey);
                assertTrue(ecKey.getPrivate() instanceof ECPrivateKey);
                KeyPair keyPairPub = new KeyPair(keyPair.getPublic(), null);
                String jsonJWKPub = JWKUtil.toJWK(keyPairPub, false);
                System.out.println("toEC521JWK:" + jsonJWKPub);
            } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException | ParseException | JOSEException ex) {
                fail(ex.getMessage(), ex);
            }
            try {
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Ed25519", "BC");
                KeyPair keyPair = keyGen.generateKeyPair();
                String jsonJWK = JWKUtil.toJWK(keyPair, false);
                System.out.println("toEd25519JWK:" + jsonJWK);
                JWK jwk = JWK.parse(jsonJWK);
                System.out.println("toEd25519:" + jwk.toString());
//                OctetKeyPair edKey = jwk.toOctetKeyPair();
//                System.out.println("toEd25519.pri:" + priKey.getAlgorithm());
//                System.out.println("toEd25519.pub:" + pubKey.getAlgorithm());

            } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException | ParseException ex) {
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
        }
    }


}
