package extend.util.external.jws;

import com.google.gson.JsonElement;
import extension.helpers.json.JsonUtil;
import java.math.BigInteger;
import java.security.KeyFactory;
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
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
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
                KeyPair genKeyPair = kpg.generateKeyPair();
                String jsonJWK = JWKUtil.toJWK(genKeyPair, false);
                System.out.println("toRSAJWK:" + jsonJWK);
                KeyPair keyPairPub = new KeyPair(genKeyPair.getPublic(), null);
                String jsonJWKPub = JWKUtil.toJWK(keyPairPub, false);
                System.out.println("toRSAJWK:" + jsonJWKPub);
                KeyPair keyPair = JWKUtil.parseJWK(jsonJWK);
                assertTrue(keyPair.getPrivate() instanceof RSAPrivateKey);
                assertTrue(keyPair.getPublic() instanceof RSAPublicKey);
                // public only
                KeyPair keyPair2 = JWKUtil.parseJWK(jsonJWKPub);
                assertNull(keyPair2.getPrivate());
                assertTrue(keyPair2.getPublic() instanceof RSAPublicKey);


            } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException ex) {
                fail(ex.getMessage(), ex);
            }
            try {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
                kpg.initialize(256);
                KeyPair genKeyPair = kpg.generateKeyPair();
                String jsonJWK = JWKUtil.toJWK(genKeyPair, false);
                System.out.println("toEC256JWK:" + jsonJWK);
                KeyPair keyPairPub = new KeyPair(genKeyPair.getPublic(), null);
                String jsonJWKPub = JWKUtil.toJWK(keyPairPub, false);
                System.out.println("toEC256JWK:" + jsonJWKPub);
                KeyPair keyPair = JWKUtil.parseJWK(jsonJWK);
                assertTrue(keyPair.getPrivate() instanceof ECPrivateKey);
                assertTrue(keyPair.getPublic() instanceof ECPublicKey);
                // public only
                KeyPair keyPair2 = JWKUtil.parseJWK(jsonJWKPub);
                assertNull(keyPair2.getPrivate());
                assertTrue(keyPair2.getPublic() instanceof ECPublicKey);
            } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException ex) {
                fail(ex.getMessage(), ex);
            }
            try {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
                kpg.initialize(384);
                KeyPair genKeyPair = kpg.generateKeyPair();
                String jsonJWK = JWKUtil.toJWK(genKeyPair, false);
                System.out.println("toEC384JWK:" + jsonJWK);
                KeyPair keyPairPub = new KeyPair(genKeyPair.getPublic(), null);
                String jsonJWKPub = JWKUtil.toJWK(keyPairPub, false);
                System.out.println("toEC384JWK:" + jsonJWKPub);
                KeyPair keyPair = JWKUtil.parseJWK(jsonJWK);
                assertTrue(keyPair.getPrivate() instanceof ECPrivateKey);
                assertTrue(keyPair.getPublic() instanceof ECPublicKey);
                // public only
                KeyPair keyPair2 = JWKUtil.parseJWK(jsonJWKPub);
                assertNull(keyPair2.getPrivate());
                assertTrue(keyPair2.getPublic() instanceof ECPublicKey);
            } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException ex) {
                fail(ex.getMessage(), ex);
            }
            try {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
                kpg.initialize(521);
                KeyPair genKeyPair = kpg.generateKeyPair();
                String jsonJWK = JWKUtil.toJWK(genKeyPair, false);
                System.out.println("toEC521JWK:" + jsonJWK);
                KeyPair keyPairPub = new KeyPair(genKeyPair.getPublic(), null);
                String jsonJWKPub = JWKUtil.toJWK(keyPairPub, false);
                System.out.println("toEC521JWK:" + jsonJWKPub);
                KeyPair keyPair = JWKUtil.parseJWK(jsonJWK);
                assertTrue(keyPair.getPrivate() instanceof ECPrivateKey);
                assertTrue(keyPair.getPublic() instanceof ECPublicKey);
                // public only
                KeyPair keyPair2 = JWKUtil.parseJWK(jsonJWKPub);
                assertNull(keyPair2.getPrivate());
                assertTrue(keyPair2.getPublic() instanceof ECPublicKey);
            } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException ex) {
                fail(ex.getMessage(), ex);
            }
            try {
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Ed25519", "BC");
                KeyPair genKeyPair = keyGen.generateKeyPair();
                String jsonJWK = JWKUtil.toJWK(genKeyPair, false);
                System.out.println("toEd25519JWK:" + jsonJWK);
                KeyPair keyPairPub = new KeyPair(genKeyPair.getPublic(), null);
                String jsonJWKPub = JWKUtil.toJWK(keyPairPub, false);
                System.out.println("toEd25519JWK:" + jsonJWKPub);
                KeyPair keyPair = JWKUtil.parseJWK(jsonJWK);
                assertTrue(keyPair.getPrivate() instanceof EdECPrivateKey);
                assertTrue(keyPair.getPublic() instanceof EdECPublicKey);
                // public only
                KeyPair keyPair2 = JWKUtil.parseJWK(jsonJWKPub);
                assertNull(keyPair2.getPrivate());
                assertTrue(keyPair2.getPublic() instanceof EdECPublicKey);
            } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException ex) {
                fail(ex.getMessage(), ex);
            }
            try {
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Ed448", "BC");
                KeyPair genKeyPair = keyGen.generateKeyPair();
                String jsonJWK = JWKUtil.toJWK(genKeyPair, false);
                System.out.println("toEd448JWK:" + jsonJWK);
                KeyPair keyPairPub = new KeyPair(genKeyPair.getPublic(), null);
                String jsonJWKPub = JWKUtil.toJWK(keyPairPub, false);
                System.out.println("toEd448JWK:" + jsonJWKPub);
                KeyPair keyPair = JWKUtil.parseJWK(jsonJWK);
                assertTrue(keyPair.getPrivate() instanceof EdECPrivateKey);
                assertTrue(keyPair.getPublic() instanceof EdECPublicKey);
                // public only
                KeyPair keyPair2 = JWKUtil.parseJWK(jsonJWKPub);
                assertNull(keyPair2.getPrivate());
                assertTrue(keyPair2.getPublic() instanceof EdECPublicKey);
            } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException ex) {
                fail(ex.getMessage(), ex);
            }
        }
    }

    // https://mkjwk.org/
    private final static String RSA_JWK = "{\"p\":\"7vFg_eDM5mYgL0-0Eo3_chZP6myjgLRb-tQer1sDBjKyjPsc-s-vgW0Tk_SHV5Ig0-elC4gOFDj00QBsQa0pCUxpR7uL5vV8NKDVho4eeokkgsT4ntd5TnsxKFv5i1B_JVXNHXOm0p3P2qWuMHMHsXInu6ds9yN8KPzRQOdWnVU\",\"kty\":\"RSA\",\"q\":\"mZvHVFCLNw8CJjDbb6epPElXqLFI0UNpjvTxdtjWCUJBzjx4ekwDSkh4s-IKcvST6OC5e40A6LBRoxlcjJdN7QV-1YN-Ly2BIiWLKmCa0440TphZmHb9dF_h9e8alaYSX1AWOjxZ-I9B5ouQnn92dc7jyBl3grR93jd9B3sAalk\",\"d\":\"Z-SH7pInGva9ae67qR3oNGz315b-V2c5Qyo9PWG3OXntKy2GlJYxDBT_eqNkiwcohGpsr4Ko4Kw_S26cQYfR3x1mH-XZxe76m4ZOmaKFrH8-MGaoqeb0ULCCvmBMbuMg_wWRZ8MnyzObtHohENQflNgmcrmG-CQ39TsPKhT3w7MF-zln6YKFEMZvACrPqmnfKVhXPWvkodwx5phlqhpKUr7iH79hVZ_jACue-lmsMKPx-JIOy7zPQAlzZw6B2CKAeg4s329ey8MYS5nQipEh_OpvlcjP3CTN9n5NUwT8PEABW7DdHNqtVfvxoTOJ_eCjFLDkPeQDPN2sIPsvoyEJwQ\",\"e\":\"AQAB\",\"use\":\"sig\",\"qi\":\"nTfo5vvgSXGw8CMirrQwD2JNWMreLenl7ZAjI1qDwHmgXDEORXWHJmlpw6R2enusUQXvyXiz3Jyz9nvHIQa00l_URSX1oTWgSiB--vrkeU4lMZlZVUdfMRSNweT1L6ebLZ8YP5wD1-qMZmMHl3rS5xzVAzCAoexVjxAAnfmBxlg\",\"dp\":\"c7mqbSt8cbZSrjdfEoF9j8boq7Q0ODiiN8iWl_1vaIgTXB6e-YavDPNEQSt0hWA70AXoNL6PexHe2H7o76IrNtqwPtLBvnl0z5R59jJM5rIXYdJ-S4g2s2EM_OwW33d8LRvyPOpviKBwNAh8ZfDAcBvGzKcZKlUgZEWWH2Yr2AU\",\"alg\":\"RS256\",\"dq\":\"Wc6F33mnqu0PaJyv7rurah_HLE1aMV6kXHxAoCduG8OtDZK1LWs7kTaFu0WwrjzoLQMV7nIl0eUkFaNCRMBBQw4vdU2HfLWyBfDFSGVqn71IP5s65rTKwjs8tLiyZkPOAgOkuy-FupinAs8eIkyLSZ1H9zlMchJsdHskkjcLqyE\",\"n\":\"j1-pKcnYHZJxfJls4PKgrJ0VcmSp8ktzVu0f0DZGolmKnrxQcHPHC1eSzk2kVF9ILY5Dm9FBNkSXBYT8EMwr5TcsllrO9IAgfIyvTWICIR_1j9Y3ve4-mAUFX7Mfne6DIfxFodyHA94C_2U2K4T3ir32E0FPm1IT8_wDWSwSojEsg3N7qYkY5K9GkAqYzYgLSvDxqridH1UWvkiRmNBRsQMspUpylHyqp34cCK8hNXhjMY0LklAGix2nhOJwAr6H_OwAH8Ovtd9QRxAaMQxSysUuuyb4fU_Xbu4CJpB26u0PMh7b8zDFZqBbEWztE90x5v1EVPEIB_U_JAtFIUHkjQ\"}";
    private final static String RSA_JWK_PUB = "{\"kty\":\"RSA\",\"e\":\"AQAB\",\"n\":\"j1-pKcnYHZJxfJls4PKgrJ0VcmSp8ktzVu0f0DZGolmKnrxQcHPHC1eSzk2kVF9ILY5Dm9FBNkSXBYT8EMwr5TcsllrO9IAgfIyvTWICIR_1j9Y3ve4-mAUFX7Mfne6DIfxFodyHA94C_2U2K4T3ir32E0FPm1IT8_wDWSwSojEsg3N7qYkY5K9GkAqYzYgLSvDxqridH1UWvkiRmNBRsQMspUpylHyqp34cCK8hNXhjMY0LklAGix2nhOJwAr6H_OwAH8Ovtd9QRxAaMQxSysUuuyb4fU_Xbu4CJpB26u0PMh7b8zDFZqBbEWztE90x5v1EVPEIB_U_JAtFIUHkjQ\"}";
    private final static String RSA_JWK_KEYS ="{\"keys\":[{\"kty\":\"RSA\",\"n\":\"j1-pKcnYHZJxfJls4PKgrJ0VcmSp8ktzVu0f0DZGolmKnrxQcHPHC1eSzk2kVF9ILY5Dm9FBNkSXBYT8EMwr5TcsllrO9IAgfIyvTWICIR_1j9Y3ve4-mAUFX7Mfne6DIfxFodyHA94C_2U2K4T3ir32E0FPm1IT8_wDWSwSojEsg3N7qYkY5K9GkAqYzYgLSvDxqridH1UWvkiRmNBRsQMspUpylHyqp34cCK8hNXhjMY0LklAGix2nhOJwAr6H_OwAH8Ovtd9QRxAaMQxSysUuuyb4fU_Xbu4CJpB26u0PMh7b8zDFZqBbEWztE90x5v1EVPEIB_U_JAtFIUHkjQ\",\"e\":\"AQAB\",\"d\":\"Z-SH7pInGva9ae67qR3oNGz315b-V2c5Qyo9PWG3OXntKy2GlJYxDBT_eqNkiwcohGpsr4Ko4Kw_S26cQYfR3x1mH-XZxe76m4ZOmaKFrH8-MGaoqeb0ULCCvmBMbuMg_wWRZ8MnyzObtHohENQflNgmcrmG-CQ39TsPKhT3w7MF-zln6YKFEMZvACrPqmnfKVhXPWvkodwx5phlqhpKUr7iH79hVZ_jACue-lmsMKPx-JIOy7zPQAlzZw6B2CKAeg4s329ey8MYS5nQipEh_OpvlcjP3CTN9n5NUwT8PEABW7DdHNqtVfvxoTOJ_eCjFLDkPeQDPN2sIPsvoyEJwQ\",\"p\":\"7vFg_eDM5mYgL0-0Eo3_chZP6myjgLRb-tQer1sDBjKyjPsc-s-vgW0Tk_SHV5Ig0-elC4gOFDj00QBsQa0pCUxpR7uL5vV8NKDVho4eeokkgsT4ntd5TnsxKFv5i1B_JVXNHXOm0p3P2qWuMHMHsXInu6ds9yN8KPzRQOdWnVU\",\"q\":\"mZvHVFCLNw8CJjDbb6epPElXqLFI0UNpjvTxdtjWCUJBzjx4ekwDSkh4s-IKcvST6OC5e40A6LBRoxlcjJdN7QV-1YN-Ly2BIiWLKmCa0440TphZmHb9dF_h9e8alaYSX1AWOjxZ-I9B5ouQnn92dc7jyBl3grR93jd9B3sAalk\",\"dp\":\"c7mqbSt8cbZSrjdfEoF9j8boq7Q0ODiiN8iWl_1vaIgTXB6e-YavDPNEQSt0hWA70AXoNL6PexHe2H7o76IrNtqwPtLBvnl0z5R59jJM5rIXYdJ-S4g2s2EM_OwW33d8LRvyPOpviKBwNAh8ZfDAcBvGzKcZKlUgZEWWH2Yr2AU\",\"dq\":\"Wc6F33mnqu0PaJyv7rurah_HLE1aMV6kXHxAoCduG8OtDZK1LWs7kTaFu0WwrjzoLQMV7nIl0eUkFaNCRMBBQw4vdU2HfLWyBfDFSGVqn71IP5s65rTKwjs8tLiyZkPOAgOkuy-FupinAs8eIkyLSZ1H9zlMchJsdHskkjcLqyE\",\"qi\":\"nTfo5vvgSXGw8CMirrQwD2JNWMreLenl7ZAjI1qDwHmgXDEORXWHJmlpw6R2enusUQXvyXiz3Jyz9nvHIQa00l_URSX1oTWgSiB--vrkeU4lMZlZVUdfMRSNweT1L6ebLZ8YP5wD1-qMZmMHl3rS5xzVAzCAoexVjxAAnfmBxlg\"}]}";
    private final static String EC256_JWK = "{\"kty\":\"EC\",\"d\":\"JaTosU8Ah_IOlqJGj5v5NiPyy856lKl-FDKuP59-nSI\",\"use\":\"sig\",\"crv\":\"P-256\",\"x\":\"sOOb4SwbfAsMDCILgme4hwLjBqCC4_MWCNFXh62Q5lY\",\"y\":\"RN2OeR9AkUrMYHlfRsAy5VZXViA31yOkCWzwSb5NRf0\",\"alg\":\"ES256\"}";
    private final static String EC256_JWK_PUB = "{\"kty\":\"EC\",\"use\":\"sig\",\"crv\":\"P-256\",\"x\":\"sOOb4SwbfAsMDCILgme4hwLjBqCC4_MWCNFXh62Q5lY\",\"y\":\"RN2OeR9AkUrMYHlfRsAy5VZXViA31yOkCWzwSb5NRf0\",\"alg\":\"ES256\"}";
    private final static String EC256_JWK_KEYS = "{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"sOOb4SwbfAsMDCILgme4hwLjBqCC4_MWCNFXh62Q5lY\",\"y\":\"RN2OeR9AkUrMYHlfRsAy5VZXViA31yOkCWzwSb5NRf0\",\"d\":\"JaTosU8Ah_IOlqJGj5v5NiPyy856lKl-FDKuP59-nSI\"}]}";
    private final static String EC384_JWK = "{\"kty\":\"EC\",\"d\":\"RyeXpTmYnuPpL_nPq5CgGTjJs6hbtq2YzsnltC5bADj-NH_26uWoWmYUZ74JM1T5\",\"use\":\"sig\",\"crv\":\"P-384\",\"x\":\"NEqzgL_3GjfV3_7MWDHFIbplOqerH4syXj7zyqGJ6z9VyklQi2wyzgeISOxBmhkX\",\"y\":\"Jsw1m7PnUO4uFhR4Zxvhpllvg5k8wai_U0AHMzZpqtGo7jGzjK1mw9_6iv08kXHl\",\"alg\":\"ES384\"}";
    private final static String EC384_JWK_PUB = "{\"kty\":\"EC\",\"use\":\"sig\",\"crv\":\"P-384\",\"x\":\"NEqzgL_3GjfV3_7MWDHFIbplOqerH4syXj7zyqGJ6z9VyklQi2wyzgeISOxBmhkX\",\"y\":\"Jsw1m7PnUO4uFhR4Zxvhpllvg5k8wai_U0AHMzZpqtGo7jGzjK1mw9_6iv08kXHl\",\"alg\":\"ES384\"}";
    private final static String EC521_JWK = "{\"kty\":\"EC\",\"d\":\"ABPQswPQGCOyPcmVeMYofoRq3w_sk2sV-NhOS9-PPgCJacCK4Xp3tdUNLCaG37go28zP8oB2eQ27pMxUeIJqVn7u\",\"use\":\"sig\",\"crv\":\"P-521\",\"x\":\"AP-eIKDH3m_Bleijed6Ku_y2XwMJmpDX9aIj4rDwEXj7Fa5nIKREcMcaKWlj5YHViEEGJy0pKQ6gbWjzWomufrSW\",\"y\":\"AfBZvb1OROt6f1myiraU_VzjuRvxF8jKrgE2ZmXXI4g8cOjWNkuW3yE4UmcFJgmK7xPBw3JfbNLslze5Pk82FJFg\",\"alg\":\"ES512\"}";
    private final static String EC521_JWK_PUB = "{\"kty\":\"EC\",\"use\":\"sig\",\"crv\":\"P-521\",\"x\":\"AP-eIKDH3m_Bleijed6Ku_y2XwMJmpDX9aIj4rDwEXj7Fa5nIKREcMcaKWlj5YHViEEGJy0pKQ6gbWjzWomufrSW\",\"y\":\"AfBZvb1OROt6f1myiraU_VzjuRvxF8jKrgE2ZmXXI4g8cOjWNkuW3yE4UmcFJgmK7xPBw3JfbNLslze5Pk82FJFg\",\"alg\":\"ES512\"}";
    private final static String ED25519_JWK = "{\"kty\":\"OKP\",\"d\":\"a6sk90NMqre9LnvZXjIOdXCT5GCzJ0TWol8TOgG2AYY\",\"use\":\"sig\",\"crv\":\"Ed25519\",\"x\":\"xb4vqs8YZ2cvuGeDTKRxyZyxwxfDdAY8HAS29pbQXGg\",\"alg\":\"EdDSA\"}";
    private final static String ED25519_JWK_PUB = "{\"kty\":\"OKP\",\"use\":\"sig\",\"crv\":\"Ed25519\",\"x\":\"xb4vqs8YZ2cvuGeDTKRxyZyxwxfDdAY8HAS29pbQXGg\",\"alg\":\"EdDSA\"}";
    private final static String ED25519_JWK_KEYS = "{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"xb4vqs8YZ2cvuGeDTKRxyZyxwxfDdAY8HAS29pbQXGg\",\"d\":\"a6sk90NMqre9LnvZXjIOdXCT5GCzJ0TWol8TOgG2AYY\"}]}";
    private final static String ED448_JWK = "{\"kty\":\"OKP\",\"d\":\"gS4I5PLxahQZlsB306UE80DWma2GjVwvxbcxJDG0vrU\",\"use\":\"sig\",\"crv\": \"Ed25519\",\"x\": \"LXOnNl3tad9vVm-vor7d0E0z8mVtogIGteY3J05dLTg\",\"alg\": \"EdDSA\"}";
    private final static String ED448_JWK_PUB = "{\"kty\":\"OKP\",\"use\":\"sig\",\"crv\": \"Ed25519\",\"x\": \"LXOnNl3tad9vVm-vor7d0E0z8mVtogIGteY3J05dLTg\",\"alg\": \"EdDSA\"}";

    @Test
    public void testParseJWK() {
        System.out.println("testParseJWK");
        try {
            {
                System.out.println("parseRSA_JWK:" + RSA_JWK);
                KeyPair keyPair = JWKUtil.parseJWK(RSA_JWK);
                assertTrue(keyPair.getPrivate() instanceof RSAPrivateKey);
                assertTrue(keyPair.getPublic() instanceof RSAPublicKey);
                String token = JWKUtil.toJWK(keyPair,false);
                System.out.println("toRSA_JWK:" + token);
            }
            {
                System.out.println("parseRSA_JWK_PUB:" + RSA_JWK_PUB);
                KeyPair keyPair = JWKUtil.parseJWK(RSA_JWK_PUB);
                assertNull(keyPair.getPrivate());
                assertTrue(keyPair.getPublic() instanceof RSAPublicKey);
                String token = JWKUtil.toJWK(keyPair,false);
                System.out.println("toRSA_JWK_PUB:" + token);
            }
            {
                System.out.println("parseRSA_JWK_KEYS:" + RSA_JWK_KEYS);
                List<KeyPair> keyPairs = JWKUtil.parseJWKSet(RSA_JWK_KEYS);
                assertEquals(keyPairs.size(), 1);
                for (int i = 0; i < keyPairs.size(); i++) {
                    assertTrue(keyPairs.get(i).getPrivate() instanceof RSAPrivateKey);
                    assertTrue(keyPairs.get(i).getPublic() instanceof RSAPublicKey);
                    String token = JWKUtil.toJWK(keyPairs.get(i),false);
                    System.out.println("toRSA_JWK_KEY:" + token);
                }
            }
            {
                System.out.println("parseEC256_JWK:" + EC256_JWK);
                KeyPair keyPair = JWKUtil.parseJWK(EC256_JWK);
                assertTrue(keyPair.getPrivate() instanceof ECPrivateKey);
                assertTrue(keyPair.getPublic() instanceof ECPublicKey);
                String token = JWKUtil.toJWK(keyPair,false);
                System.out.println("toEC256_JWK:" + token);
            }
            {
                System.out.println("parseEC256_JWK_PUB:" + EC256_JWK_PUB);
                KeyPair keyPair = JWKUtil.parseJWK(EC256_JWK_PUB);
                assertNull(keyPair.getPrivate());
                assertTrue(keyPair.getPublic() instanceof ECPublicKey);
                String token = JWKUtil.toJWK(keyPair,false);
                System.out.println("toEC256_JWK_PUB:" + token);
            }
            {
                System.out.println("parseEC256_JWK_KEYS:" + EC256_JWK_KEYS);
                List<KeyPair> keyPairs = JWKUtil.parseJWKSet(EC256_JWK_KEYS);
                assertEquals(keyPairs.size(), 1);
                for (int i = 0; i < keyPairs.size(); i++) {
                    assertTrue(keyPairs.get(i).getPrivate() instanceof ECPrivateKey);
                    assertTrue(keyPairs.get(i).getPublic() instanceof ECPublicKey);
                    String token = JWKUtil.toJWK(keyPairs.get(i),false);
                    System.out.println("toEC256_JWK_KEY:" + token);
                }
            }
            {
                System.out.println("parseEC384_JWK:" + EC384_JWK);
                KeyPair keyPair = JWKUtil.parseJWK(EC384_JWK);
                assertTrue(keyPair.getPrivate() instanceof ECPrivateKey);
                assertTrue(keyPair.getPublic() instanceof ECPublicKey);
                String token = JWKUtil.toJWK(keyPair,false);
                System.out.println("toEC384_JWK:" + token);
            }
            {
                System.out.println("parseEC384_JWK_PUB:" + EC384_JWK_PUB);
                KeyPair keyPair = JWKUtil.parseJWK(EC384_JWK_PUB);
                assertNull(keyPair.getPrivate());
                assertTrue(keyPair.getPublic() instanceof ECPublicKey);
                String token = JWKUtil.toJWK(keyPair,false);
                System.out.println("toEC384_JWK_PUB:" + token);
            }
            {
                System.out.println("parseEC521_JWK:" + EC521_JWK);
                KeyPair keyPair = JWKUtil.parseJWK(EC521_JWK);
                assertTrue(keyPair.getPrivate() instanceof ECPrivateKey);
                assertTrue(keyPair.getPublic() instanceof ECPublicKey);
                String token = JWKUtil.toJWK(keyPair,false);
                System.out.println("toEC521_JWK:" + token);
            }
            {
                System.out.println("parseEC521_JWK_PUB:" + EC521_JWK_PUB);
                KeyPair keyPair = JWKUtil.parseJWK(EC521_JWK_PUB);
                assertNull(keyPair.getPrivate());
                assertTrue(keyPair.getPublic() instanceof ECPublicKey);
                String token = JWKUtil.toJWK(keyPair,false);
                System.out.println("toEC521_JWK_PUB:" + token);
            }
            {
                System.out.println("parseED25519_JWK:" + ED25519_JWK);
                KeyPair keyPair = JWKUtil.parseJWK(ED25519_JWK);
                assertTrue(keyPair.getPrivate() instanceof EdECPrivateKey);
                assertTrue(keyPair.getPublic() instanceof EdECPublicKey);
                String token = JWKUtil.toJWK(keyPair,false);
                System.out.println("toED25519_JWK:" + token);
            }
            {
                System.out.println("parseED25519_JWK_PUB:" + ED25519_JWK_PUB);
                KeyPair keyPair = JWKUtil.parseJWK(ED25519_JWK_PUB);
                assertNull(keyPair.getPrivate());
                assertTrue(keyPair.getPublic() instanceof EdECPublicKey);
                String token = JWKUtil.toJWK(keyPair,false);
                System.out.println("toED25519_JWK_PUB:" + token);
            }
            {
                System.out.println("parseED25519_JWK_KEYS:" + ED25519_JWK_KEYS);
                List<KeyPair> keyPairs = JWKUtil.parseJWKSet(ED25519_JWK_KEYS);
                assertEquals(keyPairs.size(), 1);
                for (int i = 0; i < keyPairs.size(); i++) {
                    assertTrue(keyPairs.get(i).getPrivate() instanceof EdECPrivateKey);
                    assertTrue(keyPairs.get(i).getPublic() instanceof EdECPublicKey);
                    String token = JWKUtil.toJWK(keyPairs.get(i),false);
                    System.out.println("toED25519_JWK_KEY:" + token);
                }
            }
            {
                System.out.println("parseED448_JWK:" + ED448_JWK);
                KeyPair keyPair = JWKUtil.parseJWK(ED448_JWK);
                assertTrue(keyPair.getPrivate() instanceof EdECPrivateKey);
                assertTrue(keyPair.getPublic() instanceof EdECPublicKey);
                String token = JWKUtil.toJWK(keyPair,false);
                System.out.println("toED448_JWK:" + token);
            }
            {
                System.out.println("parseED448_JWK_PUB:" + ED448_JWK_PUB);
                KeyPair keyPair = JWKUtil.parseJWK(ED448_JWK_PUB);
                assertNull(keyPair.getPrivate());
                assertTrue(keyPair.getPublic() instanceof EdECPublicKey);
                String token = JWKUtil.toJWK(keyPair,false);
                System.out.println("toED448_JWK_PUB:" + token);
            }
        } catch (InvalidKeySpecException ex) {
            ex.printStackTrace();
            fail(ex.getMessage(), ex);
        }
    }

    @Test
    public void testGenRSA_JWK()
    {
        System.out.println("testGenRSA_JWK");
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
