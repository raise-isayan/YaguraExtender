package passive;

import extend.util.external.jws.JWSUtil;
import extension.helpers.FileUtil;
import extension.helpers.StringUtil;
import extension.helpers.json.JsonUtil;
import extension.view.base.CaptureItem;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.security.SignatureException;
import java.util.logging.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import passive.JWSToken.Algorithm;

/**
 *
 * @author isayan
 */
public class JWSTokenTest {

    private final static Logger logger = Logger.getLogger(JWSTokenTest.class.getName());

    public JWSTokenTest() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @BeforeAll
    public static void setUpClass() {
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
    public void testJWTHeader() {
        System.out.println("testJWTHeader");
        {
            JWSToken.Header header = JWSToken.Header.generateAlgorithm(Algorithm.RS256);
            assertEquals("{\"alg\":\"RS256\",\"typ\":\"JWT\"}", header.toJSON(false));
            assertEquals("{\"alg\":\"HS256\",\"typ\":\"JWT\"}", header.withAlgorithm(Algorithm.HS256).toJSON(false));
            assertEquals("{\"alg\":\"RS256\",\"typ\":\"JWT\"}", JWSToken.Header.generateAlgorithm(Algorithm.RS256).toJSON(false));
        }
        {
            JWSToken.Header header = new JWSToken.Header("");
            System.out.println("toJSON:" + header.toJSON(false));
            assertFalse(header.isValid());
        }
        {
            System.out.println("prettyJson:" + JsonUtil.prettyJson(""));
        }
    }

    private final String JWT_TOKEN00 = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ5b3VyLWFwcCIsInN1YiI6InVzZXIxMjMiLCJyb2xlIjoiYWRtaW4iLCJleHAiOjE3NTU3ODMxNzV9.dqBgwLri4YJt1FIqjjT1Ljn1LWaoDvACfpX1bgSx8bc";

    private final String JWT_COOKIE00 = "Cookie: sessionid=1234567890; token=eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ5b3VyLWFwcCIsInN1YiI6InVzZXIxMjMiLCJyb2xlIjoiYWRtaW4iLCJleHAiOjE3NTU3ODMxNzV9.dqBgwLri4YJt1FIqjjT1Ljn1LWaoDvACfpX1bgSx8bc uid=aabbcceedd";

    private final String JWT_NONE01 = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJtYWluIjoieHh4eHh4Iiwic3ViIjoi44OG44K544OIIn0.";

    /* secret */
    private final String JWT_TOKEN01 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJtYWluIjoieHh4eHh4Iiwic3ViIjoi44OG44K544OIIn0.IjbkfaSdmROAC0MeW40lJo4s_KoX0VgF0vogsXygNNc";
    /* brady */
    private final String JWT_TOKEN02 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJtYWluIjoiYWJjZGVmIiwic3ViIjoiaG9nZSIsInllYXIiOjIwMjB9.bfk79BN28BVvW6lRnITaEULZ7URDBcem4jalLOW5diM";
    /* 070162 */
    private final String JWT_TOKEN03 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.2nltdvxeDLYX1pTWqadKhePWFESVIct4s9ZKcIlWlS8";
    /* vjht008 */
    private final String JWT_TOKEN04 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJtYWluIjoieHh4eHh4Iiwic3ViIjoi44OG44K544OIIn0.BUDPcG9rb2460KWJY0bSdKeHKOywEODEbgdDh1HrQ2U";
    /* nomatch */
    private final String JWT_TOKEN05 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

    /* RS256 */
    private final String JWT_TOKEN06 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwOlwvXC9kZW1vLnNqb2VyZGxhbmdrZW1wZXIubmxcLyIsImlhdCI6MTU1ODA5NzI3NCwiZXhwIjoxNTU4MDk3Mzk0LCJkYXRhIjp7ImhlbGxvIjoid29ybGQifX0.aMwGO4WBSnVGLWHwaOf1jgo1ZGnRdX6O4mNIV6lRepO5SRykWhiUAPwPSRs9bVakcn-UIoPoHA6XOhoUuxddf48xVaN6oKG2XmkkcNdiV1H7Jh_bW7oKDshhEwtt0cmYuOFVZqyfWYWHk2kj2XOpLskxjzBPzNGW9rTpyrzX933PDiTaJb90OUJgjNthIai6rRyvg4bBeXt55dW_8Yabz5M-eiAn0lukypPVA_pJ6KDtWTmuY_uPj6xVELGwkBWaqsxmgGvNg7JvJmC8ThxBujhoJ5WCivQtWLJAGe_efMv-lDMeNYC0586qnVekqDY1oBOWZ4TOBAxiSi3_k2Pm4A";

    @Test
    public void testSign_HS() {
        System.out.println("testSign_HS");
        try {
            {
                String hs256_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.39jkN-bckg4fbZQEb0xHIxzYL9qI_g4c4WyzEYNHZok";
                String token_HS256_parts[] = JWSUtil.splitSegment(hs256_token);
                JWSToken token = new JWSToken(token_HS256_parts[0], token_HS256_parts[1], token_HS256_parts[2]);
                byte[] signature = token.sign("secret");
                assertEquals(token.getAlgorithm(), JWSToken.Algorithm.HS256);
                assertEquals(token.getSignaturePart(), JsonToken.encodeBase64UrlSafe(signature));
            }
            {
                String hs384_token = "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTc2MjkzMDE0M30.KW47erIop0RFkMPO0E0dLmEwkawLYypE8I2OrYb1Cl6_xxcpZa8NXPTbyU-eqtMP";
                String token_HS384_parts[] = JWSUtil.splitSegment(hs384_token);
                JWSToken token = new JWSToken(token_HS384_parts[0], token_HS384_parts[1], token_HS384_parts[2]);
                byte[] signature = token.sign("secret");
                assertEquals(token.getAlgorithm(), JWSToken.Algorithm.HS384);
                assertEquals(token.getSignaturePart(), JsonToken.encodeBase64UrlSafe(signature));
            }
            {
                String hs512_token = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTc2MjkzMDI2MX0.2Qj_ki8gJYpLJzSjHAL1wolcWdWylPCu-95B7peHobl-sMkKRR7Idbgr59IpNNNBcE_0zy3O7Z2Ln_YQsSEGlA";
                String token_HS512_parts[] = JWSUtil.splitSegment(hs512_token);
                JWSToken token = new JWSToken(token_HS512_parts[0], token_HS512_parts[1], token_HS512_parts[2]);
                byte[] signature = token.sign("secret");
                assertEquals(token.getAlgorithm(), JWSToken.Algorithm.HS512);
                assertEquals(token.getSignaturePart(), JsonToken.encodeBase64UrlSafe(signature));
            }
        } catch (SignatureException ex) {
            fail(ex.getMessage(), ex);
        }
    }

    @Test
    public void testSign_RS() {
        System.out.println("testSign_RS");
        try {
            String priKeyPath = JWSTokenTest.class.getResource("/resources/private-rsa-key.pem").getPath();
            String pemPrivateData = FileUtil.stringFromFile(new File(priKeyPath), StandardCharsets.UTF_8);
            String pubKeyPath = JWSTokenTest.class.getResource("/resources/public-rsa-key.pem").getPath();
            String pemPublicData = FileUtil.stringFromFile(new File(pubKeyPath), StandardCharsets.UTF_8);
            {
                String rs256_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTc2MjkzNTEyOX0.LYg6BJwOqvVsIczhvf3Q7V0PGb82Piita6-jHwME3RD7xR0cpDgdTxrraHw7z4APxJLQWAVH7LiVC_lRkjHiaXl5lc0AZpylXVgFcajOmon18Uk9BSq2uM2J984E9R4DC8t27IPDEruoe9vyDdJAgGCGDkNB5lTnnXErbgnaBq3jJi_frgkn0eCxXK0ZLciwsGaBRnRriNsG7yZUoLSzZQ9S9dgEE37aBMQiinXvrOd7NyXTlfH-aX7iqYL3HwSGODQmg99t0ZWjJeAM1wdSXpsqIfgnu2trC2HTR1Hkm1zoucJVwq-ZZ14TnFomZ_P1ZHVo5fJTV1_YuA6ScJkC3Q";
                String[] token_RS256_parts = JWSUtil.splitSegment(rs256_token);
                JWSToken token = new JWSToken(token_RS256_parts[0], token_RS256_parts[1], token_RS256_parts[2]);
                byte[] signatureBytes = token.sign(pemPrivateData);
                assertEquals(token.getAlgorithm(), JWSToken.Algorithm.RS256);
                assertEquals(token.getSignaturePart(), JsonToken.encodeBase64UrlSafe(signatureBytes));
                assertTrue(JWSToken.verify(Algorithm.RS256, pemPublicData, StringUtil.getBytesUTF8(token.getData()), signatureBytes));
            }
            {
                String rs384_token = "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTc2MjkzNTEyOX0.kyJXAW73cZqGnP5RwaFEIGPx7OMGZjww5-Zml-axKXgDw5rBCOXRry4Rqh3DvvL5Ca-w8T7zD4lzqhACz9QnqxSZHhM37QuBFnzm2-KQvkoYHobOlLNzK26H7ZGh9nhVXZCavOgOzkSGSBXRlygwUF3Gszh1mh1Q0DEIvH5zLgl5u35sQzpOAJfyU3AcdCA6qyh01109YVwB4m8SHpJeF-vxeXYYaVtJ_T2FO9OfiY1MvQRc7blKoLp3io2FhnsOSO-jSMNgTyu65OavdG5VKR5DKbEcmerYV-nLdpABdSi3cvDy7G5om4SzkkIRPZPggrctK8EfcYVtL3Zbf2ns3Q";
                String[] token_RS384_parts = JWSUtil.splitSegment(rs384_token);
                JWSToken token = new JWSToken(token_RS384_parts[0], token_RS384_parts[1], token_RS384_parts[2]);
                byte[] signatureBytes = token.sign(pemPrivateData);
                assertEquals(token.getAlgorithm(), JWSToken.Algorithm.RS384);
                assertEquals(token.getSignaturePart(), JsonToken.encodeBase64UrlSafe(signatureBytes));
                assertTrue(JWSToken.verify(Algorithm.RS384, pemPublicData, StringUtil.getBytesUTF8(token.getData()), signatureBytes));
            }
            {
                String rs512_token = "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTc2MjkzNTEyOX0.Sh5cSSY9EdxSEY2FStRFd8ksQ1Qex3R_bz4PxTjbfu8suaV05gfhNX8rFRQyNZQJ2qrKEQOHFaeqQlx7F92sov6labpCBeu1BqIRNJ9wemlkuAGMVRnxn3WDZGPD9db9DKdU5i_1masSr0jOvSl1lXzGmZlNCYYbRb1b6ZQcHUB2hh5kAfhtqgn4wuLe7RGDWO6BYUxqBUX3zVxBb6MFAgK0XrnQmonso77rCmHDfSuRSSSUT4IUsPJ8V5tvMq1LPkgWwKizxTVCsLyHvD4j_N1lpR6oKnOPcTHF9LLc-1c3G7o4G3fgEKPKowPl_Ee3Zpl2vMpgp_1qBSblyq88CA";
                String[] token_RS512_parts = JWSUtil.splitSegment(rs512_token);
                JWSToken token = new JWSToken(token_RS512_parts[0], token_RS512_parts[1], token_RS512_parts[2]);
                byte[] signatureBytes = token.sign(pemPrivateData);
                assertEquals(token.getAlgorithm(), JWSToken.Algorithm.RS512);
                assertEquals(token.getSignaturePart(), JsonToken.encodeBase64UrlSafe(signatureBytes));
                assertTrue(JWSToken.verify(Algorithm.RS512, pemPublicData, StringUtil.getBytesUTF8(token.getData()), signatureBytes));
            }
        } catch (SignatureException ex) {
            fail(ex.getMessage(), ex);
        } catch (IOException ex) {
            fail(ex.getMessage(), ex);
        }
    }

    @Test
    public void testSign_PS() {
        System.out.println("testSign_PS");
        try {
            String priKeyPath = JWSTokenTest.class.getResource("/resources/private-rsa-key.pem").getPath();
            String pemPrivateData = FileUtil.stringFromFile(new File(priKeyPath), StandardCharsets.UTF_8);
            String pubKeyPath = JWSTokenTest.class.getResource("/resources/public-rsa-key.pem").getPath();
            String pemPublicData = FileUtil.stringFromFile(new File(pubKeyPath), StandardCharsets.UTF_8);
            {
                String ps256_token = "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTc2MjkzNTEyOX0.ZGxPdvV9SKIB7UQ1Kied45DWxHCD3EKHDmdWJe6lwMm3ux-7zVgkbwUjAFpQwcyiQHStt13qbsJVzkJOEhwwmmL3fiLgcIfl3V4nm3IPEWYZwQJqLCJ8nCgsSD5piHj8JjMypdjIsVAh6uhOvnpcfZqSTMev4li65WcnbOzzsX0hFh7ofyKZae4a3yjhhFfRFEYyrUlglWDm7UEDS1e1aQ0aDtFIsUjv5HQtXeaofy-nwuE5QEhyiIbjfEouClh2TDw4z_RHDZssKXtbQ3lug17QpyNbBZWsVKXWV0hnQOvzm7m2e4DYnlizj1848jzy4Aw2AsBaXAVvWJxlS2NZFg";
                String[] token_PS256_parts = JWSUtil.splitSegment(ps256_token);
                JWSToken token = new JWSToken(token_PS256_parts[0], token_PS256_parts[1], token_PS256_parts[2]);
                byte[] signatureBytes = token.sign(pemPrivateData);
                assertEquals(token.getAlgorithm(), JWSToken.Algorithm.PS256);
                assertTrue(JWSToken.verify(Algorithm.PS256, pemPublicData, StringUtil.getBytesUTF8(token.getData()), signatureBytes));
            }
            {
                String ps384_token = "eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTc2MjkzNTEyOX0.XR-ukuVuZGwuaU-KMnRaNXxC3r7EwTlCWhhLK7PfQOayFg_F62THtpPyeFlVafl5Cc_SJfcHm9X2v9MSMKyu9yQwQhYyQKytjGLbuRTs74oUjaHxkQQRgncb7HntwcaFw0gGNJIgQoG4n4d25rKo87LL6F-7y0k8PxsgF7awd6Ol1RF2ikOsRyr1bBrRvUcJP3vZ88p3zic3YcpTFsv2eo1PVKqkalM75sMRQJRbNHLTQuLcTeQ7uYz1a3MOYmmID1EixJj9Y0RwBP4x0EXCSORSuGQvkM6NuXI3HHeCUdSG4jQq13tMgT2QwILEZHoXPme-iyaE_dL0GgfqxJ1t9w";
                String[] token_PS384_parts = JWSUtil.splitSegment(ps384_token);
                JWSToken token = new JWSToken(token_PS384_parts[0], token_PS384_parts[1], token_PS384_parts[2]);
                byte[] signatureBytes = token.sign(pemPrivateData);
                assertEquals(token.getAlgorithm(), JWSToken.Algorithm.PS384);
                assertTrue(JWSToken.verify(Algorithm.PS384, pemPublicData, StringUtil.getBytesUTF8(token.getData()), signatureBytes));
            }
            {
                String ps512_token = "eyJhbGciOiJQUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTc2MjkzNTEyOX0.cvkNlDG8pBIA6VoxO_78YaxSH3K6zd61QYylHdLCqF6iDa3ON5G-ww5bFko_DJSFzZkfCo1vm7YopcghjlOVMgpRBvjz9T7DS3ChHADCRHZhGgQGH71Zpl6_ksdN3iOaPYz-anK8BQpuGrcUe26IinLoKHpltgP4uI-d-O70IGvmsVo7DXgzxU6U7081GgPGGs8e1B5zrbeetncgnaCMpCGSaPt305nDqiZilDEFxqgieVaFPYMxWPX1uq6GdBfbhrngA3tpz2qDrWebzXZsN5myBNNFkRpL-j-oYulN4y6gih1OdHBfn6xt_sW6GUcuPhkrt1KKM29zD5fZsNn1cA";
                String[] token_PS512_parts = JWSUtil.splitSegment(ps512_token);
                JWSToken token = new JWSToken(token_PS512_parts[0], token_PS512_parts[1], token_PS512_parts[2]);
                byte[] signatureBytes = token.sign(pemPrivateData);
                assertEquals(token.getAlgorithm(), JWSToken.Algorithm.PS512);
                assertTrue(JWSToken.verify(Algorithm.PS512, pemPublicData, StringUtil.getBytesUTF8(token.getData()), signatureBytes));
            }
        } catch (SignatureException | IOException ex) {
            fail(ex.getMessage(), ex);
        }
    }

    @Test
    public void testSign_ES() {
        System.out.println("testSign_ES");
        try {
            {
                String priKeyPath = JWSTokenTest.class.getResource("/resources/private-ec256-key.pem").getPath();
                String pemPrivateData = FileUtil.stringFromFile(new File(priKeyPath), StandardCharsets.UTF_8);
                String pubKeyPath = JWSTokenTest.class.getResource("/resources/public-ec256-key.pem").getPath();
                String pemPublicData = FileUtil.stringFromFile(new File(pubKeyPath), StandardCharsets.UTF_8);
                String es256_token = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTc2MjkzNTEyOX0.-lb1vRpGrXfx2Yp6iR1NP-KgfWtRV8V3ArPEBGF2cOnYY7xNJeJxlsrLuLorj9TUHO7KKZXSUxdA9dgyzdnicA";
                String[] token_ES256_parts = JWSUtil.splitSegment(es256_token);
                JWSToken token = new JWSToken(token_ES256_parts[0], token_ES256_parts[1], token_ES256_parts[2]);
                byte[] signatureBytes = token.sign(pemPrivateData);
                assertEquals(token.getAlgorithm(), JWSToken.Algorithm.ES256);
                assertTrue(JWSToken.verify(Algorithm.ES256, pemPublicData, StringUtil.getBytesUTF8(token.getData()), signatureBytes));
            }
            {
                String priKeyPath = JWSTokenTest.class.getResource("/resources/private-ec384-key.pem").getPath();
                String pemPrivateData = FileUtil.stringFromFile(new File(priKeyPath), StandardCharsets.UTF_8);
                String pubKeyPath = JWSTokenTest.class.getResource("/resources/public-ec384-key.pem").getPath();
                String pemPublicData = FileUtil.stringFromFile(new File(pubKeyPath), StandardCharsets.UTF_8);
                String es384_token = "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTc2Mjk0NjE2Nn0.ZIkwKFr__wI9lUpj6_grHAD4rLDIf8rat3t98lC9Dl4ohIHfg1qSEudWyUkDPytDvLnJmBQtqSsY9eMrnIT6REMPkZbjuOs7LrPMhWiAu89NXeqopCcCcb4Ciw_xkRB2";
                String[] token_ES384_parts = JWSUtil.splitSegment(es384_token);
                JWSToken token = new JWSToken(token_ES384_parts[0], token_ES384_parts[1], token_ES384_parts[2]);
                byte[] signatureBytes = token.sign(pemPrivateData);
                assertEquals(token.getAlgorithm(), JWSToken.Algorithm.ES384);
                assertTrue(JWSToken.verify(Algorithm.ES384, pemPublicData, StringUtil.getBytesUTF8(token.getData()), signatureBytes));
            }
            {
                String priKeyPath = JWSTokenTest.class.getResource("/resources/private-ec512-key.pem").getPath();
                String pemPrivateData = FileUtil.stringFromFile(new File(priKeyPath), StandardCharsets.UTF_8);
                String pubKeyPath = JWSTokenTest.class.getResource("/resources/public-ec512-key.pem").getPath();
                String pemPublicData = FileUtil.stringFromFile(new File(pubKeyPath), StandardCharsets.UTF_8);
                String es512_token = "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.AbyO7ctJLHB2rlFMfVl3mm2xa8bQbDHN2ZjLxb3PojfK5VNbnSlnHPmJN5gBcDN2yjNcQ1ty7Oi0AoxTTTnByqiGACi1wzY1D1pHCEhcliMr8qRl0zkTMko-Uy2XgdjjXVknqifW5bdyCAMk1fdfmA54awQPUraOFvU20a1nNWbuzt5s";
                String[] token_ES512_parts = JWSUtil.splitSegment(es512_token);
                JWSToken token = new JWSToken(token_ES512_parts[0], token_ES512_parts[1], token_ES512_parts[2]);
                byte[] signatureBytes = token.sign(pemPrivateData);
                assertEquals(token.getAlgorithm(), JWSToken.Algorithm.ES512);
                assertTrue(JWSToken.verify(Algorithm.ES512, pemPublicData, StringUtil.getBytesUTF8(token.getData()), signatureBytes));
            }
        } catch (SignatureException | IOException ex) {
            fail(ex.getMessage(), ex);
        }
    }

    @Test
    public void testSign_ES_Jose() {
        try {
            System.out.println("testSign_ES_Jose");
            {
                // ES256
                String signature_jose = "WLQslycNXTcDc-PY4taDyyNC-z1WaCXfuhxwoI5FMR1DGm5Zd5WIy6ZsvLvpgyBpbydlXpR2gtzRy3fmAtOIFg";
                byte [] signatureDec = JsonToken.decodeBase64UrlSafeByte(signature_jose);
                byte [] signatureDer = JWSToken.joseToDer(signatureDec);
                byte [] signatureJose = JWSToken.derToJose(signatureDer, signatureDec.length);
                String signatureEnc = JsonToken.encodeBase64UrlSafe(signatureJose);
                assertEquals(signature_jose, signatureEnc);
            }
            {
                // ES384
                String signature_jose = "5tYKcddl2HyaWi0fDtl0jMvq5C9Q6in6iYDfEV-jGzWeXjmk0DhLzDf5rPSAfmum9tq9rQRsolD4URy3ac2RM-Xr6C_SjgqN4RIC-7RcnTalhpXT2cT5iwfSIKgC9lNv";
                byte [] signatureDec = JsonToken.decodeBase64UrlSafeByte(signature_jose);
                byte [] signatureDer = JWSToken.joseToDer(signatureDec);
                byte [] signatureJose = JWSToken.derToJose(signatureDer, signatureDec.length);
                String signatureEnc = JsonToken.encodeBase64UrlSafe(signatureJose);
                assertEquals(signature_jose, signatureEnc);
            }
            {
                // ES512
                String signature_jose = "AWI-UkWyXbnZggK3LSGNK5u7kbhjYPVZuvZO7no_ntSrNhf7J_Uo4GDXT3BaizDfwMBKtcYd1RzLohaJ0FiTjyemAE8PlTU9xdD3todMSOE0TN59YGkTG0IlFca0PNRlaDRqab41O2p1aMVpS3fYBwjeIqm7JajU0O0qBh-36B90Q3ji";
                byte [] signatureDec = JsonToken.decodeBase64UrlSafeByte(signature_jose);
                byte [] signatureDer = JWSToken.joseToDer(signatureDec);
                byte [] signatureJose = JWSToken.derToJose(signatureDer, signatureDec.length);
                String signatureEnc = JsonToken.encodeBase64UrlSafe(signatureJose);
                assertEquals(signature_jose, signatureEnc);
            }
        } catch (IOException ex) {
            fail(ex.getMessage(), ex);
        }
    }

    @Test
    public void testSign_EdDSA() {
        System.out.println("testSign_EdDSA");
        try {
            String priKeyPath = JWSTokenTest.class.getResource("/resources/private-eddsa-key.pem").getPath();
            String pemPrivateData = FileUtil.stringFromFile(new File(priKeyPath), StandardCharsets.UTF_8);
            String pubKeyPath = JWSTokenTest.class.getResource("/resources/public-eddsa-key.pem").getPath();
            String pemPublicData = FileUtil.stringFromFile(new File(pubKeyPath), StandardCharsets.UTF_8);
            String eddsa_token = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.JkKWCY39IdWEQttmdqR7VdsvT-_QxheW_eb0S5wr_j83ltux_JDUIXs7a3Dtn3xuqzuhetiuJrWIvy5TzimeCg";
            String[] token_EDDSA_parts = JWSUtil.splitSegment(eddsa_token);
            JWSToken token = new JWSToken(token_EDDSA_parts[0], token_EDDSA_parts[1], token_EDDSA_parts[2]);
            byte[] signatureBytes = token.sign(pemPrivateData);
            assertEquals(token.getAlgorithm(), JWSToken.Algorithm.EDDSA);
            assertTrue(JWSToken.verify(Algorithm.EDDSA, pemPublicData, StringUtil.getBytesUTF8(token.getData()), signatureBytes));
        } catch (IOException | SignatureException ex) {
            fail(ex.getMessage(), ex);
        }
    }

    @Test
    public void testSign_Empty() {
            System.out.println("testSign_Empty");
        try {
            System.out.println("testSign_Empty:" + Algorithm.HS256.name());
            JWSToken.Header header = JWSToken.Header.generateAlgorithm(Algorithm.HS256);
            JWSToken.Payload payload = new JWSToken.Payload("");
            JWSToken token = new JWSToken(header, payload);
            byte [] signature = token.sign("");
            token.getSignature().setEncodeBase64Url(signature);;
        } catch (SignatureException ex) {
            System.out.println(ex.getMessage());
//            ex.printStackTrace();
        } catch (Exception ex) {
//            System.out.println(ex.getMessage());
            ex.printStackTrace();
        }
        try {
            System.out.println("testSign_Empty:" + Algorithm.RS256.name());
            JWSToken.Header header = JWSToken.Header.generateAlgorithm(Algorithm.RS256);
            JWSToken.Payload payload = new JWSToken.Payload("");
            JWSToken token = new JWSToken(header, payload);
            byte [] signature = token.sign("");
            token.getSignature().setEncodeBase64Url(signature);;
        } catch (SignatureException ex) {
            System.out.println(ex.getMessage());
            ex.printStackTrace();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
            ex.printStackTrace();
        }

    }

    @Test
    public void testSignatureEqual_args4() {
        System.out.println("signatureEqual_args4");
        boolean expResult = true;
        // eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
        // {"alg":"HS256","typ":"JWT"}
        String alg256 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        String token256 = "eyJtYWluIjoieHh4eHh4Iiwic3ViIjoi44OG44K544OIIn0";
        String alg384 = "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9";
        String token384 = "eyJtYWluIjoieHh4eHh4Iiwic3ViIjoi44OG44K544OIIn0";
        String alg512 = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9";
        String token512 = "eyJtYWluIjoieHh4eHh4Iiwic3ViIjoi44OG44K544OIIn0";
        try {
            {
                String encodeSig = "IjbkfaSdmROAC0MeW40lJo4s_KoX0VgF0vogsXygNNc";
                boolean result = JWSToken.signatureEqual(JWSToken.Algorithm.HS256, alg256, token256, encodeSig, "secret");
                assertEquals(expResult, result);
            }
            {
                String encodeSig = "H96erEFQSxsDQmwLwZhZDJCd-sXyfTkDmDGKBPYmAG4";
                boolean result = JWSToken.signatureEqual(JWSToken.Algorithm.HS256, alg256, token256, encodeSig, "test");
                assertEquals(expResult, result);
            }
            {
                String encodeSig = "Chui3Q6dauCAgh41YUveD9-S6XR29d5udoNzT7yQkPH6t4lRB-3Ue9ovzGysDSOz";
                boolean result = JWSToken.signatureEqual(JWSToken.Algorithm.HS384, alg384, token384, encodeSig, "test");
                assertEquals(expResult, result);
            }
            {
                String encodeSig = "sx5HdJzL5IrFtZPbFnptVUvZ28qTy56vXamIy9hgB0cjc6-Zr2D5s85HSCtmQKWROseztDes9VycyPYYFUYbHA";
                boolean result = JWSToken.signatureEqual(JWSToken.Algorithm.HS512, alg512, token512, encodeSig, "test");
                assertEquals(expResult, result);
            }
        } catch (SignatureException ex) {
            fail(ex.getMessage(), ex);
        }
    }

    @Test
    public void testParseToken() {
        System.out.println("testParseToken");
        {
            String[] segments = JWSUtil.splitSegment(JWT_NONE01);
            JWSToken jwtinstance = new JWSToken();
            JWSToken token = jwtinstance.parseToken(JWT_NONE01, true);
            assertEquals(segments[0], token.getHeaderPart());
            assertEquals(segments[1], token.getPayloadPart());
            assertEquals(segments[2], token.getSignaturePart());

            assertEquals(segments[0], token.getHeader().getPart());
            assertEquals(segments[1], token.getPayload().getPart());
            assertEquals(segments[2], token.getSignature().getPart());

            assertFalse(token.isSigned());
        }
        {
            String[] segments = JWSUtil.splitSegment(JWT_TOKEN01);
            JWSToken jwtinstance = new JWSToken();
            JWSToken token = jwtinstance.parseToken(JWT_TOKEN01, true);
            assertEquals(segments[0], token.getHeaderPart());
            assertEquals(segments[1], token.getPayloadPart());
            assertEquals(segments[2], token.getSignaturePart());

            assertEquals(segments[0], token.getHeader().getPart());
            assertEquals(segments[1], token.getPayload().getPart());
            assertEquals(segments[2], token.getSignature().getPart());

            assertTrue(token.isSigned());
        }
    }

    /**
     * Test of passiveScanCheck method, of class JWTWeakToken.
     */
    @Test
    public void testSignatureEqual_args2() {
        System.out.println("signatureEqual_args2");
        String JWT_TOKEN01_SIGNATURE = "IjbkfaSdmROAC0MeW40lJo4s_KoX0VgF0vogsXygNNc";
        String JWT_TOKEN02_SIGNATURE = "bfk79BN28BVvW6lRnITaEULZ7URDBcem4jalLOW5diM";
        String JWT_TOKEN03_SIGNATURE = "2nltdvxeDLYX1pTWqadKhePWFESVIct4s9ZKcIlWlS8";
        try {
            boolean expResult = true;
            JWSToken jwtinstance = new JWSToken();
            {
                JWSToken token = jwtinstance.parseToken(JWT_TOKEN01, true);
                byte[] signature = token.sign("secret");
                System.out.println("signature:" + JsonToken.encodeBase64UrlSafe(signature));
                assertEquals(JWT_TOKEN01_SIGNATURE, JsonToken.encodeBase64UrlSafe(signature));
                boolean result = token.signatureEqual("secret");
                assertEquals(expResult, result);
            }
            {
                JWSToken token = jwtinstance.parseToken(JWT_TOKEN02, true);
                byte[] signature = token.sign("brady");
                boolean result = token.signatureEqual("brady");
                assertEquals(JWT_TOKEN02_SIGNATURE, JsonToken.encodeBase64UrlSafe(signature));
                assertEquals(expResult, result);
            }
            {
                JWSToken token = jwtinstance.parseToken(JWT_TOKEN03, true);
                byte[] signature = token.sign("070162");
                assertEquals(JWT_TOKEN03_SIGNATURE, JsonToken.encodeBase64UrlSafe(signature));
                boolean result = token.signatureEqual("070162");
                assertEquals(expResult, result);
            }
        } catch (SignatureException ex) {
            fail(ex.getMessage(), ex);
        }
    }

    /**
     * Test of isJWTFormat method, of class JWTUtil.
     */
    @Test
    public void testIsJWTFormat() {
        System.out.println("isJWTFormat");
        JWSToken jwtinstance = new JWSToken();
        {
            String value = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.5mhBHqs5_DTLdINd9p5m7ZJ6XD0Xc55kIaCRY5r6HRA";
            boolean expResult = true;
            boolean result = jwtinstance.isValidFormat(value);
            assertEquals(expResult, result);
        }
        {
            String value = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ5mhBHqs5_DTLdINd9p5m7ZJ6XD0Xc55kIaCRY5r6HRA";
            boolean expResult = false;
            boolean result = jwtinstance.isValidFormat(value);
            assertEquals(expResult, result);
        }
        {
            String value = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJtYWluIjoiPj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj8_Pz8_Pz8_Pz8_Pz8_Pz8_Pz8_Pz8_Pz8_Pz8_Pz8_Pz8_Pz8iLCJzdWIiOiLjg4bjgrnjg4gifQ.X3cI5c0oMucE4ysk-hfpqn6OSjmS-xXMVhhR_FpHJMQ";
            boolean expResult = true;
            boolean result = jwtinstance.isValidFormat(value);
            assertEquals(expResult, result);
        }
        {
            String value = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.Et9HFtf9R3GEMA0IICOfFMVXY7kkTX1wr4qCyhIf58U";
            boolean expResult = true; // payload = "{}"
            boolean result = jwtinstance.isValidFormat(value);
            assertEquals(expResult, result);
        }
        {
            String value = "xeyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ5mhBHqs5_DTLdINd9p5m7ZJ6XD0Xc55kIaCRY5r6HRA";
            boolean expResult = false;
            boolean result = jwtinstance.isValidFormat(value);
            assertEquals(expResult, result);
        }
        {
            // シグネチャなしはJWT
            String value = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.";
            boolean expResult = true;
            boolean result = jwtinstance.isValidFormat(value);
            assertEquals(expResult, result);
        }
//        /* URL Encode */
//        {
//            String value = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9%2eeyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ%2e5mhBHqs5%5fDTLdINd9p5m7ZJ6XD0Xc55kIaCRY5r6HRA";
//            boolean expResult = true;
//            boolean result = JWTToken.isTokenFormat(value);
//            assertEquals(expResult, result);
//        }
//        /* URL Encode2 */
//        {
//            String value = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9%2eeyJtYWluIjoiPj4%2dPj4%2dPj4%2dPj4%2dPj4%2dPj4%2dPj4%2dPj4%2dPj4%2dPj4%2dPj4%2dPj4%2dPj4%2dPj4%2dPj4%2dPj4%2dPj8%5fPz8%5fPz8%5fPz8%5fPz8%5fPz8%5fPz8%5fPz8%5fPz8%5fPz8%5fPz8%5fPz8%5fPz8iLCJzdWIiOiLjg4bjgrnjg4gifQ%2eX3cI5c0oMucE4ysk%2dhfpqn6OSjmS%2dxXMVhhR%5fFpHJMQ";
//            boolean expResult = true;
//            boolean result = JWTToken.isTokenFormat(value);
//            assertEquals(expResult, result);
//        }
    }

    /**
     * Test of parseJWTToken method, of class JWTUtil.
     */
    @Test
    public void testParseJWTToken() {
        System.out.println("parseJWTToken");
        JWSToken jwsinstance = new JWSToken();
        {
            String value = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.5mhBHqs5_DTLdINd9p5m7ZJ6XD0Xc55kIaCRY5r6HRA";
            JWSToken expResult = null;
            JWSToken result = jwsinstance.parseToken(value, true);
            assertNotEquals(expResult, result);
        }
        {
            String value = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ5mhBHqs5_DTLdINd9p5m7ZJ6XD0Xc55kIaCRY5r6HRA";
            JWSToken expResult = null;
            JWSToken result = jwsinstance.parseToken(value, true);
            assertEquals(expResult, result);
        }
        {
            String value = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJtYWluIjoiPj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj8_Pz8_Pz8_Pz8_Pz8_Pz8_Pz8_Pz8_Pz8_Pz8_Pz8_Pz8_Pz8iLCJzdWIiOiLjg4bjgrnjg4gifQ.X3cI5c0oMucE4ysk-hfpqn6OSjmS-xXMVhhR_FpHJMQ";
            JWSToken expResult = null;
            JWSToken result = jwsinstance.parseToken(value, true);
            assertNotEquals(expResult, result);
        }
        {
            String value = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.Et9HFtf9R3GEMA0IICOfFMVXY7kkTX1wr4qCyhIf58U";
            JWSToken expResult = null; // payload = "{}"
            JWSToken result = jwsinstance.parseToken(value, true);
            assertNotEquals(expResult, result);
        }
        {
            String value = "xeyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ5mhBHqs5_DTLdINd9p5m7ZJ6XD0Xc55kIaCRY5r6HRA";
            JWSToken expResult = null;
            JWSToken result = jwsinstance.parseToken(value, false);
            assertEquals(expResult, result);
        }
        {
            String value = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.";
            JWSToken expResult = null;
            JWSToken result = jwsinstance.parseToken(value, true);
            assertNotEquals(expResult, result);
            if (result != null) {
                System.out.println(result.getAlgorithm());
            }
        }
        {
            String value = JWT_TOKEN00;
            JWSToken expResult = null;
            JWSToken result = jwsinstance.parseToken(value, true);
            assertNotEquals(expResult, result);
        }
        {
            String value = JWT_COOKIE00;
            JWSToken expResult = null;
            JWSToken result = jwsinstance.parseToken(value, true);
            assertEquals(expResult, result);
        }
        {
            String value = JWT_COOKIE00;
            JWSToken expResult = null;
            JWSToken result = jwsinstance.parseToken(value, false);
            assertNotEquals(expResult, result);
        }

//        /* URL Encode */
//        {
//            String value = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9%2eeyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ%2e5mhBHqs5%5fDTLdINd9p5m7ZJ6XD0Xc55kIaCRY5r6HRA";
//            JWTToken expResult = null;
//            JWTToken result = jwtinstance.parseToken(value, true);
//            assertNotEquals(expResult, result);
//        }
//        /* URL Encode */
//        {
//            String value = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9%2eeyJtYWluIjoiPj4%2dPj4%2dPj4%2dPj4%2dPj4%2dPj4%2dPj4%2dPj4%2dPj4%2dPj4%2dPj4%2dPj4%2dPj4%2dPj4%2dPj4%2dPj4%2dPj8%5fPz8%5fPz8%5fPz8%5fPz8%5fPz8%5fPz8%5fPz8%5fPz8%5fPz8%5fPz8%5fPz8%5fPz8iLCJzdWIiOiLjg4bjgrnjg4gifQ%2eX3cI5c0oMucE4ysk%2dhfpqn6OSjmS%2dxXMVhhR%5fFpHJMQ";
//            JWTToken expResult = null;
//            JWTToken result = jwtinstance.parseToken(value, true);
//            assertNotEquals(expResult, result);
//        }
    }

    /**
     * Test of ContainsJWTFormat method, of class JWTUtil.
     */
    @Test
    public void testContainsJWTFormat() {
        System.out.println("containsJWTFormat");
        {
            String value = "Auth: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiLjgYLjgYTjgYbjgYjjgYoifQ.I6fGHWldnjdhfOjxcs9Wtzm41dIjBiAHYl3ZAcKl4Ks";
            boolean expResult = true;
            boolean result = JWSUtil.containsTokenFormat(value);
            assertEquals(expResult, result);
        }
//        /* URL Encode */
//        {
//            String value = "Auth: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9%2eeyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ%2e5mhBHqs5%5fDTLdINd9p5m7ZJ6XD0Xc55kIaCRY5r6HRA";
//            boolean expResult = true;
//            boolean result = JWTToken.containsTokenFormat(value);
//            assertEquals(expResult, result);
//        }
//        /* URL Encode */
//        {
//            String value = "Auth: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9%2eeyJtYWluIjoiPj4%2dPj4%2dPj4%2dPj4%2dPj4%2dPj4%2dPj4%2dPj4%2dPj4%2dPj4%2dPj4%2dPj4%2dPj4%2dPj4%2dPj4%2dPj4%2dPj8%5fPz8%5fPz8%5fPz8%5fPz8%5fPz8%5fPz8%5fPz8%5fPz8%5fPz8%5fPz8%5fPz8%5fPz8iLCJzdWIiOiLjg4bjgrnjg4gifQ%2eX3cI5c0oMucE4ysk%2dhfpqn6OSjmS%2dxXMVhhR%5fFpHJMQ";
//            boolean expResult = true;
//            boolean result = JWTToken.containsTokenFormat(value);
//            assertEquals(expResult, result);
//        }
    }

    /**
     * Test of testParseJWTObject method, of class JWTUtil.
     */
    @Test
    public void testParseJWSToken() {
        System.out.println("parseJWTObject");
        JWSToken jwtinstance = new JWSToken();
        {
            String test = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.5mhBHqs5_DTLdINd9p5m7ZJ6XD0Xc55kIaCRY5r6HRA";
            String expResult1 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
            String expResult2 = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ";
            String expResult3 = "5mhBHqs5_DTLdINd9p5m7ZJ6XD0Xc55kIaCRY5r6HRA";
            JWSToken result = jwtinstance.parseToken(test, true);
            assertEquals(expResult1, result.getHeaderPart());
            assertEquals(expResult2, result.getPayloadPart());
            assertEquals(expResult3, result.getSignaturePart());
        }
    }

    /**
     * Test of testParseJWTObject method, of class JWTUtil.
     */
    @Test
    public void testParseJWTObject_json() {
        System.out.println("parseJWTObject");
        JWSToken jwtinstance = new JWSToken();
        {
            String test = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.5mhBHqs5_DTLdINd9p5m7ZJ6XD0Xc55kIaCRY5r6HRA";
            String expResult1 = "{\n  \"alg\": \"HS256\",\n  \"typ\": \"JWT\"\n}";
            String expResult2 = "{\n  \"sub\": \"1234567890\",\n  \"name\": \"John Doe\",\n  \"iat\": 1516239022\n}";
            JWSToken token = jwtinstance.parseToken(test, true);

            System.out.println(expResult1);

            System.out.println("======================");

            System.out.println(token.getHeader().toJSON(true));

            assertEquals(expResult1, token.getHeader().toJSON(true));
            assertEquals(expResult2, token.getPayload().toJSON(true));
        }
        {
            String test = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiLjgYLjgYTjgYbjgYjjgYoifQ.I6fGHWldnjdhfOjxcs9Wtzm41dIjBiAHYl3ZAcKl4Ks";
            String expResult1 = "{\n  \"alg\": \"HS256\",\n  \"typ\": \"JWT\"\n}";
            String expResult2 = "{\n  \"sub\": \"あいうえお\"\n}";
            JWSToken token = jwtinstance.parseToken(test, true);
            assertEquals(expResult1, token.getHeader().toJSON(true));
            assertEquals(expResult2, token.getPayload().toJSON(true));
        }
    }

    @Test
    public void testGenerateNoneToken() {
        {
            String test = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.5mhBHqs5_DTLdINd9p5m7ZJ6XD0Xc55kIaCRY5r6HRA";
            String[] tokens = JWSToken.generateNoneToken(test);
            for (int i = 0; i < tokens.length; i++) {
                System.out.println("none0:" + tokens[i]);
            }
            assertEquals(tokens[0], "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.");
            assertEquals(tokens[1], "eyJhbGciOiJOT05FIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.");
            assertEquals(tokens[2], "eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.");
        }
        {
            String test = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwOlwvXC9kZW1vLnNqb2VyZGxhbmdrZW1wZXIubmxcLyIsImlhdCI6MTU4NTk1Mzk5OCwiZXhwIjoxNTg1OTU0MTE4LCJkYXRhIjp7ImhlbGxvIjoid29ybGQifX0.ebkW_7-HqAV7SzfX7m0fKEfZ1T0A4BeNjTM0fx2LYZYxi9qMT7dpsd0lNMixCbrpLD0WAdWZJXQDOjfIZd6A6AJSSSioEDmFzh8QusLxuTzaUnrRSipiWwVtyVk9YmGkyucr4hCkckbsIe-0tIOCrdNwCmah5vhYtyQ3veaFizJodHvnBnNpq4fG2cWMmke32Hp_Y62h2kUdEGrAKFC_tQDPKFTz_-mNLxCgWcuvXwqGcoHkSxIObyGyk6pHPgbvVRppM_nFrc548jmpgIzN2oRCUTHdVWxoC-CBgNNJwMZ2Sn4zmvKEceqZ0e8QO1ea7hHGY0R1LWJhuE_X1__8bw";
            String[] tokens = JWSToken.generateNoneToken(test);
            for (int i = 0; i < tokens.length; i++) {
                System.out.println("none1:" + tokens[i]);
            }
            assertEquals(tokens[0], "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJpc3MiOiJodHRwOlwvXC9kZW1vLnNqb2VyZGxhbmdrZW1wZXIubmxcLyIsImlhdCI6MTU4NTk1Mzk5OCwiZXhwIjoxNTg1OTU0MTE4LCJkYXRhIjp7ImhlbGxvIjoid29ybGQifX0.");
            assertEquals(tokens[1], "eyJ0eXAiOiJKV1QiLCJhbGciOiJOT05FIn0.eyJpc3MiOiJodHRwOlwvXC9kZW1vLnNqb2VyZGxhbmdrZW1wZXIubmxcLyIsImlhdCI6MTU4NTk1Mzk5OCwiZXhwIjoxNTg1OTU0MTE4LCJkYXRhIjp7ImhlbGxvIjoid29ybGQifX0.");
            assertEquals(tokens[2], "eyJ0eXAiOiJKV1QiLCJhbGciOiJOb25lIn0.eyJpc3MiOiJodHRwOlwvXC9kZW1vLnNqb2VyZGxhbmdrZW1wZXIubmxcLyIsImlhdCI6MTU4NTk1Mzk5OCwiZXhwIjoxNTg1OTU0MTE4LCJkYXRhIjp7ImhlbGxvIjoid29ybGQifX0.");
        }
    }

    @Test
    public void testGeneratePublicToHashToken() {
        System.out.println("testGeneratePublicToHashToken");
        JWSToken jwtinstance = new JWSToken();
        String expected = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwOlwvXC9kZW1vLnNqb2VyZGxhbmdrZW1wZXIubmxcLyIsImlhdCI6MTc2MjY3OTAwOSwiZXhwIjoxNzYyNjc5MTI5LCJkYXRhIjp7ImhlbGxvIjoid29ybGQifX0.IAAudafZXmamTqudTV7kJ3mjR29i5BExqoCoTN29e9o";
        String test = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwOlwvXC9kZW1vLnNqb2VyZGxhbmdrZW1wZXIubmxcLyIsImlhdCI6MTc2MjY3OTAwOSwiZXhwIjoxNzYyNjc5MTI5LCJkYXRhIjp7ImhlbGxvIjoid29ybGQifX0.IAAudafZXmamTqudTV7kJ3mjR29i5BExqoCoTN29e9o";
        try {
            byte[] publicKeyPem = FileUtil.readAllBytes(JWSTokenTest.class.getResourceAsStream("/resources/public.pem"));
            {
                JWSToken except_token = jwtinstance.parseToken(test, true);
                except_token.sign(Algorithm.HS256, StringUtil.getStringRaw(publicKeyPem));
                String result = except_token.getToken();
                System.out.println("result:" + except_token.getToken());
                assertEquals(expected, result);
            }
        } catch (IOException | SignatureException ex) {
            fail(ex.getMessage(), ex);
        }
    }

    @Test
    public void testForceSignToken() {
//        {
        JWSToken jwtinstance = new JWSToken();
        String expected = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOlwvXC9kZW1vLnNqb2VyZGxhbmdrZW1wZXIubmxcLyIsImlhdCI6MTc2MjY3MzA1OSwiZXhwIjoxNzYyNjczMTc5LCJkYXRhIjp7ImhlbGxvIjoid29ybGQifX0.uIZdNHCi79eFa2UcTutub8RtwQYsCiOIEapNs7GZZKA";
        String tokentest = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwOlwvXC9kZW1vLnNqb2VyZGxhbmdrZW1wZXIubmxcLyIsImlhdCI6MTc2MjY3MzA1OSwiZXhwIjoxNzYyNjczMTc5LCJkYXRhIjp7ImhlbGxvIjoid29ybGQifX0.okX7HfAFDS2pEBqEffkoS30VMKW-lkGlm25HnaPcJkRk0BQEFGkvCZc8E_4Gi7peLa_XTg1N-Ss4uO9-m-HueXzlxmwjxKstQKLGLheKcDmb8rNi11EEc_bo0R8PNT3VkACOJvPbWf2lfq-wt2PKCGjnPqoHeO7g4tBGxf-A3Srh5Bk9n94EbZfEiFLBkHkVZAbveVeF0PtfmWw1cfIVBB9YNgSnqJh3E1hSgadv4aNhXf3FeDn6l7PYhg1PR4H2VgBTbSPJHzxkq8mrMA2CUIjTLkbIMNsMhjgLdS_4sJQDPZ3D0sElCVaz7JWm9fpmZrONyBWuzMnYs0PwX8VgjQ";
        try {
            byte[] publicKeyPem = FileUtil.readAllBytes(JWSTokenTest.class.getResourceAsStream("/resources/public.pem"));
            {
                JWSToken except_token = jwtinstance.parseToken(expected, true);
                byte sign[] = except_token.sign(Algorithm.HS256, StringUtil.getStringRaw(publicKeyPem));
                System.out.println("hsdata:" + except_token.getData());
                System.out.println("except:" + JsonToken.encodeBase64UrlSafe(sign));
                assertEquals(JsonToken.encodeBase64UrlSafe(sign), except_token.getSignaturePart());
            }
            {
                JWSToken rs_token = jwtinstance.parseToken(tokentest, true);
                JWSToken hs_token = new JWSToken(rs_token.getHeader().withAlgorithm(Algorithm.HS256), rs_token.getPayload());
                byte[] sign = hs_token.sign(StringUtil.getStringRaw(publicKeyPem));
                System.out.println("hsdata:" + hs_token.getData());
                System.out.println("hssign:" + JsonToken.encodeBase64UrlSafe(sign));
                hs_token.getSignature().setEncodeBase64Url(sign);
                String result = hs_token.getToken();
                assertEquals(rs_token.getPayloadPart(), hs_token.getPayloadPart());
                System.out.println("result:" + result);
                assertEquals(expected, result);
                String[] tokens = JWSToken.generatePublicToHashToken(tokentest, StringUtil.getStringRaw(publicKeyPem));
                for (String token : tokens) {
                    System.out.println("token:" + token);
                }
                assertEquals(expected, tokens[0]);
            }
        } catch (IOException ex) {
            fail(ex.getMessage(), ex);
        } catch (SignatureException ex) {
            fail(ex.getMessage(), ex);
        }
    }

    private final static String REQ_MESSAGE_URLENCODE_TOKEN00 = "POST /cgi-bin/multienc.cgi?charset=Shift_JIS&mode=disp HTTP/1.1\r\n"
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

    private final static String REQ_MESSAGE_URLENCODE_TOKEN01
            = "POST /cgi-bin/multienc.cgi?charset=Shift_JIS&mode=disp HTTP/1.1\r\n"
            + "Host: 192.168.0.1\r\n"
            + "Content-Length: 60\r\n"
            + "Cache-Control: max-age=0\r\n"
            + "Origin: http://192.168.0.1\r\n"
            + "Content-Type: application/x-www-form-urlencoded\r\n"
            + "User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36\r\n"
            + "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8\r\n"
            + "Auth: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJtYWluIjoiYWJjZGVmIiwic3ViIjoiaG9nZSIsInllYXIiOjIwMjB9.bfk79BN28BVvW6lRnITaEULZ7URDBcem4jalLOW5diM\r\n"
            + "Accept-Encoding: gzip, deflate\r\n"
            + "Accept-Language: ja,en-US;q=0.9,en;q=0.8\r\n"
            + "Connection: close\r\n"
            + "\r\n"
            + "text=%82%A0%82%A2%82%A4%82%A6%82%A8&OS=win&submit=%91%97%90M\r\n";

    @Test
    public void testJWTTokenNothing() {
        System.out.println("testJWTTokenNothing");
        {
            boolean expResult = false;
            boolean result = JWSUtil.containsTokenFormat(REQ_MESSAGE_URLENCODE_TOKEN00);
            assertEquals(expResult, result);
        }
        {
            CaptureItem[] token = JWSUtil.findToken(REQ_MESSAGE_URLENCODE_TOKEN00);
            assertEquals(0, token.length);
        }
    }

    @Test
    public void testJWTToken() {
        System.out.println("testJWTToken");
        {
            boolean expResult = true;
            boolean result = JWSUtil.containsTokenFormat(REQ_MESSAGE_URLENCODE_TOKEN01);
            assertEquals(expResult, result);
        }
        {
            String expResult = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJtYWluIjoiYWJjZGVmIiwic3ViIjoiaG9nZSIsInllYXIiOjIwMjB9.bfk79BN28BVvW6lRnITaEULZ7URDBcem4jalLOW5diM";
            CaptureItem[] token = JWSUtil.findToken(REQ_MESSAGE_URLENCODE_TOKEN01);
            for (CaptureItem item : token) {
                assertEquals(expResult, item.getCaptureValue());
                System.out.println(item.getCaptureValue());
            }
        }
    }

    @Test
    public void testJWTTokenRequest() {
        System.out.println("testJWTTokenRequest");
        {
            JWSToken jwtInstance = new JWSToken();
            String expResult = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJtYWluIjoiYWJjZGVmIiwic3ViIjoiaG9nZSIsInllYXIiOjIwMjB9.bfk79BN28BVvW6lRnITaEULZ7URDBcem4jalLOW5diM";
            JWSToken result = jwtInstance.parseToken(REQ_MESSAGE_URLENCODE_TOKEN01, false);
            assertEquals(Algorithm.HS256, result.getAlgorithm());
            assertEquals("eyJtYWluIjoiYWJjZGVmIiwic3ViIjoiaG9nZSIsInllYXIiOjIwMjB9", result.getPayloadPart());
            assertEquals("bfk79BN28BVvW6lRnITaEULZ7URDBcem4jalLOW5diM", result.getSignaturePart());
            assertEquals("{\"main\":\"abcdef\",\"sub\":\"hoge\",\"year\":2020}", result.getPayload().toJSON(false));
            assertEquals(expResult, result.getToken());
        }
    }

}
