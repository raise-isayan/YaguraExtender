package passive;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import extend.util.external.jws.JWSUtil;
import extension.helpers.FileUtil;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.SignatureException;
import java.text.ParseException;
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
public class JWSTokenJoseTest {

    public JWSTokenJoseTest() {
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
    public void testVerify_HS() {
        System.out.println("testVerify_HS");
        try {
            String secretKey = "a-string-secret-at-least-256-bits-long";
            String except_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTc2MzEwOTcyMn0.0fcA6XZyBC5Z9BMlF-pdisZ4f_dJbmp8N5YjlkKN5zc";
            JWSObject parsedJWS = JWSObject.parse(except_token);
            MACVerifier verifier = new MACVerifier("a-string-secret-at-least-256-bits-long");
            assertTrue(parsedJWS.verify(verifier));
            String[] token_HS256_parts = JWSUtil.splitSegment(except_token);
            JWSToken jws_token = new JWSToken(token_HS256_parts[0], token_HS256_parts[1], token_HS256_parts[2]);
            byte[] jws_sign = jws_token.sign(secretKey);
            jws_token.getSignature().setEncodeBase64Url(jws_sign);
            assertEquals(except_token, jws_token.getToken());
            boolean jws_verify = jws_token.verify(JWSToken.Algorithm.HS256, secretKey);
            assertTrue(jws_verify);
        } catch (ParseException ex) {
            fail(ex.getMessage(), ex);
        } catch (JOSEException ex) {
            fail(ex.getMessage(), ex);
        } catch (SignatureException ex) {
            fail(ex.getMessage(), ex);
        }
    }

    @Test
    public void testVerify_RS() {
        System.out.println("testVerify_RS");
        try {
            String priKeyPath = JWSTokenTest.class.getResource("/resources/private-rsa-key.pem").getPath();
            String pemPrivateData = FileUtil.stringFromFile(new File(priKeyPath), StandardCharsets.UTF_8);
            String pubKeyPath = JWSTokenTest.class.getResource("/resources/public-rsa-key.pem").getPath();
            String pemPublicData = FileUtil.stringFromFile(new File(pubKeyPath), StandardCharsets.UTF_8);

            String except_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTc2MzExMTkyMn0.d0xOIObOLChXK-Vp_aJAsw1y9n7zB2wfNwS1X-2xlqIHq3g3KNTpP1HjjMFqSUqJWth3ixGikaQJ4obQwp3FmLQV9nO2ncrQoPoDw97k8viuEVwwAK23kaZqcu6rF2LIDFXMijBN4CCVdEtFJgLAZwQuSLIL6c4qrz5kVY0M0fc5FSjQzpzZw4RAf643UEekZ7JNbrrJ_nX_G7AI55JsbJROB0wG1-YJykwNpC-LVR_brukh8lcH7EOUFxmKXPdcBlSBW7-FFUpJ81oHgnxapiFbsYZGBfPmSw6kwBNwsCBYsIvkRW9U3zFWoPyHFpQ0iFDlgkHvh8dbngbx8Ey1Qw";

            JWSObject parsedJWS = JWSObject.parse(except_token);
            JWSVerifier verifier = new RSASSAVerifier(JWSUtil.toRSAPublicKey(pemPublicData));
            assertTrue(parsedJWS.verify(verifier));

            String[] token_RS256_parts = JWSUtil.splitSegment(except_token);
            JWSToken jws_token = new JWSToken(token_RS256_parts[0], token_RS256_parts[1], token_RS256_parts[2]);
            byte[] jws_sign = jws_token.sign(JWSToken.Algorithm.RS256, pemPrivateData);
            jws_token.getSignature().setEncodeBase64Url(jws_sign);
            assertEquals(except_token, jws_token.getToken());
            boolean jws_verify = jws_token.verify(JWSToken.Algorithm.RS256, pemPublicData);
            assertTrue(jws_verify);
        } catch (ParseException ex) {
            fail(ex.getMessage(), ex);
        } catch (JOSEException ex) {
            fail(ex.getMessage(), ex);
        } catch (SignatureException ex) {
            fail(ex.getMessage(), ex);
        } catch (IOException ex) {
            System.getLogger(JWSTokenJoseTest.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        }
    }

    @Test
    public void testVerify_PS() {
        System.out.println("testVerify_PS");
        try {
            String priKeyPath = JWSTokenTest.class.getResource("/resources/private-rsa-key.pem").getPath();
            String pemPrivateData = FileUtil.stringFromFile(new File(priKeyPath), StandardCharsets.UTF_8);
            String pubKeyPath = JWSTokenTest.class.getResource("/resources/public-rsa-key.pem").getPath();
            String pemPublicData = FileUtil.stringFromFile(new File(pubKeyPath), StandardCharsets.UTF_8);
            String except_token = "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTc2MzExNTM3MX0.b7Lecm2xSnFjOsHnotYamnKBw5bpiZcWrpV_kLBRSJrzgx_kBk8SYFW-bZbF4HBYr_6wlW6MxJVV9_mJJHXEHc-Ns44nr_I6fkFWHyaeAhWafa4y_D7QOv_nM2cg23QNwhOTO0Cmd64W3TM8_hKe739KG3bjthZ9qyaqePZJFLW_jXJS3rX5P5unoGVEpJaddsCCG9Qeg0vJh_aA3kEzHj0bm0dG5eusopHGx_WH1tb4e1d2pvzjD5AgNyKxIjiLfiDvDd-jwrtrXjA8HKxcKHqcgbnyQk3p11MItORm00-lqCsI8DWDEaco5daBSTOFAgywDLWFSeWoUr_TtAqxIg";
            {
                String[] token_PS256_parts = JWSUtil.splitSegment(except_token);
                JWSToken jws_token = new JWSToken(token_PS256_parts[0], token_PS256_parts[1], token_PS256_parts[2]);
                byte[] jws_sign = jws_token.sign(JWSToken.Algorithm.PS256, pemPrivateData);
                jws_token.getSignature().setEncodeBase64Url(jws_sign);
                String result_token = jws_token.getToken();

                JWSObject parsedJWS = JWSObject.parse(result_token);
                JWSVerifier verifier = new RSASSAVerifier(JWSUtil.toRSAPublicKey(pemPublicData));
                assertTrue(parsedJWS.verify(verifier));
            }
            {
                String[] token_PS256_parts = JWSUtil.splitSegment(except_token);
                JWSObject signJWT = new JWSObject(
                        com.nimbusds.jose.JWSHeader.parse(com.nimbusds.jose.util.Base64URL.from(token_PS256_parts[0])),
                        new com.nimbusds.jose.Payload(com.nimbusds.jose.util.Base64URL.from(token_PS256_parts[1])));
                JWSSigner signer = new RSASSASigner(JWSUtil.toRSAPrivateKey(pemPrivateData));
                signJWT.sign(signer);
                String veryfy_token = signJWT.serialize();
                String[] veryfy_PS256_parts = JWSUtil.splitSegment(veryfy_token);
                JWSToken jws_token = new JWSToken(veryfy_PS256_parts[0], veryfy_PS256_parts[1], veryfy_PS256_parts[2]);
                boolean jws_verify = jws_token.verify(JWSToken.Algorithm.PS256, pemPublicData);
                assertTrue(jws_verify);
            }
        } catch (ParseException ex) {
            fail(ex.getMessage(), ex);
        } catch (JOSEException ex) {
            fail(ex.getMessage(), ex);
        } catch (SignatureException ex) {
            fail(ex.getMessage(), ex);
        } catch (IOException ex) {
            fail(ex.getMessage(), ex);
        }
    }

    @Test
    public void testVerify_EC() {
        System.out.println("testVerify_EC");
        try {
            String priKeyPath = JWSTokenTest.class.getResource("/resources/private-ec256-key.pem").getPath();
            String pemPrivateData = FileUtil.stringFromFile(new File(priKeyPath), StandardCharsets.UTF_8);
            String pubKeyPath = JWSTokenTest.class.getResource("/resources/public-ec256-key.pem").getPath();
            String pemPublicData = FileUtil.stringFromFile(new File(pubKeyPath), StandardCharsets.UTF_8);
            String except_token = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTc2MzExMzIyNH0.GbIZ8HE1z0DIdP6Pq_3AC-Hbz9M8P4cGNX2wbQOtO8w2VTbpGDfmaaUCGMeCs04r5tMXWwJ4bogl0QuVJMQoeA";
            {
                String[] token_ES256_parts = JWSUtil.splitSegment(except_token);
                JWSToken jws_token = new JWSToken(token_ES256_parts[0], token_ES256_parts[1], token_ES256_parts[2]);
                byte[] jws_sign = jws_token.sign(JWSToken.Algorithm.ES256, pemPrivateData);
                jws_token.getSignature().setEncodeBase64Url(jws_sign);
                String result_token = jws_token.getToken();

                JWSObject parsedJWT = JWSObject.parse(result_token);
                JWSVerifier verifier = new ECDSAVerifier(JWSUtil.toECPublicKey(pemPublicData));
                assertTrue(parsedJWT.verify(verifier));
            }
            {
                String[] token_ES256_parts = JWSUtil.splitSegment(except_token);
                JWSObject signJWT = new JWSObject(
                        com.nimbusds.jose.JWSHeader.parse(com.nimbusds.jose.util.Base64URL.from(token_ES256_parts[0])),
                        new com.nimbusds.jose.Payload(com.nimbusds.jose.util.Base64URL.from(token_ES256_parts[1])));
                JWSSigner signer = new ECDSASigner(JWSUtil.toECPrivateKey(pemPrivateData));
                signJWT.sign(signer);
                String veryfy_token = signJWT.serialize();
                String[] veryfy_ES256_parts = JWSUtil.splitSegment(veryfy_token);
                JWSToken jws_token = new JWSToken(veryfy_ES256_parts[0], veryfy_ES256_parts[1], veryfy_ES256_parts[2]);
                boolean jws_verify = jws_token.verify(JWSToken.Algorithm.ES256, pemPublicData);
                assertTrue(jws_verify);
            }
        } catch (ParseException ex) {
            fail(ex.getMessage(), ex);
        } catch (JOSEException ex) {
            fail(ex.getMessage(), ex);
        } catch (SignatureException ex) {
            fail(ex.getMessage(), ex);
        } catch (IOException ex) {
            fail(ex.getMessage(), ex);
        }
    }

}
