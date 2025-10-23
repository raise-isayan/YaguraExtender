package passive;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.util.Base64URL;
import extend.util.external.jws.JWSUtil;
import extension.helpers.FileUtil;
import extension.view.base.CaptureItem;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.logging.Logger;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.fail;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 *
 * @author isayan
 */
public class JWSTokenTest {

    private final static Logger logger = Logger.getLogger(JWSTokenTest.class.getName());

    public JWSTokenTest() {
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
        {
            String token = JWSUtil.algNoneHeaderJSON();
            assertEquals("{\"alg\":\"none\",\"typ\":\"JWT\"}", token);
        }
        {
            String token = JWSUtil.toHeaderJSON(JWSAlgorithm.HS256);
            assertEquals("{\"typ\":\"JWT\",\"alg\":\"HS256\"}", token);
        }
    }

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

    /**
     * Test of passiveScanCheck method, of class JWTWeakToken.
     */
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
        {
            String encodeSig = "IjbkfaSdmROAC0MeW40lJo4s_KoX0VgF0vogsXygNNc";
            boolean result = JWSToken.signatureEqual(JWSAlgorithm.HS256, alg256, token256, encodeSig, "secret");
            assertEquals(expResult, result);
        }
        {
            String encodeSig = "H96erEFQSxsDQmwLwZhZDJCd-sXyfTkDmDGKBPYmAG4";
            boolean result = JWSToken.signatureEqual(JWSAlgorithm.HS256, alg256, token256, encodeSig, "test");
            assertEquals(expResult, result);
        }
        {
            String encodeSig = "Chui3Q6dauCAgh41YUveD9-S6XR29d5udoNzT7yQkPH6t4lRB-3Ue9ovzGysDSOz";
            boolean result = JWSToken.signatureEqual(JWSAlgorithm.HS384, alg384, token384, encodeSig, "test");
            assertEquals(expResult, result);
        }
        {
            String encodeSig = "sx5HdJzL5IrFtZPbFnptVUvZ28qTy56vXamIy9hgB0cjc6-Zr2D5s85HSCtmQKWROseztDes9VycyPYYFUYbHA";
            boolean result = JWSToken.signatureEqual(JWSAlgorithm.HS512, alg512, token512, encodeSig, "test");
            assertEquals(expResult, result);
        }

    }

    /**
     * Test of passiveScanCheck method, of class JWTWeakToken.
     */
    @Test
    public void testSignatureEqual_args2() {
        System.out.println("signatureEqual_args2");
        boolean expResult = true;
        JWSToken jwtinstance = new JWSToken();
        {
            JWSToken token = jwtinstance.parseToken(JWT_TOKEN01, true);
            boolean result = token.signatureEqual("secret");
            assertEquals(expResult, result);
        }
        {
            JWSToken token = jwtinstance.parseToken(JWT_TOKEN02, true);
            boolean result = token.signatureEqual("brady");
            assertEquals(expResult, result);
        }
        {
            JWSToken token = jwtinstance.parseToken(JWT_TOKEN03, true);
            boolean result = token.signatureEqual("070162");
            assertEquals(expResult, result);
        }
    }

    /**
     * Test of testSignatureSign method, of class JWTWeakToken.
     */
    @Test
    public void testSignatureSign() {
        System.out.println("signatureSign");
        String expResult_HS256 = "IjbkfaSdmROAC0MeW40lJo4s_KoX0VgF0vogsXygNNc";
        String expResult_HS384 = "-H-yEWagRVfn4rhmL2YBoRYh7qE0n1qcQmzZ_DzqdFW7aaMSf81SPnyRWrHEE5JU";
        String expResult_HS512 = "3Tyuj-LyrChj5zJefsrV-RwR4rzxVugMDkZFPHZVWKO0YHy4tN69-mopqasUx6--itLymk8pOuJiQZ_YriQlJg";
        String expResult_RS256 = "MrArWO1bfkwbSGY6WMQnROXBheoKZ-BwquRNyaBFLs2Smf8kEQCH3uCeKrMSHTRmXmJKHNRF4B7l9eRjKn6BRs9EcHXaVax22MBWnYgNpMyTiGcbUxnBzBDNcHZr4oPKUxmtg0Xtx5kYCi327r1-G_bTwoPXwJhLxfuNfb6IWns";
        String expResult_RS384 = "GYguhpCB91u6ZDHJVJo4JaVvrosV0DqUbpCraQcP4iZGJ0UPVDqAvVxIBrx8hSN6OQsiWIK-fszgjbquJ00Y7C8cPXZcKd2mgTWWH5R4wAQYuQSimmmqgPR5JmsaeRbiEatQpbTYEAdZh78fND7LS2C_0KuIfnlhA7rfIE6KTrU";
        String expResult_RS512 = "VzpJSKj33uOvZj-DDLnoV8bknfP51LLALQndtApEGBIcbLHttA1JcS-GZat_e4iAIiMaSybCXWTxoO7p63mnCWp8n5mQobg8sv6OCc9fbYALtMN_qPtdDG_ArqPxPhhaZxcQtvBIUqpAuWNqwYnOLO2Bz35LkCz6oVE17gaM52w";
        String header_HS256 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        String header_HS384 = "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9";
        String header_HS512 = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9";
        String header_RS256 = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9";
        String header_RS384 = "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9";
        String header_RS512 = "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9";
        String payload = "eyJtYWluIjoieHh4eHh4Iiwic3ViIjoi44OG44K544OIIn0";
        try {
            {
                Base64URL signURL = JWSToken.sign(JWSAlgorithm.HS256, header_HS256, payload, JWSToken.toSecretKey("secret"));
                String result = signURL.toString();
                assertEquals(expResult_HS256, result);
            }
            {
                Base64URL signURL = JWSToken.sign(JWSAlgorithm.HS384, header_HS384, payload, JWSToken.toSecretKey("secret"));
                String result = signURL.toString();
                assertEquals(expResult_HS384, result);
            }
            {
                Base64URL signURL = JWSToken.sign(JWSAlgorithm.HS512, header_HS512, payload, JWSToken.toSecretKey("secret"));
                String result = signURL.toString();
                assertEquals(expResult_HS512, result);
            }
//            {
//                byte [] privateKey = Util.readAllBytes(JWSTokenTest.class.getResourceAsStream("/resources/private-key.pem"));
//                byte [] sign = JWTToken.sign(JWTToken.Algorithm.RS256, header_RS256, + token, Util.getRawStr(privateKey));
//                String result = JWTToken.encodeBase64UrlSafe(sign);
//                assertEquals(expResult_RS256, result);
//            }
//            {
//                byte [] privateKey = Util.readAllBytes(JWTUtilTest.class.getResourceAsStream("/resources/private-key.pem"));
//                byte [] sign = JWTToken.sign(Algorithm.RS384, header_RS384 + token, Util.getRawStr(privateKey));
//                String result = JWTToken.encodeBase64UrlSafe(sign);
//                assertEquals(expResult_RS384, result);
//            }
//            {
//                byte [] privateKey = Util.readAllBytes(JWTUtilTest.class.getResourceAsStream("/resources/private-key.pem"));
//                byte [] sign = JWTToken.sign(Algorithm.RS512, header_RS512 + token, Util.getRawStr(privateKey));
//                String result = JWTToken.encodeBase64UrlSafe(sign);
//                assertEquals(expResult_RS512, result);
//            }
        } catch (ParseException ex) {
            fail(ex);
        } catch (JOSEException ex) {
            fail(ex);
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
            // シグネチャなしはJWTとみなさない
            String value = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.";
            boolean expResult = false;
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
            assertEquals(expResult, result);
            if (result != null) {
                System.out.println(result.getAlgorithm());
            }

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
            boolean result = JWSToken.containsTokenFormat(value);
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
    public void testParseJWTObject() {
        System.out.println("parseJWTObject");
        JWTToken jwtinstance = new JWTToken();
        {
            String test = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.5mhBHqs5_DTLdINd9p5m7ZJ6XD0Xc55kIaCRY5r6HRA";
            String expResult1 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
            String expResult2 = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ";
            String expResult3 = "5mhBHqs5_DTLdINd9p5m7ZJ6XD0Xc55kIaCRY5r6HRA";
            JWTToken result = jwtinstance.parseToken(test, true);
            assertEquals(expResult1, result.getHeader());
            assertEquals(expResult2, result.getPayload());
            assertEquals(expResult3, result.getSignature());
        }
    }

    /**
     * Test of testParseJWTObject method, of class JWTUtil.
     */
    @Test
    public void testParseJWTObject_json() {
        System.out.println("parseJWTObject");
        JWTToken jwtinstance = new JWTToken();
        {
            String test = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.5mhBHqs5_DTLdINd9p5m7ZJ6XD0Xc55kIaCRY5r6HRA";
            String expResult1 = "{\n  \"alg\": \"HS256\",\n  \"typ\": \"JWT\"\n}";
            String expResult2 = "{\n  \"sub\": \"1234567890\",\n  \"name\": \"John Doe\",\n  \"iat\": 1516239022\n}";
            JWTToken token = jwtinstance.parseToken(test, true);

            System.out.println(expResult1);

            System.out.println("======================");

            System.out.println(token.getHeaderJSON(true));

            assertEquals(expResult1, token.getHeaderJSON(true));
            assertEquals(expResult2, token.getPayloadJSON(true));
        }
        {
            String test = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiLjgYLjgYTjgYbjgYjjgYoifQ.I6fGHWldnjdhfOjxcs9Wtzm41dIjBiAHYl3ZAcKl4Ks";
            String expResult1 = "{\n  \"alg\": \"HS256\",\n  \"typ\": \"JWT\"\n}";
            String expResult2 = "{\n  \"sub\": \"あいうえお\"\n}";
            JWTToken token = jwtinstance.parseToken(test, true);
            assertEquals(expResult1, token.getHeaderJSON(true));
            assertEquals(expResult2, token.getPayloadJSON(true));
        }
    }

    @Test
    public void testGenerateNoneToken() {
        {
            String test = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.5mhBHqs5_DTLdINd9p5m7ZJ6XD0Xc55kIaCRY5r6HRA";
            String[] tokens = JWTToken.generateNoneToken(test);
            for (int i = 0; i < tokens.length; i++) {
                System.out.println("none0:" + tokens[i]);
            }
            assertEquals(tokens[0], "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.");
            assertEquals(tokens[1], "eyJhbGciOiJOT05FIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.");
            assertEquals(tokens[2], "eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.");
        }
        {
            String test = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwOlwvXC9kZW1vLnNqb2VyZGxhbmdrZW1wZXIubmxcLyIsImlhdCI6MTU4NTk1Mzk5OCwiZXhwIjoxNTg1OTU0MTE4LCJkYXRhIjp7ImhlbGxvIjoid29ybGQifX0.ebkW_7-HqAV7SzfX7m0fKEfZ1T0A4BeNjTM0fx2LYZYxi9qMT7dpsd0lNMixCbrpLD0WAdWZJXQDOjfIZd6A6AJSSSioEDmFzh8QusLxuTzaUnrRSipiWwVtyVk9YmGkyucr4hCkckbsIe-0tIOCrdNwCmah5vhYtyQ3veaFizJodHvnBnNpq4fG2cWMmke32Hp_Y62h2kUdEGrAKFC_tQDPKFTz_-mNLxCgWcuvXwqGcoHkSxIObyGyk6pHPgbvVRppM_nFrc548jmpgIzN2oRCUTHdVWxoC-CBgNNJwMZ2Sn4zmvKEceqZ0e8QO1ea7hHGY0R1LWJhuE_X1__8bw";
            String[] tokens = JWTToken.generateNoneToken(test);
            for (int i = 0; i < tokens.length; i++) {
                System.out.println("none1:" + tokens[i]);
            }
            assertEquals(tokens[0], "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJpc3MiOiJodHRwOlwvXC9kZW1vLnNqb2VyZGxhbmdrZW1wZXIubmxcLyIsImlhdCI6MTU4NTk1Mzk5OCwiZXhwIjoxNTg1OTU0MTE4LCJkYXRhIjp7ImhlbGxvIjoid29ybGQifX0.");
            assertEquals(tokens[1], "eyJ0eXAiOiJKV1QiLCJhbGciOiJOT05FIn0.eyJpc3MiOiJodHRwOlwvXC9kZW1vLnNqb2VyZGxhbmdrZW1wZXIubmxcLyIsImlhdCI6MTU4NTk1Mzk5OCwiZXhwIjoxNTg1OTU0MTE4LCJkYXRhIjp7ImhlbGxvIjoid29ybGQifX0.");
            assertEquals(tokens[2], "eyJ0eXAiOiJKV1QiLCJhbGciOiJOb25lIn0.eyJpc3MiOiJodHRwOlwvXC9kZW1vLnNqb2VyZGxhbmdrZW1wZXIubmxcLyIsImlhdCI6MTU4NTk1Mzk5OCwiZXhwIjoxNTg1OTU0MTE4LCJkYXRhIjp7ImhlbGxvIjoid29ybGQifX0.");
        }
    }

    @Test
    public void testGenerateHSToken() {
        {
            JWSToken jwtinstance = new JWSToken();
//            String expected = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwOlwvXC9kZW1vLnNqb2VyZGxhbmdrZW1wZXIubmxcLyIsImlhdCI6MTU4NTk2Nzg3OSwiZXhwIjoxNTg1OTY3OTk5LCJkYXRhIjp7ImhlbGxvIjoid29ybGQifX0.UuMTEE-w3GjZ29jgU1VBXYKDN_MgWJPHjreI60OYjyY";
            String expected = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOlwvXC9kZW1vLnNqb2VyZGxhbmdrZW1wZXIubmxcLyIsImlhdCI6MTU4NTk2Nzg3OSwiZXhwIjoxNTg1OTY3OTk5LCJkYXRhIjp7ImhlbGxvIjoid29ybGQifX0.Rh5NHyMEvoYuTxEDkNMElZMCLSCC4kjD9H_mOu9i35I";
            String test = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwOlwvXC9kZW1vLnNqb2VyZGxhbmdrZW1wZXIubmxcLyIsImlhdCI6MTU4NTk2Nzg3OSwiZXhwIjoxNTg1OTY3OTk5LCJkYXRhIjp7ImhlbGxvIjoid29ybGQifX0.eaA2Y_8y3tT2dznH4TZvFt-D_2FgtUDAN7kdzDhh-P84zdqdFVyI3qSGBxHHZNkplscTWnmxGJiLvRtRYKX_wevRgijvW4KeWGI6oK4BhgHfcQuL4MrI3cE7djnA8hL5_QQ16zGeNKaNSno6ZImIT1aY-PRxViwMjOGmQoIWzw7ci4TtY_uak32s7T_XYcfJY8wO8QtWIjQFLXD-IbS20U-ZF-gyPrjfpKZhdCkBjZEnvc2K1vMk36nSXnFdjdPOa_021FGfGUlYBlELmpZvu_4oGm6s93DHu1vnCfNsnQF4QmVgmrePkqXU6SoLb3vbj_IPN2KYqSOyKjCWH1nlDg";
            try {
                byte[] publicKey = FileUtil.readAllBytes(JWTTokenTest.class.getResourceAsStream("/resources/public.pem"));
                {
                    JWSToken token = jwtinstance.parseToken(test, true);
                    Base64URL sign = JWSToken.forceSign(JWSAlgorithm.HS256, token.getHeader(), token.getPayload(), JWSToken.toSecretKey(publicKey));
                    String result = JsonToken.encodeBase64UrlSafe(JWSUtil.toHeaderJSON(JWSAlgorithm.HS256)) + "." + token.getPayload() + "." + sign.toString();
                    //System.out.println("expected:" + expected);
                    System.out.println("result:" + result);
                    assertEquals(expected, result);
                }
                {
                    String[] tokens = JWSToken.generatePublicToHashToken(test, publicKey);
                    assertEquals(expected, tokens[0]);
                }
            } catch (IOException ex) {
                fail(ex);
            } catch (NoSuchAlgorithmException ex) {
                fail(ex);
            }
        }
    }

    private final static String REQ_MESSAGE_URLENCODE_TOKEN00
            = "POST /cgi-bin/multienc.cgi?charset=Shift_JIS&mode=disp HTTP/1.1\r\n"
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
            boolean result = JWSToken.containsTokenFormat(REQ_MESSAGE_URLENCODE_TOKEN00);
            assertEquals(expResult, result);
        }
        {
            CaptureItem[] token = JWSToken.findToken(REQ_MESSAGE_URLENCODE_TOKEN00);
            assertEquals(0, token.length);
        }
    }

    @Test
    public void testJWTToken() {
        System.out.println("testJWTToken");
        {
            boolean expResult = true;
            boolean result = JWSToken.containsTokenFormat(REQ_MESSAGE_URLENCODE_TOKEN01);
            assertEquals(expResult, result);
        }
        {
            String expResult = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJtYWluIjoiYWJjZGVmIiwic3ViIjoiaG9nZSIsInllYXIiOjIwMjB9.bfk79BN28BVvW6lRnITaEULZ7URDBcem4jalLOW5diM";
            CaptureItem[] token = JWSToken.findToken(REQ_MESSAGE_URLENCODE_TOKEN01);
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
            assertEquals(JWSAlgorithm.HS256, result.getAlgorithm());
            assertEquals("eyJtYWluIjoiYWJjZGVmIiwic3ViIjoiaG9nZSIsInllYXIiOjIwMjB9", result.getPayload());
            assertEquals("bfk79BN28BVvW6lRnITaEULZ7URDBcem4jalLOW5diM", result.getSignature());
            assertEquals("{\"main\":\"abcdef\",\"sub\":\"hoge\",\"year\":2020}", result.getPayloadJSON(false));
            assertEquals(expResult, result.getToken());
        }
    }

}
