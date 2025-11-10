package passive;

import extend.util.external.jws.JWSUtil;
import extension.helpers.FileUtil;
import extension.helpers.StringUtil;
import extension.view.base.CaptureItem;
import java.io.IOException;
import java.security.SignatureException;
import java.util.logging.Logger;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
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
            JWSToken.Header header = JWSToken.Header.generateAlgorithm(Algorithm.HS256);
            assertEquals("{\"alg\":\"HS256\",\"typ\":\"JWT\"}", header.toJSON(false));
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
            byte[] publicKeyPem = FileUtil.readAllBytes(JWSTokenTest.class.getResourceAsStream("/resources/public.pem"));            {
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
        String expected = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwOlwvXC9kZW1vLnNqb2VyZGxhbmdrZW1wZXIubmxcLyIsImlhdCI6MTc2MjY3MzA1OSwiZXhwIjoxNzYyNjczMTc5LCJkYXRhIjp7ImhlbGxvIjoid29ybGQifX0.okX7HfAFDS2pEBqEffkoS30VMKW-lkGlm25HnaPcJkRk0BQEFGkvCZc8E_4Gi7peLa_XTg1N-Ss4uO9-m-HueXzlxmwjxKstQKLGLheKcDmb8rNi11EEc_bo0R8PNT3VkACOJvPbWf2lfq-wt2PKCGjnPqoHeO7g4tBGxf-A3Srh5Bk9n94EbZfEiFLBkHkVZAbveVeF0PtfmWw1cfIVBB9YNgSnqJh3E1hSgadv4aNhXf3FeDn6l7PYhg1PR4H2VgBTbSPJHzxkq8mrMA2CUIjTLkbIMNsMhjgLdS_4sJQDPZ3D0sElCVaz7JWm9fpmZrONyBWuzMnYs0PwX8VgjQ";
        String test = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwOlwvXC9kZW1vLnNqb2VyZGxhbmdrZW1wZXIubmxcLyIsImlhdCI6MTc2MjY3MzA1OSwiZXhwIjoxNzYyNjczMTc5LCJkYXRhIjp7ImhlbGxvIjoid29ybGQifX0.okX7HfAFDS2pEBqEffkoS30VMKW-lkGlm25HnaPcJkRk0BQEFGkvCZc8E_4Gi7peLa_XTg1N-Ss4uO9-m-HueXzlxmwjxKstQKLGLheKcDmb8rNi11EEc_bo0R8PNT3VkACOJvPbWf2lfq-wt2PKCGjnPqoHeO7g4tBGxf-A3Srh5Bk9n94EbZfEiFLBkHkVZAbveVeF0PtfmWw1cfIVBB9YNgSnqJh3E1hSgadv4aNhXf3FeDn6l7PYhg1PR4H2VgBTbSPJHzxkq8mrMA2CUIjTLkbIMNsMhjgLdS_4sJQDPZ3D0sElCVaz7JWm9fpmZrONyBWuzMnYs0PwX8VgjQ";
        try {
            byte[] publicKeyPem = FileUtil.readAllBytes(JWSTokenTest.class.getResourceAsStream("/resources/public.pem"));            {
                JWSToken except_token = jwtinstance.parseToken(test, true);
                except_token.sign(Algorithm.HS256, StringUtil.getStringRaw(publicKeyPem));
                System.out.println("result:" + except_token.getToken());
            }
            {
                JWSToken rs_token = jwtinstance.parseToken(test, true);
                JWSToken hs_token = new JWSToken(rs_token.getHeader().withAlgorithm(Algorithm.HS256), rs_token.getPayload());
                byte[] sign = JWSToken.sign(Algorithm.HS256, StringUtil.getStringRaw(publicKeyPem), hs_token.getData());
                hs_token.getSignature().setEncodeBase64Url(sign);
                String result = hs_token.getToken();
                assertEquals(rs_token.getPayloadPart(), hs_token.getPayloadPart());
                System.out.println("result:" + result);
                assertEquals(expected, result);
                String[] tokens = JWSToken.generatePublicToHashToken(test, StringUtil.getStringRaw(publicKeyPem));
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
