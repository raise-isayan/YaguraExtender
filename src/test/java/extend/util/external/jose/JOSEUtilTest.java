package extend.util.external.jose;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.crypto.opts.AllowWeakRSAKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.*;
import extend.util.external.jws.JWSUtilTest;
import extension.helpers.FileUtil;
import extension.helpers.StringUtil;
import extension.helpers.json.JsonUtil;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.ListIterator;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.text.ParseException;
import org.bouncycastle.openssl.PEMException;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 *
 * @author isayan
 */
public class JOSEUtilTest {

    private final static Logger logger = Logger.getLogger(JOSEUtilTest.class.getName());

    public JOSEUtilTest() {
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
    public void testNoneAlg() {
        System.out.println("testNoneAlg");
        {
            PlainHeader header = new PlainHeader(); // JWSAlgorithm.NONE
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .subject("user123")
                    .issuer("your-app")
                    .expirationTime(new Date(new Date().getTime() + 3600 * 1000)) // 1時間後に期限切れ
                    .claim("role", "admin")
                    .build();
            System.out.println("header:" + header.toBase64URL());
            System.out.println("payload:" + claims.toPayload().toBase64URL());
        }
        {
            JWTClaimsSet header = new JWTClaimsSet.Builder()
                    .claim("alg", "None")
                    .build();
            System.out.println("header2:" + header.toPayload().toBase64URL());
        }

    }

    @Test
    public void testJWEUtil() {
        System.out.println("testJWEUtil");
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject("user123")
                .issuer("your-app")
                .expirationTime(new Date(new Date().getTime() + 3600 * 1000)) // 1時間後に期限切れ
                .claim("role", "admin")
                .build();
        String jwt = JOSEUtil.algNone(claims.toPayload());
        System.out.println("jwt:" + jwt);
    }


    @Test
    public void testJWEParse() {
        System.out.println("testJWEParse");
        try {
//            String token = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJ5b3VyLWFwcCIsInN1YiI6InVzZXIxMjMiLCJyb2xlIjoiYWRtaW4iLCJleHAiOjE3NTU3ODI1MjF9.";
            String token = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ5b3VyLWFwcCIsInN1YiI6InVzZXIxMjMiLCJyb2xlIjoiYWRtaW4iLCJleHAiOjE3NTU3ODMxNzV9.dqBgwLri4YJt1FIqjjT1Ljn1LWaoDvACfpX1bgSx8bc";
            JWSObject jwt = JWSObject.parse(token);
            {
                System.out.println("jws.header:" + jwt.getHeader().toBase64URL().decodeToString());
                System.out.println("jws.payload:" + jwt.getPayload().toBase64URL().decodeToString());
                System.out.println("jws.signature:" + jwt.getSignature().toString());
            }
            {
                System.out.println("jws.header:" + JsonUtil.prettyJson(jwt.getHeader().toBase64URL().decodeToString(), true));
                System.out.println("jws.payload:" + JsonUtil.prettyJson(jwt.getPayload().toBase64URL().decodeToString(), true));
                System.out.println("jws.signature:" + jwt.getSignature().toString());
            }
        } catch (ParseException ex) {
            fail(ex.getMessage(), ex);
        }
    }

    @Test
    public void testJWESplit() {
        System.out.println("testJWESplit");
        {
            try {
                String token = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJ5b3VyLWFwcCIsInN1YiI6InVzZXIxMjMiLCJyb2xlIjoiYWRtaW4iLCJleHAiOjE3NTU3ODI1MjF9.";
                Base64URL jwt[] = JWSObject.split(token);
                System.out.println("jws:" + jwt.length);
                System.out.println("jws[0]:" + jwt[0].toString());
                System.out.println("jws[1]:" + jwt[1].toString());
                System.out.println("jws[2]:" + jwt[2].toString());
            } catch (ParseException ex) {
                fail(ex.getMessage(), ex);
            }
        }
        {
            try {
                String token = "e30.e30.";
                Base64URL jwt[] = JWSObject.split(token);
                System.out.println("jws:" + jwt.length);
                System.out.println("jws[0]:" + jwt[0].toString());
                System.out.println("jws[1]:" + jwt[1].toString());
                System.out.println("jws[2]:" + jwt[2].toString());
            } catch (ParseException ex) {
                fail(ex.getMessage(), ex);
            }
        }
        {
            try {
                String token = "e.e.";
                Base64URL jwt[] = JWSObject.split(token);
                System.out.println("jws:" + jwt.length);
                System.out.println("jws[0]:" + jwt[0].toString());
                System.out.println("jws[1]:" + jwt[1].toString());
                System.out.println("jws[2]:" + jwt[2].toString());
            } catch (ParseException ex) {
                fail(ex.getMessage(), ex);
            }
        }
    }

    @Test
    public void testJWEVeryfy() {
        System.out.println("testJWEVeryfy");
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ5b3VyLWFwcCIsInN1YiI6InVzZXIxMjMiLCJyb2xlIjoiYWRtaW4iLCJleHAiOjE3NTU5MTA3NzV9.w059vUCr4vzJ3gFYBC1_iabPR0wEWICcnhdfVovfT3I";
        {
            try {
                JWSObject jwt = JWSObject.parse(token);
                String secret = "8350e5a3e24c153df2275c9f80692773";
                byte[] sharedSecret = secret.getBytes(StandardCharsets.ISO_8859_1);
                JWSVerifier verifier = new MACVerifier(sharedSecret);
                boolean result = jwt.verify(verifier);
                assertTrue(result);
            } catch (ParseException ex) {
                fail(ex.getMessage(), ex);
            } catch (JOSEException ex) {
                fail(ex.getMessage(), ex);
            }
        }
        {
            try {
                JWSObject jwt = JWSObject.parse(token);
                String secret = "0";
                byte[] sharedSecret = secret.getBytes(StandardCharsets.ISO_8859_1);
                WeakMACSigner signer = new WeakMACSigner(sharedSecret);
                boolean result = jwt.verify(signer);
                assertFalse(result);
            } catch (ParseException ex) {
                fail(ex.getMessage(), ex);
            } catch (JOSEException ex) {
                fail(ex.getMessage(), ex);
            }
        }
    }

    @Test
    public void testHS256Alg() {
        System.out.println("testHS256Alg");
        try {
            String secret = "8350e5a3e24c153df2275c9f80692773";
            byte[] sharedSecret = secret.getBytes(StandardCharsets.ISO_8859_1);
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .subject("user123")
                    .issuer("your-app")
                    .expirationTime(new Date(new Date().getTime() + 3600 * 1000))
                    .claim("role", "admin")
                    .build();

//            JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256)
                    .type(JOSEObjectType.JWT)
                    .build();

            SignedJWT signedJWT = new SignedJWT(header, claims);
            JWSSigner signer = new MACSigner(sharedSecret);
            signedJWT.sign(signer);
            String token = signedJWT.serialize();
            System.out.println("Generated JWT Token:");
            System.out.println(token);
        } catch (KeyLengthException ex) {
            fail(ex.getMessage(), ex);
        } catch (JOSEException ex) {
            fail(ex.getMessage(), ex);
        }

    }


    @Test
    public void testWeakHS256Alg() {
        System.out.println("testWeakHS256Alg");
        try {
            {
                String secret = "0";
                byte[] sharedSecret = secret.getBytes();

                JWTClaimsSet claims = new JWTClaimsSet.Builder()
                        .subject("user123")
                        .issuer("your-app")
                        .expirationTime(new Date(new Date().getTime() + 3600 * 1000))
                        .claim("role", "admin")
                        .build();

                JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);
                SignedJWT signedJWT = new SignedJWT(header, claims);
                WeakMACSigner signer = new WeakMACSigner(sharedSecret);
                signedJWT.sign(signer);
                String token = signedJWT.serialize();
                System.out.println("Generated Weak JWT Token:");
                System.out.println(token);
            }
            {
                String secret = "ddd";
                byte[] sharedSecret = secret.getBytes();

                JWTClaimsSet claims = new JWTClaimsSet.Builder()
                        .subject("user123")
                        .issuer("your-app")
                        .expirationTime(new Date(new Date().getTime() + 3600 * 1000))
                        .claim("role", "admin")
                        .build();

                JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);
                SignedJWT signedJWT = new SignedJWT(header, claims);
                WeakMACSigner signer = new WeakMACSigner(sharedSecret);
                signedJWT.sign(signer);
                String token = signedJWT.serialize();
                System.out.println("Generated Weak JWT Token:");
                System.out.println(token);
            }
        } catch (KeyLengthException ex) {
            fail(ex.getMessage(), ex);
        } catch (JOSEException ex) {
            fail(ex.getMessage(), ex);
        }
    }

    @Test
    public void testRS256Alg() {
        System.out.println("testRS256Alg");
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(512);
            KeyPair keyPair = keyGen.generateKeyPair();
            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .subject("user123")
                    .issuer("your-app")
                    .expirationTime(new Date(new Date().getTime() + 3600 * 1000))
                    .claim("role", "admin")
                    .build();

            // JWS ヘッダー（RS256）
            //JWSHeader header = new JWSHeader(JWSAlgorithm.RS256);
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .type(JOSEObjectType.JWT)
                    .build();

            SignedJWT signedJWT = new SignedJWT(header, claims);

            HashSet<JWSSignerOption> opts = new HashSet();
            opts.add(AllowWeakRSAKey.getInstance());
            JWSSigner signer = new RSASSASigner(privateKey, opts);
            signedJWT.sign(signer);

            String token = signedJWT.serialize();
            System.out.println("Signed JWT: " + token);

            SignedJWT parsedJWT = SignedJWT.parse(token);
            JWSVerifier verifier = new RSASSAVerifier(publicKey);
            boolean isValid = parsedJWT.verify(verifier);
            System.out.println("Signature is valid: " + isValid);

        } catch (NoSuchAlgorithmException ex) {
            fail(ex.getMessage(), ex);
        } catch (JOSEException ex) {
            fail(ex.getMessage(), ex);
        } catch (ParseException ex) {
            fail(ex.getMessage(), ex);
        }
    }

    @Test
    public void testES256Alg() throws InvalidAlgorithmParameterException {
        System.out.println("testES256Alg");
        try {
            // 🔐 EC 鍵ペアを生成（P-256）
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            keyGen.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair keyPair = keyGen.generateKeyPair();
            ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
            ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();

            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .subject("user123")
                    .issuer("your-app")
                    .expirationTime(new Date(new Date().getTime() + 3600 * 1000))
                    .claim("role", "admin")
                    .build();

            // 🛡️ ヘッダー作成（ES256）
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .type(JOSEObjectType.JWT)
                    .build();

            SignedJWT signedJWT = new SignedJWT(header, claims);

            JWSSigner signer = new ECDSASigner(privateKey);
            signedJWT.sign(signer);

            String token = signedJWT.serialize();
            System.out.println("JWT Token (ES256): " + token);

            SignedJWT parsedJWT = SignedJWT.parse(token);
            JWSVerifier verifier = new ECDSAVerifier(publicKey);
            boolean isValid = parsedJWT.verify(verifier);
            System.out.println("Signature is valid: " + isValid);
        } catch (NoSuchAlgorithmException ex) {
            fail(ex.getMessage(), ex);
        } catch (JOSEException ex) {
            fail(ex.getMessage(), ex);
        } catch (ParseException ex) {
            fail(ex.getMessage(), ex);
        }
    }

    @Test
    public void testAttackList() {
        try {
            System.out.println("testAttackList");
            List<String> list = List.of("aaa", "bbb", "ccc", "ddd", "eee", "fff");
            ListIterator<String> ite = list.listIterator();
            System.out.println("next:" + ite.next());
            System.out.println("prev:" + ite.previous());
            List<SecretKey> keys = list.stream()
                    .map(key -> {
                        return new SecretKeySpec(key.getBytes(StandardCharsets.ISO_8859_1), "MAC");
                    }).collect(Collectors.toList());
            AttackMACVerifier veryfy = new AttackMACVerifier(keys);
            String token = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ5b3VyLWFwcCIsInN1YiI6InVzZXIxMjMiLCJyb2xlIjoiYWRtaW4iLCJleHAiOjE3NTYwMjg4Mjh9.j8j2ZVmOBt52HSNGmPKZOKS0qHTgrP8eWmVnHFIJwY0";
            SignedJWT parsedJWT = SignedJWT.parse(token);
            while (veryfy.hasNextSecretKey()) {
                boolean isValid = parsedJWT.verify(veryfy);
                if (isValid) {
                    System.out.println("match:" + StringUtil.getStringRaw(veryfy.currentSecretKey().getEncoded()));
                    break;
                }
            }

        } catch (ParseException ex) {
            fail(ex.getMessage(), ex);
        } catch (JOSEException ex) {
            fail(ex.getMessage(), ex);
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
        String expResult_RS256 = "iaUirc6CsXPQJax5DkV_Qj-NSA0sPmrsIcbLYxu2e8L9D4EpU5wgRCzos3fo34XTV-CNyOAQ7UDyCpsfvvKZZiuZ3quGVoZb8Y9OlAhBMKuk4Fme3HWz466dzRwx7GGXHwL-T95pZcmoOdhlah8-H85xAepq4DyH3K_P1capW2Nzq_EM4VCNyzNi9-WWYvsFH-Fxj1KgLh3DqStdmGLZb-9D_DruzC0-8pO09BdqQaUTEFs0Ion9OHRJk-IG_pQ2piczt_DenpakbRDKctFhW21TaDxFJdlSr-tVMGZAZ6vWXv3P5PXIfnD-vm-nGkTYZFbzhNaldguPKGpNE6RRKA";
        String expResult_RS384 = "QoglwabVYYxXrLUEzsj0ayvIoQmlx8chSx3-12wyYKehm1ur9IXcuGdKRcQCuoF4qLtoAKOlqjYiU6cMKTqSik6tBTZY2WJCWhV14cwI8P2tWt77b1W8JCQyHgdMr1HnD8a-acPU04tYEgTGPC5aIiqQA67MYhqDmH2HYdhdOoS3EUlHjboONunAMRRkx3udrcCRmsQ6CcwKGEoTU57MixEcHZqF5GngiqIOcy8p6cQXmtSiZ3rEDSXunVuxFTyBU6c6sLD_zWgTbIa9ebaC2vxbQp3yiYq0zgp9N0tGc57aPdVJZITaDBKdvUYyMPK_NjOdCLcxvg_YvHl3U4O54g";
        String expResult_RS512 = "G7sDI6C7Hu7wymfaaxXHnvFWJmXpt4-mrdV3D_LLubh8X6VQMBqSS5uN_yyHEyRI9mLCxAzyCJdLPMQCK-Rt5bldukHGPNrFrBMulAacqKNaX7GyUE9VMJkKIxndNsMuV8LVJcIIAS_HVSj_Uh2NMKgPASzf5qhmZMlpLj8Mc1DPtIohaK2Xkxf6IxW9xxE6Fg0U-cVylXhO5G9FoFw-YuxZMQF40lsBm5gt1hnJ1W9YtxixKUQtEbFaKarbGwgitHiazaEHm7DlnvDhVpxdFNpYQawGG6ShppUzPL5XUwRhxNDeACYLo_JuI0ru5eqAlPHKJYlZPR2e-n1URX6K8w";
        String header_HS256 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        String header_HS384 = "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9";
        String header_HS512 = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9";
        String header_RS256 = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9";
        String header_RS384 = "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9";
        String header_RS512 = "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9";
        String payload = "eyJtYWluIjoieHh4eHh4Iiwic3ViIjoi44OG44K544OIIn0";
        try {
            {
                JWSObject result = JOSEUtil.sign(JWSAlgorithm.HS256, header_HS256, payload, JOSEUtil.toSecretKey("secret"));
                assertEquals(expResult_HS256, result.getSignature().toString());
                System.out.println("signatureSign:" + JWSAlgorithm.HS256 + ":" + result.serialize());
            }
            {
                JWSObject result = JOSEUtil.sign(JWSAlgorithm.HS384, header_HS384, payload, JOSEUtil.toSecretKey("secret"));
                assertEquals(expResult_HS384, result.getSignature().toString());
            }
            {
                JWSObject result = JOSEUtil.sign(JWSAlgorithm.HS512, header_HS512, payload, JOSEUtil.toSecretKey("secret"));
                assertEquals(expResult_HS512, result.getSignature().toString());
            }
            byte [] rsaPrivateKey = FileUtil.readAllBytes(JWSUtilTest.class.getResourceAsStream("/resources/private-rsa-key.pem"));
            {
                JWSObject result = JOSEUtil.sign(JWSAlgorithm.RS256, header_RS256, payload, JOSEUtil.toPrivateKey(StringUtil.getStringRaw(rsaPrivateKey)));
                assertEquals(expResult_RS256, result.getSignature().toString());
                System.out.println("RS356:" + result.serialize());
            }
            {
                JWSObject result = JOSEUtil.sign(JWSAlgorithm.RS384, header_RS384, payload, JOSEUtil.toPrivateKey(StringUtil.getStringRaw(rsaPrivateKey)));
                assertEquals(expResult_RS384, result.getSignature().toString());
                System.out.println("RS384:" + result.serialize());
            }
            {
                JWSObject result = JOSEUtil.sign(JWSAlgorithm.RS512, header_RS512, payload, JOSEUtil.toPrivateKey(StringUtil.getStringRaw(rsaPrivateKey)));
                assertEquals(expResult_RS512, result.getSignature().toString());
                System.out.println("RS512:" + result.serialize());
            }
        } catch (IOException ex) {
            fail(ex.getMessage(), ex);
        } catch (ParseException ex) {
            fail(ex.getMessage(), ex);
        } catch (JOSEException ex) {
            fail(ex.getMessage(), ex);
        }
    }

    @Test
    public void testBase64() {
        try {
            System.out.println("testBase64");
            String signature_RS256 = "nJX1lasf0mOIRy4LvPKWCE5saddZLJF_nUguCpqQewhw9TC4mtzssM59c238lTvHJoC9OPIzFJ7EcvH1_kjCgEzZ7lR6j_ilYiF48VExDhWSC5Wr3W9PnmGjXANtYbnDTnjnFP2k5o_H8D1P5pVQCa-FgI2mUIadTx7zrvlP1MWzyabqJiB7K7J3h-gf1nHtEUv9OeFrUusfp463LgZl__9O5jq6PreQOxPH_YHTJl-s0a4IKL19rvRvumiFKExNZMUCawUw86zS2XXB9IjwAC7Kwy15iqBHrAj-m9JxaxmceZB_llhhCSqdDfu9l80-4mh5Xa-cBpsn_nknwtPnDA";
            String header_RS256 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9";
            String header_RS256_JSON = "{\"typ\":\"JWT\",\"alg\":\"RS256\"}";
            String payload_comon = "eyJtYWluIjoieHh4eHh4Iiwic3ViIjoi44OG44K544OIIn0";
            String payload_JSON = "{\"main\":\"xxxxxx\",\"sub\":\"テスト\"}";
            String token_RS256 = header_RS256 + "." + payload_comon + "." + signature_RS256;

            JWSHeader header = JWSHeader.parse(header_RS256_JSON);
            Base64URL header_b64 = header.toBase64URL();
            System.out.println("parseHeader:" + header_b64.decodeToString());
            Payload payload = new Payload(payload_JSON);
            Base64URL payload_b64 = payload.toBase64URL();
            System.out.println("parsePayload:" + payload_b64.decodeToString());
            byte [] privateKey = FileUtil.readAllBytes(JWSUtilTest.class.getResourceAsStream("/resources/private-rsa-key.pem"));
            {
                JWSObject result00 = JOSEUtil.sign(JWSAlgorithm.RS256, header_RS256, payload_comon, JOSEUtil.toPrivateKey(StringUtil.getStringRaw(privateKey)));
                assertEquals(token_RS256, result00.serialize());
                System.out.println("result00:" + result00.getSignature().toString());
                JWSObject result01 = JOSEUtil.sign(JWSAlgorithm.RS256, Base64URL.from(header_RS256), Base64URL.from(payload_comon), JOSEUtil.toPrivateKey(StringUtil.getStringRaw(privateKey)));
                System.out.println("result10:" + result01.getSignature().toString());
                JWSObject result02 = JOSEUtil.sign(JWSAlgorithm.RS256, header, payload, JOSEUtil.toPrivateKey(StringUtil.getStringRaw(privateKey)));
                System.out.println("result02:" + result02.getSignature().toString());
                JWTClaimsSet claims = JWTClaimsSet.parse(payload_JSON);
                JWSObject result03 = JOSEUtil.sign(JWSAlgorithm.RS256, header, claims.toPayload(), JOSEUtil.toPrivateKey(StringUtil.getStringRaw(privateKey)));
                System.out.println("result03:" + result03.getSignature().toString());
                JWSHeader header2 = JWSHeader.parse(header_RS256_JSON);
                Payload payload2 = new Payload(payload_JSON);
                JWSObject result04 = JOSEUtil.sign(JWSAlgorithm.RS256, header2, payload2, JOSEUtil.toPrivateKey(StringUtil.getStringRaw(privateKey)));
                assertEquals(token_RS256, result04.serialize());
                System.out.println("result04:" + result04.getSignature().toString());
            }
            {
                JWSHeader jws_header = JWSHeader.parse(header_RS256_JSON);
                Payload jws_payload = new Payload(Base64URL.from(payload_comon));
                JWSObject result10 = JOSEUtil.sign(JWSAlgorithm.RS256, jws_header, jws_payload, JOSEUtil.toPrivateKey(StringUtil.getStringRaw(privateKey)));
                System.out.println("result10:" + result10.getSignature().toString());
            }

            // RS512
            // eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiJ9.
            // eyJtYWluIjoieHh4eHh4Iiwic3ViIjoi44OG44K544OIIn0.
            // HuyEczRlPyGNUpPijiwL2W-Ig6rF_CgaRCglyTQMD-a1U_5tro16oeZ1HP823QX4HZDKLQRypIffRvaCVDrVabn_jd2XKaxHPYzjcb0bxiHKsGZu18-CnpB678GPagJQduSIGQ1RTaTvJiRjgx1POrx29Z5rP-yiC-ZPrADdIszSS35borR5DucwA2NiHF0nacnkYKXEuDJen0bU3a0vj3LF7y9X2hqKx-n9b1OEwe2uPzP-bCMlPJs87lhwj6aRqhVo-Mwez7fi1-3obWyH3gxZHfjnXRhZFygZS-nOrdCN6HcysiOdb4cW62kvbgEW-UKORjfG8qVf1W1n7xeXPA

            String signature_RS512 = "HuyEczRlPyGNUpPijiwL2W-Ig6rF_CgaRCglyTQMD-a1U_5tro16oeZ1HP823QX4HZDKLQRypIffRvaCVDrVabn_jd2XKaxHPYzjcb0bxiHKsGZu18-CnpB678GPagJQduSIGQ1RTaTvJiRjgx1POrx29Z5rP-yiC-ZPrADdIszSS35borR5DucwA2NiHF0nacnkYKXEuDJen0bU3a0vj3LF7y9X2hqKx-n9b1OEwe2uPzP-bCMlPJs87lhwj6aRqhVo-Mwez7fi1-3obWyH3gxZHfjnXRhZFygZS-nOrdCN6HcysiOdb4cW62kvbgEW-UKORjfG8qVf1W1n7xeXPA";
            String header_RS512 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiJ9";
            String token_RS512 = header_RS512 + "." + payload_comon + "." + signature_RS512;
            {
                JWSObject result00 = JOSEUtil.sign(JWSAlgorithm.RS512, header_RS512, payload_comon, JOSEUtil.toPrivateKey(StringUtil.getStringRaw(privateKey)));
                assertEquals(token_RS512, result00.serialize());
            }

        } catch (ParseException ex) {
            fail(ex.getMessage(), ex);
        } catch (PEMException ex) {
            fail(ex.getMessage(), ex);
        } catch (IOException ex) {
            fail(ex.getMessage(), ex);
        } catch (JOSEException ex) {
            fail(ex.getMessage(), ex);
        }
    }

    @Test
    public void testHeader() {
        try {
            System.out.println("testHeader");
            {
                String header_RS256_JSON = "{\n\t\"typ\":\"JWT\",\n\t\"alg\":\"RS256\"\n}";
                Header header = Header.parse(header_RS256_JSON);
                System.out.println("toHeader10" + header.toString());
                System.out.println("toHeader10" + header.toBase64URL().decodeToString());
                JWSHeader jwsHeader = JWSHeader.parse(header_RS256_JSON);
                System.out.println("toHeader11:" + jwsHeader.toString());
                System.out.println("toHeader11:" + jwsHeader.toBase64URL().decodeToString());

                Payload payload = new Payload(header_RS256_JSON);
                System.out.println("toPayload21:" + payload.toString());
                System.out.println("toPayload22:" + payload.toBase64URL().decodeToString());
            }
            {
                String header_RS256_JSON = "{\n\t\"alg\":\"RS256\",\n\t\"typ\":\"JWT\"\n}";
                Header header = Header.parse(header_RS256_JSON);
                System.out.println("toHeader20" + header.toString());
                System.out.println("toHeader20" + header.toBase64URL().decodeToString());
                JWSHeader jwsHeader = JWSHeader.parse(header_RS256_JSON);
                System.out.println("toHeader61:" + jwsHeader.toString());
                System.out.println("toHeader61:" + jwsHeader.toBase64URL().decodeToString());
                Payload payload = new Payload(header_RS256_JSON);
                System.out.println("toPayload71:" + payload.toString());
                System.out.println("toPayload71" + payload.toBase64URL().decodeToString());
            }

        } catch (ParseException ex) {
            fail(ex.getMessage(), ex);
        }
    }

    @Test
    public void testPayload() {
        try {
            System.out.println("testPayload");
            String payload_JSON = "{\"main\":\"xxxxxx\",\"sub\":\"テスト\"}";
            Payload payload = new Payload(payload_JSON);
            System.out.println("toString:" + payload.toString());
            System.out.println("toJSONString:" + payload.toBase64URL().decodeToString());
            String payload_JSON2 = "{\"sub\":\"テスト\",\"main\":\"xxxxxx\"}";
            Payload payload2 = new Payload(payload_JSON2);
            System.out.println("toString2:" + payload2.toString());
            System.out.println("toJSONString2:" + payload2.toBase64URL().decodeToString());
            String payload_JSON3 = "{\n\"sub\":\"テスト\",\n\t\"main\":\"xxxxxx\"\n}";
            Payload payload3 = new Payload(payload_JSON3);
            System.out.println("toString3:" + payload3.toString());
            System.out.println("toJSONString3:" + payload3.toBase64URL().decodeToString());
            System.out.println("compact3:" + JSONObjectUtils.toJSONString(JSONObjectUtils.parse(payload_JSON3)));
            String payload_JSON4 = "{\n\"main\":\"xxxxxx\",\n\t\"sub\":\"テスト\"\n}";
            Payload payload4 = new Payload(payload_JSON4);
            System.out.println("toString4:" + payload4.toString());
            System.out.println("toJSONString4:" + payload4.toBase64URL().decodeToString());
            System.out.println("compact4:" + JSONObjectUtils.toJSONString(JSONObjectUtils.parse(payload_JSON4)));
            String payload_JSON5 = "{\"main\":\"xxxxxx\",\"sub\":\"テスト\"}";
            Payload payload5 = new Payload(payload_JSON5);
            System.out.println("toString5:" + payload5.toString());
            System.out.println("toJSONString5:" + payload5.toBase64URL().decodeToString());
            System.out.println("compact5:" + JSONObjectUtils.toJSONString(JSONObjectUtils.parse(payload_JSON5)));
        } catch (ParseException ex) {
            fail(ex.getMessage(), ex);
        }
    }

    @Test
    public void testSerialize() {
        try {
            System.out.println("testSerialize");
            String header_HS256_JSON = "{\n\t\"typ\":\"JWT\",\n\t\"alg\":\"HS256\"\n}";
            String payload_JSON = "{\n\"main\":\"xxxxxx\",\n\t\"sub\":\"テスト\"\n}";
            WeakMACSigner signer = new WeakMACSigner("test");
            JWSHeader header = JWSHeader.parse(header_HS256_JSON);
            Payload payload = new Payload(payload_JSON);
            JWSObject token = new JWSObject(header, payload);
            token.sign(signer);
            System.out.println("testSerialize:" + token.serialize());
            System.out.println("headerJSON:" + header_HS256_JSON);
            System.out.println("headerJSON:" + token.getHeader().toBase64URL().decodeToString());
            System.out.println("headerJSON:" + JsonUtil.prettyJson(header_HS256_JSON, true));
            System.out.println("payloadJSON:" + payload_JSON);
            System.out.println("payloadJSON:" + token.getPayload().toBase64URL().decodeToString());
            System.out.println("payloadJSON:" + JsonUtil.prettyJson(payload_JSON, true));
            System.out.println("payloadJSON:" + JSONObjectUtils.toJSONString(JSONObjectUtils.parse(payload_JSON)));

        } catch (ParseException ex) {
            fail(ex.getMessage(), ex);
        } catch (JOSEException ex) {
            fail(ex.getMessage(), ex);
        }

    }

}
