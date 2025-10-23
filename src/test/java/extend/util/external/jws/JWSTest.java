package extend.util.external.jws;

import java.util.logging.Level;
import java.util.logging.Logger;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.crypto.opts.AllowWeakRSAKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.*;
import extension.helpers.StringUtil;
import extension.helpers.json.JsonUtil;
import extension.view.base.CaptureItem;
import java.nio.charset.StandardCharsets;
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

import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.ListIterator;
import java.util.stream.Collectors;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author isayan
 */
public class JWSTest {

    private final static Logger logger = Logger.getLogger(JWSTest.class.getName());

    public JWSTest() {
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
    public void testFindToken()
    {
        System.out.println("testFindToken");
        {
            String token = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ5b3VyLWFwcCIsInN1YiI6InVzZXIxMjMiLCJyb2xlIjoiYWRtaW4iLCJleHAiOjE3NTU3ODMxNzV9.dqBgwLri4YJt1FIqjjT1Ljn1LWaoDvACfpX1bgSx8bc";
            CaptureItem[] tokens = JWSUtil.findToken(token);
            for (CaptureItem t : tokens) {
                System.out.println("token:" + t.getCaptureValue());
                System.out.println("start:" + t.start());
                System.out.println("end:" + t.end());
            }
        }
        {
            String token = "Cookie: sessionid=1234567890; token=eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ5b3VyLWFwcCIsInN1YiI6InVzZXIxMjMiLCJyb2xlIjoiYWRtaW4iLCJleHAiOjE3NTU3ODMxNzV9.dqBgwLri4YJt1FIqjjT1Ljn1LWaoDvACfpX1bgSx8bc uid=aabbcceedd";
            CaptureItem[] tokens = JWSUtil.findToken(token);
            for (CaptureItem t : tokens) {
                System.out.println("token:" + t.getCaptureValue());
                System.out.println("start:" + t.start());
                System.out.println("end:" + t.end());
            }
        }
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
        String jwt = JWSUtil.algNone(claims.toPayload());
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
            fail(ex);
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
                fail(ex);
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
                fail(ex);
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
                fail(ex);
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
                fail(ex);
            } catch (JOSEException ex) {
                fail(ex);
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
                fail(ex);
            } catch (JOSEException ex) {
                fail(ex);
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
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        } catch (JOSEException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
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
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        } catch (JOSEException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
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
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        } catch (JOSEException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        } catch (ParseException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
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
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        } catch (JOSEException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        } catch (ParseException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
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
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        } catch (JOSEException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }

}
