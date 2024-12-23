package extend.util.external;

import burp.BurpPreferences;
import extension.helpers.CertUtil;
import extension.helpers.StringUtil;
import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.BeforeAll;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.Test;

/**
 *
 * @author isayan
 */
public class BoncyUtilTest {

    private final static Logger logger = Logger.getLogger(BoncyUtilTest.class.getName());

    private final static BouncyCastleProvider BC_PROVIDER = new BouncyCastleProvider();

    public BoncyUtilTest() {
    }

    @BeforeAll
    public static void setUpClass() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BC_PROVIDER);
        }
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
    public void testBouncyUtil() {
        System.out.println("testBouncyUtil");
        String storeFileName = BoncyUtilTest.class.getResource("/resources/burpca.p12").getPath();
        HashMap<String, Map.Entry<Key, X509Certificate>> certMap = CertUtil.loadFromPKCS12(new File(storeFileName), "testca");
        for (String key : certMap.keySet()) {
            Map.Entry<Key, X509Certificate> cert = certMap.get(key);
            System.out.println(cert.getValue().getType());
            System.out.println(cert.getValue().getSubjectX500Principal().getName());
        }
    }

    @Test
    public void testCN() {
        System.out.println("testCN");
        System.out.println("CN ->" + BCStyle.CN);
        org.bouncycastle.asn1.x500.X500Name subjectDN = new org.bouncycastle.asn1.x500.X500Name("cn=hoge, ou=fuga, o=\"Foo Co., Ltd.\", c=JP");
        for (RDN rdn : subjectDN.getRDNs()) {
            for (AttributeTypeAndValue t : rdn.getTypesAndValues()) {
                System.out.println("t.Type:" + BCStyle.INSTANCE.oidToDisplayName(t.getType()) + " t.Value:" + t.getValue());
            }
        }
    }

    @Test
    public void testSelfCA() {
        System.out.println("testSelfCA");
        try {
            Security.addProvider(new BouncyCastleProvider());
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair caKeyPair = keyGen.generateKeyPair();
            org.bouncycastle.asn1.x500.X500Name subjectDN = new org.bouncycastle.asn1.x500.X500Name("cn=hoge, ou=fuga, o=\"Foo Co., Ltd.\", c=JP");
            System.out.println("subjectDN:");
            X509Certificate cert = BouncyUtil.createRootCA(caKeyPair, subjectDN, 2);
            System.out.println("createCA:" + cert.getSubjectX500Principal().getName());
            File pem = File.createTempFile("pem", ".cer");
            pem.deleteOnExit();
            System.out.println("pem:" + pem.getAbsolutePath());
            BouncyUtil.storeCertificatePem(caKeyPair.getPrivate(), cert, pem);
        } catch (NoSuchAlgorithmException | CertificateException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        } catch (IOException ex) {
            Logger.getLogger(BoncyUtilTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    @Test
    public void testBurpSign() {
        System.out.println("testBurpSign");
        try {
            Security.addProvider(new BouncyCastleProvider());
            KeyStore burpKeyStore = BurpPreferences.loadCACeart();
            KeyPair burpKeyPair = BurpPreferences.loadCAKeyPair();
            X509Certificate burpCert = (X509Certificate) burpKeyStore.getCertificate(CertUtil.getFirstAlias(burpKeyStore));

            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair keyPair = keyGen.generateKeyPair();
            System.out.println("subjectDN:");
            X509Certificate cert = BouncyUtil.issueSignCert(burpKeyPair.getPrivate(), burpCert, keyPair, "www.example.com", new String[]{"www.example.com"}, 2);
            System.out.println("createCA:" + cert.getSubjectX500Principal().getName());
        } catch (NoSuchAlgorithmException | KeyStoreException | CertificateException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }

    @Test
    public void testHashUtil() {
        System.out.println("testHashUtil");
        {
            try {
                String hash = BouncyUtil.toMD2Sum("hello world", true);
                assertEquals("D9CCE882EE690A5C1CE70BEFF3A78C77", hash);
                String hash2 = BouncyUtil.toMD2Sum(StringUtil.getBytesRaw("hello world"), true);
                assertEquals("D9CCE882EE690A5C1CE70BEFF3A78C77", hash2);
                String hash3 = BouncyUtil.toMD2Sum("hello world", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("D9CCE882EE690A5C1CE70BEFF3A78C77", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
        {
            try {
                String hash = BouncyUtil.toMD4Sum("hello world", true);
                assertEquals("AA010FBC1D14C795D86EF98C95479D17", hash);
                String hash2 = BouncyUtil.toMD4Sum(StringUtil.getBytesRaw("hello world"), true);
                assertEquals("AA010FBC1D14C795D86EF98C95479D17", hash2);
                String hash3 = BouncyUtil.toMD4Sum("hello world", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("AA010FBC1D14C795D86EF98C95479D17", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
        {
            try {
                String hash = BouncyUtil.toMD5Sum("hello world", true);
                assertEquals("5EB63BBBE01EEED093CB22BB8F5ACDC3", hash);
                String hash2 = BouncyUtil.toMD5Sum(StringUtil.getBytesRaw("hello world"), true);
                assertEquals("5EB63BBBE01EEED093CB22BB8F5ACDC3", hash2);
                String hash3 = BouncyUtil.toMD5Sum("hello world", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("5EB63BBBE01EEED093CB22BB8F5ACDC3", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }

        {
            try {
                String hash = BouncyUtil.toSHA1Sum("hello world", true);
                assertEquals("2AAE6C35C94FCFB415DBE95F408B9CE91EE846ED", hash);
                String hash2 = BouncyUtil.toSHA1Sum(StringUtil.getBytesRaw("hello world"), true);
                assertEquals("2AAE6C35C94FCFB415DBE95F408B9CE91EE846ED", hash2);
                String hash3 = BouncyUtil.toSHA1Sum("hello world", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("2AAE6C35C94FCFB415DBE95F408B9CE91EE846ED", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
        {
            try {
                String hash = BouncyUtil.toSHA224Sum("hello world", true);
                assertEquals("2F05477FC24BB4FAEFD86517156DAFDECEC45B8AD3CF2522A563582B", hash);
                String hash2 = BouncyUtil.toSHA224Sum(StringUtil.getBytesRaw("hello world"), true);
                assertEquals("2F05477FC24BB4FAEFD86517156DAFDECEC45B8AD3CF2522A563582B", hash2);
                String hash3 = BouncyUtil.toSHA224Sum("hello world", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("2F05477FC24BB4FAEFD86517156DAFDECEC45B8AD3CF2522A563582B", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
        {
            try {
                String hash = BouncyUtil.toSHA256Sum("hello world", true);
                assertEquals("B94D27B9934D3E08A52E52D7DA7DABFAC484EFE37A5380EE9088F7ACE2EFCDE9", hash);
                String hash2 = BouncyUtil.toSHA256Sum(StringUtil.getBytesRaw("hello world"), true);
                assertEquals("B94D27B9934D3E08A52E52D7DA7DABFAC484EFE37A5380EE9088F7ACE2EFCDE9", hash2);
                String hash3 = BouncyUtil.toSHA256Sum("hello world", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("B94D27B9934D3E08A52E52D7DA7DABFAC484EFE37A5380EE9088F7ACE2EFCDE9", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
        {
            try {
                String hash = BouncyUtil.toSHA384Sum("hello world", true);
                assertEquals("FDBD8E75A67F29F701A4E040385E2E23986303EA10239211AF907FCBB83578B3E417CB71CE646EFD0819DD8C088DE1BD", hash);
                String hash2 = BouncyUtil.toSHA384Sum(StringUtil.getBytesRaw("hello world"), true);
                assertEquals("FDBD8E75A67F29F701A4E040385E2E23986303EA10239211AF907FCBB83578B3E417CB71CE646EFD0819DD8C088DE1BD", hash2);
                String hash3 = BouncyUtil.toSHA384Sum("hello world", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("FDBD8E75A67F29F701A4E040385E2E23986303EA10239211AF907FCBB83578B3E417CB71CE646EFD0819DD8C088DE1BD", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
        {
            try {
                String hash = BouncyUtil.toSHA512Sum("hello world", true);
                assertEquals("309ECC489C12D6EB4CC40F50C902F2B4D0ED77EE511A7C7A9BCD3CA86D4CD86F989DD35BC5FF499670DA34255B45B0CFD830E81F605DCF7DC5542E93AE9CD76F", hash);
                String hash2 = BouncyUtil.toSHA512Sum(StringUtil.getBytesRaw("hello world"), true);
                assertEquals("309ECC489C12D6EB4CC40F50C902F2B4D0ED77EE511A7C7A9BCD3CA86D4CD86F989DD35BC5FF499670DA34255B45B0CFD830E81F605DCF7DC5542E93AE9CD76F", hash2);
                String hash3 = BouncyUtil.toSHA512Sum("hello world", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("309ECC489C12D6EB4CC40F50C902F2B4D0ED77EE511A7C7A9BCD3CA86D4CD86F989DD35BC5FF499670DA34255B45B0CFD830E81F605DCF7DC5542E93AE9CD76F", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
        {
            try {
                String hash = BouncyUtil.toSHA512_224Sum("hello world", true);
                assertEquals("22E0D52336F64A998085078B05A6E37B26F8120F43BF4DB4C43A64EE", hash);
                String hash2 = BouncyUtil.toSHA512_224Sum(StringUtil.getBytesRaw("hello world"), true);
                assertEquals("22E0D52336F64A998085078B05A6E37B26F8120F43BF4DB4C43A64EE", hash2);
                String hash3 = BouncyUtil.toSHA512_224Sum("hello world", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("22E0D52336F64A998085078B05A6E37B26F8120F43BF4DB4C43A64EE", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
        {
            try {
                String hash = BouncyUtil.toSHA512_256Sum("hello world", true);
                assertEquals("0AC561FAC838104E3F2E4AD107B4BEE3E938BF15F2B15F009CCCCD61A913F017", hash);
                String hash2 = BouncyUtil.toSHA512_256Sum(StringUtil.getBytesRaw("hello world"), true);
                assertEquals("0AC561FAC838104E3F2E4AD107B4BEE3E938BF15F2B15F009CCCCD61A913F017", hash2);
                String hash3 = BouncyUtil.toSHA512_256Sum("hello world", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("0AC561FAC838104E3F2E4AD107B4BEE3E938BF15F2B15F009CCCCD61A913F017", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
        {
            try {
                String hash = BouncyUtil.toSHA3_224Sum("hello world", true);
                assertEquals("DFB7F18C77E928BB56FAEB2DA27291BD790BC1045CDE45F3210BB6C5", hash);
                String hash2 = BouncyUtil.toSHA3_224Sum(StringUtil.getBytesRaw("hello world"), true);
                assertEquals("DFB7F18C77E928BB56FAEB2DA27291BD790BC1045CDE45F3210BB6C5", hash2);
                String hash3 = BouncyUtil.toSHA3_224Sum("hello world", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("DFB7F18C77E928BB56FAEB2DA27291BD790BC1045CDE45F3210BB6C5", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
        {
            try {
                String hash = BouncyUtil.toSHA3_256Sum("hello world", true);
                assertEquals("644BCC7E564373040999AAC89E7622F3CA71FBA1D972FD94A31C3BFBF24E3938", hash);
                String hash2 = BouncyUtil.toSHA3_256Sum(StringUtil.getBytesRaw("hello world"), true);
                assertEquals("644BCC7E564373040999AAC89E7622F3CA71FBA1D972FD94A31C3BFBF24E3938", hash2);
                String hash3 = BouncyUtil.toSHA3_256Sum("hello world", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("644BCC7E564373040999AAC89E7622F3CA71FBA1D972FD94A31C3BFBF24E3938", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
        {
            try {
                String hash = BouncyUtil.toSHA3_384Sum("hello world", true);
                assertEquals("83BFF28DDE1B1BF5810071C6643C08E5B05BDB836EFFD70B403EA8EA0A634DC4997EB1053AA3593F590F9C63630DD90B", hash);
                String hash2 = BouncyUtil.toSHA3_384Sum(StringUtil.getBytesRaw("hello world"), true);
                assertEquals("83BFF28DDE1B1BF5810071C6643C08E5B05BDB836EFFD70B403EA8EA0A634DC4997EB1053AA3593F590F9C63630DD90B", hash2);
                String hash3 = BouncyUtil.toSHA3_384Sum("hello world", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("83BFF28DDE1B1BF5810071C6643C08E5B05BDB836EFFD70B403EA8EA0A634DC4997EB1053AA3593F590F9C63630DD90B", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
        {
            try {
                String hash = BouncyUtil.toSHA3_512Sum("hello world", true);
                assertEquals("840006653E9AC9E95117A15C915CAAB81662918E925DE9E004F774FF82D7079A40D4D27B1B372657C61D46D470304C88C788B3A4527AD074D1DCCBEE5DBAA99A", hash);
                String hash2 = BouncyUtil.toSHA3_512Sum(StringUtil.getBytesRaw("hello world"), true);
                assertEquals("840006653E9AC9E95117A15C915CAAB81662918E925DE9E004F774FF82D7079A40D4D27B1B372657C61D46D470304C88C788B3A4527AD074D1DCCBEE5DBAA99A", hash2);
                String hash3 = BouncyUtil.toSHA3_512Sum("hello world", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("840006653E9AC9E95117A15C915CAAB81662918E925DE9E004F774FF82D7079A40D4D27B1B372657C61D46D470304C88C788B3A4527AD074D1DCCBEE5DBAA99A", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
        {
            try {
                String hash = BouncyUtil.toRIPEMD128Sum("hello world", true);
                assertEquals("C52AC4D06245286B33953957BE6C6F81", hash);
                String hash2 = BouncyUtil.toRIPEMD128Sum(StringUtil.getBytesRaw("hello world"), true);
                assertEquals("C52AC4D06245286B33953957BE6C6F81", hash2);
                String hash3 = BouncyUtil.toRIPEMD128Sum("hello world", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("C52AC4D06245286B33953957BE6C6F81", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
        {
            try {
                String hash = BouncyUtil.toRIPEMD160Sum("hello world", true);
                assertEquals("98C615784CCB5FE5936FBC0CBE9DFDB408D92F0F", hash);
                String hash2 = BouncyUtil.toRIPEMD160Sum(StringUtil.getBytesRaw("hello world"), true);
                assertEquals("98C615784CCB5FE5936FBC0CBE9DFDB408D92F0F", hash2);
                String hash3 = BouncyUtil.toRIPEMD160Sum("hello world", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("98C615784CCB5FE5936FBC0CBE9DFDB408D92F0F", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
        {
            try {
                String hash = BouncyUtil.toRIPEMD256Sum("hello world", true);
                assertEquals("0D375CF9D9EE95A3BB15F757C81E93BB0AD963EDF69DC4D12264031814608E37", hash);
                String hash2 = BouncyUtil.toRIPEMD256Sum(StringUtil.getBytesRaw("hello world"), true);
                assertEquals("0D375CF9D9EE95A3BB15F757C81E93BB0AD963EDF69DC4D12264031814608E37", hash2);
                String hash3 = BouncyUtil.toRIPEMD256Sum("hello world", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("0D375CF9D9EE95A3BB15F757C81E93BB0AD963EDF69DC4D12264031814608E37", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
        {
            try {
                String hash = BouncyUtil.toRIPEMD320Sum("hello world", true);
                assertEquals("0E12FE7D075F8E319E07C106917EDDB0135E9A10AEFB50A8A07CCB0582FF1FA27B95ED5AF57FD5C6", hash);
                String hash2 = BouncyUtil.toRIPEMD320Sum(StringUtil.getBytesRaw("hello world"), true);
                assertEquals("0E12FE7D075F8E319E07C106917EDDB0135E9A10AEFB50A8A07CCB0582FF1FA27B95ED5AF57FD5C6", hash2);
                String hash3 = BouncyUtil.toRIPEMD320Sum("hello world", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("0E12FE7D075F8E319E07C106917EDDB0135E9A10AEFB50A8A07CCB0582FF1FA27B95ED5AF57FD5C6", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
        {
            try {
                String hash = BouncyUtil.toTigerSum("hello world", true);
                assertEquals("4C8FBDDAE0B6F25832AF45E7C62811BB64EC3E43691E9CC3", hash);
                String hash2 = BouncyUtil.toTigerSum(StringUtil.getBytesRaw("hello world"), true);
                assertEquals("4C8FBDDAE0B6F25832AF45E7C62811BB64EC3E43691E9CC3", hash2);
                String hash3 = BouncyUtil.toTigerSum("hello world", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("4C8FBDDAE0B6F25832AF45E7C62811BB64EC3E43691E9CC3", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
        {
            try {
                String hash = BouncyUtil.toGOST3411Sum("hello world", true);
                assertEquals("C5AA1455AFE9F0C440EEC3C96CCCCB5C8495097572CC0F625278BD0DA5EA5E07", hash);
                String hash2 = BouncyUtil.toGOST3411Sum(StringUtil.getBytesRaw("hello world"), true);
                assertEquals("C5AA1455AFE9F0C440EEC3C96CCCCB5C8495097572CC0F625278BD0DA5EA5E07", hash2);
                String hash3 = BouncyUtil.toGOST3411Sum("hello world", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("C5AA1455AFE9F0C440EEC3C96CCCCB5C8495097572CC0F625278BD0DA5EA5E07", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
        {
            try {
                String hash = BouncyUtil.toGOST3411_2012_256Sum("hello world", true);
                assertEquals("C600FD9DD049CF8ABD2F5B32E840D2CB0E41EA44DE1C155DCD88DC84FE58A855", hash);
                String hash2 = BouncyUtil.toGOST3411_2012_256Sum(StringUtil.getBytesRaw("hello world"), true);
                assertEquals("C600FD9DD049CF8ABD2F5B32E840D2CB0E41EA44DE1C155DCD88DC84FE58A855", hash2);
                String hash3 = BouncyUtil.toGOST3411_2012_256Sum("hello world", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("C600FD9DD049CF8ABD2F5B32E840D2CB0E41EA44DE1C155DCD88DC84FE58A855", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
        {
            try {
                String hash = BouncyUtil.toGOST3411_2012_512Sum("hello world", true);
                assertEquals("84D883EDE9FA6CE855D82D8C278ECD9F5FC88BF0602831AE0C38B9B506EA3CB02F3FA076B8F5664ADF1FF862C0157DA4CC9A83E141B738FF9268A9BA3ED6F563", hash);
                String hash2 = BouncyUtil.toGOST3411_2012_512Sum(StringUtil.getBytesRaw("hello world"), true);
                assertEquals("84D883EDE9FA6CE855D82D8C278ECD9F5FC88BF0602831AE0C38B9B506EA3CB02F3FA076B8F5664ADF1FF862C0157DA4CC9A83E141B738FF9268A9BA3ED6F563", hash2);
                String hash3 = BouncyUtil.toGOST3411_2012_512Sum("hello world", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("84D883EDE9FA6CE855D82D8C278ECD9F5FC88BF0602831AE0C38B9B506EA3CB02F3FA076B8F5664ADF1FF862C0157DA4CC9A83E141B738FF9268A9BA3ED6F563", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }

        {
            try {
                String hash = BouncyUtil.toDSTU7564_256Sum("hello world", true);
                assertEquals("59602A882A49C1AA6443225004E5796A664793C8D26CD4B8A40D63AAB024F02B", hash);
                String hash2 = BouncyUtil.toDSTU7564_256Sum(StringUtil.getBytesRaw("hello world"), true);
                assertEquals("59602A882A49C1AA6443225004E5796A664793C8D26CD4B8A40D63AAB024F02B", hash2);
                String hash3 = BouncyUtil.toDSTU7564_256Sum("hello world", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("59602A882A49C1AA6443225004E5796A664793C8D26CD4B8A40D63AAB024F02B", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
        {
            try {
                String hash = BouncyUtil.toDSTU7564_384Sum("hello world", true);
                assertEquals("850FA7480A3ABFBC0FFE20181896868AE20F87BB16E79FAC62D85F59D84D3FC45871830BEF8FD9C967AA6CF5779AA17C", hash);
                String hash2 = BouncyUtil.toDSTU7564_384Sum(StringUtil.getBytesRaw("hello world"), true);
                assertEquals("850FA7480A3ABFBC0FFE20181896868AE20F87BB16E79FAC62D85F59D84D3FC45871830BEF8FD9C967AA6CF5779AA17C", hash2);
                String hash3 = BouncyUtil.toDSTU7564_384Sum("hello world", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("850FA7480A3ABFBC0FFE20181896868AE20F87BB16E79FAC62D85F59D84D3FC45871830BEF8FD9C967AA6CF5779AA17C", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
        {
            try {
                String hash = BouncyUtil.toDSTU7564_512Sum("hello world", true);
                assertEquals("8C3DD617D29BF9102475BF2CF58BC57F850FA7480A3ABFBC0FFE20181896868AE20F87BB16E79FAC62D85F59D84D3FC45871830BEF8FD9C967AA6CF5779AA17C", hash);
                String hash2 = BouncyUtil.toDSTU7564_512Sum(StringUtil.getBytesRaw("hello world"), true);
                assertEquals("8C3DD617D29BF9102475BF2CF58BC57F850FA7480A3ABFBC0FFE20181896868AE20F87BB16E79FAC62D85F59D84D3FC45871830BEF8FD9C967AA6CF5779AA17C", hash2);
                String hash3 = BouncyUtil.toDSTU7564_512Sum("hello world", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("8C3DD617D29BF9102475BF2CF58BC57F850FA7480A3ABFBC0FFE20181896868AE20F87BB16E79FAC62D85F59D84D3FC45871830BEF8FD9C967AA6CF5779AA17C", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
        {
            try {
                String hash = BouncyUtil.toWHIRLPOOLSum("hello world", true);
                assertEquals("8D8309CA6AF848095BCABAF9A53B1B6CE7F594C1434FD6E5177E7E5C20E76CD30936D8606E7F36ACBEF8978FEA008E6400A975D51ABE6BA4923178C7CF90C802", hash);
                String hash2 = BouncyUtil.toWHIRLPOOLSum(StringUtil.getBytesRaw("hello world"), true);
                assertEquals("8D8309CA6AF848095BCABAF9A53B1B6CE7F594C1434FD6E5177E7E5C20E76CD30936D8606E7F36ACBEF8978FEA008E6400A975D51ABE6BA4923178C7CF90C802", hash2);
                String hash3 = BouncyUtil.toWHIRLPOOLSum("hello world", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("8D8309CA6AF848095BCABAF9A53B1B6CE7F594C1434FD6E5177E7E5C20E76CD30936D8606E7F36ACBEF8978FEA008E6400A975D51ABE6BA4923178C7CF90C802", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
        {
            try {
                String hash = BouncyUtil.toSM3Sum("hello world", true);
                assertEquals("44F0061E69FA6FDFC290C494654A05DC0C053DA7E5C52B84EF93A9D67D3FFF88", hash);
                String hash2 = BouncyUtil.toSM3Sum(StringUtil.getBytesRaw("hello world"), true);
                assertEquals("44F0061E69FA6FDFC290C494654A05DC0C053DA7E5C52B84EF93A9D67D3FFF88", hash2);
                String hash3 = BouncyUtil.toSM3Sum("hello world", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("44F0061E69FA6FDFC290C494654A05DC0C053DA7E5C52B84EF93A9D67D3FFF88", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
        {
            try {
                String hash = BouncyUtil.toSKEIN256_128Sum("hello world", true);
                assertEquals("D0B3699C73E4456E1890FCE77194442E", hash);
                String hash2 = BouncyUtil.toSKEIN256_128Sum(StringUtil.getBytesRaw("hello world"), true);
                assertEquals("D0B3699C73E4456E1890FCE77194442E", hash2);
                String hash3 = BouncyUtil.toSKEIN256_128Sum("hello world", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("D0B3699C73E4456E1890FCE77194442E", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
        {
            try {
                String hash = BouncyUtil.toBLAKE2B_160Sum("hello world", true);
                assertEquals("70E8ECE5E293E1BDA064DEEF6B080EDDE357010F", hash);
                String hash2 = BouncyUtil.toBLAKE2B_160Sum(StringUtil.getBytesRaw("hello world"), true);
                assertEquals("70E8ECE5E293E1BDA064DEEF6B080EDDE357010F", hash2);
                String hash3 = BouncyUtil.toBLAKE2B_160Sum("hello world", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("70E8ECE5E293E1BDA064DEEF6B080EDDE357010F", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
        {
            try {
                String hash = BouncyUtil.toBLAKE2B_256Sum("hello world", true);
                assertEquals("256C83B297114D201B30179F3F0EF0CACE9783622DA5974326B436178AEEF610", hash);
                String hash2 = BouncyUtil.toBLAKE2B_256Sum(StringUtil.getBytesRaw("hello world"), true);
                assertEquals("256C83B297114D201B30179F3F0EF0CACE9783622DA5974326B436178AEEF610", hash2);
                String hash3 = BouncyUtil.toBLAKE2B_256Sum("hello world", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("256C83B297114D201B30179F3F0EF0CACE9783622DA5974326B436178AEEF610", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
        {
            try {
                String hash = BouncyUtil.toBLAKE2B_384Sum("hello world", true);
                assertEquals("8C653F8C9C9AA2177FB6F8CF5BB914828FAA032D7B486C8150663D3F6524B086784F8E62693171AC51FC80B7D2CBB12B", hash);
                String hash2 = BouncyUtil.toBLAKE2B_384Sum(StringUtil.getBytesRaw("hello world"), true);
                assertEquals("8C653F8C9C9AA2177FB6F8CF5BB914828FAA032D7B486C8150663D3F6524B086784F8E62693171AC51FC80B7D2CBB12B", hash2);
                String hash3 = BouncyUtil.toBLAKE2B_384Sum("hello world", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("8C653F8C9C9AA2177FB6F8CF5BB914828FAA032D7B486C8150663D3F6524B086784F8E62693171AC51FC80B7D2CBB12B", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
        {
            try {
                String hash = BouncyUtil.toBLAKE2S_160Sum("hello world", true);
                assertEquals("5B61362BD56823FD6ED1D3BEA2F3FF0D2A0214D7", hash);
                String hash2 = BouncyUtil.toBLAKE2S_160Sum(StringUtil.getBytesRaw("hello world"), true);
                assertEquals("5B61362BD56823FD6ED1D3BEA2F3FF0D2A0214D7", hash2);
                String hash3 = BouncyUtil.toBLAKE2S_160Sum("hello world", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("5B61362BD56823FD6ED1D3BEA2F3FF0D2A0214D7", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
        {
            try {
                String hash = BouncyUtil.toBLAKE2S_224Sum("hello world", true);
                assertEquals("00D9F56EA4202532F8FD42B12943E6EE8EA6FBEF70052A6563D041A1", hash);
                String hash2 = BouncyUtil.toBLAKE2S_224Sum(StringUtil.getBytesRaw("hello world"), true);
                assertEquals("00D9F56EA4202532F8FD42B12943E6EE8EA6FBEF70052A6563D041A1", hash2);
                String hash3 = BouncyUtil.toBLAKE2S_224Sum("hello world", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("00D9F56EA4202532F8FD42B12943E6EE8EA6FBEF70052A6563D041A1", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
        {
            try {
                String hash = BouncyUtil.toBLAKE2S_256Sum("hello world", true);
                assertEquals("9AEC6806794561107E594B1F6A8A6B0C92A0CBA9ACF5E5E93CCA06F781813B0B", hash);
                String hash2 = BouncyUtil.toBLAKE2S_256Sum(StringUtil.getBytesRaw("hello world"), true);
                assertEquals("9AEC6806794561107E594B1F6A8A6B0C92A0CBA9ACF5E5E93CCA06F781813B0B", hash2);
                String hash3 = BouncyUtil.toBLAKE2S_256Sum("hello world", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("9AEC6806794561107E594B1F6A8A6B0C92A0CBA9ACF5E5E93CCA06F781813B0B", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
        {
            try {
                String hash = BouncyUtil.toBLAKE2S_128Sum("hello world", true);
                assertEquals("37DEAE0226C30DA2AB424A7B8EE14E83", hash);
                String hash2 = BouncyUtil.toBLAKE2S_128Sum(StringUtil.getBytesRaw("hello world"), true);
                assertEquals("37DEAE0226C30DA2AB424A7B8EE14E83", hash2);
                String hash3 = BouncyUtil.toBLAKE2S_128Sum("hello world", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("37DEAE0226C30DA2AB424A7B8EE14E83", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
        {
            try {
                String hash = BouncyUtil.toBLAKE3_256Sum("hello world", true);
                assertEquals("D74981EFA70A0C880B8D8C1985D075DBCBF679B99A5F9914E5AAF96B831A9E24", hash);
                String hash2 = BouncyUtil.toBLAKE3_256Sum(StringUtil.getBytesRaw("hello world"), true);
                assertEquals("D74981EFA70A0C880B8D8C1985D075DBCBF679B99A5F9914E5AAF96B831A9E24", hash2);
                String hash3 = BouncyUtil.toBLAKE3_256Sum("hello world", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("D74981EFA70A0C880B8D8C1985D075DBCBF679B99A5F9914E5AAF96B831A9E24", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
        {
            try {
                String hash = BouncyUtil.toBLAKE2B_160Sum("hello world", true);
                assertEquals("70E8ECE5E293E1BDA064DEEF6B080EDDE357010F", hash);
                String hash2 = BouncyUtil.toBLAKE2B_160Sum(StringUtil.getBytesRaw("hello world"), true);
                assertEquals("70E8ECE5E293E1BDA064DEEF6B080EDDE357010F", hash2);
                String hash3 = BouncyUtil.toBLAKE2B_160Sum("hello world", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("70E8ECE5E293E1BDA064DEEF6B080EDDE357010F", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
        {
            try {
                String hash = BouncyUtil.toSKEIN256_160Sum("hello world", true);
                assertEquals("CBEE4D9CBB3133D31AC3FCE28601C664A037B5F2", hash);
                String hash2 = BouncyUtil.toSKEIN256_160Sum(StringUtil.getBytesRaw("hello world"), true);
                assertEquals("CBEE4D9CBB3133D31AC3FCE28601C664A037B5F2", hash2);
                String hash3 = BouncyUtil.toSKEIN256_160Sum("hello world", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("CBEE4D9CBB3133D31AC3FCE28601C664A037B5F2", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
        {
            try {
                String hash = BouncyUtil.toSKEIN256_224Sum("hello world", true);
                assertEquals("EA5380DE5F67C1F870B88C9C825DE2D932ADB9FC39C2290171126FF2", hash);
                String hash2 = BouncyUtil.toSKEIN256_224Sum(StringUtil.getBytesRaw("hello world"), true);
                assertEquals("EA5380DE5F67C1F870B88C9C825DE2D932ADB9FC39C2290171126FF2", hash2);
                String hash3 = BouncyUtil.toSKEIN256_224Sum("hello world", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("EA5380DE5F67C1F870B88C9C825DE2D932ADB9FC39C2290171126FF2", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
        {
            try {
                String hash = BouncyUtil.toSKEIN256_256Sum("hello world", true);
                assertEquals("CD9C8FEFC0B6BD07CAB959EE0EE0C8A1FD1F27E5ADBEB47E6F2C165956D8C972", hash);
                String hash2 = BouncyUtil.toSKEIN256_256Sum(StringUtil.getBytesRaw("hello world"), true);
                assertEquals("CD9C8FEFC0B6BD07CAB959EE0EE0C8A1FD1F27E5ADBEB47E6F2C165956D8C972", hash2);
                String hash3 = BouncyUtil.toSKEIN256_256Sum("hello world", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("CD9C8FEFC0B6BD07CAB959EE0EE0C8A1FD1F27E5ADBEB47E6F2C165956D8C972", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
        {
            try {
                String hash = BouncyUtil.toSKEIN512_128Sum("hello world", true);
                assertEquals("FD0533815B22BEBAD79E2FBCA4437369", hash);
                String hash2 = BouncyUtil.toSKEIN512_128Sum(StringUtil.getBytesRaw("hello world"), true);
                assertEquals("FD0533815B22BEBAD79E2FBCA4437369", hash2);
                String hash3 = BouncyUtil.toSKEIN512_128Sum("hello world", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("FD0533815B22BEBAD79E2FBCA4437369", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
        {
            try {
                String hash = BouncyUtil.toSKEIN512_160Sum("hello world", true);
                assertEquals("106E75EC084BD88C92D1E750408FEF9113572210", hash);
                String hash2 = BouncyUtil.toSKEIN512_160Sum(StringUtil.getBytesRaw("hello world"), true);
                assertEquals("106E75EC084BD88C92D1E750408FEF9113572210", hash2);
                String hash3 = BouncyUtil.toSKEIN512_160Sum("hello world", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("106E75EC084BD88C92D1E750408FEF9113572210", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
        {
            try {
                String hash = BouncyUtil.toSKEIN512_224Sum("hello world", true);
                assertEquals("A47EDD3A57141AA79191011338D83F4BE1652C8437E823E1138B3585", hash);
                String hash2 = BouncyUtil.toSKEIN512_224Sum(StringUtil.getBytesRaw("hello world"), true);
                assertEquals("A47EDD3A57141AA79191011338D83F4BE1652C8437E823E1138B3585", hash2);
                String hash3 = BouncyUtil.toSKEIN512_224Sum("hello world", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("A47EDD3A57141AA79191011338D83F4BE1652C8437E823E1138B3585", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
        {
            try {
                String hash = BouncyUtil.toSKEIN512_256Sum("hello world", true);
                assertEquals("D049BC150AA047A0435129D1D06A0AE4830A58C4D2A41383B71CED3CB233A702", hash);
                String hash2 = BouncyUtil.toSKEIN512_256Sum(StringUtil.getBytesRaw("hello world"), true);
                assertEquals("D049BC150AA047A0435129D1D06A0AE4830A58C4D2A41383B71CED3CB233A702", hash2);
                String hash3 = BouncyUtil.toSKEIN512_256Sum("hello world", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("D049BC150AA047A0435129D1D06A0AE4830A58C4D2A41383B71CED3CB233A702", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
        {
            try {
                String hash = BouncyUtil.toSKEIN512_384Sum("hello world", true);
                assertEquals("A5CB4ED297AE04326CC9303E926B1B09999A58D932439A821D9E14BC110D0E1BAA3F65CB2F12F127D291BC35E325FB24", hash);
                String hash2 = BouncyUtil.toSKEIN512_384Sum(StringUtil.getBytesRaw("hello world"), true);
                assertEquals("A5CB4ED297AE04326CC9303E926B1B09999A58D932439A821D9E14BC110D0E1BAA3F65CB2F12F127D291BC35E325FB24", hash2);
                String hash3 = BouncyUtil.toSKEIN512_384Sum("hello world", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("A5CB4ED297AE04326CC9303E926B1B09999A58D932439A821D9E14BC110D0E1BAA3F65CB2F12F127D291BC35E325FB24", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
        {
            try {
                String hash = BouncyUtil.toSKEIN512_512Sum("hello world", true);
                assertEquals("8B4830244FC36DAA11177311DC6BF7636376180DCE2D29193335878142E7D6F5E9016BEBA729E0A353DD2FD421C8B2022EE8927F0BCE6B88631BB01BE2E0F5BA", hash);
                String hash2 = BouncyUtil.toSKEIN512_512Sum(StringUtil.getBytesRaw("hello world"), true);
                assertEquals("8B4830244FC36DAA11177311DC6BF7636376180DCE2D29193335878142E7D6F5E9016BEBA729E0A353DD2FD421C8B2022EE8927F0BCE6B88631BB01BE2E0F5BA", hash2);
                String hash3 = BouncyUtil.toSKEIN512_512Sum("hello world", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("8B4830244FC36DAA11177311DC6BF7636376180DCE2D29193335878142E7D6F5E9016BEBA729E0A353DD2FD421C8B2022EE8927F0BCE6B88631BB01BE2E0F5BA", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
        {
            try {
                String hash = BouncyUtil.toSKEIN1024_384Sum("hello world", true);
                assertEquals("7FCFD63A8FC1E16395C3EDC467C89682A4332C24A6D46870D69DCFDAE2C120E82E93C7B4CE7EAA51A46972554407AF23", hash);
                String hash2 = BouncyUtil.toSKEIN1024_384Sum(StringUtil.getBytesRaw("hello world"), true);
                assertEquals("7FCFD63A8FC1E16395C3EDC467C89682A4332C24A6D46870D69DCFDAE2C120E82E93C7B4CE7EAA51A46972554407AF23", hash2);
                String hash3 = BouncyUtil.toSKEIN1024_384Sum("hello world", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("7FCFD63A8FC1E16395C3EDC467C89682A4332C24A6D46870D69DCFDAE2C120E82E93C7B4CE7EAA51A46972554407AF23", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
        {
            try {
                String hash = BouncyUtil.toSKEIN1024_512Sum("hello world", true);
                assertEquals("C560FB919EDD6F5E2825B134FE1159FF37F6C7AB87891FA63DBC2396403D92A211C1CB55328E8C8A7E626EE91F07A6486200E440696D678707E9000DB090641B", hash);
                String hash2 = BouncyUtil.toSKEIN1024_512Sum(StringUtil.getBytesRaw("hello world"), true);
                assertEquals("C560FB919EDD6F5E2825B134FE1159FF37F6C7AB87891FA63DBC2396403D92A211C1CB55328E8C8A7E626EE91F07A6486200E440696D678707E9000DB090641B", hash2);
                String hash3 = BouncyUtil.toSKEIN1024_512Sum("hello world", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("C560FB919EDD6F5E2825B134FE1159FF37F6C7AB87891FA63DBC2396403D92A211C1CB55328E8C8A7E626EE91F07A6486200E440696D678707E9000DB090641B", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
        {
            try {
                String hash = BouncyUtil.toSKEIN1024_1024Sum("hello world", true);
                assertEquals("97E2D9444C3564F14C748D85D28DC8E6B86C2752D8C10573DEAA59E86649FE4139DEBF58CE07FE9C8A5E86778C047F371AABC221818487AB9B74F2951DA1527C562D920167EB861A032C1DD124B880D63C4E0928C35E1FD67844FF52CF44BA8D8FDD1A11F248BFACB8919728200BDBE9D77CA5C4928D8886E63AA9C96CB5080F", hash);
                String hash2 = BouncyUtil.toSKEIN1024_1024Sum(StringUtil.getBytesRaw("hello world"), true);
                assertEquals("97E2D9444C3564F14C748D85D28DC8E6B86C2752D8C10573DEAA59E86649FE4139DEBF58CE07FE9C8A5E86778C047F371AABC221818487AB9B74F2951DA1527C562D920167EB861A032C1DD124B880D63C4E0928C35E1FD67844FF52CF44BA8D8FDD1A11F248BFACB8919728200BDBE9D77CA5C4928D8886E63AA9C96CB5080F", hash2);
                String hash3 = BouncyUtil.toSKEIN1024_1024Sum("hello world", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("97E2D9444C3564F14C748D85D28DC8E6B86C2752D8C10573DEAA59E86649FE4139DEBF58CE07FE9C8A5E86778C047F371AABC221818487AB9B74F2951DA1527C562D920167EB861A032C1DD124B880D63C4E0928C35E1FD67844FF52CF44BA8D8FDD1A11F248BFACB8919728200BDBE9D77CA5C4928D8886E63AA9C96CB5080F", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
        {
            try {
                String hash = BouncyUtil.toHARAKA256Sum("01234567890123456789012345678912", true);
                assertEquals("E434BF5EB641D5C577E9FBCDFE01A796524EA83D5AA39E06A99DEC9FC37B09BC", hash);
                String hash2 = BouncyUtil.toHARAKA256Sum(StringUtil.getBytesRaw("01234567890123456789012345678912"), true);
                assertEquals("E434BF5EB641D5C577E9FBCDFE01A796524EA83D5AA39E06A99DEC9FC37B09BC", hash2);
                String hash3 = BouncyUtil.toHARAKA256Sum("01234567890123456789012345678912", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("E434BF5EB641D5C577E9FBCDFE01A796524EA83D5AA39E06A99DEC9FC37B09BC", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
        {
            try {
                String hash = BouncyUtil.toHARAKA512Sum("0123456789012345678901234567891201234567890123456789012345678912", true);
                assertEquals("46F82AD5094998371F9ADFFF9EA4B5B6E56BC59ED5B0999A8E3C19A1717DB7F5", hash);
                String hash2 = BouncyUtil.toHARAKA512Sum(StringUtil.getBytesRaw("0123456789012345678901234567891201234567890123456789012345678912"), true);
                assertEquals("46F82AD5094998371F9ADFFF9EA4B5B6E56BC59ED5B0999A8E3C19A1717DB7F5", hash2);
                String hash3 = BouncyUtil.toHARAKA512Sum("0123456789012345678901234567891201234567890123456789012345678912", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("46F82AD5094998371F9ADFFF9EA4B5B6E56BC59ED5B0999A8E3C19A1717DB7F5", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
        {
            try {
                String hash = BouncyUtil.toKECCAK224Sum("hello world", true);
                assertEquals("25F3ECFEBABE99686282F57F5C9E1F18244CFEE2813D33F955AAE568", hash);
                String hash2 = BouncyUtil.toKECCAK224Sum(StringUtil.getBytesRaw("hello world"), true);
                assertEquals("25F3ECFEBABE99686282F57F5C9E1F18244CFEE2813D33F955AAE568", hash2);
                String hash3 = BouncyUtil.toKECCAK224Sum("hello world", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("25F3ECFEBABE99686282F57F5C9E1F18244CFEE2813D33F955AAE568", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
        {
            try {
                String hash = BouncyUtil.toKECCAK256Sum("hello world", true);
                assertEquals("47173285A8D7341E5E972FC677286384F802F8EF42A5EC5F03BBFA254CB01FAD", hash);
                String hash2 = BouncyUtil.toKECCAK256Sum(StringUtil.getBytesRaw("hello world"), true);
                assertEquals("47173285A8D7341E5E972FC677286384F802F8EF42A5EC5F03BBFA254CB01FAD", hash2);
                String hash3 = BouncyUtil.toKECCAK256Sum("hello world", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("47173285A8D7341E5E972FC677286384F802F8EF42A5EC5F03BBFA254CB01FAD", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
        {
            try {
                String hash = BouncyUtil.toKECCAK288Sum("hello world", true);
                assertEquals("00242D4B2268A76904C446002980C137A00ABA89ED3A437C4C734EF2B49A314BB795CB09", hash);
                String hash2 = BouncyUtil.toKECCAK288Sum(StringUtil.getBytesRaw("hello world"), true);
                assertEquals("00242D4B2268A76904C446002980C137A00ABA89ED3A437C4C734EF2B49A314BB795CB09", hash2);
                String hash3 = BouncyUtil.toKECCAK288Sum("hello world", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("00242D4B2268A76904C446002980C137A00ABA89ED3A437C4C734EF2B49A314BB795CB09", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
        {
            try {
                String hash = BouncyUtil.toKECCAK384Sum("hello world", true);
                assertEquals("65FC99339A2A40E99D3C40D695B22F278853CA0F925CDE4254BCAE5E22ECE47E6441F91B6568425ADC9D95B0072EB49F", hash);
                String hash2 = BouncyUtil.toKECCAK384Sum(StringUtil.getBytesRaw("hello world"), true);
                assertEquals("65FC99339A2A40E99D3C40D695B22F278853CA0F925CDE4254BCAE5E22ECE47E6441F91B6568425ADC9D95B0072EB49F", hash2);
                String hash3 = BouncyUtil.toKECCAK384Sum("hello world", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("65FC99339A2A40E99D3C40D695B22F278853CA0F925CDE4254BCAE5E22ECE47E6441F91B6568425ADC9D95B0072EB49F", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
        {
            try {
                String hash = BouncyUtil.toKECCAK512Sum("hello world", true);
                assertEquals("3EE2B40047B8060F68C67242175660F4174D0AF5C01D47168EC20ED619B0B7C42181F40AA1046F39E2EF9EFC6910782A998E0013D172458957957FAC9405B67D", hash);
                String hash2 = BouncyUtil.toKECCAK512Sum(StringUtil.getBytesRaw("hello world"), true);
                assertEquals("3EE2B40047B8060F68C67242175660F4174D0AF5C01D47168EC20ED619B0B7C42181F40AA1046F39E2EF9EFC6910782A998E0013D172458957957FAC9405B67D", hash2);
                String hash3 = BouncyUtil.toKECCAK512Sum("hello world", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("3EE2B40047B8060F68C67242175660F4174D0AF5C01D47168EC20ED619B0B7C42181F40AA1046F39E2EF9EFC6910782A998E0013D172458957957FAC9405B67D", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
        {
            try {
                String hash = BouncyUtil.toSHAKE128Sum("hello world", true);
                assertEquals("3A9159F071E4DD1C8C4F968607C30942E120D8156B8B1E72E0D376E8871CB8B8", hash);
                String hash2 = BouncyUtil.toSHAKE128Sum(StringUtil.getBytesRaw("hello world"), true);
                assertEquals("3A9159F071E4DD1C8C4F968607C30942E120D8156B8B1E72E0D376E8871CB8B8", hash2);
                String hash3 = BouncyUtil.toSHAKE128Sum("hello world", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("3A9159F071E4DD1C8C4F968607C30942E120D8156B8B1E72E0D376E8871CB8B8", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
        {
            try {
                String hash = BouncyUtil.toSHAKE256um("hello world", true);
                assertEquals("369771BB2CB9D2B04C1D54CCA487E372D9F187F73F7BA3F65B95C8EE7798C527F4F3C2D55C2D46A29F2E945D469C3DF27853A8735271F5CC2D9E889544357116", hash);
                String hash2 = BouncyUtil.toSHAKE256um(StringUtil.getBytesRaw("hello world"), true);
                assertEquals("369771BB2CB9D2B04C1D54CCA487E372D9F187F73F7BA3F65B95C8EE7798C527F4F3C2D55C2D46A29F2E945D469C3DF27853A8735271F5CC2D9E889544357116", hash2);
                String hash3 = BouncyUtil.toSHAKE256um("hello world", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("369771BB2CB9D2B04C1D54CCA487E372D9F187F73F7BA3F65B95C8EE7798C527F4F3C2D55C2D46A29F2E945D469C3DF27853A8735271F5CC2D9E889544357116", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
        {
            try {
                String hash = BouncyUtil.toPARALLELHASH128_256Sum("hello world", true);
                assertEquals("FE34147E1BBCA35381E6EB09F74F8FAD9C48AB4673D2DF97F7B78244E5C6A705", hash);
                String hash2 = BouncyUtil.toPARALLELHASH128_256Sum(StringUtil.getBytesRaw("hello world"), true);
                assertEquals("FE34147E1BBCA35381E6EB09F74F8FAD9C48AB4673D2DF97F7B78244E5C6A705", hash2);
                String hash3 = BouncyUtil.toPARALLELHASH128_256Sum("hello world", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("FE34147E1BBCA35381E6EB09F74F8FAD9C48AB4673D2DF97F7B78244E5C6A705", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
        {
            try {
                String hash = BouncyUtil.toPARALLELHASH256_512Sum("hello world", true);
                assertEquals("15A36398E9E0E939558A3C1BF919A6DB7ACE03864A3599641C3F49EA4BB5474ABE194A2DB10416329CE99C619B21298537C3CE28DD3441235606EB33A5D700AD", hash);
                String hash2 = BouncyUtil.toPARALLELHASH256_512Sum(StringUtil.getBytesRaw("hello world"), true);
                assertEquals("15A36398E9E0E939558A3C1BF919A6DB7ACE03864A3599641C3F49EA4BB5474ABE194A2DB10416329CE99C619B21298537C3CE28DD3441235606EB33A5D700AD", hash2);
                String hash3 = BouncyUtil.toPARALLELHASH256_512Sum("hello world", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("15A36398E9E0E939558A3C1BF919A6DB7ACE03864A3599641C3F49EA4BB5474ABE194A2DB10416329CE99C619B21298537C3CE28DD3441235606EB33A5D700AD", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
        {
            try {
                String hash = BouncyUtil.toTUPLEHASH128_256Sum("hello world", true);
                assertEquals("7657A64DF9CF98B5C82ADB343858A57C03785031D46755B871BE5552A7850F56", hash);
                String hash2 = BouncyUtil.toTUPLEHASH128_256Sum(StringUtil.getBytesRaw("hello world"), true);
                assertEquals("7657A64DF9CF98B5C82ADB343858A57C03785031D46755B871BE5552A7850F56", hash2);
                String hash3 = BouncyUtil.toTUPLEHASH128_256Sum("hello world", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("7657A64DF9CF98B5C82ADB343858A57C03785031D46755B871BE5552A7850F56", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
        {
            try {
                String hash = BouncyUtil.toTUPLEHASH256_512Sum("hello world", true);
                assertEquals("E7CA4B2A739699EC0566D810BB9243DF8B2EC56212DE061041CD7A6290A828EEED9FF92948FD6E357AF66FA54D5C4E83FC5F6EE582BE12F5252BFDDD3554A59D", hash);
                String hash2 = BouncyUtil.toTUPLEHASH256_512Sum(StringUtil.getBytesRaw("hello world"), true);
                assertEquals("E7CA4B2A739699EC0566D810BB9243DF8B2EC56212DE061041CD7A6290A828EEED9FF92948FD6E357AF66FA54D5C4E83FC5F6EE582BE12F5252BFDDD3554A59D", hash2);
                String hash3 = BouncyUtil.toTUPLEHASH256_512Sum("hello world", StandardCharsets.ISO_8859_1.name(), true);
                assertEquals("E7CA4B2A739699EC0566D810BB9243DF8B2EC56212DE061041CD7A6290A828EEED9FF92948FD6E357AF66FA54D5C4E83FC5F6EE582BE12F5252BFDDD3554A59D", hash3);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }

    }

}
