package yagura.external;

import extend.util.Util;
import extend.util.external.CertUtil;
import java.io.File;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 *
 * @author t.isayama
 */
public class CertUtilTest {
    
    public CertUtilTest() {
    }
    
    @BeforeClass
    public static void setUpClass() {
    }
    
    @AfterClass
    public static void tearDownClass() {
    }
    
    @Before
    public void setUp() {
    }
    
    @After
    public void tearDown() {
    }

//    /**
//     * Test of loadFromKeyPKCS12 method, of class CertUtil.
//     */
//    @Test
//    public void testLoadFromKeyPKCS12() throws Exception {
//        System.out.println("loadFromKeyPKCS12");
//        File storeFile = null;
//        String password = "";
//        HashMap<String, CertificateInKey> expResult = null;
//        HashMap<String, CertificateInKey> result = CertUtil.loadFromKeyPKCS12(storeFile, password);
//        assertEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of loadFromKeyJKS method, of class CertUtil.
//     */
//    @Test
//    public void testLoadFromKeyJKS() throws Exception {
//        System.out.println("loadFromKeyJKS");
//        File storeFile = null;
//        String password = "";
//        HashMap<String, CertificateInKey> expResult = null;
//        HashMap<String, CertificateInKey> result = CertUtil.loadFromKeyJKS(storeFile, password);
//        assertEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of loadFromKeyStore method, of class CertUtil.
//     */
//    @Test
//    public void testLoadFromKeyStore() throws Exception {
//        System.out.println("loadFromKeyStore");
//        File storeFile = null;
//        String keyPassword = "";
//        String storeType = "";
//        HashMap<String, CertificateInKey> expResult = null;
//        HashMap<String, CertificateInKey> result = CertUtil.loadFromKeyStore(storeFile, keyPassword, storeType);
//        assertEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }

    /**
     * Test of exportToPem method, of class CertUtil.
     */
    @Test
    public void testExportToPem_Key_X509Certificate_JKS() throws Exception {
        System.out.println("exportToPem JKS");
        String storeFileName = CertUtilTest.class.getResource("/resources/server.keystore").getPath();
        HashMap<String, Map.Entry<Key, X509Certificate>> certMap = CertUtil.loadFromJKS(new File(storeFileName), "testca");
        for (String ailias : certMap.keySet()) {
            Map.Entry<Key, X509Certificate> cert = certMap.get(ailias);
            String result = CertUtil.exportToPem(cert.getKey(), cert.getValue());
            System.out.println(result);
        }
    }

    /**
     * Test of exportToPem method, of class CertUtil.
     */
    @Test
    public void testExportToPem_Key_X509Certificate_PKCS12() throws Exception {
        System.out.println("exportToPem PKCS12");
        String storeFileName = CertUtilTest.class.getResource("/resources/burpca.p12").getPath();
        HashMap<String, Map.Entry<Key, X509Certificate>> certMap = CertUtil.loadFromPKCS12(new File(storeFileName), "testca");
        for (String ailias : certMap.keySet()) {
            System.out.println("ailias:" + ailias);
            Map.Entry<Key, X509Certificate> cert = certMap.get(ailias);
            String result = CertUtil.exportToPem(cert.getKey(), cert.getValue());
            System.out.println(result);
        }
    }
    
    /**
     * Test of exportToPem method, of class CertUtil.
     */
    @Test
    public void testExportToPem_Key() throws Exception {
        System.out.println("exportToPem");
        String storeFileName = CertUtilTest.class.getResource("/resources/server.keystore").getPath();
        HashMap<String, Map.Entry<Key, X509Certificate>> certMap = CertUtil.loadFromJKS(new File(storeFileName), "testca");
        for (String ailias : certMap.keySet()) {
            Map.Entry<Key, X509Certificate> cert = certMap.get(ailias);
            PKCS8EncodedKeySpec pkcs8Key = new PKCS8EncodedKeySpec(cert.getKey().getEncoded());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(pkcs8Key);
        }        
    }

    @Test
    public void testPemToPrivateKey() throws Exception {
        System.out.println("pemToPrivateKey");
        String storeFileName = CertUtilTest.class.getResource("/resources/burpca.pem").getPath();
        PrivateKey priKey = CertUtil.pemToPrivateKey(Util.getRawStr(Util.bytesFromFile(new File(storeFileName))));
    }
    
    @Test
    public void testPemToCertificate() throws Exception {
        System.out.println("pemToCerficate");
        String storeFileName = CertUtilTest.class.getResource("/resources/burpca.pem").getPath();
        X509Certificate x509Cert = CertUtil.pemToCertificate(Util.getRawStr(Util.bytesFromFile(new File(storeFileName))));
    }

//
//    /**
//     * Test of exportToPem method, of class CertUtil.
//     */
//    @Test
//    public void testExportToPem_X509Certificate() throws Exception {
//        System.out.println("exportToPem");
//        X509Certificate x509cert = null;
//        String expResult = "";
//        String result = CertUtil.exportToPem(x509cert);
//        assertEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of exportToDer method, of class CertUtil.
//     */
//    @Test
//    public void testExportToDer_Key() throws Exception {
//        System.out.println("exportToDer");
//        Key privateKey = null;
//        String expResult = "";
//        String result = CertUtil.exportToDer(privateKey);
//        assertEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of exportToDer method, of class CertUtil.
//     */
//    @Test
//    public void testExportToDer_X509Certificate() throws Exception {
//        System.out.println("exportToDer");
//        X509Certificate x509cert = null;
//        String expResult = "";
//        String result = CertUtil.exportToDer(x509cert);
//        assertEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
    
}
