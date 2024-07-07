package extend.util.external;

import extension.helpers.CertUtil;
import extension.helpers.ConvertUtil;
import extension.helpers.DateUtil;
import extension.helpers.StringUtil;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.cert.Certificate;
import java.security.Key;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.AbstractMap;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;

/**
 *
 * @author isayan
 */
public class BouncyUtil {

    private final static Logger logger = Logger.getLogger(BouncyUtil.class.getName());

    private final static BouncyCastleProvider BC_PROVIDER_INSTANCE = new BouncyCastleProvider();

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BC_PROVIDER_INSTANCE);
        }
    }

    public static Map.Entry<Key, X509Certificate> loadFromPem(File storeFile, String password) {
        try {
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            PemReader pemParser = new PemReader(new FileReader(storeFile));
            PemObject pemObject = pemParser.readPemObject();
            PrivateKey privateKey = null;
            X509Certificate x509Certificate = null;
            while (pemObject != null) {
                if ("TYPE_CERTIFICATE".equals(pemObject.getType())) {
                    byte cert[] = pemObject.getContent();
                    try (ByteArrayInputStream inStream = new ByteArrayInputStream(cert)) {
                        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
                        Certificate certificate = certificateFactory.generateCertificate(inStream);
                        x509Certificate = (X509Certificate) certificate;
                    }
                } else {
                    PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(pemObject);
                    privateKey = converter.getPrivateKey(privateKeyInfo);
                }
                pemObject = pemParser.readPemObject();
            }
            return new AbstractMap.SimpleEntry(privateKey, x509Certificate);
        } catch (IOException | CertificateException | NoSuchProviderException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    public static void storeCertificatePem(Key key, File to) throws IOException {
        try (JcaPEMWriter pw = new JcaPEMWriter(new FileWriter(to))) {
            pw.writeObject(key);
        }
    }

    public static void storeCertificatePem(Certificate cert, File to) throws IOException {
        try (JcaPEMWriter pw = new JcaPEMWriter(new FileWriter(to))) {
            pw.writeObject(cert);
        }
    }

    public static void storeCertificatePem(Key key, Certificate cert, File to) throws IOException {
        try (JcaPEMWriter pw = new JcaPEMWriter(new FileWriter(to))) {
            pw.writeObject(key);
            pw.writeObject(cert);
        }
    }

    public static String exportCertificatePem(Certificate cert) throws IOException {
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter pw = new JcaPEMWriter(sw)) {
            pw.writeObject(cert);
        }
        return sw.toString();
    }

    public static String exportCertificatePem(Key key, Certificate cert) throws IOException {
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter pw = new JcaPEMWriter(sw)) {
            pw.writeObject(key);
            pw.writeObject(cert);
        }
        return sw.toString();
    }

    public static void storeCertificateDer(Key key, File to) throws IOException {
        byte[] keyBytes = key.getEncoded();
        try (FileOutputStream fos = new FileOutputStream(to)) {
            fos.write(keyBytes);
        }
    }

    public static void storeCertificateDer(Certificate cert, File to) throws IOException {
        try {
            byte[] certBytes = cert.getEncoded();
            try (FileOutputStream fos = new FileOutputStream(to)) {
                fos.write(certBytes);
            }
        } catch (CertificateEncodingException ex) {
            throw new IOException(ex);
        }
    }

    public static byte[] exportPrivateKeyDer(Key key) throws IOException {
        return key.getEncoded();
    }

    public static byte[] exportCertificateDer(Certificate cert) throws IOException {
        try {
            return cert.getEncoded();
        } catch (CertificateEncodingException ex) {
            throw new IOException(ex);
        }
    }

    public static String getSubjectCN(byte[] storeData, String storePassword) throws IOException {
        HashMap<String, Map.Entry<Key, X509Certificate>> certMap = CertUtil.loadFromPKCS12(storeData, storePassword);
        for (String key : certMap.keySet()) {
            Map.Entry<Key, X509Certificate> cert = certMap.get(key);
            return cert.getValue().getSubjectX500Principal().getName();
        }
        return null;
    }

    // https://github.com/rtyley/test-bc-java-cvsimport/blob/master/crypto/test/src/org/bouncycastle/jce/provider/test/DigestTest.java
    /**
     * ハッシュ値の取得
     *
     * @param algorithm
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     * @throws java.security.NoSuchAlgorithmException
     */
    public static String toMessageDigest(String algorithm, String str, Charset charset, boolean upperCase)
            throws NoSuchAlgorithmException {
        return toMessageDigest(algorithm, StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * ハッシュ値の取得
     *
     * @param algorithm
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     * @throws java.security.NoSuchAlgorithmException
     */
    public static String toMessageDigest(String algorithm, String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException, NoSuchAlgorithmException {
        return toMessageDigest(algorithm, StringUtil.getBytesCharset(str, charset), upperCase);
    }

    public static String toMessageDigest(String algorithm, byte[] binary, boolean upperCase)
            throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(algorithm, BC_PROVIDER_INSTANCE);
        md.reset();
        md.update(binary);
        String digeststr = ConvertUtil.toHexString(md.digest());
        if (upperCase) {
            return digeststr;
        } else {
            return digeststr.toLowerCase();
        }
    }

    /**
     * SHAKE128値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSHAKE128um(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("SHAKE128", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * SHAKE128値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSHAKE128Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("SHAKE128", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * SHAKE128値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toSHAKE128Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return toSHAKE128um(StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * SHAKE256値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSHAKE256um(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("SHAKE256", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * SHAKE256値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSHAKE256um(String str, boolean upperCase) {
        try {
            return toMessageDigest("SHAKE256", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * SHAKE256値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toSHAKE256um(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return toSHAKE256um(StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * RIPEMD128値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toRIPEMD128Sum(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("RIPEMD128", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * RIPEMD128値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toRIPEMD128Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("RIPEMD128", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * RIPEMD128値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toRIPEMD128Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return toRIPEMD128Sum(StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * RIPEMD160値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toRIPEMD160Sum(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("RIPEMD160", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * RIPEMD160値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toRIPEMD160Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("RIPEMD160", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * RIPEMD160値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toRIPEMD160Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return toRIPEMD160Sum(StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * RIPEMD256値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toRIPEMD256Sum(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("RIPEMD256", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * RIPEMD256値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toRIPEMD256Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("RIPEMD256", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * RIPEMD256値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toRIPEMD256Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return toRIPEMD256Sum(StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * RIPEMD160値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toRIPEMD320Sum(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("RIPEMD320", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * RIPEMD320値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toRIPEMD320Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("RIPEMD320", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * RIPEMD320値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toRIPEMD320Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return toRIPEMD320Sum(StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * Tiger値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toTigerSum(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("Tiger", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * Tiger値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toTigerSum(String str, boolean upperCase) {
        try {
            return toMessageDigest("Tiger", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * Tiger値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toTigerSum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return toTigerSum(StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * GOST3411値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toGOST3411Sum(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("GOST3411", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * GOST3411値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toGOST3411Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("GOST3411", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * GOST3411値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toGOST3411Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return toGOST3411Sum(StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * WHIRLPOOL値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toWHIRLPOOLSum(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("WHIRLPOOL", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * WHIRLPOOL値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toWHIRLPOOLSum(String str, boolean upperCase) {
        try {
            return toMessageDigest("WHIRLPOOL", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * WHIRLPOOL値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toWHIRLPOOLSum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return toWHIRLPOOLSum(StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * https://gist.github.com/vivekkr12/c74f7ee08593a8c606ed96f4b62a208a
     * https://magnus-k-karlsson.blogspot.com/2020/03/creating-x509-certificate-with-bouncy.html
     */
    private static final String BC_PROVIDER = "BC";
    private static final String KEY_ALGORITHM = "RSA";
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

    public static X509Certificate createRootCA(KeyPair rootKeyPair, org.bouncycastle.asn1.x500.X500Name rootCertSubject, int numberOfYears) throws CertificateException {
        try {
            BigInteger rootSerialNum = BigInteger.valueOf(System.currentTimeMillis());
            ContentSigner rootCertContentSigner = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(BC_PROVIDER).build(rootKeyPair.getPrivate());
            long now = System.currentTimeMillis();
            Date startDate = new Date(now - DateUtil.TOTAL_DAY_TIME_MILLIS);
            Date endDate = new Date(now + (long) (numberOfYears * 365L * DateUtil.TOTAL_DAY_TIME_MILLIS));
            X509v3CertificateBuilder rootCertBuilder = new JcaX509v3CertificateBuilder(rootCertSubject, rootSerialNum, startDate, endDate, rootCertSubject, rootKeyPair.getPublic());

            // Add Extensions
            // A BasicConstraint to mark root certificate as CA certificate
            JcaX509ExtensionUtils rootCertExtUtils = new JcaX509ExtensionUtils();
            rootCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            rootCertBuilder.addExtension(Extension.subjectKeyIdentifier, false, rootCertExtUtils.createSubjectKeyIdentifier(rootKeyPair.getPublic()));

            // Create a cert holder and export to X509Certificate
            X509CertificateHolder rootCertHolder = rootCertBuilder.build(rootCertContentSigner);
            X509Certificate rootCert = new JcaX509CertificateConverter().setProvider(BC_PROVIDER).getCertificate(rootCertHolder);
            return rootCert;
        } catch (OperatorCreationException | NoSuchAlgorithmException | CertIOException ex) {
            throw new CertificateException(ex);
        }
    }

    public static X509Certificate issueSignCert(PrivateKey caPrivateKey, X509Certificate caCert, KeyPair keyPair, String hostname, int numberOfYears) throws CertificateException {
        return issueSignCert(caPrivateKey, caCert, keyPair, hostname, new String[]{hostname}, numberOfYears);
    }

    public static X509Certificate issueSignCert(PrivateKey caPrivateKey, X509Certificate caCert, KeyPair keyPair, String subjectCN, String[] hostnames, int numberOfYears) throws CertificateException {
        try {
            long now = System.currentTimeMillis();
            Date startDate = new Date(now - DateUtil.TOTAL_DAY_TIME_MILLIS);
            Date endDate = new Date(now + (long) (numberOfYears * 365L * DateUtil.TOTAL_DAY_TIME_MILLIS));
            // Generate a new KeyPair and sign it using the Root Cert Private Key
            // by generating a CSR (Certificate Signing Request)
            BigInteger issuedCertSerialNum = BigInteger.valueOf(System.currentTimeMillis());;

            org.bouncycastle.asn1.x500.X500Name issueName = new org.bouncycastle.asn1.x500.X500Name(caCert.getIssuerX500Principal().getName());
            org.bouncycastle.asn1.x500.X500NameBuilder subjectDN = new org.bouncycastle.asn1.x500.X500NameBuilder();

            for (RDN rdn : issueName.getRDNs()) {
                if (rdn.getFirst().getType().equals(BCStyle.CN)) {
                    subjectDN.addRDN(BCStyle.CN, subjectCN);
                } else {
                    subjectDN.addRDN(rdn.getFirst().getType(), rdn.getFirst().getValue());
                }
            }
            PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(subjectDN.build(), caCert.getPublicKey());
            JcaContentSignerBuilder csrBuilder = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(BC_PROVIDER);

            // Sign the new KeyPair with the root cert Private Key
            ContentSigner csrContentSigner = csrBuilder.build(caPrivateKey);
            PKCS10CertificationRequest csr = p10Builder.build(csrContentSigner);

            // Use the Signed KeyPair and CSR to generate an issued Certificate
            // Here serial number is randomly generated. In general, CAs use
            // a sequence to generate Serial number and avoid collisions
            X509v3CertificateBuilder issuedCertBuilder = new X509v3CertificateBuilder(subjectDN.build(), issuedCertSerialNum, startDate, endDate, csr.getSubject(), csr.getSubjectPublicKeyInfo());

            JcaX509ExtensionUtils issuedCertExtUtils = new JcaX509ExtensionUtils();

            // Add Extensions
            // Use BasicConstraints to say that this Cert is not a CA
            issuedCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

            // Add Issuer cert identifier as Extension
            issuedCertBuilder.addExtension(Extension.authorityKeyIdentifier, false, issuedCertExtUtils.createAuthorityKeyIdentifier(caCert));
            issuedCertBuilder.addExtension(Extension.subjectKeyIdentifier, false, issuedCertExtUtils.createSubjectKeyIdentifier(csr.getSubjectPublicKeyInfo()));

            // Add intended key usage extension if needed
            issuedCertBuilder.addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.keyEncipherment));

            // Add DNS name is cert is to used for SSL
            GeneralName[] generalNames = new GeneralName[hostnames.length];
            for (int i = 0; i < hostnames.length; ++i) {
                generalNames[i] = new GeneralName(GeneralName.dNSName, hostnames[i]);
            }
            issuedCertBuilder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(generalNames));

            X509CertificateHolder issuedCertHolder = issuedCertBuilder.build(csrContentSigner);
            X509Certificate issuedCert = new JcaX509CertificateConverter().setProvider(BC_PROVIDER).getCertificate(issuedCertHolder);

            // Verify the issued cert signature against the root (issuer) cert
            issuedCert.verify(caCert.getPublicKey(), BC_PROVIDER);

            return issuedCert;
        } catch (OperatorCreationException | NoSuchAlgorithmException | CertIOException | InvalidKeyException | NoSuchProviderException | SignatureException ex) {
            throw new CertificateException(ex);
        }
    }

    protected static byte[] generateSig(ContentSigner signer, ASN1Object tbsObj) throws IOException {
        try (OutputStream sOut = signer.getOutputStream()) {
            tbsObj.encodeTo(sOut, ASN1Encoding.DER);
        }
        return signer.getSignature();
    }

    protected static org.bouncycastle.asn1.x509.Certificate generateStructure(TBSCertificate tbsCert, AlgorithmIdentifier sigAlgId, byte[] signature) {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(tbsCert);
        v.add(sigAlgId);
        v.add(new DERBitString(signature));
        return org.bouncycastle.asn1.x509.Certificate.getInstance(new DERSequence(v));
    }

}
