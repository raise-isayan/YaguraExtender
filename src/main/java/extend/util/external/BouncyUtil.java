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

    // https://github.com/bcgit/bc-java/tree/main/prov/src/main/java/org/bouncycastle/jcajce/provider/digest
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
        String digeststr = ConvertUtil.toHexString(md.digest(), upperCase);
        return digeststr;
    }

    /**
     * MD2値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toMD2Sum(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("MD2", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            return null;
        }
    }

    /**
     * MD2値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toMD2Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("MD2", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            return null;
        }
    }

    /**
     * MD2値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toMD2Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return toMD2Sum(StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * MD4値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toMD4Sum(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("MD4", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            return null;
        }
    }

    /**
     * MD4値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toMD4Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("MD4", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            return null;
        }
    }

    /**
     * MD4値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toMD4Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return toMD4Sum(StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * MD5値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toMD5Sum(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("MD5", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            return null;
        }
    }

    /**
     * MD5値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toMD5Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("MD5", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            return null;
        }
    }

    /**
     * MD5値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toMD5Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return toMD5Sum(StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * SHA1値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSHA1Sum(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("SHA1", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            return null;
        }
    }

    /**
     * SHA1値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSHA1Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("SHA1", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            return null;
        }
    }

    /**
     * SHA1値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toSHA1Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return toSHA1Sum(StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * SHA224値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSHA224Sum(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("SHA224", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            return null;
        }
    }

    /**
     * SHA224値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSHA224Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("SHA224", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            return null;
        }
    }

    /**
     * SHA224値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toSHA224Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return toSHA224Sum(StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * SHA256値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSHA256Sum(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("SHA256", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            return null;
        }
    }

    /**
     * SHA256値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSHA256Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("SHA256", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            return null;
        }
    }

    /**
     * SHA256値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toSHA256Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return toSHA256Sum(StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * SHA384値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSHA384Sum(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("SHA384", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            return null;
        }
    }

    /**
     * SHA384値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSHA384Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("SHA384", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            return null;
        }
    }

    /**
     * SHA384値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toSHA384Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return toSHA384Sum(StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * SHA512値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSHA512Sum(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("SHA512", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            return null;
        }
    }

    /**
     * SHA512値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSHA512Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("SHA512", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            return null;
        }
    }

    /**
     * SHA512値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toSHA512Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return toSHA512Sum(StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * SHA512-224値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSHA512_224Sum(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("SHA512/224", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            return null;
        }
    }

    /**
     * SHA512-224値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSHA512_224Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("SHA512/224", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            return null;
        }
    }

    /**
     * SHA512-224値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toSHA512_224Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return toSHA512_224Sum(StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * SHA512-256値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSHA512_256Sum(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("SHA512/256", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            return null;
        }
    }

    /**
     * SHA512-512値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSHA512_256Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("SHA512/256", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            return null;
        }
    }

    /**
     * SHA512-256値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toSHA512_256Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return toSHA512_256Sum(StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * SHA3-224値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSHA3_224Sum(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("SHA3-224", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            return null;
        }
    }

    /**
     * SHA3-224値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSHA3_224Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("SHA3-224", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            return null;
        }
    }

    /**
     * SHA3-224値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toSHA3_224Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return toSHA3_224Sum(StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * SHA3-256値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSHA3_256Sum(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("SHA3-256", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            return null;
        }
    }

    /**
     * SHA3-256値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSHA3_256Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("SHA3-256", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            return null;
        }
    }

    /**
     * SHA3-256値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toSHA3_256Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return toSHA3_256Sum(StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * SHA3-384値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSHA3_384Sum(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("SHA3-384", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            return null;
        }
    }

    /**
     * SHA3-384値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSHA3_384Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("SHA3-384", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            return null;
        }
    }

    /**
     * SHA3-384値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toSHA3_384Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return toSHA3_384Sum(StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * SHA3-512値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSHA3_512Sum(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("SHA3-512", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            return null;
        }
    }

    /**
     * SHA3-512値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSHA3_512Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("SHA3-512", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            return null;
        }
    }

    /**
     * SHA3-512値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toSHA3_512Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return toSHA3_512Sum(StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * SHAKE128値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSHAKE128Sum(byte[] binary, boolean upperCase) {
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
        return toSHAKE128Sum(StringUtil.getBytesCharset(str, charset), upperCase);
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
     * DSTU7564-256値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toDSTU7564_256Sum(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("DSTU7564-256", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * DSTU7564-256値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toDSTU7564_256Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("DSTU7564-256", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * DSTU7564-256値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toDSTU7564_256Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return toDSTU7564_256Sum(StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * DSTU7564-384値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toDSTU7564_384Sum(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("DSTU7564-384", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * DSTU7564-384値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toDSTU7564_384Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("DSTU7564-384", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * DSTU7564-384値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toDSTU7564_384Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return toDSTU7564_384Sum(StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * DSTU7564-512値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toDSTU7564_512Sum(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("DSTU7564-512", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * DSTU7564-512値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toDSTU7564_512Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("DSTU7564-512", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * DSTU7564-512値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toDSTU7564_512Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return toDSTU7564_512Sum(StringUtil.getBytesCharset(str, charset), upperCase);
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
     * GOST-3411値の取得
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
     * GOST-3411-2012-256値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toGOST3411_2012_256Sum(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("GOST-3411-2012-256", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * GOST-3411-2012-256値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toGOST3411_2012_256Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("GOST-3411-2012-256", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * GOST-3411-2012-256値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toGOST3411_2012_256Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return toGOST3411_2012_256Sum(StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * GOST-3411-2012-512値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toGOST3411_2012_512Sum(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("GOST-3411-2012-512", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * GOST-3411-2012-512値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toGOST3411_2012_512Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("GOST-3411-2012-512", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * GOST-3411-2012-512値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toGOST3411_2012_512Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return toGOST3411_2012_512Sum(StringUtil.getBytesCharset(str, charset), upperCase);
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
     * SM3値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSM3Sum(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("SM3", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * SM3値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSM3Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("SM3", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * SM3値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toSM3Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return toSM3Sum(StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * BLAKE2S-128値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toBLAKE2S_128Sum(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("BLAKE2S-128", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * BLAKE2S-128値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toBLAKE2S_128Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("BLAKE2S-128", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * BLAKE2S-128値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toBLAKE2S_128Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return toBLAKE2S_128Sum(StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * BLAKE2B-160値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toBLAKE2B_160Sum(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("BLAKE2B-160", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * BLAKE2B-160値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toBLAKE2B_160Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("BLAKE2B-160", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * BLAKE2B-160値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toBLAKE2B_160Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return toBLAKE2B_160Sum(StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * BLAKE2B-256値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toBLAKE2B_256Sum(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("BLAKE2B-256", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * BLAKE2B-256値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toBLAKE2B_256Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("BLAKE2B-256", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * BLAKE2B-256値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toBLAKE2B_256Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return toBLAKE2B_256Sum(StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * BLAKE2B-384値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toBLAKE2B_384Sum(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("BLAKE2B-384", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * BLAKE2B-384値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toBLAKE2B_384Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("BLAKE2B-384", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * BLAKE2B-384値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toBLAKE2B_384Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return toBLAKE2B_384Sum(StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * BLAKE2B-512値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toBLAKE2B_512Sum(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("BLAKE2B-512", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * BLAKE2B-512値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toBLAKE2B_512Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("BLAKE2B-512", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * BLAKE2B-512値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toBLAKE2B_512Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return toBLAKE2B_512Sum(StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * BLAKE2S-160値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toBLAKE2S_160Sum(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("BLAKE2S-160", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * BLAKE2S-160値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toBLAKE2S_160Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("BLAKE2S-160", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * BLAKE2S-160値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toBLAKE2S_160Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return toBLAKE2S_160Sum(StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * BLAKE2S-224値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toBLAKE2S_224Sum(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("BLAKE2S-224", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * BLAKE2S-224値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toBLAKE2S_224Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("BLAKE2S-224", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * BLAKE2S-224値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toBLAKE2S_224Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return toBLAKE2S_224Sum(StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * BLAKE2S-256値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toBLAKE2S_256Sum(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("BLAKE2S-256", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * BLAKE2S-256値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toBLAKE2S_256Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("BLAKE2S-256", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * BLAKE2S-256値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toBLAKE2S_256Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return toBLAKE2S_256Sum(StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * BLAKE3-256値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toBLAKE3_256Sum(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("BLAKE3-256", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * BLAKE3-256値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toBLAKE3_256Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("BLAKE3-256", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * BLAKE3-256値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toBLAKE3_256Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return toBLAKE3_256Sum(StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * HARAKA-256値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toHARAKA256Sum(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("HARAKA-256", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * HARAKA-256値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toHARAKA256Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("HARAKA-256", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * HARAKA-256値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toHARAKA256Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return toHARAKA256Sum(StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * HARAKA-512値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toHARAKA512Sum(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("HARAKA-512", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * HARAKA-512値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toHARAKA512Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("HARAKA-512", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * HARAKA-512値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toHARAKA512Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return toHARAKA512Sum(StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * KECCAK-224値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toKECCAK224Sum(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("KECCAK-224", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * KECCAK-224値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toKECCAK224Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("KECCAK-224", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * KECCAK-224値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toKECCAK224Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return toKECCAK224Sum(StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * KECCAK-256値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toKECCAK256Sum(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("KECCAK-256", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * KECCAK-256値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toKECCAK256Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("KECCAK-256", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * KECCAK-256値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toKECCAK256Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return toKECCAK256Sum(StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * KECCAK-288値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toKECCAK288Sum(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("KECCAK-288", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * KECCAK-288値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toKECCAK288Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("KECCAK-288", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * KECCAK-288値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toKECCAK288Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return toKECCAK288Sum(StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * KECCAK-384値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toKECCAK384Sum(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("KECCAK-384", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * KECCAK-384値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toKECCAK384Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("KECCAK-384", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * KECCAK-384値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toKECCAK384Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return toKECCAK384Sum(StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * KECCAK-512値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toKECCAK512Sum(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("KECCAK-512", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * KECCAK-512値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toKECCAK512Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("KECCAK-512", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * KECCAK-512値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toKECCAK512Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return toKECCAK512Sum(StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * SKEIN-256-128値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSKEIN256_128Sum(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("SKEIN-256-128", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * SKEIN-256-128値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSKEIN256_128Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("SKEIN-256-128", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * SKEIN-256-128値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toSKEIN256_128Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return toSKEIN256_128Sum(StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * SKEIN-256-160値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSKEIN256_160Sum(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("SKEIN-256-160", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * SKEIN-256-160値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSKEIN256_160Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("SKEIN-256-160", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * SKEIN-256-160値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toSKEIN256_160Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return toSKEIN256_160Sum(StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * SKEIN-256-224値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSKEIN256_224Sum(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("SKEIN-256-224", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * SKEIN-256-224値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSKEIN256_224Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("SKEIN-256-224", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * SKEIN-256-224値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toSKEIN256_224Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return toSKEIN256_224Sum(StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * SKEIN-256-256値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSKEIN256_256Sum(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("SKEIN-256-256", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * SKEIN-256-256値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSKEIN256_256Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("SKEIN-256-256", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * SKEIN-256-256値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toSKEIN256_256Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return toSKEIN256_256Sum(StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * SKEIN-512-128値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSKEIN512_128Sum(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("SKEIN-512-128", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * SKEIN-512-128値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSKEIN512_128Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("SKEIN-512-128", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * SKEIN-512-128値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toSKEIN512_128Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return toSKEIN512_128Sum(StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * SKEIN-512-160値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSKEIN512_160Sum(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("SKEIN-512-160", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * SKEIN-512-160値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSKEIN512_160Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("SKEIN-512-160", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * SKEIN-512-160値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toSKEIN512_160Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return toSKEIN512_160Sum(StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * SKEIN-512-224値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSKEIN512_224Sum(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("SKEIN-512-224", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * SKEIN-512-224値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSKEIN512_224Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("SKEIN-512-224", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * SKEIN-512-224値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toSKEIN512_224Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return toSKEIN512_224Sum(StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * SKEIN-512-256値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSKEIN512_256Sum(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("SKEIN-512-256", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * SKEIN-512-256値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSKEIN512_256Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("SKEIN-512-256", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * SKEIN-512-256値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toSKEIN512_256Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return toSKEIN512_256Sum(StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * SKEIN-512-384値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSKEIN512_384Sum(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("SKEIN-512-384", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * SKEIN-512-384値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSKEIN512_384Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("SKEIN-512-384", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * SKEIN-512-384値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toSKEIN512_384Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return toSKEIN512_384Sum(StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * SKEIN-512-512値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSKEIN512_512Sum(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("SKEIN-512-512", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * SKEIN-512-512値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSKEIN512_512Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("SKEIN-512-512", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * SKEIN-256-512値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toSKEIN512_512Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return toSKEIN512_512Sum(StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * SKEIN-1024-384値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSKEIN1024_384Sum(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("SKEIN-1024-384", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * SKEIN-1024-384値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSKEIN1024_384Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("SKEIN-1024-384", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * SKEIN-1024-384値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toSKEIN1024_384Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return toSKEIN1024_384Sum(StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * SKEIN-1024-512値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSKEIN1024_512Sum(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("SKEIN-1024-512", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * SKEIN-1024-512値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSKEIN1024_512Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("SKEIN-1024-512", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * SKEIN-1024-512値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toSKEIN1024_512Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return toSKEIN1024_512Sum(StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * SKEIN-1024-1024値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSKEIN1024_1024Sum(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("SKEIN-1024-1024", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * SKEIN-1024-1024値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSKEIN1024_1024Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("SKEIN-1024-1024", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * SKEIN-1024-1024値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toSKEIN1024_1024Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return toSKEIN1024_1024Sum(StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * PARALLELHASH128-256値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toPARALLELHASH128_256Sum(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("PARALLELHASH128-256", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * PARALLELHASH128-256値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toPARALLELHASH128_256Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("PARALLELHASH128-256", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * PARALLELHASH128-256値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toPARALLELHASH128_256Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return toPARALLELHASH128_256Sum(StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * PARALLELHASH128-512値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toPARALLELHASH256_512Sum(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("PARALLELHASH256-512", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * PARALLELHASH128-512値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toPARALLELHASH256_512Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("PARALLELHASH256-512", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * PARALLELHASH128-512値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toPARALLELHASH256_512Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return BouncyUtil.toPARALLELHASH256_512Sum(StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * TUPLEHASH128-256値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toTUPLEHASH128_256Sum(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("TUPLEHASH128-256", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * TUPLEHASH128-256値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toTUPLEHASH128_256Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("TUPLEHASH128-256", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * TUPLEHASH128-256値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toTUPLEHASH128_256Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return BouncyUtil.toTUPLEHASH128_256Sum(StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * TUPLEHASH256-512値の取得
     *
     * @param binary 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toTUPLEHASH256_512Sum(byte[] binary, boolean upperCase) {
        try {
            return toMessageDigest("TUPLEHASH256-512", binary, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * TUPLEHASH256-512値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toTUPLEHASH256_512Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("TUPLEHASH256-512", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * TUPLEHASH256-512値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toTUPLEHASH256_512Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        return BouncyUtil.toTUPLEHASH256_512Sum(StringUtil.getBytesCharset(str, charset), upperCase);
    }

    // https://github.com/bcgit/bc-java/tree/main/core/src/test/java/org/bouncycastle/crypto/test
    /**
     * 証明書 https://gist.github.com/vivekkr12/c74f7ee08593a8c606ed96f4b62a208a
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
