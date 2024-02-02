package extend.util.external;

import extension.helpers.CertUtil;
import extension.helpers.ConvertUtil;
import extension.helpers.StringUtil;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.AbstractMap;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.io.pem.PemObject;

/**
 *
 * @author isayan
 */
public class BouncyUtil {

    private final static BouncyCastleProvider BC_PROVIDER = new BouncyCastleProvider();

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BC_PROVIDER);
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
        String digeststr = "";
        MessageDigest md = MessageDigest.getInstance(algorithm, BC_PROVIDER);
        md.reset();
        md.update(binary);
        digeststr = ConvertUtil.toHexString(md.digest());
        if (upperCase) {
            return digeststr;
        } else {
            return digeststr.toLowerCase();
        }
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
            return null;
        }
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
            return null;
        }
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
            return null;
        }
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
            return null;
        }
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
            return null;
        }
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
            return null;
        }
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
            return null;
        }
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
            return null;
        }
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
            return null;
        }
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
            return null;
        }
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
            return null;
        }
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
            return null;
        }
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
            return null;
        }
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
            return null;
        }
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

}
