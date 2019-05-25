package extend.util.external;

import extend.util.ConvertUtil;
import extend.util.Util;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.AbstractMap;
import java.util.Base64;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import sun.security.util.DerInputStream;
import sun.security.util.DerValue;

/**
 *
 * @author isayan
 */
public class CertUtil {

    private final static Pattern PEM_PRIVATE = Pattern.compile("-{2,}BEGIN PRIVATE KEY-{2,}\n(.*?)-{2,}END PRIVATE KEY-{2,}\n", Pattern.DOTALL);
    private final static Pattern PEM_CERTIFICATE = Pattern.compile("-{2,}BEGIN CERTIFICATE-{2,}\n(.*?)-{2,}END CERTIFICATE-{2,}\n", Pattern.DOTALL);
    private final static Pattern PEM_PUBLIC = Pattern.compile("-{2,}BEGIN PUBLIC KEY-{2,}\n(.*?)-{2,}END PUBLIC KEY-{2,}\n", Pattern.DOTALL);

    // PKCS#1 format
    private final static String PEM_RSA_PRIVATE_START = "-----BEGIN RSA PRIVATE KEY-----";
    private final static String PEM_RSA_PRIVATE_END = "-----END RSA PRIVATE KEY-----";

    private final static String BEGIN_PRIVATE = "-----BEGIN PRIVATE KEY-----\n";
    private final static String END_PRIVATE = "-----END PRIVATE KEY-----\n";

    private final static String BEGIN_CERTIFICATE = "-----BEGIN CERTIFICATE-----\n";
    private final static String END_CERTIFICATE = "-----END CERTIFICATE-----\n";

    public static PrivateKey pemToPrivateKey(String pem) throws UnsupportedEncodingException {
        pem = pem.replaceAll("\r\n", "\n");
        Matcher m = PEM_PRIVATE.matcher(pem);
        if (m.find()) {
            try {
                String encoded = m.group(1);
                encoded = encoded.replaceAll("\\s", "");
                PKCS8EncodedKeySpec pkcs8Key = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(encoded));
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                PrivateKey privateKey = keyFactory.generatePrivate(pkcs8Key);
                return privateKey;
            } catch (NoSuchAlgorithmException ex) {
                throw new UnsupportedEncodingException(ex.getMessage());
            } catch (InvalidKeySpecException ex) {
                throw new UnsupportedEncodingException(ex.getMessage());
            }
        }
        throw new UnsupportedEncodingException("PEM format was not found");
    }

    public static X509Certificate pemToCertificate(String pem) throws UnsupportedEncodingException {
        pem = pem.replaceAll("\r\n", "\n");
        Matcher m = PEM_CERTIFICATE.matcher(pem);
        if (m.find()) {
            try {
                String encoded = m.group(1);
                encoded = encoded.replaceAll("[\n]", "");
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509Certificate cert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(encoded)));
                return cert;
            } catch (CertificateException ex) {
                throw new UnsupportedEncodingException(ex.getMessage());
            }
        }
        throw new UnsupportedEncodingException("PEM format was not found");
    }
    
    public static String exportToPem(Key privateKey, X509Certificate x509cert) throws UnsupportedEncodingException, CertificateEncodingException {
        StringBuilder pemCert = new StringBuilder();
        pemCert.append(exportToPem(privateKey));
        pemCert.append(exportToPem(x509cert));
        return pemCert.toString();
    }

    public static String exportToPem(Key privateKey) throws UnsupportedEncodingException {
        StringBuilder pemKey = new StringBuilder();
        byte[] derKey = privateKey.getEncoded();
        String pemKeyPre = TransUtil.newLine("\n", ConvertUtil.toBase64Encode(Util.getRawStr(derKey), StandardCharsets.ISO_8859_1, true), 64);
        pemKey.append(BEGIN_PRIVATE);
        pemKey.append(pemKeyPre);
        pemKey.append("\n");
        pemKey.append(END_PRIVATE);
        return pemKey.toString();
    }

    public static String exportToPem(X509Certificate x509cert) throws UnsupportedEncodingException, CertificateEncodingException {
        StringBuilder pemCert = new StringBuilder();
        byte[] derCert = x509cert.getEncoded();
        String pemCertPre = TransUtil.newLine("\n", ConvertUtil.toBase64Encode(Util.getRawStr(derCert), StandardCharsets.ISO_8859_1, true), 64);
        pemCert.append(BEGIN_CERTIFICATE);
        pemCert.append(pemCertPre);
        pemCert.append("\n");
        pemCert.append(END_CERTIFICATE);
        return pemCert.toString();
    }

    public static String exportToDer(Key privateKey) throws CertificateEncodingException {
        byte[] derKey = privateKey.getEncoded();
        return Util.getRawStr(derKey);
    }

    public static String exportToDer(X509Certificate x509cert) throws CertificateEncodingException {
        byte[] derCert = x509cert.getEncoded();
        return Util.getRawStr(derCert);
    }

    protected static HashMap<String, Map.Entry<Key, X509Certificate>> loadFromKeyStore(File storeFile, String keyPassword, String storeType) throws CertificateEncodingException, IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        HashMap<String, Map.Entry<Key, X509Certificate>> certMap = new HashMap<>();
        KeyStore ks = KeyStore.getInstance(storeType);
        ks.load(new FileInputStream(storeFile), keyPassword.toCharArray());
        Enumeration e = ks.aliases();
        while (e.hasMoreElements()) {
            String alias = (String) e.nextElement();
            Key key = ks.getKey(alias, keyPassword.toCharArray());
            X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
            certMap.put(alias, new AbstractMap.SimpleEntry<>(key, cert));
        }
        return certMap;
    }

    public static HashMap<String, Map.Entry<Key, X509Certificate>> loadFromPKCS12(File storeFile, String password) throws CertificateEncodingException, IOException, UnrecoverableKeyException {
        try {
            return loadFromKeyStore(storeFile, password, "pkcs12");
        } catch (KeyStoreException ex) {
        } catch (CertificateException ex) {
        } catch (NoSuchAlgorithmException ex) {
        }
        return null;
    }

    public static HashMap<String, Map.Entry<Key, X509Certificate>> loadFromJKS(File storeFile, String password) throws CertificateEncodingException, IOException, UnrecoverableKeyException {
        try {
            return loadFromKeyStore(storeFile, password, "jks");
        } catch (KeyStoreException ex) {
        } catch (CertificateException ex) {
        } catch (NoSuchAlgorithmException ex) {
        }
        return null;
    }

    public static String getFirstAlias(KeyStore ks) throws KeyStoreException {
        String alias = null;
        // 最初にみつかったalias
        if (alias == null) {
            Enumeration<String> e = ks.aliases();
            while (e.hasMoreElements()) {
                alias = e.nextElement();
                break;
            }
        }
        return alias;
    }

}
