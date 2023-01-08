package extension.helpers;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.AbstractMap;
import java.util.Base64;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 * @author isayan
 */
public class CertUtil {
    private final static Pattern PEM_PKCS1_PRIVATE = Pattern.compile("-{2,}BEGIN RSA PRIVATE KEY-{2,}\n(.*?)-{2,}END RSA PRIVATE KEY-{2,}\n", Pattern.DOTALL);
    private final static Pattern PEM_PKCS8_PRIVATE = Pattern.compile("-{2,}BEGIN PRIVATE KEY-{2,}\n(.*?)-{2,}END PRIVATE KEY-{2,}\n", Pattern.DOTALL);
    private final static Pattern PEM_CERTIFICATE = Pattern.compile("-{2,}BEGIN CERTIFICATE-{2,}\n(.*?)-{2,}END CERTIFICATE-{2,}\n", Pattern.DOTALL);
    private final static Pattern PEM_PUBLIC = Pattern.compile("-{2,}BEGIN PUBLIC KEY-{2,}\n(.*?)-{2,}END PUBLIC KEY-{2,}\n", Pattern.DOTALL);

    // PKCS#1 format
    private final static String PEM_RSA_PRIVATE_START = "-----BEGIN RSA PRIVATE KEY-----";
    private final static String PEM_RSA_PRIVATE_END = "-----END RSA PRIVATE KEY-----";

    private final static String BEGIN_PRIVATE = "-----BEGIN PRIVATE KEY-----\n";
    private final static String END_PRIVATE = "-----END PRIVATE KEY-----\n";

    private final static String BEGIN_CERTIFICATE = "-----BEGIN CERTIFICATE-----\n";
    private final static String END_CERTIFICATE = "-----END CERTIFICATE-----\n";

    public static PrivateKey pemToPrivateKey(String pemData) throws UnsupportedEncodingException {
        pemData = pemData.replaceAll("\r\n", "\n");
        Matcher m = PEM_PKCS8_PRIVATE.matcher(pemData);
        if (m.find()) {
            try {
                String encoded = m.group(1);
                PKCS8EncodedKeySpec pkcs8Key = new PKCS8EncodedKeySpec(Base64.getMimeDecoder().decode(encoded));
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

    public static String exportToPem(Key privateKey, X509Certificate x509cert) throws UnsupportedEncodingException, CertificateEncodingException {
        StringBuilder pemCert = new StringBuilder();
        pemCert.append(exportToPem(privateKey));
        pemCert.append(exportToPem(x509cert));
        return pemCert.toString();
    }

    public static String exportToPem(Key privateKey) throws UnsupportedEncodingException {
        StringBuilder pemKey = new StringBuilder();
        byte[] derKey = privateKey.getEncoded();
        String pemKeyPre = ConvertUtil.newLine("\n", ConvertUtil.toBase64Encode(StringUtil.getBytesRawString(derKey), StandardCharsets.ISO_8859_1, true), 64);
        pemKey.append(BEGIN_PRIVATE);
        pemKey.append(pemKeyPre);
        pemKey.append("\n");
        pemKey.append(END_PRIVATE);
        return pemKey.toString();
    }

    public static String exportToPem(X509Certificate x509cert) throws UnsupportedEncodingException, CertificateEncodingException {
        StringBuilder pemCert = new StringBuilder();
        byte[] derCert = x509cert.getEncoded();
        String pemCertPre = ConvertUtil.newLine("\n", ConvertUtil.toBase64Encode(StringUtil.getBytesRawString(derCert), StandardCharsets.ISO_8859_1, true), 64);
        pemCert.append(BEGIN_CERTIFICATE);
        pemCert.append(pemCertPre);
        pemCert.append("\n");
        pemCert.append(END_CERTIFICATE);
        return pemCert.toString();
    }

    public static byte [] exportToDer(Key privateKey) throws CertificateEncodingException {
        return privateKey.getEncoded();
    }

    public static byte [] exportToDer(X509Certificate x509cert) throws CertificateEncodingException {
        return x509cert.getEncoded();
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

    public static PrivateKey loadPrivateKey(String pemData) throws GeneralSecurityException, IOException {
        Matcher m1 = PEM_PKCS1_PRIVATE.matcher(pemData);
        if (m1.find()) {
            // OpenSSL / PKCS#1 Base64 PEM encoded file
            String pemEncode = m1.group(1);
            return readPkcs1PrivateKey(Base64.getMimeDecoder().decode(pemEncode));
        }
        Matcher m8 = PEM_PKCS8_PRIVATE.matcher(pemData);
        if (m8.find()) {
            // PKCS#8 Base64 PEM encoded file
            String pemEncode = m8.group(1);
            return readPkcs8PrivateKey(Base64.getMimeDecoder().decode(pemEncode));
        }
        // We assume it's a PKCS#8 DER encoded binary file
        return readPkcs8PrivateKey(StringUtil.getBytesRaw(pemData));
    }

    public static PublicKey loadPublicKey(String pemData) throws GeneralSecurityException, IOException {
        Matcher mp = PEM_PUBLIC.matcher(pemData);
        if (mp.find()) {
            String pemEncode = mp.group(1);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(Base64.getMimeDecoder().decode(pemEncode));
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(spec);
        }
        X509EncodedKeySpec spec = new X509EncodedKeySpec(Base64.getMimeDecoder().decode(pemData));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    public static X509Certificate loadCertificate(String pemData) throws UnsupportedEncodingException {
        pemData = pemData.replaceAll("\r\n", "\n");
        Matcher m = PEM_CERTIFICATE.matcher(pemData);
        if (m.find()) {
            try {
                String encoded = m.group(1);
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(Base64.getMimeDecoder().decode(encoded)));
                return cert;
            } catch (CertificateException ex) {
                throw new UnsupportedEncodingException(ex.getMessage());
            }
        }
        throw new UnsupportedEncodingException("PEM format was not found");
    }


    private static PrivateKey readPkcs8PrivateKey(byte[] pkcs8Bytes) throws GeneralSecurityException {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA", "SunRsaSign");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8Bytes);
        try {
            return keyFactory.generatePrivate(keySpec);
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException("Unexpected key format!", e);
        }
    }

    private static PrivateKey readPkcs1PrivateKey(byte[] pkcs1Bytes) throws GeneralSecurityException {
        // We can't use Java internal APIs to parse ASN.1 structures, so we build a PKCS#8 key Java can understand
        int pkcs1Length = pkcs1Bytes.length;
        int totalLength = pkcs1Length + 22;
        byte[] pkcs8Header = new byte[]{
            (byte) 0x30, (byte) 0x82, (byte) ((totalLength >> 8) & 0xff), (byte) (totalLength & 0xff), // Sequence + total length
            (byte) 0x02, (byte) 0x01, (byte) 0x00, // Integer (0)
            (byte) 0x30, (byte) 0x0d, (byte) 0x06, (byte) 0x09, (byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0x86, (byte) 0xf7, (byte) 0x0d, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x05, (byte) 0x00, // Sequence: 1.2.840.113549.1.1.1, NULL
            (byte) 0x04, (byte) 0x82, (byte) ((pkcs1Length >> 8) & 0xff), (byte) (pkcs1Length & 0xff) // Octet string + length
        };
        byte[] pkcs8bytes = ConvertUtil.appandByte(pkcs8Header, pkcs1Bytes);
        return readPkcs8PrivateKey(pkcs8bytes);
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
