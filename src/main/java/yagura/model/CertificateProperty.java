package yagura.model;

import extension.burp.BurpConfig;
import extension.helpers.CertUtil;
import extension.helpers.CertUtil.StoreType;
import extension.helpers.ConvertUtil;
import extension.helpers.StringUtil;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author isayan
 */
public class CertificateProperty {

    private boolean selected = false;
    private StoreType storeType = StoreType.PKCS12;
    private byte[] clientCertificate = new byte[]{};
    private String clientCertificatePasswd = "";

    /**
     * @return the selected
     */
    public boolean isSelected() {
        return selected;
    }

    /**
     * @param selected the selected to set
     */
    public void setSelected(boolean selected) {
        this.selected = selected;
    }

    /**
     * @return the storeType
     */
    public StoreType getStoreType() {
        return storeType;
    }

    /**
     * @param storeType the storeType to set
     */
    public void setStoreType(StoreType storeType) {
        this.storeType = storeType;
    }

    /**
     * @return the clientCertificate
     */
    public byte[] getClientCertificate() {
        return clientCertificate;
    }

    /**
     * @param clientCertificate the clientCertificate to set
     */
    public void setClientCertificate(byte[] clientCertificate) {
        this.clientCertificate = clientCertificate;
    }

    /**
     * @return the clientCertificatePasswd
     */
    public String getClientCertificatePasswd() {
        return clientCertificatePasswd;
    }

    /**
     * @param clientCertificatePasswd the clientCertificatePasswd to set
     */
    public void setClientCertificatePasswd(String clientCertificatePasswd) {
        this.clientCertificatePasswd = clientCertificatePasswd;
    }

    public void setProperty(CertificateProperty prop) {
        this.setSelected(prop.isSelected());
        this.setStoreType(prop.getStoreType());
        this.setClientCertificate(prop.getClientCertificate());
        this.setClientCertificatePasswd(prop.getClientCertificatePasswd());
    }

    public static Object[] toObjects(CertificateProperty certProp) {
        String certCN = "";
        try {
            HashMap<String, Map.Entry<Key, X509Certificate>> mapCert = CertUtil.loadFromKeyStore(certProp.getClientCertificate(), certProp.getClientCertificatePasswd(), certProp.getStoreType());
            if (mapCert.entrySet().iterator().hasNext()) {
                Map.Entry<String, Map.Entry<Key, X509Certificate>> cert = mapCert.entrySet().iterator().next();
                certCN = cert.getValue().getValue().getSubjectX500Principal().getName();
            }
        } catch (IOException | KeyStoreException | CertificateException | NoSuchAlgorithmException | UnrecoverableKeyException ex) {
            Logger.getLogger(CertificateProperty.class.getName()).log(Level.SEVERE, null, ex);
        }

        Object[] beans = new Object[5];
        beans[0] = certProp.isSelected();
        beans[1] = certProp.getStoreType().name();
        beans[2] = ConvertUtil.toBase64Encode(StringUtil.getStringRaw(certProp.getClientCertificate()), StandardCharsets.ISO_8859_1);
        beans[3] = certProp.getClientCertificatePasswd();
        beans[4] = certCN;
        return beans;
    }

    public static CertificateProperty fromObjects(Object[] rows) {
        CertificateProperty cert = new CertificateProperty();
        cert.setSelected((Boolean) rows[0]);
        cert.setStoreType(CertUtil.StoreType.valueOf((String)rows[1]));
        cert.setClientCertificate(ConvertUtil.toBase64Decode((String)rows[2]));
        cert.setClientCertificatePasswd((String)rows[3]);
        return cert;
    }


}
