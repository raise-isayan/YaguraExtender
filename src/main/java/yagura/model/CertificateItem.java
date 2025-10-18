package yagura.model;

import com.google.gson.annotations.Expose;
import extension.helpers.CertUtil;
import extension.helpers.CertUtil.StoreType;
import extension.helpers.ConvertUtil;
import extension.helpers.StringUtil;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author isayan
 */
public class CertificateItem {

    private final static Logger logger = Logger.getLogger(CertificateItem.class.getName());

    @Expose
    private boolean selected = false;

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

    @Expose
    private StoreType storeType = StoreType.PKCS12;

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

    @Expose
    private byte[] clientCertificate = new byte[]{};

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

    @Expose
    private String clientCertificatePasswd = "";

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


    public void setProperty(CertificateItem prop) {
        this.setSelected(prop.isSelected());
        this.setStoreType(prop.getStoreType());
        this.setClientCertificate(prop.getClientCertificate());
        this.setClientCertificatePasswd(prop.getClientCertificatePasswd());
    }

    public Properties getProperties() {
        Properties prop = new Properties();
        prop.setProperty("useClientCertificate", StringUtil.toString(this.isSelected()));
        if (this.isSelected()) {
            prop.setProperty("clientCertificateStoreType", this.getStoreType().name());
            prop.setProperty("clientCertificate", ConvertUtil.toBase64Encode(StringUtil.getStringRaw(this.getClientCertificate()), StandardCharsets.ISO_8859_1));
            prop.setProperty("clientCertificatePasswd", this.getClientCertificatePasswd());
        }
        return prop;
    }

    public void setProperties(Properties prop) {
        this.setSelected(Boolean.parseBoolean(prop.getProperty("useClientCertificate")));
        if (this.isSelected()) {
            this.setStoreType(CertUtil.StoreType.valueOf(prop.getProperty("clientCertificateStoreType")));
            this.setClientCertificate(ConvertUtil.toBase64Decode(prop.getProperty("clientCertificate")));
            this.setClientCertificatePasswd(prop.getProperty("clientCertificatePasswd"));
        }
    }

    public static Object[] toObjects(CertificateItem certProp) {
        String certCN = "";
        try {
            X509Certificate cert = CertUtil.loadCertificate(certProp.getClientCertificate());
            certCN = CertUtil.getSubjectName(cert);
        } catch (CertificateException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        Object[] beans = new Object[5];
        beans[0] = certProp.isSelected();
        beans[1] = certProp.getStoreType().name();
        beans[2] = ConvertUtil.toBase64Encode(StringUtil.getStringRaw(certProp.getClientCertificate()), StandardCharsets.ISO_8859_1);
        beans[3] = certProp.getClientCertificatePasswd();
        beans[4] = certCN;
        return beans;
    }

    public static CertificateItem fromObjects(Object[] rows) {
        CertificateItem cert = new CertificateItem();
        cert.setSelected((Boolean) rows[0]);
        cert.setStoreType(CertUtil.StoreType.valueOf((String) rows[1]));
        cert.setClientCertificate(ConvertUtil.toBase64Decode((String) rows[2]));
        cert.setClientCertificatePasswd((String) rows[3]);
        return cert;
    }

}
