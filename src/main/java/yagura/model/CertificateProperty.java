package yagura.model;

import extension.helpers.CertUtil.StoreType;

/**
 *
 * @author isayan
 */
public class CertificateProperty {

    private boolean useClientCertificate = false;
    private StoreType storeType = StoreType.PKCS12;
    private byte[] clientCertificate = new byte[]{};
    private String clientCertificatePasswd = "";

    /**
     * @return the useClientCertificate
     */
    public boolean isUseClientCertificate() {
        return useClientCertificate;
    }

    /**
     * @param useClientCertificate the useClientCertificate to set
     */
    public void setUseClientCertificate(boolean useClientCertificate) {
        this.useClientCertificate = useClientCertificate;
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
        this.setUseClientCertificate(prop.isUseClientCertificate());
        this.setStoreType(prop.getStoreType());
        this.setClientCertificate(prop.getClientCertificate());
        this.setClientCertificatePasswd(prop.getClientCertificatePasswd());
    }

}
