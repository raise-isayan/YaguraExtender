package yagura.model;

import extension.helpers.CertUtil;
import extension.helpers.ConvertUtil;
import extension.helpers.StringUtil;
import java.net.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.Properties;

/**
 *
 * @author isayan
 */
public class HttpExtendProperty {

    public enum HttpClientType {
        BURP, CUSTOM
    };

    public enum AuthorizationType {
        NONE, BASIC, DIGEST
    };

    private HttpClientType httpClientType = HttpClientType.BURP;

    private AuthorizationType authorizationType = AuthorizationType.NONE;
    private String authorizationUser = "";
    private String authorizationPasswd = "";

    private Proxy.Type proxyProtocol = Proxy.Type.DIRECT;
    private String proxyHost = "";
    private int proxyPort = 8080;
    private String proxyUser = "";
    private String proxyPasswd = "";

    private final CertificateProperty clientCertificate = new CertificateProperty();

    private boolean ignoreValidateCertification = true;

    /**
     * @return the useClientCertificate
     */
    public boolean isUseClientCertificate() {
        return this.clientCertificate.isSelected();
    }

    /**
     * @param useClientCertificate the useClientCertificate to set
     */
    public void setUseClientCertificate(boolean useClientCertificate) {
        this.clientCertificate.setSelected(useClientCertificate);
    }

    /**
     * @return the storeType
     */
    public CertUtil.StoreType getClientCertificateStoreType() {
        return this.clientCertificate.getStoreType();
    }

    /**
     * @param storeType the storeType to set
     */
    public void setClientCertificateStoreType(CertUtil.StoreType storeType) {
        this.clientCertificate.setStoreType(storeType);
    }

    /**
     * @return the clientCertificate
     */
    public byte[] getClientCertificate() {
        return this.clientCertificate.getClientCertificate();
    }

    /**
     * @param clientCertificate the clientCertificate to set
     */
    public void setClientCertificate(byte[] clientCertificate) {
        this.clientCertificate.setClientCertificate(clientCertificate);
    }

    /**
     * @return the clientCertificatePasswd
     */
    public String getClientCertificatePasswd() {
        return this.clientCertificate.getClientCertificatePasswd();
    }

    /**
     * @param clientCertificatePasswd the clientCertificatePasswd to set
     */
    public void setClientCertificatePasswd(String clientCertificatePasswd) {
        this.clientCertificate.setClientCertificatePasswd(clientCertificatePasswd);
    }

    /**
     * @return the httpClientType
     */
    public HttpClientType getHttpClientType() {
        return httpClientType;
    }

    /**
     * @param httpClientType the httpClientType to set
     */
    public void setHttpClientType(HttpClientType httpClientType) {
        this.httpClientType = httpClientType;
    }

    /**
     * @return the authorizationType
     */
    public AuthorizationType getAuthorizationType() {
        return authorizationType;
    }

    /**
     * @param authorizationType the authorizationType to set
     */
    public void setAuthorizationType(AuthorizationType authorizationType) {
        this.authorizationType = authorizationType;
    }

    /**
     * @return the authorizationUser
     */
    public String getAuthorizationUser() {
        return authorizationUser;
    }

    /**
     * @param authorizationUser the authorizationUser to set
     */
    public void setAuthorizationUser(String authorizationUser) {
        this.authorizationUser = authorizationUser;
    }

    /**
     * @return the authorizationPasswd
     */
    public String getAuthorizationPasswd() {
        return authorizationPasswd;
    }

    /**
     * @param authorizationPasswd the authorizationPasswd to set
     */
    public void setAuthorizationPasswd(String authorizationPasswd) {
        this.authorizationPasswd = authorizationPasswd;
    }

    /**
     * @return the proxyProtocol
     */
    public Proxy.Type getProxyProtocol() {
        return proxyProtocol;
    }

    /**
     * @param proxyProtocol the proxyProtocol to set
     */
    public void setProxyProtocol(Proxy.Type proxyProtocol) {
        this.proxyProtocol = proxyProtocol;
    }

    /**
     * @return the proxyHost
     */
    public String getProxyHost() {
        return proxyHost;
    }

    /**
     * @param proxyHost the proxyHost to set
     */
    public void setProxyHost(String proxyHost) {
        this.proxyHost = proxyHost;
    }

    /**
     * @return the proxyPort
     */
    public int getProxyPort() {
        return proxyPort;
    }

    /**
     * @param proxyPort the proxyPort to set
     */
    public void setProxyPort(int proxyPort) {
        this.proxyPort = proxyPort;
    }

    /**
     * @return the proxyUser
     */
    public String getProxyUser() {
        return proxyUser;
    }

    /**
     * @param proxyUser the proxyUser to set
     */
    public void setProxyUser(String proxyUser) {
        this.proxyUser = proxyUser;
    }

    /**
     * @return the proxyPasswd
     */
    public String getProxyPasswd() {
        return proxyPasswd;
    }

    /**
     * @param proxyPasswd the proxyPasswd to set
     */
    public void setProxyPasswd(String proxyPasswd) {
        this.proxyPasswd = proxyPasswd;
    }

    /**
     * @return the ignoreValidateCertification
     */
    public boolean isIgnoreValidateCertification() {
        return ignoreValidateCertification;
    }

    /**
     * @param ignoreValidateCertification the ignoreValidateCertification to set
     */
    public void setIgnoreValidateCertification(boolean ignoreValidateCertification) {
        this.ignoreValidateCertification = ignoreValidateCertification;
    }

    public void setProperty(HttpExtendProperty property) {
        this.httpClientType = property.httpClientType;

        this.clientCertificate.setSelected(property.isUseClientCertificate());
        if (this.clientCertificate.isSelected()) {
            this.clientCertificate.setStoreType(property.getClientCertificateStoreType());
            this.clientCertificate.setClientCertificate(property.getClientCertificate());
            this.clientCertificate.setClientCertificatePasswd(property.getClientCertificatePasswd());
        }
        this.ignoreValidateCertification = property.ignoreValidateCertification;

        this.authorizationType = property.authorizationType;
        this.authorizationUser = property.authorizationUser;
        this.authorizationPasswd = property.authorizationPasswd;

        this.proxyProtocol = property.proxyProtocol;
        this.proxyHost = property.proxyHost;
        this.proxyPort = property.proxyPort;
        this.proxyUser = property.proxyUser;
        this.proxyPasswd = property.proxyPasswd;
    }

    public void setProperties(Properties prop) {
        this.httpClientType = HttpClientType.valueOf(prop.getProperty("useHttpClient", HttpClientType.BURP.name()));

        this.clientCertificate.setSelected(Boolean.parseBoolean(prop.getProperty("useClientCertificate")));
        if (this.clientCertificate.isSelected()) {
            this.clientCertificate.setStoreType(CertUtil.StoreType.valueOf(prop.getProperty("clientCertificateStoreType")));
            this.clientCertificate.setClientCertificate(ConvertUtil.toBase64Decode(prop.getProperty("clientCertificate")));
            this.clientCertificate.setClientCertificatePasswd(prop.getProperty("clientCertificatePasswd"));
        }
        this.ignoreValidateCertification = Boolean.parseBoolean(prop.getProperty("ignoreValidateCertification", StringUtil.toString(Boolean.TRUE)));

        this.authorizationType = AuthorizationType.valueOf(prop.getProperty("authorizationType", AuthorizationType.NONE.name()));
        this.authorizationUser = prop.getProperty("authorizationUser", "");
        this.authorizationPasswd = prop.getProperty("authorizationPasswd", "");

        this.proxyProtocol = Proxy.Type.valueOf(prop.getProperty("proxyProtocol", Proxy.Type.DIRECT.name()));
        this.proxyHost = prop.getProperty("proxyHost", "");
        this.proxyPort = ConvertUtil.parseIntDefault(prop.getProperty("proxyPort"), 8080);
        this.proxyUser = prop.getProperty("proxyUser", "");
        this.proxyPasswd = prop.getProperty("proxyPasswd", "");
    }

    public Properties getProperties() {
        Properties prop = new Properties();
        prop.setProperty("useHttpClient", this.httpClientType.name());

        prop.setProperty("useClientCertificate", StringUtil.toString(this.clientCertificate.isSelected()));
        if (this.clientCertificate.isSelected()) {
            prop.setProperty("clientCertificateStoreType", this.clientCertificate.getStoreType().name());
            prop.setProperty("clientCertificate", ConvertUtil.toBase64Encode(StringUtil.getStringRaw(this.clientCertificate.getClientCertificate()), StandardCharsets.ISO_8859_1));
            prop.setProperty("clientCertificatePasswd", this.clientCertificate.getClientCertificatePasswd());
        }
        prop.setProperty("ignoreValidateCertification", StringUtil.toString(this.ignoreValidateCertification));

        prop.setProperty("authorizationType", this.authorizationType.name());
        prop.setProperty("authorizationUser", this.authorizationUser);
        prop.setProperty("authorizationPasswd", this.authorizationPasswd);

        prop.setProperty("proxyProtocol", this.proxyProtocol.name());
        prop.setProperty("proxyHost", this.proxyHost);
        prop.setProperty("proxyPort", StringUtil.toString(this.proxyPort));
        prop.setProperty("proxyUser", this.proxyUser);
        prop.setProperty("proxyPasswd", this.proxyPasswd);
        return prop;
    }

}