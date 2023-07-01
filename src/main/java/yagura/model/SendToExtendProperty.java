package yagura.model;

import java.util.Properties;

/**
 *
 * @author isayan
 */
public class SendToExtendProperty {

    private final SendToParameterProperty sendToParameter = new SendToParameterProperty();
    private final HttpExtendProperty httpExtend = new HttpExtendProperty();

    /**
     * @return the sendToOverrideProperty
     */
    public SendToParameterProperty getSendToParameterProperty() {
        return sendToParameter;
    }

    /**
     * @return the httpExtendProperty
     */
    public HttpExtendProperty getHttpExtendProperty() {
        return httpExtend;
    }

    public void setProperty(SendToExtendProperty property) {
        this.httpExtend.setProperty(property.getHttpExtendProperty());
        this.sendToParameter.setProperty(property.getSendToParameterProperty());
    }

    public void setProperty(HttpExtendProperty property) {
        this.httpExtend.setProperty(property);
    }

    public void setProperty(SendToParameterProperty property) {
        this.sendToParameter.setProperty(property);
    }

    public void setProperties(Properties prop) {
        this.httpExtend.setProperties(prop);
        this.sendToParameter.setProperties(prop);
    }

    public Properties getProperties() {
        Properties prop = new Properties();
        prop.putAll(this.httpExtend.getProperties());
        prop.putAll(this.sendToParameter.getProperties());
        return prop;
    }

}
