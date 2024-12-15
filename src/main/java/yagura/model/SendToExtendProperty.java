package yagura.model;

import java.util.Properties;

/**
 *
 * @author isayan
 */
public class SendToExtendProperty {

    private final HttpExtendProperty httpExtend = new HttpExtendProperty();
    private final SendToParameterProperty sendToParameter = new SendToParameterProperty();
    private final SendToArgsProperty sendToArgs = new SendToArgsProperty();

    public enum ExtendView {
        HTTP_EXTEND,
        SENDTO_PARAMETER,
        SENDTO_ARGS,
    }

    /**
     * @return the httpExtendProperty
     */
    public HttpExtendProperty getHttpExtendProperty() {
        return httpExtend;
    }

    /**
     * @return the sendToOverrideProperty
     */
    public SendToParameterProperty getSendToParameterProperty() {
        return sendToParameter;
    }

    /**
     * @return the sendToArgs
     */
    public SendToArgsProperty getSendToArgsProperty() {
        return sendToArgs;
    }

    public void setProperty(SendToExtendProperty property) {
        this.httpExtend.setProperty(property.getHttpExtendProperty());
        this.sendToParameter.setProperty(property.getSendToParameterProperty());
        this.sendToArgs.setProperty(property.getSendToArgsProperty());
    }

    public void setProperty(HttpExtendProperty property) {
        this.httpExtend.setProperty(property);
    }

    public void setProperty(SendToParameterProperty property) {
        this.sendToParameter.setProperty(property);
    }

    public void setProperty(SendToArgsProperty property) {
        this.sendToArgs.setProperty(property);
    }

    public void setProperties(Properties prop) {
        this.httpExtend.setProperties(prop);
        this.sendToParameter.setProperties(prop);
        this.sendToArgs.setProperties(prop);
    }

    public Properties getProperties() {
        Properties prop = new Properties();
        prop.putAll(this.httpExtend.getProperties());
        prop.putAll(this.sendToParameter.getProperties());
        prop.putAll(this.sendToArgs.getProperties());
        return prop;
    }

}
