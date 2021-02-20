package yagura.model;

import com.google.gson.annotations.Expose;

/**
 *
 * @author raise.isayan
 */
public class OptionProperty implements IOptionProperty {

    /**
     * implements UniversalViewProperty 
     */
    @Expose
    private final UniversalViewProperty universalViewProperty = new UniversalViewProperty();

    @Override
    public UniversalViewProperty getEncodingProperty() {
        return this.universalViewProperty;
    }

    @Override
    public void setEncodingProperty(UniversalViewProperty encodingProperty) {
        this.universalViewProperty.setProperty(encodingProperty);
    }

    /**
     * implements MatchReplaceProperty 
     */
    @Expose
    private final MatchReplaceProperty matchReplaceProperty = new MatchReplaceProperty();

    @Override
    public MatchReplaceProperty getMatchReplaceProperty() {
        return this.matchReplaceProperty;
    }

    @Override
    public void setMatchReplaceProperty(MatchReplaceProperty matchReplaceProperty) {
        this.matchReplaceProperty.setProperty(matchReplaceProperty);
    }

    /**
     * implements MatchAlertProperty 
     */
    @Expose
    private final MatchAlertProperty matchAlertProperty = new MatchAlertProperty();

    @Override
    public MatchAlertProperty getMatchAlertProperty() {
        return this.matchAlertProperty;
    }

    @Override
    public void setMatchAlertProperty(MatchAlertProperty matchAlertProperty) {
        this.matchAlertProperty.setProperty(matchAlertProperty);
    }

    /**
     * implements SendToProperty 
     */
    @Expose
    private final SendToProperty sendToProperty = new SendToProperty();

    @Override
    public SendToProperty getSendToProperty() {
        return this.sendToProperty;
    }

    @Override
    public void setSendToProperty(SendToProperty sendtoProperty) {
        this.sendToProperty.setProperty(sendtoProperty);
    }

    /**
     * implements LoggingProperty 
     */
    @Expose
    private final LoggingProperty logProperty = new LoggingProperty();

    @Override
    public LoggingProperty getLoggingProperty() {
        return this.logProperty;
    }

    @Override
    public void setLoggingProperty(LoggingProperty loggingProperty) {
        this.logProperty.setProperty(loggingProperty);
    }

    /**
     * implements JSearchProperty 
     */
    @Expose
    private final JSearchProperty searchProperty = new JSearchProperty();

    @Override
    public JSearchProperty getJSearchProperty() {
        return this.searchProperty;
    }

    @Override
    public void setJSearchProperty(JSearchProperty searchProperty) {
        this.searchProperty.setProperty(searchProperty);
    }

    /**
     * implements JTransCoderProperty 
     */
    @Expose
    private final JTransCoderProperty transcoderProperty = new JTransCoderProperty();

    @Override
    public JTransCoderProperty getJTransCoderProperty() {
        return this.transcoderProperty;
    }

    @Override
    public void setJTransCoderProperty(JTransCoderProperty transcoderProperty) {
        this.transcoderProperty.setProperty(transcoderProperty);
    }

    /**
     * debugModeの取得
     */
    private boolean debugMode = false;

    @Override
    public boolean getDebugMode() {
        return this.debugMode;
    }

    @Override
    public void setDebugMode(boolean debugMode) {
        this.debugMode = debugMode;
    }

    /**
     * IOptionProperty
     * @param property
     */
    public void setProperty(IOptionProperty property) {
        this.setEncodingProperty(property.getEncodingProperty());
        this.setMatchReplaceProperty(property.getMatchReplaceProperty());
        this.setMatchAlertProperty(property.getMatchAlertProperty());
        this.setSendToProperty(property.getSendToProperty());
        this.setLoggingProperty(property.getLoggingProperty());
        this.setJSearchProperty(property.getJSearchProperty());
        this.setJTransCoderProperty(property.getJTransCoderProperty());
        this.setDebugMode(property.getDebugMode());
    }

}
