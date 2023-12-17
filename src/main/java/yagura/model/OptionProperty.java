package yagura.model;

import com.google.gson.annotations.Expose;
import extension.burp.IOptionProperty;
import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author raise.isayan
 */
public class OptionProperty implements IOptionProperty {

    private final Map<String, String> config = new HashMap();

    @Override
    public void saveConfigSetting(final Map<String, String> value) {
        this.config.putAll(value);
    }

    @Override
    public Map<String, String> loadConfigSetting() {
        return this.config;
    }

    /**
     * implements UniversalViewProperty
     */
    @Expose
    private final UniversalViewProperty universalViewProperty = new UniversalViewProperty();

    public void defaultSettingProperty() {
        Map<String, String> map = loadConfigSetting();
        String value = map.get(UniversalViewProperty.CJK_VIEW_PROPERTY);
        if (value == null) {
            value = this.universalViewProperty.defaultSetting();
            this.universalViewProperty.saveSetting(value);    
        }
    }
    
    public UniversalViewProperty getEncodingProperty() {
        return this.universalViewProperty;
    }

    public void setEncodingProperty(UniversalViewProperty encodingProperty) {
        this.universalViewProperty.setProperty(encodingProperty);
    }

    /**
     * implements MatchReplaceProperty
     */
    @Expose
    private final MatchReplaceProperty matchReplaceProperty = new MatchReplaceProperty();

    public MatchReplaceProperty getMatchReplaceProperty() {
        return this.matchReplaceProperty;
    }

    public void setMatchReplaceProperty(MatchReplaceProperty matchReplaceProperty) {
        this.matchReplaceProperty.setProperty(matchReplaceProperty);
    }

    /**
     * implements MatchAlertProperty
     */
    @Expose
    private final MatchAlertProperty matchAlertProperty = new MatchAlertProperty();

    public MatchAlertProperty getMatchAlertProperty() {
        return this.matchAlertProperty;
    }

    public void setMatchAlertProperty(MatchAlertProperty matchAlertProperty) {
        this.matchAlertProperty.setProperty(matchAlertProperty);
    }

    /**
     * implements ResultFilterProperty
     */
    @Expose
    private final ResultFilterProperty resultFilterProperty = new ResultFilterProperty();

    public ResultFilterProperty getResultFilterProperty() {
        return this.resultFilterProperty;
    }

    public void setResultFilterProperty(ResultFilterProperty filterProperty) {
        this.resultFilterProperty.setProperty(filterProperty);
    }

    /**
     * implements SendToProperty
     */
    @Expose
    private final SendToProperty sendToProperty = new SendToProperty();

    public SendToProperty getSendToProperty() {
        return this.sendToProperty;
    }

    public void setSendToProperty(SendToProperty sendtoProperty) {
        this.sendToProperty.setProperty(sendtoProperty);
    }

    /**
     * implements LoggingProperty
     */
    @Expose
    private final LoggingProperty logProperty = new LoggingProperty();

    public LoggingProperty getLoggingProperty() {
        return this.logProperty;
    }

    public void setLoggingProperty(LoggingProperty loggingProperty) {
        this.logProperty.setProperty(loggingProperty);
    }

    /**
     * implements JSearchProperty
     */
    @Expose
    private final JSearchProperty searchProperty = new JSearchProperty();

    public JSearchProperty getJSearchProperty() {
        return this.searchProperty;
    }

    public void setJSearchProperty(JSearchProperty searchProperty) {
        this.searchProperty.setProperty(searchProperty);
    }

    /**
     * implements JTransCoderProperty
     */
    @Expose
    private final JTransCoderProperty transcoderProperty = new JTransCoderProperty();

    public JTransCoderProperty getJTransCoderProperty() {
        return this.transcoderProperty;
    }

    public void setJTransCoderProperty(JTransCoderProperty transcoderProperty) {
        this.transcoderProperty.setProperty(transcoderProperty);
    }

    /**
     * implements AutoResponder
     */
    @Expose
    private final AutoResponderProperty autoResponderProperty = new AutoResponderProperty();

    public AutoResponderProperty getAutoResponderProperty() {
        return this.autoResponderProperty;
    }

    public void setAutoResponderProperty(AutoResponderProperty autoResponderProperty) {
        this.autoResponderProperty.setProperty(autoResponderProperty);
    }

    /**
     * debugModeの取得
     */
    private boolean debugMode = false;

    public boolean getDebugMode() {
        return this.debugMode;
    }

    public void setDebugMode(boolean debugMode) {
        this.debugMode = debugMode;
    }

    /**
     *
     * @return
     */
    public Map<String, String> getProperty() {
        this.config.put(this.universalViewProperty.getSettingName(), this.universalViewProperty.loadSetting());
        this.config.put(this.matchReplaceProperty.getSettingName(), this.matchReplaceProperty.loadSetting());
        this.config.put(this.matchAlertProperty.getSettingName(), this.matchAlertProperty.loadSetting());
        this.config.put(this.autoResponderProperty.getSettingName(), this.autoResponderProperty.loadSetting());
        this.config.put(this.resultFilterProperty.getSettingName(), this.resultFilterProperty.loadSetting());
        this.config.put(this.sendToProperty.getSettingName(), this.sendToProperty.loadSetting());
        this.config.put(this.logProperty.getSettingName(), this.logProperty.loadSetting());
        this.config.put(this.searchProperty.getSettingName(), this.searchProperty.loadSetting());
        this.config.put(this.transcoderProperty.getSettingName(), this.transcoderProperty.loadSetting());
        return this.config;
    }

    public void setProperty(Map<String, String> config) {
        String configUniversalViewProperty = config.get(this.universalViewProperty.getSettingName());
        if (configUniversalViewProperty != null) {
            this.universalViewProperty.saveSetting(configUniversalViewProperty);
        }
        String configMatchReplaceProperty = config.get(this.matchReplaceProperty.getSettingName());
        if (configMatchReplaceProperty != null) {
            this.matchReplaceProperty.saveSetting(configMatchReplaceProperty);
        }
        String configMatchAlertProperty = config.get(this.matchAlertProperty.getSettingName());
        if (configMatchAlertProperty != null) {
            this.matchAlertProperty.saveSetting(configMatchAlertProperty);
        }
        String configAutoResponderProperty = config.get(this.autoResponderProperty.getSettingName());
        if (configAutoResponderProperty != null) {
            this.autoResponderProperty.saveSetting(configAutoResponderProperty);
        }
        String configResultFilterProperty = config.get(this.resultFilterProperty.getSettingName());
        if (configResultFilterProperty != null) {
            this.resultFilterProperty.saveSetting(configResultFilterProperty);
        }
        String configSendToProperty = config.get(this.sendToProperty.getSettingName());
        if (configSendToProperty != null) {
            this.sendToProperty.saveSetting(configSendToProperty);
        }
        String configLoggingProperty = config.get(this.logProperty.getSettingName());
        if (configLoggingProperty != null) {
            this.logProperty.saveSetting(configLoggingProperty);
        }
        String configSearchProperty = config.get(this.searchProperty.getSettingName());
        if (configSearchProperty != null) {
            this.searchProperty.saveSetting(configSearchProperty);
        }
        String configTranscoderProperty = config.get(this.transcoderProperty.getSettingName());
        if (configTranscoderProperty != null) {
            this.transcoderProperty.saveSetting(configTranscoderProperty);
        }
    }

}
