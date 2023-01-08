package extension.burp;

/**
 *
 * @author isayan
 */
public interface IPropertyConfig {

    public String getSettingName();

    public void saveSetting(String value);

    public String loadSetting();

    public String defaultSetting();
    
    
}
