package extension.burp;

import java.util.Map;

/**
 *
 * @author isayan
 */
public interface IOptionProperty {

    public void saveConfigSetting(final Map<String, String> value);

    public Map<String, String> loadConfigSetting();

}
