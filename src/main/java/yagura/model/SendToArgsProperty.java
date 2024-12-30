package yagura.model;

import com.google.gson.reflect.TypeToken;
import extension.helpers.ConvertUtil;
import extension.helpers.json.JsonUtil;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.logging.Logger;

/**
 *
 * @author isayan
 */
public class SendToArgsProperty {

    private final static Logger logger = Logger.getLogger(SendToArgsProperty.class.getName());

    private boolean useOverride = false;

    private final List<String> argsList = new ArrayList<>();

    private boolean useMacOpenCommand = false;

    /**
     * @return the useOverride
     */
    public boolean isUseOverride() {
        return useOverride;
    }

    /**
     * @param useOverride the useOverride to set
     */
    public void setUseOverride(boolean useOverride) {
        this.useOverride = useOverride;
    }

    public void setArgsList(List<String> argsList) {
        this.argsList.clear();
        this.argsList.addAll(argsList);
    }

    public List<String> getArgsList() {
        return this.argsList;
    }

    /**
     * @return the useMacOpenCommand
     */
    public boolean isUseMacOpenCommand() {
        return useMacOpenCommand;
    }

    /**
     * @param useMacOpenCommand the useMacOpenCommand to set
     */
    public void setUseMacOpenCommand(boolean useMacOpenCommand) {
        this.useMacOpenCommand = useMacOpenCommand;
    }

    public void setProperty(SendToArgsProperty property) {
        this.useOverride = property.useOverride;
        this.argsList.clear();
        this.argsList.addAll(property.argsList);
        this.useMacOpenCommand = property.useMacOpenCommand;
    }

    public void setProperties(Properties property) {
        this.useOverride = ConvertUtil.parseBooleanDefault(property.getProperty("SendToArgs.useOverride"), false);
        String propArgs = property.getProperty("SendToArgs.argsList", "[]");
        Type listType = new TypeToken<List<String>>() {
        }.getType();
        List<String> paramArgs = JsonUtil.jsonFromString(propArgs, listType, true);
        this.argsList.clear();
        this.argsList.addAll(paramArgs);
        this.useMacOpenCommand = ConvertUtil.parseBooleanDefault(property.getProperty("SendToArgs.useMacOpenCommand"), false);
    }

    public Properties getProperties() {
        Properties prop = new Properties();
        prop.setProperty("SendToArgs.useOverride", Boolean.toString(this.useOverride));
        prop.setProperty("SendToArgs.argsList", JsonUtil.jsonToString(this.argsList, true));
        prop.setProperty("SendToArgs.useMacOpenCommand", Boolean.toString(this.useMacOpenCommand));
        return prop;
    }

}
