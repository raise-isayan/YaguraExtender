package yagura.model;

import java.util.Properties;

/**
 *
 * @author isayan
 */
public class HotKeyProperty {

    private String hotKeytAssign = "";

    /**
     * @return the hotkeyAssign
     */
    public String getHotKeyAssign() {
        return hotKeytAssign;
    }

    /**
     * @param hotKeytAssign the hotKeytAssign to set
     */
    public void setHotKeyAssign(String hotKeytAssign) {
        this.hotKeytAssign = hotKeytAssign;
    }

    public void setProperty(HotKeyProperty property) {
        this.hotKeytAssign = property.hotKeytAssign;
    }

    public void setProperties(Properties property) {
        this.hotKeytAssign = property.getProperty("HotKey.hotKeytAssign", "");
    }

    public Properties getProperties() {
        Properties prop = new Properties();
        prop.setProperty("HotKey.hotKeytAssign", this.hotKeytAssign);
        return prop;
    }

}
