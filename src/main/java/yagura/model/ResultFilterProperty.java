package yagura.model;

import com.google.gson.annotations.Expose;
import extension.burp.FilterProperty;
import extension.burp.IPropertyConfig;
import extension.helpers.json.JsonUtil;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 *
 * @author isayan
 */
public class ResultFilterProperty implements IPropertyConfig {

    public final static String RESULT_FILTER_PROPERTY = "resultFilterProperty";

    @Override
    public String getSettingName() {
        return RESULT_FILTER_PROPERTY;
    }

    @Override
    public void saveSetting(String value) {
        ResultFilterProperty property = JsonUtil.jsonFromString(value, ResultFilterProperty.class, true);
        this.setSelectedName(property.getSelectedName());
        this.setFilterMap(property.getFilterMap());
    }

    @Override
    public String loadSetting() {
        return JsonUtil.jsonToString(this, true);
    }

    @Override
    public String defaultSetting() {
        ResultFilterProperty property = new ResultFilterProperty();
        return JsonUtil.jsonToString(property, true);
    }

    @Expose
    private String selectedName = "";

    /**
     * @return the selectedName
     */
    public String getSelectedName() {
        return this.selectedName;
    }

    /**
     * @param selectedName the selectedName to set
     */
    public void setSelectedName(String selectedName) {
        this.selectedName = selectedName;
    }

    @Expose
    private final Map<String, FilterProperty> filterMap = Collections.synchronizedMap(new LinkedHashMap<String, FilterProperty>(16, (float) 0.75, true));

    /**
     * @return the replaceMap
     */
    public Map<String, FilterProperty> getFilterMap() {
        return this.filterMap;
    }

    /**
     * @param filterMap the replaceMap to set
     */
    public synchronized void setFilterMap(Map<String, FilterProperty> filterMap) {
        if (filterMap.get(this.selectedName) == null) {
            this.selectedName = "";
        }
        this.filterMap.clear();
        this.filterMap.putAll(filterMap);
    }

    public void setProperty(ResultFilterProperty property) {
        this.setSelectedName(property.getSelectedName());
        this.setFilterMap(property.getFilterMap());
    }

}
