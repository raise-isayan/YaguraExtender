package yagura.model;

import com.google.gson.annotations.Expose;
import extension.burp.FilterProperty;
import extension.burp.IPropertyConfig;
import extension.helpers.json.JsonUtil;
import extension.view.base.RegexItem;

/**
 *
 * @author isayan
 */
public class JSearchProperty extends RegexItem implements IPropertyConfig {

    public final static String JSEARCH_FILTER_PROPERTY = "jSearchFilterProperty";

    @Expose
    private boolean smartMatch = false;

    public void setSmartMatch(boolean value) {
        this.smartMatch = value;
    }

    public boolean isSmartMatch() {
        return this.smartMatch;
    }

    @Expose
    private boolean autoRecognise = true;

    public boolean isAutoRecogniseEncoding() {
        return this.autoRecognise;
    }

    public void setAutoRecogniseEncoding(boolean autoRecognise) {
        this.autoRecognise = autoRecognise;
    }

    @Expose
    private FilterProperty filterProp = new FilterProperty(FilterProperty.FilterCategory.HTTP);

    public FilterProperty getFilterProperty() {
        return this.filterProp;
    }

    public void setFilterProperty(FilterProperty filterProp) {
        this.filterProp = filterProp;
    }

    @Expose
    private boolean requestHeader = true;

    /**
     * @return the isRequestHeader
     */
    public boolean isRequestHeader() {
        return requestHeader;
    }

    /**
     * @param request the isRequestHeader to set
     */
    public void setRequestHeader(boolean request) {
        this.requestHeader = request;
    }

    @Expose
    private boolean requestBody = true;

    /**
     * @return the requestBody
     */
    public boolean isRequestBody() {
        return requestBody;
    }

    /**
     * @param requestBody the requestBody to set
     */
    public void setRequestBody(boolean requestBody) {
        this.requestBody = requestBody;
    }

    @Expose
    private boolean responseHeader = true;

    /**
     * @return the responseHeader
     */
    public boolean isResponseHeader() {
        return responseHeader;
    }

    /**
     * @param response the isResponseHeader to set
     */
    public void setResponseHeader(boolean response) {
        this.responseHeader = response;
    }

    private boolean responseBody = true;

    /**
     * @return the responseBody
     */
    public boolean isResponseBody() {
        return responseBody;
    }

    /**
     * @param responseBody the responseBody to set
     */
    public void setResponseBody(boolean responseBody) {
        this.responseBody = responseBody;
    }

    @Expose
    private boolean notes = true;

    /**
     * @return the notes
     */
    public boolean isNotes() {
        return notes;
    }

    /**
     * @param notes the notes to set
     */
    public void setNotes(boolean notes) {
        this.notes = notes;
    }

    @Expose
    private int listenerPort = -1;

    /**
     * @return the listenerPort
     */
    public int getListenerPort() {
        return listenerPort;
    }

    /**
     * @param listenerPort
     */
    public void setListenerPort(int listenerPort) {
        this.listenerPort = listenerPort;
    }

    public void setProperty(JSearchProperty property) {
        this.setAutoRecogniseEncoding(property.isAutoRecogniseEncoding());
        this.setFilterProperty(property.getFilterProperty());
        this.setRequestHeader(property.isRequestHeader());
        this.setRequestBody(property.isRequestBody());
        this.setResponseHeader(property.isResponseHeader());
        this.setResponseBody(property.isResponseBody());
        this.setNotes(property.isNotes());
        this.setSmartMatch(property.isSmartMatch());
        this.setRegexp(property.isRegexp());
        this.setIgnoreCase(property.isIgnoreCase());
        this.setListenerPort(property.getListenerPort());
    }

    @Override
    public String getSettingName() {
        return JSEARCH_FILTER_PROPERTY;
    }

    @Override
    public void saveSetting(String value) {
        JSearchProperty property = JsonUtil.jsonFromString(value, JSearchProperty.class, true);
        this.setProperty(property);
    }

    @Override
    public String loadSetting() {
        return JsonUtil.jsonToString(this, true);
    }

    @Override
    public String defaultSetting() {
        JSearchProperty property = new JSearchProperty();
        return JsonUtil.jsonToString(property, true);
    }

}
