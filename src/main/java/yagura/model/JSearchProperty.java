package yagura.model;

import com.google.gson.annotations.Expose;
import extend.view.base.RegexItem;

/**
 *
 * @author isayan
 */
public class JSearchProperty extends RegexItem {

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
    private FilterProperty filterProp = new FilterProperty();

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
    private boolean comment = true;

    /**
     * @return the comment
     */
    public boolean isComment() {
        return comment;
    }

    /**
     * @param comment the comment to set
     */
    public void setComment(boolean comment) {
        this.comment = comment;
    }

    public void setProperty(JSearchProperty property) {
        this.setAutoRecogniseEncoding(property.isAutoRecogniseEncoding());
        this.setFilterProperty(property.getFilterProperty());
        this.setRequestHeader(property.isRequestHeader());
        this.setRequestBody(property.isRequestBody());
        this.setResponseHeader(property.isResponseHeader());
        this.setResponseBody(property.isResponseBody());
        this.setComment(property.isComment());
        this.setSmartMatch(property.isSmartMatch());
        this.setRegexp(property.isRegexp());
        this.setIgnoreCase(property.isIgnoreCase());
    }

}
