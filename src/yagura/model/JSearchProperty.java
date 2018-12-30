package yagura.model;

import extend.view.base.RegexItem;

/**
 *
 * @author isayan
 */
public class JSearchProperty extends RegexItem {

    private boolean autoRecognise = false;

    public boolean isAutoRecogniseEncoding() {
        return this.autoRecognise;
    }

    public void setAutoRecogniseEncoding(boolean autoRecognise) {
        this.autoRecognise = autoRecognise;
    }

    private FilterProperty filterProp = new FilterProperty();
    
    public FilterProperty getFilterProperty() {
        return this.filterProp;
    }
    
    public void setFilterProperty(FilterProperty filterProp) {
        this.filterProp = filterProp;
    }
    
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
        this.setRegexp(property.isRegexp());
        this.setIgnoreCase(property.isIgnoreCase());
    }
    
}
