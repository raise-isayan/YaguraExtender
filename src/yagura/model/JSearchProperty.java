/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
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
    
    private boolean request = true;

    /**
     * @return the isRequest
     */
    public boolean isRequest() {
        return request;
    }

    /**
     * @param request the isRequest to set
     */
    public void setRequest(boolean request) {
        this.request = request;
    }
    
    private boolean response = true;

    /**
     * @return the response
     */
    public boolean isResponse() {
        return response;
    }

    /**
     * @param response the isResponse to set
     */
    public void setResponse(boolean response) {
        this.response = response;
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
    
}
