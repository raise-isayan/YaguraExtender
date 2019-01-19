package yagura.model;

import burp.IParameter;
import extend.util.Util;

/**
 *
 * @author raise.isayan
 */
public class Parameter implements IParameter {

    private final IParameter parameter;
    
    public Parameter(IParameter parameter) {
        this.parameter = parameter;
    }
    
    @Override
    public byte getType() {
        return this.parameter.getType();
    }

    @Override
    public String getName() {
        return this.parameter.getName();
    }

    @Override
    public String getValue() {
        return this.parameter.getValue();
    }

    @Override
    public int getNameStart() {
        return this.parameter.getNameStart();
    }

    @Override
    public int getNameEnd() {
        return this.parameter.getNameEnd();
    }

    @Override
    public int getValueStart() {
        return this.parameter.getValueStart();
    }

    @Override
    public int getValueEnd() {
        return this.parameter.getValueEnd();
    }

    public String getUniversalName() {
        return Util.decodeMessage(Util.getRawByte(parameter.getName()), encoding);
    }
        
    public String getUniversalValue() {
        return Util.decodeMessage(Util.getRawByte(parameter.getValue()), encoding);
    }
            
    private  String encoding = null;

    /**
     * @return the encoding
     */
    public String getEncodingOverride() {
        return encoding;
    }

    /**
     * @param encoding the encoding to set
     */
    public void setEncodingOverride(String encoding) {
        this.encoding = encoding;
    }

}
