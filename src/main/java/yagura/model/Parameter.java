package yagura.model;

import burp.IParameter;
import extend.util.Util;
import java.nio.charset.StandardCharsets;

/**
 *
 * @author raise.isayan
 */
public class Parameter implements IParameter {

    private final IParameter parameter;

    private byte type = -1;
    private String name = null;
    private String value = null;
    
    public Parameter(IParameter parameter) {
        this.parameter = parameter;
    }
    
    @Override
    public byte getType() {
        if (this.type >= 0) {
            return this.type;        
        }
        else {
            return this.parameter.getType();    
        }
    }

    public void setType(byte type) {
        this.type = type;
    }
        
    @Override
    public String getName() {
        if (this.name != null) {
            return this.name;
        }
        else {
            return this.parameter.getName();
        }
    }

    public void setName(String name) {
        this.name = name;
    }
    
    @Override
    public String getValue() {
        if (this.value != null) {
            return this.value;
        }
        else {
            return this.parameter.getValue();
        }
    }

    public void setValue(String value) {
        this.value = value;
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
        if (this.encoding != null) {
            return Util.decodeMessage(Util.getRawByte(parameter.getName()), this.encoding);
        }
        else {
            return Util.decodeMessage(Util.getRawByte(parameter.getName()), StandardCharsets.ISO_8859_1.name());        
        }
    }
        
    public String getUniversalValue() {
        if (this.encoding != null) {
            return Util.decodeMessage(Util.getRawByte(parameter.getValue()), this.encoding);
        }
        else {
            return Util.decodeMessage(Util.getRawByte(parameter.getName()), StandardCharsets.ISO_8859_1.name());
        }
    }
            
    private  String encoding = null;

    /**
     * @return the encoding
     */
    public String getEncodingOverride() {
        return this.encoding;
    }

    /**
     * @param encoding the encoding to set
     */
    public void setEncodingOverride(String encoding) {
        this.encoding = encoding;
    }

    public boolean isModified() {
        return (this.type >= 0 || this.name != null || this.value != null);
    }
 
    public static Parameter newPameter() {
        Parameter p = new Parameter(new IParameter() {
            @Override
            public byte getType() {
                return IParameter.PARAM_URL;
            }

            @Override
            public String getName() {
                return "";
            }

            @Override
            public String getValue() {
                return "";
            }

            @Override
            public int getNameStart() {
                return -1;
            }

            @Override
            public int getNameEnd() {
                return -1;
            }

            @Override
            public int getValueStart() {
                return -1;
            }

            @Override
            public int getValueEnd() {
                return -1;
            }
        
        });
        return p;        
    }
        
}
