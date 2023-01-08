package yagura.model;

import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;

import extension.helpers.StringUtil;
import java.io.UnsupportedEncodingException;

/**
 *
 * @author raise.isayan
 */
public class Parameter implements ParsedHttpParameter {
    private final ParsedHttpParameter parameter;

    private HttpParameterType type = null;
    private String name = null;
    private String value = null;

    public Parameter(HttpParameter parameter) {
        this.parameter = new ParsedHttpParameter() {

            @Override
            public HttpParameterType type() {
                return parameter.type();
            }

            @Override
            public String name() {
                return parameter.name();
            }

            @Override
            public String value() {
                return parameter.value();
            }

            @Override
            public Range nameOffsets() {
                return null;
            }

            @Override
            public Range valueOffsets() {
                return null;
            }

        };

    }

    public Parameter(ParsedHttpParameter parameter) {
        this.parameter = parameter;
    }

    public HttpParameterType getType() {
        if (this.type != null) {
            return this.type;
        } else {
            return this.parameter.type();
        }
    }

    public void setType(HttpParameterType type) {
        this.type = type;
    }

    public String getName() {
        if (this.name != null) {
            return this.name;
        } else {
            return this.parameter.name();
        }
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getValue() {
        if (this.value != null) {
            return this.value;
        } else {
            return this.parameter.value();
        }
    }

    public void setValue(String value) {
        this.value = value;
    }

    public String getUniversalName() {
        if (this.encoding != null) {
            try {
                return StringUtil.getStringCharset(StringUtil.getBytesRaw(parameter.name()), this.encoding);
            } catch (UnsupportedEncodingException ex) {
                return null;
            }
        } else {
            return StringUtil.getStringRaw(StringUtil.getBytesRaw(parameter.name()));
        }
    }

    public String getUniversalValue() {
        if (this.encoding != null) {
            try {
               return StringUtil.getStringCharset(StringUtil.getBytesRaw(parameter.value()), this.encoding);
            } catch (UnsupportedEncodingException ex) {
                return null;
            }
        } else {
            return StringUtil.getStringRaw(StringUtil.getBytesRaw(parameter.name()));
        }
    }

    private String encoding = null;

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
        return (this.type != null || this.name != null || this.value != null);
    }

    public static Parameter newPameter() {
        return new Parameter(HttpParameter.parameter("", "", HttpParameterType.URL));
    }

    @Override
    public HttpParameterType type() {
        return this.getType();
    }

    @Override
    public String name() {
        return this.getName();
    }

    @Override
    public String value() {
        return this.getValue();
    }

    @Override
    public Range nameOffsets() {
        return this.parameter.nameOffsets();
    }

    @Override
    public Range valueOffsets() {
        return this.parameter.valueOffsets();
    }

}
