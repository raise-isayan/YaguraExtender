package yagura.model;

import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import extension.helpers.StringUtil;
import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 * @author isayan
 */
public class ParameterView implements ParsedHttpParameter, TableMapBase {

    private final static Logger logger = Logger.getLogger(ParameterView.class.getName());

    final Parameter param;

    public ParameterView() {
        this.param = Parameter.newPameter();
    }

    public ParameterView(Parameter param) {
        this.param = param;
    }

    public ParameterView(ParsedHttpParameter param) {
        this.param = new Parameter(param);
    }

    public Parameter getParameter() {
        return this.param;
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
        return this.param.nameOffsets();
    }

    @Override
    public Range valueOffsets() {
        return this.param.valueOffsets();
    }


    public HttpParameterType getType() {
        if (this.type != null) {
            return this.type;
        } else {
            return this.param.type();
        }
    }

    private HttpParameterType type = null;
    private String name = null;
    private String value = null;

    public void setType(HttpParameterType type) {
        this.type = type;
    }

    public String getName() {
        if (this.name != null) {
            return this.name;
        } else {
            return this.param.name();
        }
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getValue() {
        if (this.value != null) {
            return this.value;
        } else {
            return this.param.value();
        }
    }

    public void setValue(String value) {
        this.value = value;
    }

    public String getUniversalName() {
        if (this.encoding != null) {
            try {
                return StringUtil.getStringCharset(StringUtil.getBytesRaw(param.name()), this.encoding);
            } catch (UnsupportedEncodingException ex) {
                return null;
            }
        } else {
            return StringUtil.getStringRaw(StringUtil.getBytesRaw(param.name()));
        }
    }

    public String getUniversalValue() {
        if (this.encoding != null) {
            try {
                return StringUtil.getStringCharset(StringUtil.getBytesRaw(param.value()), this.encoding);
            } catch (UnsupportedEncodingException ex) {
                return null;
            }
        } else {
            return StringUtil.getStringRaw(StringUtil.getBytesRaw(param.name()));
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

    private static final Pattern MULTIPART_CONTENT_TYPE = Pattern.compile("Content-Type: (.*)", Pattern.CASE_INSENSITIVE);

    public static String getMultipartContentType(byte[] binay, int st, int ed) {
        Matcher m = MULTIPART_CONTENT_TYPE.matcher(StringUtil.getStringRaw(Arrays.copyOfRange(binay, st, ed)));
        if (m.find()) {
            return m.group(1);
        }
        return "";
    }

}
