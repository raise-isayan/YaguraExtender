package yagura.model;

import com.google.gson.annotations.Expose;
import extend.util.external.TransUtil;
import extension.burp.IPropertyConfig;
import extension.helpers.json.JsonUtil;
import java.nio.charset.StandardCharsets;

/**
 *
 * @author isayan
 */
public class YaguraProperty implements IPropertyConfig {

    public final static String YAGURA_PROPERTY = "YaguraProperty";

    @Expose
    private String selectEncoding = StandardCharsets.UTF_8.name();

    /**
     * @return the selectEncoding
     */
    public String getSelectEncoding() {
        return selectEncoding;
    }

    /**
     * @param selectEncoding the selectEncoding to set
     */
    public void setSelectEncoding(String selectEncoding) {
        this.selectEncoding = selectEncoding;
    }

    @Expose
    private TransUtil.EncodeType encodeType = TransUtil.EncodeType.ALL;

    /**
     * @return the encodeType
     */
    public TransUtil.EncodeType getEncodeType() {
        return encodeType;
    }

    /**
     * @param encodeType the encodeType to set
     */
    public void setEncodeType(TransUtil.EncodeType encodeType) {
        this.encodeType = encodeType;
    }

    public void setProperty(YaguraProperty property) {
        this.setSelectEncoding(property.getSelectEncoding());
        this.setEncodeType(property.getEncodeType());
    }

    @Override
    public String getSettingName() {
        return YAGURA_PROPERTY;
    }

    @Override
    public void saveSetting(String value) {
        YaguraProperty property = JsonUtil.jsonFromString(value, YaguraProperty.class, true);
        this.setProperty(property);
    }

    @Override
    public String loadSetting() {
        return JsonUtil.jsonToString(this, true);
    }

    @Override
    public String defaultSetting() {
        YaguraProperty property = new YaguraProperty();
        return JsonUtil.jsonToString(property, true);
    }

}
