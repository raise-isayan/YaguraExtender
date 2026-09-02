package yagura.model;

import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.params.HttpParameterType;
import extension.helpers.SmartCodec;
import extension.helpers.StringUtil;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.table.TableModel;

/**
 *
 * @author isayan
 */
public class ParameterViewModel extends TableMapModel<ParameterView>  {

    private final static Logger logger = Logger.getLogger(ResultView.class.getName());

    public ParameterViewModel(TableModel model) {
        super(ParameterView.class, model);
    }

    private String encoding = StandardCharsets.ISO_8859_1.name();

    public String getEncoding() {
        return this.encoding;
    }

    public void setEncoding(String encoding) {
        this.encoding = encoding;
    }

    private ContentType contentType = ContentType.NONE;

    public ContentType getContentType() {
        return this.contentType;
    }

    public void setContentType(ContentType contentType) {
        this.contentType = contentType;
    }


    @Override
    protected Object getColumnValue(ParameterView param, int column) {
        Object value = null;
        try {
            switch (column) {
                case 0: //
                {
                    value = param;
                    break;
                }
                case 1: // Type
                {
                    value = param.type().name();
                    break;
                }
                case 2: // Name
                {
                    value = param.name();
                    break;
                }
                case 3: // Value
                {
                    value = param.value();
                    break;
                }
                default:
                    break;
            }
        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return value;
    }

    @Override
    protected void setColumnValue(ParameterView param, int column, Object value) {
        try {
            switch (column) {
                case 0: // Data
                    break;
                case 1: // Type
                    param.setType(HttpParameterType.valueOf((String) value));
                    break;
                case 2: // Name
                    param.setName((String) value);
                    break;
                case 3: // Value
                    param.setValue((String) value);
                    break;
            }
        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }

    public static String paramDecode(String value, String encoding, ContentType contentType) throws UnsupportedEncodingException {
        String decodeValue = value;
        switch (contentType) {
            case URL_ENCODED:
                decodeValue = StringUtil.getStringCharset(StringUtil.getBytesRaw(value), encoding);
                decodeValue = SmartCodec.toUrlDecode(decodeValue, encoding);
                break;
            case JSON:
                decodeValue = StringUtil.getStringCharset(StringUtil.getBytesRaw(value), encoding);
                decodeValue = SmartCodec.toUnicodeDecode(decodeValue);
                break;
            case XML:
                decodeValue = StringUtil.getStringCharset(StringUtil.getBytesRaw(value), encoding);
                decodeValue = SmartCodec.toHtmlUnicodeDecode(decodeValue);
                break;
            default:
                break;
        }
        return decodeValue;
    }

    public static String paramEncode(String value, String encoding, ContentType contentType) throws UnsupportedEncodingException {
        String encodeValue = value;
        switch (contentType) {
            case URL_ENCODED:
                encodeValue = SmartCodec.toUrlEncode(value, encoding, SmartCodec.ENCODE_PATTERN_BURP, false);
                break;
            case JSON:
                encodeValue = SmartCodec.toUnicodeEncode(value, SmartCodec.ENCODE_PATTERN_BURP, false);
                break;
            case XML:
                encodeValue = SmartCodec.toHtmlUnicodeEncode(value, SmartCodec.ENCODE_PATTERN_BURP, false);
                break;
            default:
                break;
        }
        return encodeValue;
    }

}
