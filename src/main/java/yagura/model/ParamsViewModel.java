package yagura.model;

import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.params.HttpParameterType;
import java.nio.charset.StandardCharsets;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.table.TableModel;
import extension.helpers.SmartCodec;
import extension.helpers.StringUtil;
import extension.view.base.DefaultObjectTableModel;
import java.io.UnsupportedEncodingException;

/**
 *
 * @author raise.isayan
 */
public class ParamsViewModel extends DefaultObjectTableModel<ParamsView> {

    private final static Logger logger = Logger.getLogger(ParamsViewModel.class.getName());

    public ParamsViewModel(TableModel model) {
        super(model);
    }

    private boolean editable = false;

    @Override
    public void setCellEditable(boolean enable) {
        this.editable = enable;
    }

    @Override
    public boolean getCellEditable() {
        return this.editable;
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return this.editable;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        Object value = null;
        try {
            ParamsView param = super.getData(rowIndex);
            switch (columnIndex) {
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
                    String rawValue = param.name();
                    if (this.getContentType() != ContentType.NONE) {
                        value = paramDecode((String) rawValue, encoding, this.getContentType());

                    } else {
                        value = StringUtil.getStringCharset(StringUtil.getBytesRaw(rawValue), encoding);
                    }
                    break;
                }
                case 3: // Value
                {
                    String rawValue = param.value();
                    if (this.getContentType() != ContentType.NONE) {
                        value = paramDecode((String) rawValue, encoding, this.getContentType());
                    } else {
                        value = StringUtil.getStringCharset(StringUtil.getBytesRaw(rawValue), encoding);
                    }
                    break;
                }
                default:
                    break;
            }
        } catch (UnsupportedEncodingException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return value;
    }

    @Override
    public void setValueAt(Object value, int rowIndex, int columnIndex) {
        try {
            ParamsView param = super.getData(rowIndex);
            switch (columnIndex) {
                case 0: // Data
                    break;
                case 1: // Type
                    param.getParameter().setType((HttpParameterType.valueOf((String) value)));
                    break;
                case 2: // Name
                    if (this.getContentType() != ContentType.NONE) {
                        String encodeValue = paramEncode((String) value, encoding, this.getContentType());
                        param.getParameter().setName(encodeValue);
                    } else {
                        String rawValue = StringUtil.getBytesCharsetString((String) value, encoding);
                        param.getParameter().setName(rawValue);
                    }
                    break;
                case 3: // Value
                    if (this.getContentType() != ContentType.NONE) {
                        String encodeValue = paramEncode((String) value, encoding, this.getContentType());
                        param.getParameter().setValue(encodeValue);
                    } else {
                        String rawValue = StringUtil.getBytesCharsetString((String) value, encoding);
                        param.getParameter().setValue(rawValue);
                    }
                    break;
            }
            super.setData(rowIndex, param);
        } catch (UnsupportedEncodingException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
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
                encodeValue = SmartCodec.toUnocodeEncode(value, SmartCodec.ENCODE_PATTERN_BURP, false);
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
