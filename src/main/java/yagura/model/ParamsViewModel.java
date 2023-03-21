package yagura.model;

import burp.api.montoya.http.message.params.HttpParameterType;
import java.nio.charset.StandardCharsets;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.table.TableModel;
import extend.util.external.TransUtil;
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
                    String raw = param.name();
                    if (this.urldecode) {
                        value = SmartCodec.toUrlDecode(raw, encoding);
                    } else {
                        value = StringUtil.getStringCharset(StringUtil.getBytesRaw(raw), encoding);
                    }
                    break;
                }
                case 3: // Value
                {
                    String raw = param.value();
                    if (this.urldecode) {
                        value = SmartCodec.toUrlDecode(raw, encoding);
                    } else {
                        value = StringUtil.getStringCharset(StringUtil.getBytesRaw(raw), encoding);
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
                    if (this.urldecode) {
                        String raw = StringUtil.getBytesCharsetString((String) value, encoding);
                        raw = SmartCodec.toUrlEncode(raw, encoding, true);
                        param.getParameter().setName(raw);
                    } else {
                        String rowMessage = StringUtil.getBytesCharsetString((String) value, encoding);
                        param.getParameter().setName(rowMessage);
                    }
                    break;
                case 3: // Value
                    if (this.urldecode) {
                        String raw = StringUtil.getBytesCharsetString((String) value, encoding);
                        raw = SmartCodec.toUrlEncode(raw, encoding, true);
                        param.getParameter().setValue(raw);
                    } else {
                        String raw = StringUtil.getBytesCharsetString((String) value, encoding);
                        param.getParameter().setValue(raw);
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

    private boolean urldecode = false;

    public boolean getUrlDecode() {
        return this.urldecode;
    }

    public void setUrlDeocde(boolean urldecode) {
        this.urldecode = urldecode;
    }

}
