package yagura.model;

import java.nio.charset.StandardCharsets;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.table.TableModel;
import extend.util.external.TransUtil;
import extension.helpers.StringUtil;
import extension.view.base.DefaultObjectTableModel;

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
                    value = ParamsView.getType(param.getType());
                    break;
                }
                case 2: // Name
                {
                    String raw = param.getName();
                    if (this.urldecode) {
                        value = TransUtil.decodeUrl(raw, encoding);
                    } else {
                        value = StringUtil.getStringCharset(StringUtil.getBytesRaw(raw), encoding);
                    }
                    break;
                }
                case 3: // Value
                {
                    String raw = param.getValue();
                    if (this.urldecode) {
                        value = TransUtil.decodeUrl(raw, encoding);
                    } else {
                        value = StringUtil.getStringCharset(StringUtil.getBytesRaw(raw), encoding);
                    }
                    break;
                }
                default:
                    break;
            }
        } catch (Exception ex) {
            logger.log(Level.SEVERE, null, ex);
        }
        return value;
    }

    @Override
    public void setValueAt(Object value, int rowIndex, int columnIndex) {
        try {
            ParamsView param = new ParamsView();
            switch (columnIndex) {
                case 0: // Data
                    break;
                case 1: // Type
                    param.setType((ParamsView.parseType((String) value)));
                    break;
                case 2: // Name
                    if (this.urldecode) {
                        String raw = StringUtil.getBytesCharsetString((String) value, encoding);
                        raw = TransUtil.encodeUrl(raw, encoding, true);
                        param.setName(raw);
                    } else {
                        String rowMessage = StringUtil.getBytesCharsetString((String) value, encoding);
                        param.setName(rowMessage);
                    }
                    break;
                case 3: // Value
                    if (this.urldecode) {
                        String raw = StringUtil.getBytesCharsetString((String) value, encoding);
                        raw = TransUtil.encodeUrl(raw, encoding, true);
                        param.setValue(raw);
                    } else {
                        String raw = StringUtil.getBytesCharsetString((String) value, encoding);
                        param.setValue(raw);
                    }
                    break;
            }
            super.setData(rowIndex, param);
        } catch (Exception ex) {
            logger.log(Level.SEVERE, null, ex);
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
