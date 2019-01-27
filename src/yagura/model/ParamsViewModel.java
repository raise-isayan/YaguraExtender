package yagura.model;

import burp.IParameter;
import extend.model.base.ObjectTableModel;
import extend.util.Util;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.table.TableModel;
import yagura.external.TransUtil;

/**
 *
 * @author raise.isayan
 */
public class ParamsViewModel extends ObjectTableModel<Parameter> {

    public ParamsViewModel(TableModel model) {
        super(model);
    }

    public ParamsViewModel(TableModel model, List<Parameter> d) {
        super(model, d);
    }

    private boolean editable = false;
    public void setCellEditable(boolean enable) {
        this.editable = enable;
    }
        
    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return this.editable;
    }
    
    @Override
    public Object getValueAt(int row, int col) {
        Object value = null;
        try {
            if (row < 0 || row >= this.getRowCount()) {
                return value;
            }
            IParameter param = this.getData(row);
            switch (col) {
                case 0: // 
                {
                    value = param;
                    break;
                }
                case 1: // Type
                {
                    value = getType(param.getType());
                    break;
                }
                case 2: // Name
                {
                    String raw = param.getName();
                    if (this.urldecode) {
                        value = TransUtil.decodeUrl(raw, encoding);
                    }
                    else {
                        value = Util.decodeMessage(Util.getRawByte(raw), encoding);                
                    }
                    break;
                }
                case 3: // Value
                {
                    String raw = param.getValue();
                    if (this.urldecode) {
                        value = TransUtil.decodeUrl(raw, encoding);
                    }
                    else {
                        value = Util.decodeMessage(Util.getRawByte(raw), encoding);
                    }
                    break;
                }
                default:
                    break;
            }
        } catch (Exception ex) {
            Logger.getLogger(ParamsViewModel.class.getName()).log(Level.SEVERE, null, ex);
        }
        return value;
    }

    @Override
    public void setValueAt(Object value, int row, int col) {
        try {
            Parameter param = this.getData(row);
            switch (col) {
                case 0: // Data
                    break;
                case 1: // Type
                    param.setType((parseType((String)value)));
                    break;
                case 2: // Name
                    param.setName((String)value);
                    break;
                case 3: // Value
                    param.setValue((String)value);
                    break;
            }
            this.fireTableDataChanged();
        } catch (Exception ex) {
            Logger.getLogger(ParamsViewModel.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private final static String[] TYPES = {"URL", "Body", "Cookie", "XML", "-", "(file)", "JSON"};

    public static String getType(byte type) {
        return TYPES[type];
    }

    public static byte parseType(String type) {
        for (int i = 0; i < TYPES.length; i++) {
            if (TYPES[i].equals(type)) return (byte)i;
        }
        return (byte)-1;
    }
        
    @Override
    public Object[] getRows(int row) {
        try {
            IParameter msg = this.getData(row);
            return new Object[]{row, msg.getType(), msg.getName(), msg.getValue()};
        } catch (Exception ex) {
            Logger.getLogger(ParamsViewModel.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    private String encoding = "8859_1";

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
