/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package yagura.model;

import burp.IParameter;
import extend.model.base.ObjectTableModel;
import extend.util.Util;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.table.TableModel;

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
                    value = param;
                    break;
                case 1: // Type
                    value = getType(param.getType());
                    break;
                case 2: // Name
//                    value = param.getName();
                    value = Util.decodeMessage(Util.getRawByte(param.getName()), encoding);
                    break;
                case 3: // Value
//                    value = param.getValue();
                    value = Util.decodeMessage(Util.getRawByte(param.getValue()), encoding);
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
            IParameter param = this.getData(row);
            switch (col) {
                case 0: // Data
                    break;
                case 1: // Type
                    break;
                case 2: // Name
                    break;
                case 3: // Value
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

}
