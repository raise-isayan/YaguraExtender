package yagura.model;

import burp.IParameter;
import extend.model.base.ObjectTableColumn;
import extend.model.base.ObjectTableMapping;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author isayan
 */
public class ParamsView extends Parameter implements ObjectTableMapping {

    public ParamsView(IParameter parameter) {
        super(parameter);
    }

    public ParamsView() {
        super(Parameter.newPameter());
    }

    private final String[] columns = new String[]{
        "Data", "Type", "Name", "Value"
    };

    public ObjectTableColumn getColumn() {
        return new ObjectTableColumn() {
            @Override
            public String getColumnName(int column) {
                return columns[column];
            }

            @Override
            public Class<?> getColumnClass(int columnIndex) {
                return Object.class;
            }

            @Override
            public int getColumnCount() {
                return columns.length;
            }
        };
    }

    private final boolean[] canEdit = new boolean[]{
        false, false, false, false
    };

    @Override
    public boolean isCellEditable(int columnIndex) {
        return canEdit[columnIndex];
    }

    @Override
    public Object getObject(int column) {
        Object value = null;
        try {
            IParameter param = this;
            switch (column) {
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
                    value = param.getName();
                    break;
                }
                case 3: // Value
                {
                    value = param.getValue();
                    break;
                }
                default:
                    break;
            }
        } catch (Exception ex) {
            Logger.getLogger(ParamsView.class.getName()).log(Level.SEVERE, null, ex);
        }
        return value;
    }

    @Override
    public void setObject(int column, Object value) {
        try {
            Parameter param = this;
            switch (column) {
                case 0: // Data
                    break;
                case 1: // Type
                    param.setType((parseType((String) value)));
                    break;
                case 2: // Name
                    param.setName((String) value);
                    break;
                case 3: // Value
                    param.setValue((String) value);
                    break;
            }
        } catch (Exception ex) {
            Logger.getLogger(ParamsView.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private final static String[] TYPES = {"URL", "Body", "Cookie", "XML", "-", "(file)", "JSON"};

    public static String getType(byte type) {
        return TYPES[type];
    }

    public static byte parseType(String type) {
        for (int i = 0; i < TYPES.length; i++) {
            if (TYPES[i].equals(type)) {
                return (byte) i;
            }
        }
        return (byte) -1;
    }

}
