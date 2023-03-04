package yagura.model;

import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import extension.view.base.ObjectTableColumn;
import extension.view.base.ObjectTableMapping;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author isayan
 */
public class ParamsView implements ObjectTableMapping, ParsedHttpParameter {

    private final static Logger logger = Logger.getLogger(ParamsView.class.getName());

    final Parameter param;

    public ParamsView() {
        this.param = Parameter.newPameter();
    }

    public ParamsView(Parameter param) {
        this.param = param;
    }

    public ParamsView(ParsedHttpParameter param) {
        this.param = new Parameter(param);
    }

    public static String getType(HttpParameterType type) {
        String result = "-";
        switch (type) {
            case URL:
                result = "URL";
                break;
            case BODY:
                result = "Body";
                break;
            case COOKIE:
                result = "Cookie";
                break;
            case XML:
                result = "XML";
                break;
            case XML_ATTRIBUTE:
                result = "attr";
                break;
            case MULTIPART_ATTRIBUTE:
                result = "(file)";
                break;
            case JSON:
                result = "JSON";
                break;
        }
        return result;
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
    public void setObject(int column, Object value) {
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

    public Parameter getParameter() {
        return this.param;
    }

    @Override
    public Range nameOffsets() {
        return this.param.nameOffsets();
    }

    @Override
    public Range valueOffsets() {
        return this.param.valueOffsets();
    }

    @Override
    public HttpParameterType type() {
        return this.param.type();
    }

    @Override
    public String name() {
        return this.param.name();
    }

    @Override
    public String value() {
        return this.param.value();
    }
}
