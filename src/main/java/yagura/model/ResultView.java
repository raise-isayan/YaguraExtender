package yagura.model;

import burp.api.montoya.http.message.HttpRequestResponse;
import extension.burp.HttpTarget;
import extension.burp.MessageHighlightColor;
import extension.helpers.StringUtil;
import extension.view.base.NamedColor;
import extension.view.base.ObjectTableColumn;
import extension.view.base.ObjectTableMapping;
import java.awt.Color;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author isayan
 */
public class ResultView extends HttpMessageItem implements ObjectTableMapping {
    private final static Logger logger = Logger.getLogger(ResultView.class.getName());

    public ResultView() {
    }

    public ResultView(HttpMessageItem item) {
        super(item);
    }

    public ResultView(HttpRequestResponse item, int ordinal) {
        super(item, ordinal);
    }

    private final String[] columns = new String[]{
        "Data", "#", "host", "method", "URL", "status", "length", "comment"
    };

    public ObjectTableColumn getColumn() {
        return new ObjectTableColumn() {

            @Override
            public String getColumnName(int column) {
                return columns[column];
            }

            @Override
            public int getColumnCount() {
                return columns.length;
            }

            @Override
            public Class<?> getColumnClass(int columnIndex) {
                return Object.class;
            }

        };
    }

    private final boolean[] canEdit = new boolean[]{
        false, true, false, false, false, false, false, true
    };

    @Override
    public boolean isCellEditable(int columnIndex) {
        return canEdit[columnIndex];
    }

    @Override
    public Object getObject(int column) {
        Object value = null;
        try {
            HttpMessageItem msg = this;
            switch (column) {
                case 0: //
                    value = msg;
                    break;
                case 1: // #
                    int ordinal = msg.getOrdinal();
                    MessageHighlightColor hc = msg.getHighlightColor();
                    Color highlightColor = hc.toColor();
                    value = new NamedColor(highlightColor, StringUtil.toString(ordinal + 1));
                    break;
                case 2: // host
                    String protocol = HttpTarget.getProtocol(msg.httpRequest().httpService().secure());
                    value = protocol + "://" + msg.getHost();
                    break;
                case 3: // method
                    value = msg.httpRequest().method();
                    break;
                case 4: // url
                    value = StringUtil.toString(msg.getUrl());
                    break;
                case 5: // status code
                    value = 0;
                    if (this.getResponse() != null) {
                        value = StringUtil.toString((int) msg.getStatusCode());
                    }
                    break;
                case 6: // length
                    value = 0;
                    if (this.getResponse() != null) {
                        value = msg.getResponse().length;
                    }
                    break;
                case 7: // comment
                    value = msg.getComment();
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
            HttpMessageItem msg = this;
            switch (column) {
                case 0: // Data
                    break;
                case 1: // #
                    if (value instanceof NamedColor nc) {
                        msg.setHighlight(nc.toString());
                    } else {
                        msg.setHighlight(null);
                    }
                    break;

                case 2: // host
                    break;
                case 3: // method
                    break;
                case 4: // url
                    break;
                case 5: // status code
                    break;
                case 6: // length
                    break;
                case 7: // commment
                    msg.setComment((String) value);
                    break;
            }
        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }

}
