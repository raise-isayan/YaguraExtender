package yagura.model;

import extension.burp.HttpTarget;
import extension.burp.MessageHighlightColor;
import extension.helpers.StringUtil;
import extension.view.base.NamedColor;
import java.awt.Color;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.table.TableModel;

/**
 *
 * @author isayan
 */
public class ResultViewModel extends TableMapModel<ResultView> {

    private final static Logger logger = Logger.getLogger(ResultView.class.getName());

    public ResultViewModel(TableModel model) {
        super(ResultView.class, model);
    }

    @Override
    protected Object getColumnValue(ResultView msg, int column) {
        Object value = null;
        try {
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
                    String protocol = HttpTarget.getProtocol(msg.finalRequest().httpService().secure());
                    value = protocol + "://" + msg.getHost();
                    break;
                case 3: // method
                    value = msg.finalRequest().method();
                    break;
                case 4: // url
                    value = StringUtil.toString(msg.getUrl());
                    break;
                case 5: // status code
                    value = 0;
                    if (msg.getResponse() != null) {
                        value = StringUtil.toString((int) msg.getStatusCode());
                    }
                    break;
                case 6: // length
                    value = 0;
                    if (msg.getResponse() != null) {
                        value = msg.getResponse().length;
                    }
                    break;
                case 7: // comment
                    value = msg.getNotes();
                    break;
                case 8: // listener port
                    value = msg.getListenerPort();
                    break;
            }
        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return value;
    }

    @Override
    protected void setColumnValue(ResultView msg, int column, Object value) {
        try {
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
                    msg.setNotes((String) value);
                    break;
                case 8: // listener port
                    break;
            }
        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }

    public void removeAll() {
        this.clear();
    }


}
