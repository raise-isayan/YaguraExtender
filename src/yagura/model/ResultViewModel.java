/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package yagura.model;

import extend.model.base.ObjectTableModel;
import extend.view.base.NamedColor;
import extend.util.BurpWrap;
import extend.view.base.HttpRequest;
import extend.view.base.MatchItem;
import java.awt.Color;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.table.TableModel;

/**
 *
 * @author isayan
 */
public class ResultViewModel extends ObjectTableModel<HttpMessageItem> {

    public ResultViewModel(TableModel model) {
        super(model);
    }

    public ResultViewModel(TableModel model, List<HttpMessageItem> d) {
        super(model, d);
    }

    @Override
    public Object getValueAt(int row, int col) {
        Object value = null;
        try {
            if (row < 0 || row >= this.getRowCount()) {
                return value;
            }
            HttpMessageItem msg = this.getData(row);
            switch (col) {
                case 0: // 
                    value = msg;
                    break;
                case 1: // #
                    int ordinal = (msg.getOrdinal() >= 0) ? msg.getOrdinal() : row;
                    Color highlightColor = null;
                    String color = BurpWrap.getHighlightColor(msg);
                    if (color != null) {
                        MatchItem.HighlightColor hc = MatchItem.HighlightColor.parseValue(color);
                        highlightColor = hc.toColor();
                        value = new NamedColor(highlightColor, String.valueOf(ordinal + 1));
                    }
                    if (value == null) {
                        value = new NamedColor(Color.WHITE, String.valueOf(ordinal + 1));
                    }
                    break;
                case 2: // host
                    value = msg.getProtocol() + "://" + msg.getHost();
                    break;
                case 3: // method
                    HttpRequest reqmsg = HttpRequest.parseHttpRequest(msg.getRequest());
                    value = reqmsg.getMethod();
                    break;
                case 4: // url
                    value = String.valueOf(msg.getUrl());
                    break;
                case 5: // status code
                    value = String.valueOf((int) msg.getStatusCode());
                    break;
                case 6: // length
                    value = 0;
                    if (msg.getResponse() != null) {
                        value = msg.getResponse().length;
                    }
                    break;
                case 7: // comment
                    value = msg.getComment();
                    break;
            }
        } catch (Exception ex) {
            Logger.getLogger(ResultViewModel.class.getName()).log(Level.SEVERE, null, ex);
        }
        return value;
    }

    @Override
    public void setValueAt(Object value, int row, int col) {
        try {
            HttpMessageItem msg = this.getData(row);
            switch (col) {
                case 0: // Data
                    break;
                case 1: // #
                    if (value instanceof NamedColor) {
                        NamedColor nc = (NamedColor) value;
                        BurpWrap.setHighlightColor(msg, nc.toString());
                    } else {
                        BurpWrap.setHighlightColor(msg, null);
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
            this.fireTableDataChanged();
        } catch (Exception ex) {
            Logger.getLogger(ResultViewModel.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    @Override
    public Object[] getRows(int row) {
        try {
            HttpMessageItem msg = this.getData(row);
            return new Object[]{row, msg.getHost(), String.valueOf(msg.getUrl()), String.valueOf((int) msg.getStatusCode()), msg.getComment()};
        } catch (Exception ex) {
            Logger.getLogger(ResultViewModel.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
    
}
