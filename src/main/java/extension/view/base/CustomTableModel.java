package extension.view.base;

import javax.swing.JTable;
import javax.swing.event.TableModelEvent;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableModel;

/**
 *
 * @author isayan
 */
public class CustomTableModel extends DefaultTableModel {

    public CustomTableModel() {
        super();
    }

    public CustomTableModel(int rowCount, int columnCount) {
        super(rowCount, columnCount);
    }

    public CustomTableModel(Object[][] data, Object[] columnNames) {
        super(data, columnNames);
    }
    private TableModel model = null;

    public CustomTableModel(TableModel model) {
        super();
        this.model = model;
        String[] columns = new String[model.getColumnCount()];
        for (int i = 0; i < columns.length; i++) {
            columns[i] = model.getColumnName(i);
        }
        Object[][] datas = new Object[model.getRowCount()][model.getColumnCount()];
        for (int i = 0; i < datas.length; i++) {
            for (int j = 0; j < datas[i].length; j++) {
                datas[i][j] = model.getValueAt(i, j);
            }
        }
        this.setDataVector(datas, columns);
    }

    @Override
    public Class getColumnClass(int columnIndex) {
        if (this.model != null) {
            return this.model.getColumnClass(columnIndex);
        } else {
            return this.getColumnClass(columnIndex);
        }
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        if (this.model != null) {
            return this.model.isCellEditable(rowIndex, columnIndex);
        } else {
            return super.isCellEditable(rowIndex, columnIndex);
        }
    }

    /**
     * 上へ移動
     *
     * @param index インデックス
     * @return 移動後の index
     */
    public int moveUp(int index) {
        if (0 < index) {
            this.moveRow(index, index, index - 1);
            index--;
        }
        return index;
    }

    /**
     * 下へ移動
     *
     * @param index インデックス
     * @return 移動後の index
     */
    public int moveDn(int index) {
        if (-1 < index && index < this.getRowCount() - 1) {
            this.moveRow(index, index, index + 1);
            index++;
        }
        return index;
    }

    /**
     * 全て削除する
     */
    public void removeAll() {
        synchronized (this) {
            for (int i = this.getRowCount() - 1; i >= 0; i--) {
                this.removeRow(i);
            }
        }
    }

    /**
     * 指定したRowのObject配列を取得する
     *
     * @param rowIndex RowIndex
     * @return Object配列
     */
    public Object[] getRows(int rowIndex) {
        Object editRows[] = new Object[this.getColumnCount()];
        for (int j = 0; j < editRows.length; j++) {
            editRows[j] = this.getValueAt(rowIndex, j);
        }
        return editRows;
    }

    public static String tableCopy(JTable table) {
        return tableCopy(table, false);
    }

    public static String tableCopy(JTable table, boolean visible) {
        StringBuilder buffer = new StringBuilder();
        int[] rowsSelected = table.getSelectedRows();
        int[] colsSelected = table.getSelectedColumns();
        for (int i = 0; i < rowsSelected.length; i++) {
            int cnt = 0;
            for (int j = 0; j < colsSelected.length; j++) {
                if (0 < cnt) {
                    buffer.append("\t");
                }
                if (visible && table.getColumnModel().getColumn(colsSelected[j]).getPreferredWidth() > 0) {
                    Object value = table.getValueAt(rowsSelected[i], colsSelected[j]);
                    if (value != null) {
                        buffer.append(value);
                    }
                    cnt++;
                }
            }
            buffer.append(System.lineSeparator());
        }
        return buffer.toString();
    }

    private boolean lockUpdate = false;

    public synchronized void beginUpdate() {
        this.lockUpdate = true;
    }

    public synchronized void endUpdate() {
        this.lockUpdate = false;
    }

    @Override
    public void fireTableChanged(TableModelEvent e) {
        if (!this.lockUpdate) {
            super.fireTableChanged(e);
        }
    }

}
