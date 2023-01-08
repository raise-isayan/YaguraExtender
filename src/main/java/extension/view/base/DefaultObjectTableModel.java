package extension.view.base;

import java.util.ArrayList;
import javax.swing.table.AbstractTableModel;

import java.util.List;
import javax.swing.event.TableModelEvent;
import javax.swing.table.TableModel;

public class DefaultObjectTableModel<T extends ObjectTableMapping> extends AbstractTableModel {

    protected List<T> data;
    protected ObjectTableColumn columns;

    public DefaultObjectTableModel(TableModel table) {
        this(new ObjectTableColumn() {
            @Override
            public String getColumnName(int column) {
                return table.getColumnName(column);
            }

            @Override
            public Class<?> getColumnClass(int columnIndex) {
                return table.getColumnClass(columnIndex);
            }

            @Override
            public int getColumnCount() {
                return table.getColumnCount();
            }

        });
    }

    public DefaultObjectTableModel(ObjectTableColumn column) {
        this.columns = column;
        this.data = new ArrayList<T>();
    }

    public T getData(int row) {
        return this.data.get(row);
    }

    public void setData(int row, T data) {
        this.data.set(row, data);
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

    public void addRow(T rowData) {
        insertRow(getRowCount(), rowData);
    }

    public void insertRow(int row, T rowData) {
        this.data.add(row, rowData);
        fireTableRowsInserted(row, row);
    }

    private static int gcd(int i, int j) {
        return (j == 0) ? i : gcd(j, i % j);
    }

    @SuppressWarnings("unchecked")
    private static void rotate(List v, int a, int b, int shift) {
        int size = b - a;
        int r = size - shift;
        int g = gcd(size, r);
        for (int i = 0; i < g; i++) {
            int to = i;
            Object tmp = v.get(a + to);
            for (int from = (to + r) % size; from != i; from = (to + r) % size) {
                v.set(a + to, v.get(a + from));
                to = from;
            }
            v.set(a + to, tmp);
        }
    }

    public void moveRow(int start, int end, int to) {
        int shift = to - start;
        int first, last;
        if (shift < 0) {
            first = to;
            last = end;
        } else {
            first = start;
            last = to + end - start;
        }
        rotate(this.data, first, last + 1, shift);

        fireTableRowsUpdated(first, last);
    }

    public void removeRow(int row) {
        this.data.remove(row);
        fireTableRowsDeleted(row, row);
    }

    /**
     * 全て削除する
     */
    public void removeAll() {
        if (this.getRowCount() > 0) {
            int lastRow = this.getRowCount() - 1;
            this.data.clear();
            fireTableRowsDeleted(0, lastRow);
        }
    }

    //
    // Implementing the TableModel interface
    //
    @Override
    public int getRowCount() {
        return this.data.size();
    }

    @Override
    public int getColumnCount() {
        return this.columns.getColumnCount();
    }

    @Override
    public String getColumnName(int column) {
        return this.columns.getColumnName(column);
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return this.columns.getColumnClass(columnIndex);
    }

    @Override
    public boolean isCellEditable(int row, int column) {
        if (this.editable) {
            return this.data.get(row).isCellEditable(column);
        } else {
            return false;
        }
    }

    @Override
    public Object getValueAt(int row, int column) {
        T obj = this.data.get(row);
        return obj.getObject(column);
    }

    @Override
    public void setValueAt(Object aValue, int row, int column) {
        T obj = this.data.get(row);
        obj.setObject(column, aValue);
        fireTableCellUpdated(row, column);
    }

    private boolean editable = false;

    public void setCellEditable(boolean editable) {
        this.editable = editable;
    }

    public boolean getCellEditable() {
        return this.editable;
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
