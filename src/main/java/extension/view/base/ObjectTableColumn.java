package extension.view.base;

/**
 *
 * @author isayan
 */
public interface ObjectTableColumn {

    public String getColumnName(int column);

    public Class<?> getColumnClass(int columnIndex);

    public int getColumnCount();

}
