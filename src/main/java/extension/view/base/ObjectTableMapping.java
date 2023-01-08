package extension.view.base;

public interface ObjectTableMapping {

    public boolean isCellEditable(int columnIndex);

    public Object getObject(int column);

    public void setObject(int column, Object value);

}
