package yagura.model;

import java.beans.BeanInfo;
import java.beans.IntrospectionException;
import java.beans.Introspector;
import java.beans.PropertyDescriptor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.function.Predicate;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;

/**
 * JTable の各行を Bean ({@link TableMapBase} のサブクラス) にマッピングする TableModel。
 *
 * <h2>使い方 1: アノテーションでマッピング</h2>
 * <pre>
public class Bean extends TableMapBase {
    &#64;TableMapColumn(index = 0) private boolean selected;
     &#64;TableMapColumn(index = 1) private String type;
     &#64;TableMapColumn(index = 2) private String replace;
     // getter / setter
 }

 TableMapModel&lt;Bean&gt; model = new TableMapModel&lt;&gt;(Bean.class, table.getModel());
 * table.setModel(model);
 * </pre>
 *
 * <h2>使い方 2: プロパティ名の並びでマッピング (アノテーション不要)</h2>
 * <pre>
 TableMapModel&lt;Bean&gt; model =
         new TableMapModel&lt;&gt;(Bean.class, table.getModel(), "selected", "type", "replace");
 * </pre>
 *
 * <h2>使い方 3: switch 文で自前マッピング</h2>
 * {@link #getColumnValue(BaseBean, int)} / {@link #setColumnValue(BaseBean, int, Object)}
 * をオーバーライドすれば、リフレクションを使わず元のイメージ通りの switch 実装にできます。
 *
 * <p>
 * 第 2 引数の {@code template} には、GUI ビルダ (NetBeans など) が生成した
 * {@code table.getModel()} をそのまま渡せます。カラム見出し・カラム型・編集可否を
 * そこから引き継ぎます (null 可)。
 *
 * <p><b>注意</b>: JTable に {@code RowSorter} を設定している場合、ビューの行番号と
 * モデルの行番号は一致しません。{@code table.convertRowIndexToModel(viewRow)} で
 * 変換してから {@link #getBean(int)} を呼んでください。
 *
 * @param <T> 1 行に対応する Bean の型
 */
public class TableMapModel<T extends TableMapBase> extends AbstractTableModel implements Iterable<T> {

    private final Class<T> beanClass;
    private final List<ColumnMeta> columns;
    private final List<T> rows = new ArrayList<>();

    /** アノテーションのみからカラムを構築します。
     * @param beanClass */
    public TableMapModel(Class<T> beanClass) {
        this(beanClass, null);
    }

    /**
     * アノテーションからカラムを構築し、見出し・型・編集可否をテンプレートで上書きします。
     *
     * @param beanClass 行に対応する Bean のクラス
     * @param template  {@code table.getModel()} など。null 可
     */
    public TableMapModel(Class<T> beanClass, TableModel template) {
        this(beanClass, template, (String[]) null);
    }

    /**
     * カラム順に対応するプロパティ名を明示して構築します。
     *
     * @param beanClass     行に対応する Bean のクラス
     * @param template      {@code table.getModel()} など。null 可
     * @param propertyNames カラム 0,1,2... に対応するプロパティ名。
     *                      null または空の場合はアノテーションを使用します。
     *                      マッピング不要のカラムは null または "" を指定します。
     */
    public TableMapModel(Class<T> beanClass, TableModel template, String [] propertyNames) {
        if (beanClass == null) {
            throw new IllegalArgumentException("beanClass must not be null");
        }
        this.beanClass = beanClass;
        this.columns = buildColumns(beanClass, template, propertyNames);
        if (this.columns.isEmpty()) {
            throw new IllegalArgumentException(
                    "カラムを決定できません: " + beanClass.getName()
                    + " に @BeanColumn が無く、propertyNames も template も指定されていません。");
        }
    }

    // ======================================================================
    // TableModel の実装
    // ======================================================================

    private boolean editable = false;

    public void setCellEditable(boolean editable) {
        this.editable = editable;
    }

    public boolean getCellEditable() {
        return this.editable;
    }

    @Override
    public int getRowCount() {
        return this.rows.size();
    }

    @Override
    public int getColumnCount() {
        return this.columns.size();
    }

    @Override
    public String getColumnName(int column) {
        return this.columns.get(column).name;
    }

    @Override
    public Class<?> getColumnClass(int column) {
        return this.columns.get(column).columnClass;
    }

    @Override
    public boolean isCellEditable(int row, int column) {
        if (this.editable) {
            return this.columns.get(column).editable;
        }
        return false;
    }

    @Override
    public Object getValueAt(int row, int column) {
        T bean = getBean(row);
        if (bean == null) {
            return null;
        }
        return getColumnValue(bean, column);
    }

    @Override
    public void setValueAt(Object value, int row, int column) {
        T bean = getBean(row);
        if (bean == null) {
            return;
        }
        setColumnValue(bean, column, value);
        fireTableCellUpdated(row, column);
    }

    // ======================================================================
    // マッピング (オーバーライド可能なフック)
    // ======================================================================

    /**
     * カラム番号に対応する値を Bean から取り出します。
     * switch 文で自前実装したい場合はここをオーバーライドしてください。
     */
    protected Object getColumnValue(T bean, int column) {
        ColumnMeta meta = this.columns.get(column);
        if (meta.accessor == null) {
            return null;
        }
        return meta.accessor.get(bean);
    }

    /**
     * カラム番号に対応する値を Bean へ格納します。
     * switch 文で自前実装したい場合はここをオーバーライドしてください。
     */
    protected void setColumnValue(T bean, int column, Object value) {
        ColumnMeta meta = this.columns.get(column);
        if (meta.accessor == null) {
            return;
        }
        meta.accessor.set(bean, value);
    }

    // ======================================================================
    // Bean 操作 API
    // ======================================================================

    /**
     * 全て削除する
     */
    public void removeAll() {
        if (this.getRowCount() > 0) {
            int lastRow = this.getRowCount() - 1;
            this.clear();
            fireTableRowsDeleted(0, lastRow);
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
        rotate(this.rows, first, last + 1, shift);

        fireTableRowsUpdated(first, last);
    }

    /** 指定行の Bean を返します (範囲外は null)。 */
    public T getBean(int row) {
        if (row < 0 || row >= this.rows.size()) {
            return null;
        }
        return this.rows.get(row);
    }

    /** 指定行の Bean を差し替えます。 */
    public void setBean(int row, T bean) {
        this.rows.set(row, bean);
        fireTableRowsUpdated(row, row);
    }

    /** 全行の Bean を変更不可の List として返します。 */
    public List<T> getBeans() {
        return Collections.unmodifiableList(new ArrayList<>(this.rows));
    }

    /** テーブルの内容を beans で置き換えます。 */
    public void setBeans(Collection<? extends T> beans) {
        this.rows.clear();
        if (beans != null) {
            this.rows.addAll(beans);
        }
        fireTableDataChanged();
    }

    /** 末尾に 1 行追加します。 */
    public int addBean(T bean) {
        this.rows.add(bean);
        int row = this.rows.size() - 1;
        fireTableRowsInserted(row, row);
        return row;
    }

    /** 末尾に複数行追加します。 */
    public void addBeans(Collection<? extends T> beans) {
        if (beans == null || beans.isEmpty()) {
            return;
        }
        int first = this.rows.size();
        this.rows.addAll(beans);
        fireTableRowsInserted(first, this.rows.size() - 1);
    }

    /** 指定位置に 1 行挿入します。 */
    public void insertBean(int row, T bean) {
        this.rows.add(row, bean);
        fireTableRowsInserted(row, row);
    }

    /** 引数なしコンストラクタで新しい Bean を生成して末尾に追加します。 */
    public T addRow() {
        T bean = newBean();
        addBean(bean);
        return bean;
    }

    /** 引数なしコンストラクタで Bean を生成します (テーブルには追加しません)。 */
    public T newBean() {
        try {
            return this.beanClass.getDeclaredConstructor().newInstance();
        } catch (ReflectiveOperationException ex) {
            throw new IllegalStateException(
                    this.beanClass.getName() + " に public な引数なしコンストラクタが必要です", ex);
        }
    }

    /** 指定行を削除します。 */
    public T removeRow(int row) {
        T removed = this.rows.remove(row);
        fireTableRowsDeleted(row, row);
        return removed;
    }

    /** 指定 Bean を削除します。 */
    public boolean removeBean(T bean) {
        int row = indexOf(bean);
        if (row < 0) {
            return false;
        }
        removeRow(row);
        return true;
    }

    /** 全行を削除します。 */
    public void clear() {
        if (this.rows.isEmpty()) {
            return;
        }
        this.rows.clear();
        fireTableDataChanged();
    }

    /** Bean の行番号を返します (見つからない場合は -1)。同一性は equals で判定します。 */
    public int indexOf(T bean) {
        return this.rows.indexOf(bean);
    }

    /** 条件に一致する Bean だけを抽出します (例: 選択された行のみ)。 */
    public List<T> filter(Predicate<? super T> predicate) {
        List<T> list = new ArrayList<>();
        for (T bean : this.rows) {
            if (predicate.test(bean)) {
                list.add(bean);
            }
        }
        return list;
    }

    /** Bean のクラスを返します。 */
    public Class<T> getBeanClass() {
        return this.beanClass;
    }

    /** プロパティ名からカラム番号を返します (見つからない場合は -1)。 */
    public int getColumnIndex(String propertyName) {
        for (int i = 0; i < this.columns.size(); i++) {
            if (this.columns.get(i).property != null
                    && this.columns.get(i).property.equals(propertyName)) {
                return i;
            }
        }
        return -1;
    }

    @Override
    public Iterator<T> iterator() {
        return getBeans().iterator();
    }

    // ======================================================================
    // カラム定義の構築
    // ======================================================================

    private static List<ColumnMeta> buildColumns(Class<?> beanClass, TableModel template,
            String[] propertyNames) {

        Map<String, PropertyDescriptor> descriptors = descriptors(beanClass);
        List<ColumnMeta> list = new ArrayList<>();

        if (propertyNames != null && propertyNames.length > 0) {
            // --- プロパティ名の並びで構築 ---
            for (int i = 0; i < propertyNames.length; i++) {
                String property = propertyNames[i];
                Accessor accessor = (property == null || property.isEmpty())
                        ? null : createAccessor(beanClass, descriptors, property);
                Class<?> type = (accessor == null) ? Object.class : box(accessor.type());
                list.add(new ColumnMeta(property, columnName(template, i, property),
                        columnClass(template, i, type), editable(template, i, true), accessor));
            }
        } else {
            // --- @TableMapColumn アノテーションで構築 ---
            Map<Integer, Annotated> annotated = scanAnnotations(beanClass);
            if (annotated.isEmpty()) {
                if (template == null) {
                    return list; // 呼び出し元で例外
                }
                // アノテーションが無い場合はテンプレートの定義だけでカラムを作る。
                // (getColumnValue / setColumnValue のオーバーライド前提)
                for (int i = 0; i < template.getColumnCount(); i++) {
                    list.add(new ColumnMeta(null, template.getColumnName(i),
                            box(template.getColumnClass(i)), editable(template, i, true), null));
                }
                return list;
            }
            int max = Collections.max(annotated.keySet());
            for (int i = 0; i <= max; i++) {
                Annotated a = annotated.get(i);
                if (a == null) {
                    list.add(new ColumnMeta(null, columnName(template, i, "column" + i),
                            columnClass(template, i, Object.class),
                            editable(template, i, false), null));
                    continue;
                }
                Accessor accessor = createAccessor(beanClass, descriptors, a.property);
                Class<?> type = (a.column.type() != Void.class)
                        ? box(a.column.type()) : box(accessor.type());
                String name = !a.column.name().isEmpty()
                        ? a.column.name() : columnName(template, i, a.property);
                list.add(new ColumnMeta(a.property, name,
                        columnClass(template, i, type),
                        editable(template, i, a.column.editable()), accessor));
            }
        }

        if (template != null && template.getColumnCount() > list.size()) {
            throw new IllegalArgumentException(
                    "カラム数が一致しません。JTable のカラム数=" + template.getColumnCount()
                    + " / Bean のマッピング数=" + list.size()
                    + " (" + beanClass.getName() + ")");
        }
        return list;
    }

    private static String columnName(TableModel template, int index, String fallback) {
        if (template != null && index < template.getColumnCount()) {
            String name = template.getColumnName(index);
            if (name != null && !name.isEmpty()) {
                return name;
            }
        }
        return fallback;
    }

    private static Class<?> columnClass(TableModel template, int index, Class<?> fallback) {
        if (fallback != null && fallback != Object.class) {
            return fallback;
        }
        if (template != null && index < template.getColumnCount()) {
            Class<?> type = template.getColumnClass(index);
            if (type != null) {
                return box(type);
            }
        }
        return (fallback == null) ? Object.class : fallback;
    }

    private static boolean editable(TableModel template, int index, boolean fallback) {
        if (template != null && index < template.getColumnCount()) {
            try {
                // NetBeans が生成する DefaultTableModel は canEdit[] を行番号に関係なく返す
                return template.isCellEditable(0, index);
            } catch (RuntimeException ex) {
                // 行が無い等で判定できない場合は既定値
            }
        }
        return fallback;
    }

    private static Map<Integer, Annotated> scanAnnotations(Class<?> beanClass) {
        Map<Integer, Annotated> map = new TreeMap<>();
        // サブクラス側の定義を優先するため、サブクラスから順に走査する
        for (Class<?> c = beanClass; c != null && c != Object.class; c = c.getSuperclass()) {
            for (Field field : c.getDeclaredFields()) {
                TableMapColumn column = field.getAnnotation(TableMapColumn.class);
                if (column != null && !Modifier.isStatic(field.getModifiers())) {
                    map.putIfAbsent(column.index(), new Annotated(field.getName(), column));
                }
            }
            for (Method method : c.getDeclaredMethods()) {
                TableMapColumn column = method.getAnnotation(TableMapColumn.class);
                if (column != null && method.getParameterCount() == 0) {
                    map.putIfAbsent(column.index(), new Annotated(propertyName(method), column));
                }
            }
        }
        return map;
    }

    private static String propertyName(Method method) {
        String name = method.getName();
        if (name.startsWith("get") && name.length() > 3) {
            return Introspector.decapitalize(name.substring(3));
        }
        if (name.startsWith("is") && name.length() > 2) {
            return Introspector.decapitalize(name.substring(2));
        }
        return name;
    }

    private static Map<String, PropertyDescriptor> descriptors(Class<?> beanClass) {
        Map<String, PropertyDescriptor> map = new LinkedHashMap<>();
        try {
            BeanInfo info = Introspector.getBeanInfo(beanClass, Object.class);
            for (PropertyDescriptor pd : info.getPropertyDescriptors()) {
                map.put(pd.getName(), pd);
            }
        } catch (IntrospectionException ex) {
            // getter/setter が取得できない場合はフィールド直接アクセスにフォールバック
        }
        return map;
    }

    private static Accessor createAccessor(Class<?> beanClass,
            Map<String, PropertyDescriptor> descriptors, String property) {

        PropertyDescriptor pd = descriptors.get(property);
        if (pd != null && (pd.getReadMethod() != null || pd.getWriteMethod() != null)) {
            return new MethodAccessor(pd);
        }
        Field field = findField(beanClass, property);
        if (field != null) {
            field.setAccessible(true);
            return new FieldAccessor(field);
        }
        throw new IllegalArgumentException(
                "プロパティ '" + property + "' が " + beanClass.getName() + " に見つかりません");
    }

    private static Field findField(Class<?> beanClass, String name) {
        for (Class<?> c = beanClass; c != null && c != Object.class; c = c.getSuperclass()) {
            try {
                return c.getDeclaredField(name);
            } catch (NoSuchFieldException ignore) {
                // 継承元を探す
            }
        }
        return null;
    }

    // ======================================================================
    // 型変換
    // ======================================================================

    private static Class<?> box(Class<?> type) {
        if (type == null || !type.isPrimitive()) {
            return (type == null) ? Object.class : type;
        }
        if (type == boolean.class) return Boolean.class;
        if (type == int.class)     return Integer.class;
        if (type == long.class)    return Long.class;
        if (type == double.class)  return Double.class;
        if (type == float.class)   return Float.class;
        if (type == short.class)   return Short.class;
        if (type == byte.class)    return Byte.class;
        if (type == char.class)    return Character.class;
        return Object.class;
    }

    /** セル値を Bean のプロパティ型へ変換します。変換できない場合は既定値を返します。 */
    @SuppressWarnings({"unchecked", "rawtypes"})
    static Object convert(Object value, Class<?> target) {
        if (target == null || target == Object.class) {
            return value;
        }
        if (value == null) {
            if (!target.isPrimitive()) {
                return null;
            }
            if (target == boolean.class) return Boolean.FALSE;
            if (target == char.class)    return (char) 0;
            if (target == int.class)     return 0;
            if (target == long.class)    return 0L;
            if (target == double.class)  return 0d;
            if (target == float.class)   return 0f;
            if (target == short.class)   return (short) 0;
            if (target == byte.class)    return (byte) 0;
        }
        Class<?> boxed = box(target);
        if (boxed.isInstance(value)) {
            return value;
        }
        String text = String.valueOf(value).trim();
        try {
            if (boxed == String.class)    return String.valueOf(value);
            if (boxed == Boolean.class)   return Boolean.valueOf(text);
            if (boxed == Integer.class)   return Integer.valueOf(text);
            if (boxed == Long.class)      return Long.valueOf(text);
            if (boxed == Double.class)    return Double.valueOf(text);
            if (boxed == Float.class)     return Float.valueOf(text);
            if (boxed == Short.class)     return Short.valueOf(text);
            if (boxed == Byte.class)      return Byte.valueOf(text);
            if (boxed == Character.class) return text.isEmpty() ? (char) 0 : text.charAt(0);
            if (boxed.isEnum())           return Enum.valueOf((Class<Enum>) boxed, text);
        } catch (RuntimeException ex) {
            // 変換失敗時は既定値へ
        }
        return target.isPrimitive() ? convert(null, target) : null;
    }

    // ======================================================================
    // 内部クラス
    // ======================================================================

    private static final class ColumnMeta {
        final String property;
        final String name;
        final Class<?> columnClass;
        final boolean editable;
        final Accessor accessor;

        ColumnMeta(String property, String name, Class<?> columnClass,
                boolean editable, Accessor accessor) {
            this.property = property;
            this.name = name;
            this.columnClass = (columnClass == null) ? Object.class : columnClass;
            // accessor == null のときは getColumnValue/setColumnValue のオーバーライド前提
            this.editable = editable && (accessor == null || accessor.writable());
            this.accessor = accessor;
        }
    }

    private static final class Annotated {
        final String property;
        final TableMapColumn column;

        Annotated(String property, TableMapColumn column) {
            this.property = property;
            this.column = column;
        }
    }

    private interface Accessor {
        Object get(Object bean);
        void set(Object bean, Object value);
        Class<?> type();
        boolean writable();
    }

    private static final class MethodAccessor implements Accessor {
        private final Method reader;
        private final Method writer;
        private final Class<?> type;

        MethodAccessor(PropertyDescriptor pd) {
            this.reader = pd.getReadMethod();
            this.writer = pd.getWriteMethod();
            this.type = pd.getPropertyType();
            if (this.reader != null) this.reader.setAccessible(true);
            if (this.writer != null) this.writer.setAccessible(true);
        }

        @Override
        public Object get(Object bean) {
            if (this.reader == null) {
                return null;
            }
            try {
                return this.reader.invoke(bean);
            } catch (IllegalAccessException | InvocationTargetException ex) {
                throw new IllegalStateException(this.reader + " の呼び出しに失敗しました", ex);
            }
        }

        @Override
        public void set(Object bean, Object value) {
            if (this.writer == null) {
                return;
            }
            try {
                this.writer.invoke(bean, convert(value, this.type));
            } catch (IllegalAccessException | InvocationTargetException ex) {
                throw new IllegalStateException(this.writer + " の呼び出しに失敗しました", ex);
            }
        }

        @Override
        public Class<?> type() {
            return this.type;
        }

        @Override
        public boolean writable() {
            return this.writer != null;
        }
    }

    private static final class FieldAccessor implements Accessor {
        private final Field field;

        FieldAccessor(Field field) {
            this.field = field;
        }

        @Override
        public Object get(Object bean) {
            try {
                return this.field.get(bean);
            } catch (IllegalAccessException ex) {
                throw new IllegalStateException(this.field + " の読み取りに失敗しました", ex);
            }
        }

        @Override
        public void set(Object bean, Object value) {
            try {
                this.field.set(bean, convert(value, this.field.getType()));
            } catch (IllegalAccessException ex) {
                throw new IllegalStateException(this.field + " の書き込みに失敗しました", ex);
            }
        }

        @Override
        public Class<?> type() {
            return this.field.getType();
        }

        @Override
        public boolean writable() {
            return !Modifier.isFinal(this.field.getModifiers());
        }
    }
}
