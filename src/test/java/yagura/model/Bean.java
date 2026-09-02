package yagura.model;

import yagura.model.TableMapBase;
import yagura.model.TableMapColumn;

/**
 * 1 行分のデータを表す Bean の例。
 * <p>
 * フィールドに {@link TableMapColumn} を付けるだけでカラムと対応付きます。
 * (アノテーションを使わず、コンストラクタでプロパティ名を並べる方式でも可)
 */
public class Bean implements TableMapBase {
//public class Bean extends TableMapBase {

    private static final long serialVersionUID = 1L;

    @TableMapColumn(index = 0, name = "選択")
    private boolean selected;

    @TableMapColumn(index = 1, name = "種別")
    private String type;

    @TableMapColumn(index = 2, name = "置換")
    private String replace;

    public Bean() {
        // BeanTableModel#newBean() で使用するため引数なしコンストラクタが必要
    }

    public Bean(boolean selected, String type, String replace) {
        this.selected = selected;
        this.type = type;
        this.replace = replace;
    }

    public boolean isSelected() {
        return this.selected;
    }

    public void setSelected(boolean selected) {
        this.selected = selected;
    }

    public String getType() {
        return this.type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getReplace() {
        return this.replace;
    }

    public void setReplace(String replace) {
        this.replace = replace;
    }

    @Override
    public String toString() {
        return "Bean{selected=" + this.selected
                + ", type=" + this.type
                + ", replace=" + this.replace + "}";
    }
}
