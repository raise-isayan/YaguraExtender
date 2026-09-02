package yagura.model;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Bean のプロパティと JTable のカラムを対応付けるアノテーション。
 * <p>
 * フィールドか getter のどちらかに付与します。
 *
 * <pre>
 * public class Bean extends BaseBean {
 *     &#64;TableMapColumn(index = 0, name = "選択")
    private boolean selected;
    &#64;TableMapColumn(index = 1, name = "種別")
    private String type;
}
</pre>
 *
 * 注意: {@code javax.swing.table.TableColumn} と名前が衝突しないよう
 * {@code TableMapColumn} という名前にしています。
 */
@Documented
@Inherited
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.FIELD, ElementType.METHOD})
public @interface TableMapColumn {

    /** JTable 上のカラム番号 (0 始まり)。 */
    int index();

    /** カラム見出し。省略時はプロパティ名、またはテンプレート TableModel の見出しを使用。 */
    String name() default "";

    /** セルを編集可能にするか。 */
    boolean editable() default true;

    /**
     * {@code getColumnClass()} が返す型。
     * 省略時はプロパティの型から自動判定します (primitive はラッパー型に変換)。
     */
    Class<?> type() default Void.class;
}
