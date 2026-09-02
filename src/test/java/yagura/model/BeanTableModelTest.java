package yagura.model;

import java.util.Arrays;
import java.util.List;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableModel;

/**
 * 動作確認用 (ヘッドレスで実行可能)。
 */
public final class BeanTableModelTest {

    private static int failed = 0;

    public static void main(String[] args) {
        TableModel template = template();

        // ---- 1. アノテーションによるマッピング ----
        TableMapModel<Bean> model = new TableMapModel<>(Bean.class, template);
        check("カラム数", 3, model.getColumnCount());
        check("見出し[0]", "選択", model.getColumnName(0));
        check("見出し[1]", "種別", model.getColumnName(1));
        check("カラム型[0]", Boolean.class, model.getColumnClass(0));
        check("カラム型[1]", String.class, model.getColumnClass(1));
        check("編集可否[2]", false, model.isCellEditable(0, 2)); // template で false

        model.setBeans(Arrays.asList(
                new Bean(true, "regex", "^foo"),
                new Bean(false, "text", "bar")));
        check("行数", 2, model.getRowCount());
        check("getValueAt(0,0)", Boolean.TRUE, model.getValueAt(0, 0));
        check("getValueAt(0,1)", "regex", model.getValueAt(0, 1));
        check("getValueAt(1,2)", "bar", model.getValueAt(1, 2));

        // セル編集 -> Bean に反映
        model.setValueAt(Boolean.FALSE, 0, 0);
        model.setValueAt("changed", 0, 1);
        check("編集後 selected", false, model.getBean(0).isSelected());
        check("編集後 type", "changed", model.getBean(0).getType());

        // null / 型不一致の入力でも落ちないこと
        model.setValueAt(null, 0, 0);
        check("null -> primitive boolean", false, model.getBean(0).isSelected());
        model.setValueAt("true", 0, 0);
        check("String -> boolean", true, model.getBean(0).isSelected());

        // 行の追加・削除
        Bean added = model.addRow();
        check("addRow 後の行数", 3, model.getRowCount());
        added.setType("new");
        check("addRow の Bean 参照", "new", model.getValueAt(2, 1));
        model.removeRow(2);
        check("removeRow 後の行数", 2, model.getRowCount());

        // 絞り込み
        List<Bean> selected = model.filter(Bean::isSelected);
        check("filter 件数", 1, selected.size());

        check("getColumnIndex", 2, model.getColumnIndex("replace"));

        // ---- 2. プロパティ名の並びによるマッピング (アノテーション不要) ----
        TableMapModel<Bean> byName
                = new TableMapModel<>(Bean.class, template, new String[] {"selected", "type", "replace"});
        byName.addBean(new Bean(true, "aaa", "bbb"));
        check("プロパティ名指定 getValueAt", "aaa", byName.getValueAt(0, 1));

        // ---- 3. switch でのマッピング (フックのオーバーライド) ----
        TableMapModel<Bean> manual = new TableMapModel<Bean>(Bean.class, template,
               new String[] {"selected", "type", "replace"}) {
            private static final long serialVersionUID = 1L;

            @Override
            protected Object getColumnValue(Bean bean, int column) {
                switch (column) {
                    case 0:
                        return bean.isSelected();
                    case 1:
                        return bean.getType();
                    case 2:
                        return bean.getReplace();
                    default:
                        return null;
                }
            }

            @Override
            protected void setColumnValue(Bean bean, int column, Object value) {
                switch (column) {
                    case 0:
                        bean.setSelected(Boolean.TRUE.equals(value));
                        break;
                    case 1:
                        bean.setType((String) value);
                        break;
                    case 2:
                        bean.setReplace((String) value);
                        break;
                    default:
                        break;
                }
            }
        };
        manual.addBean(new Bean(false, "ccc", "ddd"));
        manual.setValueAt(Boolean.TRUE, 0, 0);
        check("switch 実装 get", "ccc", manual.getValueAt(0, 1));
        check("switch 実装 set", true, manual.getBean(0).isSelected());

        // ---- 4. 継承した Bean ----
        TableMapModel<ChildBean> child = new TableMapModel<>(ChildBean.class);
        check("継承 Bean のカラム数", 4, child.getColumnCount());
        ChildBean cb = child.addRow();
        child.setValueAt("memo!", 0, 3);
        check("継承 Bean の setValueAt", "memo!", cb.getNote());

        // ---- 5. カラム数不一致は例外 ----
        try {
            new TableMapModel<>(Bean.class, template, new String[]{"selected", "type"});
            check("カラム数不一致の検出", "例外", "例外なし");
        } catch (IllegalArgumentException expected) {
            check("カラム数不一致の検出", "例外", "例外");
        }

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " FAILED");
        if (failed > 0) {
            System.exit(1);
        }
    }

    /**
     * GUI ビルダが生成する DefaultTableModel を模したもの。
     */
    private static TableModel template() {
        return new DefaultTableModel(new Object[][]{}, new String[]{"選択", "種別", "置換"}) {
            private static final long serialVersionUID = 1L;
            final Class<?>[] types = {Boolean.class, String.class, String.class};
            final boolean[] canEdit = {true, true, false};

            @Override
            public Class<?> getColumnClass(int columnIndex) {
                return this.types[columnIndex];
            }

            @Override
            public boolean isCellEditable(int rowIndex, int columnIndex) {
                return this.canEdit[columnIndex];
            }
        };
    }

    /**
     * 継承した Bean の例。
     */
    public static class ChildBean extends Bean {

        private static final long serialVersionUID = 1L;

        @TableMapColumn(index = 3, name = "備考")
        private String note;

        public String getNote() {
            return this.note;
        }

        public void setNote(String note) {
            this.note = note;
        }
    }

    private static void check(String label, Object expected, Object actual) {
        boolean ok = (expected == null) ? actual == null : expected.equals(actual);
        System.out.printf("%-28s %s (expected=%s, actual=%s)%n",
                label, ok ? "OK  " : "NG  ", expected, actual);
        if (!ok) {
            failed++;
        }
    }

    private BeanTableModelTest() {
    }
}
