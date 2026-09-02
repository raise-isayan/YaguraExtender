package yagura.model;

import java.awt.BorderLayout;
import java.util.Arrays;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import javax.swing.table.DefaultTableModel;

/**
 * 使用例。
 * <p>
 * {@code table} は NetBeans などの GUI ビルダで カラムを定義した JTable のつもりです。
 */
public class BeanTableModelDemo extends JFrame {

    private static final long serialVersionUID = 1L;

    private final JTable table = new JTable();
    private final TableMapModel<Bean> model;

    public BeanTableModelDemo() {
        super("BeanTableModel Demo");
        setDefaultCloseOperation(EXIT_ON_CLOSE);

        // --- GUI ビルダが生成する部分に相当 (カラム定義) ---
        this.table.setModel(new DefaultTableModel(
                new Object[][]{},
                new String[]{"選択", "種別", "置換"}) {
            private static final long serialVersionUID = 1L;
            final Class<?>[] types = {Boolean.class, String.class, String.class};
            final boolean[] canEdit = {true, true, true};

            @Override
            public Class<?> getColumnClass(int columnIndex) {
                return this.types[columnIndex];
            }

            @Override
            public boolean isCellEditable(int rowIndex, int columnIndex) {
                return this.canEdit[columnIndex];
            }
        });

        final Class<?>[] types = {Boolean.class, String.class, String.class};
        // --- ここからが本題: 既存のカラム定義を引き継いで Bean モデルに差し替える ---
        this.model = new TableMapModel<>(Bean.class, this.table.getModel());
        this.table.setModel(this.model);

        // 初期データ
        this.model.setBeans(Arrays.asList(
                new Bean(true, "regex", "^foo"),
                new Bean(false, "text", "bar"),
                new Bean(true, "text", "baz")));

        JButton add = new JButton("行追加");
        add.addActionListener(e -> {
            Bean bean = this.model.addRow();
            bean.setType("text");
        });

        JButton remove = new JButton("選択行を削除");
        remove.addActionListener(e -> {
            int viewRow = this.table.getSelectedRow();
            if (viewRow >= 0) {
                // RowSorter を使う場合はモデル行へ変換すること
                this.model.removeRow(this.table.convertRowIndexToModel(viewRow));
            }
        });

        JButton dump = new JButton("チェック済みを出力");
        dump.addActionListener(e -> {
            for (Bean bean : this.model.filter(Bean::isSelected)) {
                System.out.println(bean);
            }
        });

        JPanel buttons = new JPanel();
        buttons.add(add);
        buttons.add(remove);
        buttons.add(dump);

        add(new JScrollPane(this.table), BorderLayout.CENTER);
        add(buttons, BorderLayout.SOUTH);
        setSize(520, 300);
        setLocationRelativeTo(null);
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new BeanTableModelDemo().setVisible(true));
    }
}
