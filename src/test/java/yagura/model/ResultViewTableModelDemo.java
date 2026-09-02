package yagura.model;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.TimingData;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.requests.HttpTransformation;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import extension.helpers.HttpRequestResponseWapper;
import java.awt.BorderLayout;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;
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
public class ResultViewTableModelDemo extends JFrame {

    private final JTable table = new JTable();
    private final ResultViewModel model;

    private final String[] columnsName = new String[]{
        "Data", "#", "host", "method", "URL", "status", "length", "comment", "listener port"
    };

    private final Class[] types = new Class [] {
        java.lang.Object.class, java.lang.Object.class, java.lang.String.class, java.lang.String.class, java.lang.String.class, java.lang.String.class, java.lang.Integer.class, java.lang.String.class, java.lang.Integer.class
    };
    private final boolean[] canEdit = new boolean [] {
        false, true, false, false, false, false, false, true, true
    };

    public ResultViewTableModelDemo() {
        super("BeanTableModel Demo");
        setDefaultCloseOperation(EXIT_ON_CLOSE);


        // --- GUI ビルダが生成する部分に相当 (カラム定義) ---
        this.table.setModel(new DefaultTableModel(
                new Object[][]{},
                columnsName) {

            @Override
            public Class<?> getColumnClass(int columnIndex) {
                return types[columnIndex];
            }

            @Override
            public boolean isCellEditable(int rowIndex, int columnIndex) {
                return canEdit[columnIndex];
            }
        });

        // --- ここからが本題: 既存のカラム定義を引き継いで Bean モデルに差し替える ---
        this.model = new ResultViewModel(this.table.getModel());
        this.table.setModel(this.model);


        JButton add = new JButton("行追加");
        add.addActionListener(e -> {
//            this.model.addBean(new ResultView(http, 1));
        });

        JButton remove = new JButton("選択行を削除");
        remove.addActionListener(e -> {
            int viewRow = this.table.getSelectedRow();
            if (viewRow >= 0) {
                // RowSorter を使う場合はモデル行へ変換すること
                this.model.removeRow(this.table.convertRowIndexToModel(viewRow));
            }
        });

        JPanel buttons = new JPanel();
        buttons.add(add);
        buttons.add(remove);

        add(new JScrollPane(this.table), BorderLayout.CENTER);
        add(buttons, BorderLayout.SOUTH);
        setSize(520, 300);
        setLocationRelativeTo(null);
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new ResultViewTableModelDemo().setVisible(true));
    }
}
