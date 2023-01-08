package extension.helpers;

import extension.view.base.DefaultObjectTableModel;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.Transferable;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.awt.im.InputContext;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableModel;
import javax.swing.text.AttributeSet;
import javax.swing.text.BadLocationException;
import javax.swing.text.Document;
import javax.swing.text.JTextComponent;
import javax.swing.text.PlainDocument;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreeModel;
import javax.swing.tree.TreeNode;
import javax.swing.tree.TreePath;

/**
 *
 * @author isayan
 */
public final class SwingUtil {
    private final static Logger logger = Logger.getLogger(SwingUtil.class.getName());

    private SwingUtil() {
    }

    private static Robot robot = null;

    public static synchronized Robot getRobot() {
        try {
            if (robot == null) {
                robot = new Robot();
            }
        } catch (AWTException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return robot;
    }

    public static JFrame getRootJFrame(Component c) {
        for(Container p = c.getParent(); p != null; p = p.getParent()) {
            if (p instanceof JFrame) {
                return (JFrame)p;
            }
        }
        return null;
    }

    public static JFrame [] getJFrames() {
        java.util.List<JFrame> jframes = new ArrayList<>();
        Frame [] frames = Frame.getFrames();
        for (int i = 0; i < frames.length; i++) {
            if (frames[i] instanceof JFrame) {
                jframes.add((JFrame)frames[i]);
            }
        }
        return jframes.toArray(new JFrame[0]);
    }

    public static JMenuBar[] getJMenuBars() {
        java.util.List<JMenuBar> menuBars = new ArrayList<>();
        JFrame[] frames = getJFrames();
        for (int i = 0; i < frames.length; i++) {
            JMenuBar menuBar = frames[i].getJMenuBar();
            if (menuBar != null) {
                menuBars.add(menuBar);
            }
        }
        return menuBars.toArray(new JMenuBar[menuBars.size()]);
    }

    /**
     * 行の追加または更新
     *
     * @param srcTable 対象テーブル
     * @param items 追加オブジェクト
     * @param update 更新かどうか
     */
    public static void addOrUpdateItem(javax.swing.JTable srcTable, Object[] items, boolean update) {
        if (update) {
            updateItem(srcTable, items);
        } else {
            addItem(srcTable, items);
        }
    }

    public static void addItem(javax.swing.JTable srcTable, Object[] items) {
        TableModel modelSrc = srcTable.getModel();
        int lastIndex = modelSrc.getRowCount() - 1;
        if (modelSrc instanceof DefaultTableModel) {
            ((DefaultTableModel) modelSrc).addRow(items);
        }
        //        else if (modelSrc instanceof DefaultObjectTableModel) {
        //            ((DefaultObjectTableModel)modelSrc).addRow(items);
        //        }
        else {
            throw new java.lang.ClassCastException("class cast Excaption:" + modelSrc.getClass().getName());
        }
        srcTable.getSelectionModel().setSelectionInterval(lastIndex, lastIndex);
    }

    public static void insertItem(javax.swing.JTable srcTable, Object[] items) {
        TableModel modelSrc = srcTable.getModel();
        int index = srcTable.getSelectedRow();
        if (-1 < index && index < srcTable.getRowCount()) {
            int rowIndex = srcTable.convertRowIndexToModel(index);
            if (modelSrc instanceof DefaultTableModel) {
                ((DefaultTableModel) modelSrc).insertRow(rowIndex, items);
            }
//            else {
//                throw new java.lang.ClassCastException("class cast Excaption:" + modelSrc.getClass().getName());
//            }
        } else {
            throw new java.lang.ClassCastException("class cast Excaption:" + modelSrc.getClass().getName());
        }
    }

    public static void updateItem(javax.swing.JTable srcTable, Object[] items, int viewIndex) {
        TableModel modelSrc = srcTable.getModel();
        int index = viewIndex;
        if (-1 < index && index < srcTable.getRowCount()) {
            int rowIndex = srcTable.convertRowIndexToModel(index);
            if (modelSrc instanceof DefaultTableModel) {
                ((DefaultTableModel) modelSrc).removeRow(rowIndex);
                ((DefaultTableModel) modelSrc).insertRow(rowIndex, items);
            }
            //            else if (modelSrc instanceof DefaultObjectTableModel) {
            //                ((DefaultObjectTableModel)modelSrc).removeRow(rowIndex);
            //                ((DefaultObjectTableModel)modelSrc).insertRow(rowIndex, items);
            //            }
            else {
                throw new java.lang.ClassCastException("class cast Excaption:" + modelSrc.getClass().getName());
            }
            srcTable.getSelectionModel().setSelectionInterval(rowIndex, rowIndex);
        }
    }

    public static void updateItem(javax.swing.JTable srcTable, Object[] items) {
        updateItem(srcTable, items, srcTable.getSelectedRow());
    }

    public static boolean removeItem(javax.swing.JTable srcTable) {
        TableModel modelSrc = srcTable.getModel();
        int index = srcTable.getSelectedRow();
        if (index > -1) {
            int rowIndex = srcTable.convertRowIndexToModel(index);
            if (modelSrc instanceof DefaultTableModel) {
                ((DefaultTableModel) modelSrc).removeRow(rowIndex);
            } else if (modelSrc instanceof DefaultObjectTableModel) {
                ((DefaultObjectTableModel) modelSrc).removeRow(rowIndex);
            } else {
                throw new java.lang.ClassCastException("class cast Excaption:" + modelSrc.getClass().getName());
            }
            return true;
        }
        return false;
    }

    public static Object[] editItem(javax.swing.JTable srcTable) {
        TableModel modelSrc = srcTable.getModel();
        int index = srcTable.getSelectedRow();
        Object[] editRows = null;
        if (index > -1) {
            int rowIndex = srcTable.convertRowIndexToModel(index);
            editRows = new Object[modelSrc.getColumnCount()];
            for (int i = 0; i < editRows.length; i++) {
                editRows[i] = modelSrc.getValueAt(rowIndex, i);
            }
        }
        return editRows;
    }

    public static void allNodesChanged(JTree tree) {
        DefaultTreeModel model = (DefaultTreeModel) tree.getModel();
        DefaultMutableTreeNode root = (DefaultMutableTreeNode) model.getRoot();
        Enumeration e = root.preorderEnumeration();
        while (e.hasMoreElements()) {
            Object element = e.nextElement();
            if (element instanceof TreeNode) {
                TreeNode node = (TreeNode) element;
                model.nodeChanged(node);
            }
        }
    }

    public static void expandAll(JTree tree, TreePath path) {
        Object node = path.getLastPathComponent();
        TreeModel model = tree.getModel();
        if (model.isLeaf(node)) {
            return;
        }
        int num = model.getChildCount(node);
        for (int i = 0; i < num; i++) {
            expandAll(tree, path.pathByAddingChild(model.getChild(node, i)));
        }
        tree.expandPath(path);
    }

    public static void collapseAll(JTree tree, TreePath path) {
        Object node = path.getLastPathComponent();
        TreeModel model = tree.getModel();
        if (model.isLeaf(node)) {
            return;
        }
        int num = model.getChildCount(node);
        for (int i = 0; i < num; i++) {
            collapseAll(tree, path.pathByAddingChild(model.getChild(node, i)));
        }
        tree.collapsePath(path);
    }

    public static void setContainerEnable(Container container, boolean enabled) {
        Component[] list = container.getComponents();
        for (Component c : list) {
            if (c instanceof Container) {
                setContainerEnable((Container) c, enabled);
                c.setEnabled(enabled);
            } else {
                c.setEnabled(enabled);
            }
        }
    }

    /**
     * ファイル上書き確認ダイアログを表示する。
     *
     * @param file 上書き対象ファイル
     * @param message ダイヤログメッセージ
     * @param title ダイヤログタイトル
     * @return 上書きOKが指示されたらtrue
     */
    public static boolean isFileOverwriteConfirmed(File file, String message, String title) {
        if (!file.exists()) {
            return true;
        }
        int confirm = JOptionPane.showConfirmDialog(
                null, message, title,
                JOptionPane.WARNING_MESSAGE,
                JOptionPane.OK_CANCEL_OPTION);
        return (confirm == JOptionPane.OK_OPTION);
    }

    public static ImageIcon createCloseIcon() {
        return new ImageIcon() {
            private final int width = 16;
            private final int height = 16;

            @Override
            public void paintIcon(Component c, Graphics g, int x, int y) {
                g.translate(x, y);
                g.setColor(Color.BLACK);
                g.drawLine(4, 4, 11, 11);
                g.drawLine(4, 5, 10, 11);
                g.drawLine(5, 4, 11, 10);
                g.drawLine(11, 4, 4, 11);
                g.drawLine(11, 5, 5, 11);
                g.drawLine(10, 4, 4, 10);
                g.translate(-x, -y);
            }

            @Override
            public int getIconWidth() {
                return width;
            }

            @Override
            public int getIconHeight() {
                return height;
            }
        };
    }

    public static ImageIcon createSquareIcon(final Color color, final int w, final int h) {
        return new ImageIcon() {
            @Override
            public int getIconWidth() {
                return w + 2;
            }

            @Override
            public int getIconHeight() {
                return h + 2;
            }

            @Override
            public void paintIcon(Component c, Graphics g, int x, int y) {
                g.setColor(color);
                g.fillRoundRect(x, y, w, h, 0, 0);
            }
        };
    }

    public static Icon createEmptyIcon() {
        return new Icon() {
            @Override
            public void paintIcon(Component c, Graphics g, int x, int y) {
                /* Empty icon */ }

            @Override
            public int getIconWidth() {
                return 2;
            }

            @Override
            public int getIconHeight() {
                return 0;
            }
        };
    }

    public static class IntegerDocument extends PlainDocument {

        BigInteger currentValue = BigInteger.valueOf(0);
        int radix = 10;

        public IntegerDocument() {
            super();
        }

        public IntegerDocument(int radix) {
            super();
            this.radix = radix;
        }

        public long getLongValue() {
            return currentValue.longValue();
        }

        public BigInteger getValue() {
            return currentValue;
        }

        @Override
        public void insertString(int offset, String str, AttributeSet attributes) throws BadLocationException {
            if (str == null) {
            } else {
                String newValue;
                int length = getLength();
                if (length == 0) {
                    newValue = str;
                } else {
                    String currentContent = getText(0, length);
                    StringBuilder currentBuffer = new StringBuilder(currentContent);
                    currentBuffer.insert(offset, str);
                    newValue = currentBuffer.toString();
                }
                currentValue = checkInput(newValue, offset);
                super.insertString(offset, str, attributes);
            }
        }

        @Override
        public void remove(int offset, int length) throws BadLocationException {
            int currentLength = getLength();
            String currentContent = getText(0, currentLength);
            String before = currentContent.substring(0, offset);
            String after = currentContent.substring(length + offset, currentLength);
            String newValue = before + after;
            currentValue = checkInput(newValue, offset);
            super.remove(offset, length);
        }

        private BigInteger checkInput(String proposedValue, int offset) throws BadLocationException {
            if (proposedValue.length() > 0) {
                try {
                    BigInteger newValue = new BigInteger(proposedValue, this.radix);
                    return newValue;
                } catch (NumberFormatException e) {
                    throw new BadLocationException(proposedValue, offset);
                }
            } else {
                return BigInteger.valueOf(0);
            }
        }
    }

    public static class ReadOnlyDocument extends PlainDocument {

        public ReadOnlyDocument() {
            super();
        }

        @Override
        public void insertString(int offset, String str, AttributeSet attributes) throws BadLocationException {
        }

        @Override
        public void remove(int offset, int length) throws BadLocationException {
        }

    }

    private static final Toolkit TOOLKIT = Toolkit.getDefaultToolkit();

    public static String systemSelection() {

        String selection = null;
        try {
            Clipboard cb = TOOLKIT.getSystemSelection();
            if (cb != null) {
                Transferable t = cb.getContents(null);
                selection = (String) t.getTransferData(DataFlavor.stringFlavor);
            }
        } catch (UnsupportedFlavorException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        } catch (IOException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return selection;
    }

    /**
     * クリップボードにコピー
     *
     * @param s 文字列
     */
    public static void systemClipboardCopy(String s) {
        StringSelection ss = new StringSelection(s);
        Clipboard systemClipbord = TOOLKIT.getSystemClipboard();
        systemClipbord.setContents(ss, null);
    }

    /**
     * クリップボードからペースト
     *
     * @return s 文字列
     */
    public static String systemClipboardPaste() {
        Clipboard systemClipbord = TOOLKIT.getSystemClipboard();
        Transferable t = systemClipbord.getContents(null);
        String s = "";
        try {
            s = (String) t.getTransferData(DataFlavor.stringFlavor);
        } catch (UnsupportedFlavorException ex) {
            logger.log(Level.WARNING, ex.getMessage(), ex);
        } catch (IOException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return s;
    }

    public static Popup createToolTip(Component owner, String tip, int x, int y) {
        JToolTip toolTip = new JToolTip();
        toolTip.setTipText(tip);
        PopupFactory popupFactory = PopupFactory.getSharedInstance();
        return popupFactory.getPopup(owner, toolTip, x, y);
    }

    public static void showToolTip(Component owner, String tip, int x, int y, long millis) {
        Popup popTip = createToolTip(owner, tip, x, y);
        Runnable thread = new Runnable() {
            @Override
            public void run() {
                try {
                    popTip.show();
                    Thread.sleep(millis);
                    popTip.hide();
                } catch (InterruptedException ex) {
                    logger.log(Level.SEVERE, ex.getMessage(), ex);
                }
            }
        };
        (new Thread(thread)).start();
    }

    public static String getKeyText(java.awt.event.KeyEvent evt) {
        StringBuilder keyIdent = new StringBuilder();
        keyIdent.append(java.awt.event.KeyEvent.getModifiersExText(evt.getModifiersEx()));
        if (evt.getKeyCode() != java.awt.event.KeyEvent.CHAR_UNDEFINED
                && evt.getKeyCode() != java.awt.event.KeyEvent.VK_CONTROL
                && evt.getKeyCode() != java.awt.event.KeyEvent.VK_SHIFT
                && evt.getKeyCode() != java.awt.event.KeyEvent.VK_ALT
                && evt.getKeyCode() != java.awt.event.KeyEvent.VK_META) {
            if (keyIdent.length() > 0) {
                keyIdent.append("+");
            }
            keyIdent.append(java.awt.event.KeyEvent.getKeyText(evt.getKeyCode()));
        }
        return keyIdent.toString();
    }

    public static void sendKeys(int key) {
        getRobot().keyPress(key);
        getRobot().keyRelease(key);
    }

    public static void sendMouse(int buttons) {
        getRobot().mousePress(buttons);
        getRobot().mouseRelease(buttons);
    }

    public static class FileDropAndClipbordTransferHandler extends TransferHandler {

        public FileDropAndClipbordTransferHandler() {

        }

        @Override
        public void exportToClipboard(JComponent comp, Clipboard clipboard,
                int action) throws IllegalStateException {
            if (comp instanceof JTextComponent) {
                JTextComponent text = (JTextComponent) comp;
                int p0 = text.getSelectionStart();
                int p1 = text.getSelectionEnd();
                if (p0 != p1) {
                    try {
                        Document doc = text.getDocument();
                        String srcData = doc.getText(p0, p1 - p0);
                        StringSelection contents = new StringSelection(srcData);
                        clipboard.setContents(contents, null);

                        if (action == TransferHandler.MOVE) {
                            doc.remove(p0, p1 - p0);
                        }
                    } catch (BadLocationException ex) {
                        logger.log(Level.SEVERE, ex.getMessage(), ex);
                    }
                }
            }
        }

        @Override
        public boolean importData(JComponent comp, Transferable t) {
            if (comp instanceof JTextComponent) {
                DataFlavor flavor = getFlavor(t.getTransferDataFlavors());
                if (flavor != null) {
                    InputContext ic = comp.getInputContext();
                    if (ic != null) {
                        ic.endComposition();
                    }
                    try {
                        String data = (String) t.getTransferData(flavor);
                        ((JTextComponent) comp).replaceSelection(data);
                        return true;
                    } catch (UnsupportedFlavorException ex) {
                        logger.log(Level.WARNING, ex.getMessage(), ex);
                    } catch (IOException ex) {
                        logger.log(Level.SEVERE, ex.getMessage(), ex);
                    }
                }
            }
            return false;
        }

        @Override
        public boolean canImport(JComponent comp, DataFlavor[] transferFlavors) {
            JTextComponent c = (JTextComponent) comp;
            if (!(c.isEditable() && c.isEnabled())) {
                return false;
            }
            return (getFlavor(transferFlavors) != null);
        }

        @Override
        public boolean importData(TransferHandler.TransferSupport support) {
            Transferable t = support.getTransferable();
            if (support.isDrop()) {
                try {
                    Object data = t.getTransferData(DataFlavor.javaFileListFlavor);
                    java.util.List lists = (java.util.List) data;
                    for (Object item : lists) {
                        if (item instanceof File) {
                            File file = (File) item;
                            byte[] rawData = new byte[0];
                            rawData = FileUtil.readAllBytes(new FileInputStream(file));
                            setData(rawData);
                            break;
                        }
                    }
                } catch (UnsupportedFlavorException ex) {
                    logger.log(Level.WARNING, ex.getMessage(), ex);
                } catch (IOException ex) {
                    logger.log(Level.SEVERE, ex.getMessage(), ex);
                }
            } else {
                return support.getComponent() instanceof JComponent
                        ? importData((JComponent) support.getComponent(), support.getTransferable())
                        : false;
            }
            return false;
        }

        @Override
        public boolean canImport(TransferHandler.TransferSupport support) {
            if (support.isDrop()) {
                if (support.isDataFlavorSupported(DataFlavor.javaFileListFlavor)) {
                    return true;
                }
            } else {
                return support.getComponent() instanceof JComponent
                        ? canImport((JComponent) support.getComponent(), support.getDataFlavors())
                        : false;
            }
            return false;
        }


        public void setData(byte[] rawData) {

        }


        @Override
        public int getSourceActions(JComponent c) {
            return NONE;
        }

        private DataFlavor getFlavor(DataFlavor[] flavors) {
            if (flavors != null) {
                for (DataFlavor flavor : flavors) {
                    if (flavor.equals(DataFlavor.stringFlavor)) {
                        return flavor;
                    }
                }
            }
            return null;
        }

    }

}
