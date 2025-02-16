package yagura.view;

import yagura.model.SendToItem;
import java.io.File;
import java.util.List;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import extension.helpers.ConvertUtil;
import extension.helpers.HttpUtil;
import extension.helpers.SwingUtil;
import extension.view.base.CustomDialog;
import java.util.EnumSet;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import yagura.model.SendToExtendProperty;

/**
 *
 * @author isayan
 */
public class SendToItemDlg extends CustomDialog {

    private final static Logger logger = Logger.getLogger(SendToItemDlg.class.getName());
    private final static java.util.ResourceBundle BUNDLE = java.util.ResourceBundle.getBundle("yagura/resources/Resource");

    /**
     * Creates new form SendToItemDlg
     *
     * @param parent
     * @param modal
     */
    public SendToItemDlg(java.awt.Frame parent, boolean modal) {
        super(parent, modal);
        initComponents();
        customizeComponents();
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        pnlApply = new javax.swing.JPanel();
        btnCancel = new javax.swing.JButton();
        btnOK = new javax.swing.JButton();
        tabbetSendTo = new javax.swing.JTabbedPane();
        tabBase = new javax.swing.JPanel();
        lblMenuCaption = new javax.swing.JLabel();
        txtMenuCaption = new javax.swing.JTextField();
        chkServer = new javax.swing.JCheckBox();
        btnSelectExecute = new javax.swing.JButton();
        cmbTargetLocal = new javax.swing.JComboBox<>();
        pnlRequest = new javax.swing.JPanel();
        chkRequestHeader = new javax.swing.JCheckBox();
        chkRequestBody = new javax.swing.JCheckBox();
        pnlRequest1 = new javax.swing.JPanel();
        chkResponseHeader = new javax.swing.JCheckBox();
        chkResponseBody = new javax.swing.JCheckBox();
        chkReverseOrder = new javax.swing.JCheckBox();
        btnExtendProperty = new javax.swing.JButton();
        tabExtend = new javax.swing.JPanel();
        cmbExtend = new javax.swing.JComboBox();

        setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);

        pnlApply.setPreferredSize(new java.awt.Dimension(550, 50));

        btnCancel.setText("Cancel");
        btnCancel.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnCancelActionPerformed(evt);
            }
        });

        btnOK.setText("OK");
        btnOK.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnOKActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout pnlApplyLayout = new javax.swing.GroupLayout(pnlApply);
        pnlApply.setLayout(pnlApplyLayout);
        pnlApplyLayout.setHorizontalGroup(
            pnlApplyLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, pnlApplyLayout.createSequentialGroup()
                .addContainerGap(347, Short.MAX_VALUE)
                .addComponent(btnOK, javax.swing.GroupLayout.PREFERRED_SIZE, 84, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(btnCancel, javax.swing.GroupLayout.PREFERRED_SIZE, 95, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap())
        );
        pnlApplyLayout.setVerticalGroup(
            pnlApplyLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(pnlApplyLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(pnlApplyLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(btnCancel)
                    .addComponent(btnOK))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        getContentPane().add(pnlApply, java.awt.BorderLayout.SOUTH);

        tabbetSendTo.setTabPlacement(javax.swing.JTabbedPane.BOTTOM);

        lblMenuCaption.setText("Menu Caption:");

        chkServer.setText("Server:");
        chkServer.addChangeListener(new javax.swing.event.ChangeListener() {
            public void stateChanged(javax.swing.event.ChangeEvent evt) {
                chkServerStateChanged(evt);
            }
        });

        btnSelectExecute.setIcon(new javax.swing.ImageIcon(getClass().getResource("/yagura/resources/folder_page.png"))); // NOI18N
        btnSelectExecute.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnSelectExecuteActionPerformed(evt);
            }
        });

        cmbTargetLocal.setEditable(true);

        pnlRequest.setBorder(javax.swing.BorderFactory.createTitledBorder("Request"));

        chkRequestHeader.setSelected(true);
        chkRequestHeader.setText("Header");

        chkRequestBody.setSelected(true);
        chkRequestBody.setText("Body");

        javax.swing.GroupLayout pnlRequestLayout = new javax.swing.GroupLayout(pnlRequest);
        pnlRequest.setLayout(pnlRequestLayout);
        pnlRequestLayout.setHorizontalGroup(
            pnlRequestLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(pnlRequestLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(pnlRequestLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(chkRequestHeader)
                    .addComponent(chkRequestBody))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        pnlRequestLayout.setVerticalGroup(
            pnlRequestLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(pnlRequestLayout.createSequentialGroup()
                .addComponent(chkRequestHeader)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(chkRequestBody))
        );

        pnlRequest1.setBorder(javax.swing.BorderFactory.createTitledBorder("Response"));

        chkResponseHeader.setSelected(true);
        chkResponseHeader.setText("Header");

        chkResponseBody.setSelected(true);
        chkResponseBody.setText("Body");

        javax.swing.GroupLayout pnlRequest1Layout = new javax.swing.GroupLayout(pnlRequest1);
        pnlRequest1.setLayout(pnlRequest1Layout);
        pnlRequest1Layout.setHorizontalGroup(
            pnlRequest1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(pnlRequest1Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(pnlRequest1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(chkResponseHeader)
                    .addComponent(chkResponseBody))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        pnlRequest1Layout.setVerticalGroup(
            pnlRequest1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(pnlRequest1Layout.createSequentialGroup()
                .addComponent(chkResponseHeader)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(chkResponseBody))
        );

        chkReverseOrder.setText("reverse order");

        btnExtendProperty.setIcon(new javax.swing.ImageIcon(getClass().getResource("/yagura/resources/wrench.png"))); // NOI18N
        btnExtendProperty.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnExtendPropertyActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout tabBaseLayout = new javax.swing.GroupLayout(tabBase);
        tabBase.setLayout(tabBaseLayout);
        tabBaseLayout.setHorizontalGroup(
            tabBaseLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(tabBaseLayout.createSequentialGroup()
                .addGroup(tabBaseLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(tabBaseLayout.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(chkServer))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, tabBaseLayout.createSequentialGroup()
                        .addGap(25, 25, 25)
                        .addComponent(lblMenuCaption)))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(tabBaseLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(txtMenuCaption, javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(cmbTargetLocal, 0, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(btnSelectExecute, javax.swing.GroupLayout.PREFERRED_SIZE, 34, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(btnExtendProperty, javax.swing.GroupLayout.PREFERRED_SIZE, 34, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap())
            .addGroup(tabBaseLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(chkReverseOrder)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(pnlRequest, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(pnlRequest1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(257, Short.MAX_VALUE))
        );
        tabBaseLayout.setVerticalGroup(
            tabBaseLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(tabBaseLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(tabBaseLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(lblMenuCaption)
                    .addComponent(txtMenuCaption, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(2, 2, 2)
                .addGroup(tabBaseLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(btnExtendProperty, javax.swing.GroupLayout.DEFAULT_SIZE, 32, Short.MAX_VALUE)
                    .addComponent(btnSelectExecute, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, tabBaseLayout.createSequentialGroup()
                        .addGap(0, 0, Short.MAX_VALUE)
                        .addGroup(tabBaseLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(cmbTargetLocal, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(chkServer))))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(tabBaseLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(pnlRequest1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(pnlRequest, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(chkReverseOrder))
                .addGap(45, 45, 45))
        );

        tabbetSendTo.addTab("Base", tabBase);

        javax.swing.GroupLayout tabExtendLayout = new javax.swing.GroupLayout(tabExtend);
        tabExtend.setLayout(tabExtendLayout);
        tabExtendLayout.setHorizontalGroup(
            tabExtendLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(tabExtendLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(cmbExtend, javax.swing.GroupLayout.PREFERRED_SIZE, 348, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(185, Short.MAX_VALUE))
        );
        tabExtendLayout.setVerticalGroup(
            tabExtendLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(tabExtendLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(cmbExtend, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(160, Short.MAX_VALUE))
        );

        tabbetSendTo.addTab("Extend", tabExtend);

        getContentPane().add(tabbetSendTo, java.awt.BorderLayout.CENTER);

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private final SendToServerExtendDlg sendToServerExtendDlg = new SendToServerExtendDlg(null, true);

    private DefaultComboBoxModel modelExtend = null;

    @SuppressWarnings("unchecked")
    private void customizeComponents() {
        // Drag and Drop
        this.cmbTargetLocal.setTransferHandler(new SwingUtil.FileDropAndClipbordTransferHandler() {
            @Override
            public void setData(File file, byte[] rawData) {
                cmbTargetLocal.getModel().setSelectedItem(file.getAbsolutePath());
            }
        });

        this.modelExtend = new DefaultComboBoxModel();
        this.cmbExtend.setModel(this.modelExtend);
//        this.btnExtendProperty.setEnabled(this.chkServer.isSelected());
        for (SendToItem.ExtendType extType : SendToItem.ExtendType.values()) {
            this.modelExtend.addElement(extType);
        }
    }

    private void btnCancelActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnCancelActionPerformed
        this.setModalResult(JOptionPane.CANCEL_OPTION);
        this.closeDialog(null);
    }//GEN-LAST:event_btnCancelActionPerformed

    private void btnOKActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnOKActionPerformed
        String caption = this.txtMenuCaption.getText().trim();
        String target = ConvertUtil.toEmpty(this.cmbTargetLocal.getEditor().getItem()).trim();
        boolean server = this.chkServer.isSelected();
        if (this.isSelectedBase() && caption.isEmpty()) {
            JOptionPane.showMessageDialog(this, BUNDLE.getString("view.sendto.add.empty"), "SendTo", JOptionPane.INFORMATION_MESSAGE);
        } else if (this.isSelectedBase() && server && !(HttpUtil.startsWithHttp(target))) {
            JOptionPane.showMessageDialog(this, BUNDLE.getString("view.sendto.add.target"), "SendTo", JOptionPane.INFORMATION_MESSAGE);
        } else if (this.isSelectedBase() && server && !(HttpUtil.isValidUrl(target))) {
            JOptionPane.showMessageDialog(this, BUNDLE.getString("view.sendto.add.target.invalid.url"), "SendTo", JOptionPane.INFORMATION_MESSAGE);
        } else {
            this.setModalResult(JOptionPane.OK_OPTION);
            this.closeDialog(null);
        }
    }//GEN-LAST:event_btnOKActionPerformed

    private void btnSelectExecuteActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnSelectExecuteActionPerformed
        JFileChooser filechooser = new JFileChooser();
        filechooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        filechooser.setSelectedFile(new File(ConvertUtil.toEmpty(this.cmbTargetLocal.getEditor().getItem()).trim()));
        int selected = filechooser.showOpenDialog(this);
        if (selected == JFileChooser.APPROVE_OPTION) {
            File file = filechooser.getSelectedFile();
            this.cmbTargetLocal.getEditor().setItem(file.getAbsolutePath());
        }
    }//GEN-LAST:event_btnSelectExecuteActionPerformed

    private void btnExtendPropertyActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnExtendPropertyActionPerformed
        showSendToServerExtendDlg(true);
    }//GEN-LAST:event_btnExtendPropertyActionPerformed

    private void chkServerStateChanged(javax.swing.event.ChangeEvent evt) {//GEN-FIRST:event_chkServerStateChanged
//        this.btnExtendProperty.setEnabled(this.chkServer.isSelected());
    }//GEN-LAST:event_chkServerStateChanged

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /*
         * Set the Nimbus look and feel
         */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /*
         * If Nimbus (introduced in Java SE 6) is not available, stay with the
         * default look and feel. For details see
         * http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException | InstantiationException | IllegalAccessException | javax.swing.UnsupportedLookAndFeelException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        //</editor-fold>
        //</editor-fold>

        //</editor-fold>
        //</editor-fold>

        /*
         * Create and display the dialog
         */
        java.awt.EventQueue.invokeLater(new Runnable() {

            @Override
            public void run() {
                SendToItemDlg dialog = new SendToItemDlg(new javax.swing.JFrame(), true);
                dialog.addWindowListener(new java.awt.event.WindowAdapter() {

                    @Override
                    public void windowClosing(java.awt.event.WindowEvent e) {
                        System.exit(0);
                    }
                });
                dialog.setVisible(true);
            }
        });
    }
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton btnCancel;
    private javax.swing.JButton btnExtendProperty;
    private javax.swing.JButton btnOK;
    private javax.swing.JButton btnSelectExecute;
    private javax.swing.JCheckBox chkRequestBody;
    private javax.swing.JCheckBox chkRequestHeader;
    private javax.swing.JCheckBox chkResponseBody;
    private javax.swing.JCheckBox chkResponseHeader;
    private javax.swing.JCheckBox chkReverseOrder;
    private javax.swing.JCheckBox chkServer;
    private javax.swing.JComboBox cmbExtend;
    private javax.swing.JComboBox<String> cmbTargetLocal;
    private javax.swing.JLabel lblMenuCaption;
    private javax.swing.JPanel pnlApply;
    private javax.swing.JPanel pnlRequest;
    private javax.swing.JPanel pnlRequest1;
    private javax.swing.JPanel tabBase;
    private javax.swing.JPanel tabExtend;
    private javax.swing.JTabbedPane tabbetSendTo;
    private javax.swing.JTextField txtMenuCaption;
    // End of variables declaration//GEN-END:variables

    private final Properties extendProperty = new Properties();

    private boolean isSelectedBase() {
        return (this.tabbetSendTo.getSelectedIndex() == 0);
    }

    /**
     * @return the item
     */
    public SendToItem getItem() {
        SendToItem item = new SendToItem();
        item.setSelected(true);
        if (this.isSelectedBase()) {
            item.setCaption(this.txtMenuCaption.getText().trim());
            item.setTarget(ConvertUtil.toEmpty(this.cmbTargetLocal.getEditor().getItem()).trim());
            item.setServer(this.chkServer.isSelected() || HttpUtil.startsWithHttp(item.getTarget()));
            item.setRequestHeader(this.chkRequestHeader.isSelected());
            item.setRequestBody(this.chkRequestBody.isSelected());
            item.setResponseHeader(this.chkResponseHeader.isSelected());
            item.setResponseBody(this.chkResponseBody.isSelected());
            item.setReverseOrder(this.chkReverseOrder.isSelected());
            item.getExtendProperties().clear();
            item.getExtendProperties().putAll(this.extendProperty);
        } else {
            SendToItem.ExtendType sendToExtend = (SendToItem.ExtendType) this.modelExtend.getSelectedItem();
            item.setCaption(sendToExtend.toString());
            item.setTarget(SendToItem.ExtendType.class.getSimpleName());
            item.setExtend(sendToExtend);
            item.getExtendProperties().clear();
            item.getExtendProperties().putAll(this.extendProperty);
        }
        return item;
    }

    /**
     * @param item the item to set
     */
    public void setItem(SendToItem item) {
        if (item.getExtend() == null) {
            this.tabbetSendTo.setSelectedIndex(this.tabbetSendTo.indexOfTab("Base"));
            this.txtMenuCaption.setText(item.getCaption());
            this.chkServer.setSelected(item.isServer());
            this.cmbTargetLocal.getEditor().setItem(item.getTarget());
            this.chkRequestHeader.setSelected(item.isRequestHeader());
            this.chkRequestBody.setSelected(item.isRequestBody());
            this.chkResponseHeader.setSelected(item.isResponseHeader());
            this.chkResponseBody.setSelected(item.isResponseBody());
            this.chkReverseOrder.setSelected(item.isReverseOrder());
            this.extendProperty.clear();
            this.extendProperty.putAll(item.getExtendProperties());
        } else {
            this.tabbetSendTo.setSelectedIndex(this.tabbetSendTo.indexOfTab("Extend"));
            SendToItem.ExtendType sendToExtend = item.getExtend();
            this.cmbExtend.setSelectedItem(sendToExtend);
            this.extendProperty.clear();
            this.extendProperty.putAll(item.getExtendProperties());
        }
    }

    public void setItemList(List<SendToItem> sendToItemList) {
        this.cmbTargetLocal.removeAllItems();
        for (SendToItem item : sendToItemList) {
            if (item.getExtend() != null) {
                continue;
            }
            this.cmbTargetLocal.addItem(item.getTarget());
        }
    }

    @SuppressWarnings("unchecked")
    private void showSendToServerExtendDlg(boolean editMode) {
        this.sendToServerExtendDlg.setLocationRelativeTo(this);
        if (editMode) {
            SendToExtendProperty prop = new SendToExtendProperty();
            prop.setProperties(this.extendProperty);
            this.sendToServerExtendDlg.setProperty(prop);
        } else {
            SendToExtendProperty prop = new SendToExtendProperty();
            this.sendToServerExtendDlg.setProperty(prop);
        }
        if (this.chkServer.isSelected()) {
            this.sendToServerExtendDlg.setExtendView(EnumSet.of(SendToExtendProperty.ExtendView.HTTP_EXTEND, SendToExtendProperty.ExtendView.SENDTO_PARAMETER));
        }
        else {
            this.sendToServerExtendDlg.setExtendView(EnumSet.of(SendToExtendProperty.ExtendView.SENDTO_ARGS));
        }
        this.sendToServerExtendDlg.setVisible(true);
        if (this.sendToServerExtendDlg.getModalResult() == JOptionPane.OK_OPTION) {
            SendToExtendProperty prop = this.sendToServerExtendDlg.getProperty();
            this.extendProperty.clear();
            this.extendProperty.putAll(prop.getProperties());
        }
    }

}
