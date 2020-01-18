package yagura.view;

import extend.view.base.CustomDialog;
import extend.util.external.TransUtil;
import javax.swing.JOptionPane;

/**
 *
 * @author isayan
 */
public class MultiItemDlg extends CustomDialog {

    /**
     * Creates new form MatchReplaceMultiItemDlg
     */
    public MultiItemDlg(java.awt.Frame parent, boolean modal) {
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
        pnlMain = new javax.swing.JPanel();
        scrollMultiline = new javax.swing.JScrollPane();
        txtMultiLine = new javax.swing.JTextArea();

        setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);
        setMinimumSize(new java.awt.Dimension(400, 200));
        setModal(true);
        setResizable(false);

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
                .addContainerGap(216, Short.MAX_VALUE)
                .addComponent(btnOK, javax.swing.GroupLayout.PREFERRED_SIZE, 84, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
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
                .addContainerGap(19, Short.MAX_VALUE))
        );

        getContentPane().add(pnlApply, java.awt.BorderLayout.SOUTH);

        txtMultiLine.setColumns(20);
        txtMultiLine.setRows(5);
        scrollMultiline.setViewportView(txtMultiLine);

        javax.swing.GroupLayout pnlMainLayout = new javax.swing.GroupLayout(pnlMain);
        pnlMain.setLayout(pnlMainLayout);
        pnlMainLayout.setHorizontalGroup(
            pnlMainLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(pnlMainLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(scrollMultiline, javax.swing.GroupLayout.DEFAULT_SIZE, 390, Short.MAX_VALUE)
                .addContainerGap())
        );
        pnlMainLayout.setVerticalGroup(
            pnlMainLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(pnlMainLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(scrollMultiline, javax.swing.GroupLayout.DEFAULT_SIZE, 235, Short.MAX_VALUE)
                .addContainerGap())
        );

        getContentPane().add(pnlMain, java.awt.BorderLayout.CENTER);
    }// </editor-fold>//GEN-END:initComponents

    public void setMultiLine(String[] lines) {
        this.txtMultiLine.setText(TransUtil.join("\n", lines));
    }

    public String[] getMultiLine() {
        String s = this.txtMultiLine.getText();
        return s.split("\n");
    }

    private void btnCancelActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnCancelActionPerformed
        this.setModalResult(JOptionPane.CANCEL_OPTION);
        this.closeDialog(null);
    }//GEN-LAST:event_btnCancelActionPerformed

    private void btnOKActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnOKActionPerformed
        this.setModalResult(JOptionPane.OK_OPTION);
        this.closeDialog(null);
    }//GEN-LAST:event_btnOKActionPerformed

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton btnCancel;
    private javax.swing.JButton btnOK;
    private javax.swing.JPanel pnlApply;
    private javax.swing.JPanel pnlMain;
    private javax.swing.JScrollPane scrollMultiline;
    private javax.swing.JTextArea txtMultiLine;
    // End of variables declaration//GEN-END:variables

    private void customizeComponents() {
    }
}