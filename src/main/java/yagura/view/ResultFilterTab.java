package yagura.view;

import extension.burp.FilterProperty;
import extension.burp.IBurpTab;
import extension.view.base.CustomListModel;
import java.awt.Component;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.swing.JOptionPane;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import yagura.model.ResultFilterProperty;

/**
 *
 * @author isayan
 */
public class ResultFilterTab extends javax.swing.JPanel implements IBurpTab {

    private final static java.util.ResourceBundle BUNDLE = java.util.ResourceBundle.getBundle("yagura/resources/Resource");

    /**
     * Creates new form ResultFilter
     */
    public ResultFilterTab() {
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

        scrollMatchReplace = new javax.swing.JScrollPane();
        listResultFilter = new javax.swing.JList();
        btnRepDownArraw = new javax.swing.JButton();
        btnRepUpArraw = new javax.swing.JButton();
        btnRepRemove = new javax.swing.JButton();
        btnRepEdit = new javax.swing.JButton();
        btnRepNew = new javax.swing.JButton();

        scrollMatchReplace.setViewportView(listResultFilter);

        btnRepDownArraw.setIcon(new javax.swing.ImageIcon(getClass().getResource("/yagura/resources/arrow_down.png"))); // NOI18N
        btnRepDownArraw.setText("down");
        btnRepDownArraw.setHorizontalAlignment(javax.swing.SwingConstants.LEADING);
        btnRepDownArraw.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnRepDownArrawActionPerformed(evt);
            }
        });

        btnRepUpArraw.setIcon(new javax.swing.ImageIcon(getClass().getResource("/yagura/resources/arrow_up.png"))); // NOI18N
        btnRepUpArraw.setText("up");
        btnRepUpArraw.setHideActionText(true);
        btnRepUpArraw.setHorizontalAlignment(javax.swing.SwingConstants.LEADING);
        btnRepUpArraw.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnRepUpArrawActionPerformed(evt);
            }
        });

        btnRepRemove.setText("Remove");
        btnRepRemove.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnRepRemoveActionPerformed(evt);
            }
        });

        btnRepEdit.setText("Edit");
        btnRepEdit.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnRepEditActionPerformed(evt);
            }
        });

        btnRepNew.setText("New");
        btnRepNew.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnRepNewActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(scrollMatchReplace, javax.swing.GroupLayout.PREFERRED_SIZE, 246, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                        .addComponent(btnRepEdit, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(btnRepNew, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(btnRepRemove, javax.swing.GroupLayout.PREFERRED_SIZE, 165, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(layout.createSequentialGroup()
                        .addGap(25, 25, 25)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(btnRepUpArraw, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(btnRepDownArraw, javax.swing.GroupLayout.PREFERRED_SIZE, 116, javax.swing.GroupLayout.PREFERRED_SIZE))))
                .addContainerGap(175, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(btnRepNew)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(btnRepEdit)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(btnRepRemove)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(btnRepUpArraw)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(btnRepDownArraw))
                    .addComponent(scrollMatchReplace, javax.swing.GroupLayout.PREFERRED_SIZE, 400, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
    }// </editor-fold>//GEN-END:initComponents

    @SuppressWarnings("unchecked")
    private void customizeComponents() {
        // ResultFilterTab Tab
        this.listResultFilter.setModel(this.modelResultFilter);
        this.btnRepEdit.setEnabled((listResultFilter.getSelectedIndices().length > 0));
        this.btnRepRemove.setEnabled((listResultFilter.getSelectedIndices().length > 0));

        this.listResultFilter.getSelectionModel().addListSelectionListener(new ListSelectionListener() {

            @Override
            public void valueChanged(ListSelectionEvent e) {
                if (e.getValueIsAdjusting()) {
                    return;
                }
                int rowCount = listResultFilter.getSelectedIndices().length;
                btnRepEdit.setEnabled((rowCount > 0));
                btnRepRemove.setEnabled((rowCount > 0));
            }
        });

    }

    private final CustomListModel<String> modelResultFilter = new CustomListModel<>();

    private void btnRepDownArrawActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnRepDownArrawActionPerformed
        int index = this.modelResultFilter.moveDown(this.listResultFilter.getSelectedIndex());
        this.listResultFilter.setSelectedIndex(index);
        firePropertyChange(ResultFilterProperty.RESULT_FILTER_PROPERTY, null, this.getResultFilter());
    }//GEN-LAST:event_btnRepDownArrawActionPerformed

    private void btnRepUpArrawActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnRepUpArrawActionPerformed
        int index = this.modelResultFilter.moveUp(this.listResultFilter.getSelectedIndex());
        this.listResultFilter.setSelectedIndex(index);
        firePropertyChange(ResultFilterProperty.RESULT_FILTER_PROPERTY, null, this.getResultFilter());
    }//GEN-LAST:event_btnRepUpArrawActionPerformed

    private void btnRepRemoveActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnRepRemoveActionPerformed
        if (JOptionPane.showConfirmDialog(this, BUNDLE.getString("view.matchreplace.remove"), "Match and Replace", JOptionPane.YES_NO_OPTION) == JOptionPane.YES_OPTION) {
            String name = this.getFilterSelectedName();
            this.modelResultFilter.removeElement(name);
            this.filterMap.remove(name);
            firePropertyChange(ResultFilterProperty.RESULT_FILTER_PROPERTY, null, this.getResultFilter());
        }
    }//GEN-LAST:event_btnRepRemoveActionPerformed

    private void btnRepEditActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnRepEditActionPerformed
        this.showResultFilterDlg(true);
    }//GEN-LAST:event_btnRepEditActionPerformed

    private void btnRepNewActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnRepNewActionPerformed
        this.showResultFilterDlg(false);
    }//GEN-LAST:event_btnRepNewActionPerformed

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton btnRepDownArraw;
    private javax.swing.JButton btnRepEdit;
    private javax.swing.JButton btnRepNew;
    private javax.swing.JButton btnRepRemove;
    private javax.swing.JButton btnRepUpArraw;
    private javax.swing.JList listResultFilter;
    private javax.swing.JScrollPane scrollMatchReplace;
    // End of variables declaration//GEN-END:variables

    private final ResultFilterDlg filterDlg = new ResultFilterDlg(null, true);
    private String selectedName = "";

    public String getSelectedName() {
        return this.selectedName;
    }

    public void setSelectedName(String selectedName) {
        this.selectedName = selectedName;
    }

    private final Map<String, FilterProperty> filterMap = Collections.synchronizedMap(new LinkedHashMap<>());

    protected String getFilterSelectedName() {
        int index = this.listResultFilter.getSelectedIndex();
        String name = null;
        if (index > -1) {
            name = (String) this.modelResultFilter.getElementAt(index);
        }
        return name;
    }

    @SuppressWarnings("unchecked")
    private void showResultFilterDlg(boolean editMode) {
        this.filterDlg.setLocationRelativeTo(this);
        String filterSelectedName = "";
        final FilterProperty filterProperty = new FilterProperty();
        if (editMode) {
            filterSelectedName = this.getFilterSelectedName();
            if (filterSelectedName == null || "".equals(filterSelectedName)) {
                return;
            }
            filterProperty.setProperty(this.filterMap.get(filterSelectedName));
            this.filterDlg.setEditMode(true);
            this.filterDlg.setFilterName(filterSelectedName);
            this.filterDlg.setProperty(filterProperty);
        } else {
            this.filterDlg.setEditMode(true);
            this.filterDlg.setFilterName("");
            this.filterDlg.setProperty(filterProperty);
        }
        this.filterDlg.setVisible(true);
        if (this.filterDlg.getModalResult() == JOptionPane.OK_OPTION) {
            String name = this.filterDlg.getFilterName();
            filterProperty.setProperty(this.filterDlg.getProperty());
            this.filterMap.put(name, filterProperty);

            if (this.modelResultFilter.contains(name)) {
                if (!editMode) {
                    this.modelResultFilter.removeElement(name);
                    this.modelResultFilter.addElement(name);
                }
            } else {
                this.modelResultFilter.addElement(name);
            }
            this.listResultFilter.setSelectedValue(name, true);
        }
        firePropertyChange(ResultFilterProperty.RESULT_FILTER_PROPERTY, null, this.getResultFilter());
    }

    public Map<String, FilterProperty> getFilterMap() {
        return this.filterMap;
    }

    private Map<String, FilterProperty> renewFilterMap() {
        Map<String, FilterProperty> newMap = new LinkedHashMap<>();
        for (int i = 0; i < this.modelResultFilter.size(); i++) {
            String name = (String) this.modelResultFilter.get(i);
            FilterProperty filter = this.filterMap.get(name);
            newMap.put(name, filter);
        }
        this.filterMap.clear();
        this.filterMap.putAll(newMap);
        return newMap;
    }

    public void setFilterMap(Map<String, FilterProperty> filterMap) {
        this.modelResultFilter.removeAllElements();
        this.filterMap.clear();
        this.filterMap.putAll(filterMap);
        for (String name : filterMap.keySet()) {
            this.modelResultFilter.addElement(name);
        }
        this.listResultFilter.setSelectedValue(this.getSelectedName(), true);
    }

    @Override
    public String getTabCaption() {
        return "ResultFilter";
    }

    @Override
    public Component getUiComponent() {
        return this;
    }

    public void setResultFilter(ResultFilterProperty resultFilter) {
        this.setSelectedName(resultFilter.getSelectedName());
        this.setFilterMap(resultFilter.getFilterMap());
    }

    public ResultFilterProperty getResultFilter() {
        ResultFilterProperty filter = new ResultFilterProperty();
        filter.setSelectedName(this.getSelectedName());
        filter.setFilterMap(this.renewFilterMap());
        return filter;
    }

}