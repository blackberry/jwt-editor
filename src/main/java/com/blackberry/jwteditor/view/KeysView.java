/*
Author : Fraser Winterborn

Copyright 2021 BlackBerry Limited

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package com.blackberry.jwteditor.view;

import burp.IBurpExtenderCallbacks;
import burp.ITab;
import com.blackberry.jwteditor.utils.Utils;
import com.blackberry.jwteditor.model.KeysModel;
import com.blackberry.jwteditor.presenter.KeysPresenter;
import com.blackberry.jwteditor.presenter.PresenterStore;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;
import java.awt.*;
import java.awt.event.*;
import java.util.List;
import java.util.ArrayList;

/**
 * View class for the Keys tab
 */
public class KeysView implements ITab {
    private KeysPresenter presenter;

    private JFrame parent;
    private JButton buttonNewSymmetric;
    private JButton buttonNewRSA;
    private JButton buttonNewEC;
    private JButton buttonNewPassword;
    private JPanel panel;
    private JButton buttonNewOKP;
    private JTable tableKeys;

    JMenuItem menuItemDelete;
    JMenuItem menuItemCopyJWK;
    JMenuItem menuItemCopyPEM;
    JMenuItem menuItemCopyPublicJWK;
    JMenuItem menuItemCopyPublicPEM;
    JMenuItem menuItemCopyPassword;

    @Deprecated
    public KeysView(){
    }

    public KeysView(JFrame parent, PresenterStore presenters, KeysModel keysModel, RstaFactory rstaFactory){
        this(parent, presenters, null, keysModel, rstaFactory);
    }

    public KeysView(JFrame parent, PresenterStore presenters, IBurpExtenderCallbacks callbacks, KeysModel keysModel, RstaFactory rstaFactory) {
        this.parent = parent;
        // Initialise the presenter
        presenter = new KeysPresenter(this, presenters, callbacks, keysModel, rstaFactory);

        // Attach event handlers for button clicks
        buttonNewSymmetric.addActionListener(e -> presenter.onButtonNewSymmetricClick());
        buttonNewEC.addActionListener(e -> presenter.onButtonNewECClick());
        buttonNewOKP.addActionListener(e -> presenter.onButtonNewOKPClick());
        buttonNewRSA.addActionListener(e -> presenter.onButtonNewRSAClick());
        buttonNewPassword.addActionListener(e -> presenter.onButtonNewPasswordClick());
    }

    private enum KeysTableColumns {
        ID("id", 30, String.class),
        TYPE("type", 10, String.class),
        PUBLIC_KEY("public_key", 10, Boolean.class),
        PRIVATE_KEY("private_key", 10, Boolean.class),
        SIGNING("signing", 10, Boolean.class),
        VERIFICATION("verification", 10, Boolean.class),
        ENCRYPTION("encryption", 10, Boolean.class),
        DECRYPTION("decryption", 10, Boolean.class);

        final String label;
        final int widthPercentage;
        final Class<?> type;

        KeysTableColumns(String labelResourceId, int widthPercentage, Class<?> type) {
            this.label = Utils.getResourceString(labelResourceId);
            this.widthPercentage = widthPercentage;
            this.type = type;
        }
    }

    /**
     * Model for the keys table
     */
    public static class KeysTableModel extends AbstractTableModel {

        private final List<Object[]> data = new ArrayList<>();

        public void addRow(Object[] row) {
            data.add(row);
        }

        @Override
        public int getRowCount() {
            return data.size();
        }

        @Override
        public int getColumnCount() {
            return KeysTableColumns.values().length;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            return data.get(rowIndex)[columnIndex];
        }

        @Override
        public String getColumnName(int column) {
            return KeysTableColumns.values()[column].label;
        }

        @Override
        public Class<?> getColumnClass(int columnIndex) {
            return KeysTableColumns.values()[columnIndex].type;
        }
    }

    /**
     * Class for the right-click popup menu
     */
    private class JTablePopup extends JTable {
        private Integer popupRow;

        @Override
        public JPopupMenu getComponentPopupMenu() {
            // Get the row that has been right-clicked on

            Point p = getMousePosition();
            if(p != null && rowAtPoint(p) >= 0){
                popupRow = rowAtPoint(p);

                boolean copyJWKEnabled = false;
                boolean copyPEMEnabled = false;
                boolean copyPublicJWKEnabled = false;
                boolean copyPublicPEMEnabled = false;
                boolean copyPasswordEnabled = false;

                // No selection, set the selection
                if (tableKeys.getSelectedRowCount() == 0) {
                    tableKeys.changeSelection(popupRow, 0, false, false);
                }
                // Selection equals right-clicked row - this will trigger on right-click release
                else if(tableKeys.getSelectedRowCount() == 1 && tableKeys.getSelectedRow() == popupRow){
                    copyJWKEnabled = presenter.canCopyJWK(popupRow);
                    copyPEMEnabled = presenter.canCopyPEM(popupRow);
                    copyPublicJWKEnabled = presenter.canCopyPublicJWK(popupRow);
                    copyPublicPEMEnabled = presenter.canCopyPublicPEM(popupRow);
                    copyPasswordEnabled = presenter.canCopyPassword(popupRow);
                }
                // Selection doesn't equal right-clicked row, change the selection
                else if(tableKeys.getSelectedRowCount() == 1 && tableKeys.getSelectedRow() != popupRow) {
                    tableKeys.changeSelection(popupRow, 0, false, false);
                }

                menuItemCopyJWK.setEnabled(copyJWKEnabled);
                menuItemCopyPEM.setEnabled(copyPEMEnabled);
                menuItemCopyPublicJWK.setEnabled(copyPublicJWKEnabled);
                menuItemCopyPublicPEM.setEnabled(copyPublicPEMEnabled);
                menuItemCopyPassword.setEnabled(copyPasswordEnabled);

                return super.getComponentPopupMenu();
            }
            else{
                popupRow = null;
                return null;
            }
        }

        public Integer getPopupRow(){
            return popupRow;
        }
    }

    /**
     * Get the currently selected row of the table
     * @return selected row index
     */
    public int getSelectedRow() {
        return tableKeys.getSelectedRow();
    }

    /**
     * Get the name of the tab for display in BurpSuite
     * @return the tab name
     */
    public String getTabCaption() {
        return Utils.getResourceString("burp_keys_tab");
    }

    /**
     * Get the view instance for display in BurpSuite
     * @return the view as a Component
     */
    public Component getUiComponent() {
        return panel;
    }

    /**
     * Custom form initialisation
     */
    private void createUIComponents() {
        // Create the table using the custom model
        tableKeys = new JTablePopup();
        tableKeys.setModel(new KeysTableModel());

        // Add a handler for double-click events
        tableKeys.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent mouseEvent) {
                // Detect double-clicks and pass the event to the presenter
                if(mouseEvent.getButton() == 1 && mouseEvent.getClickCount() == 2){
                    presenter.onTableKeysDoubleClick();
                }
            }
        });

        // Resize the table columns on initial paint
        tableKeys.addHierarchyListener(new OneTimeColumnResizeHierarchyListener(tableKeys));

        // Decorate existing BooleanRenderer to perform alternateRow highlighting
        TableCellRenderer booleanCellRender = tableKeys.getDefaultRenderer(Boolean.class);
        tableKeys.setDefaultRenderer(Boolean.class, new AlternateRowBackgroundDecoratingTableCellRenderer(booleanCellRender));

        // Decorate existing renderer to add additional row height
        TableCellRenderer stringCellRender = tableKeys.getDefaultRenderer(String.class);
        tableKeys.setDefaultRenderer(String.class, new RowHeightDecoratingTableCellRenderer(stringCellRender));

        // Create the right-click menu
        JPopupMenu popupMenu = new JPopupMenu();

        menuItemDelete = new JMenuItem(Utils.getResourceString("delete"));
        menuItemCopyJWK = new JMenuItem(Utils.getResourceString("keys_menu_copy_jwk"));
        menuItemCopyPEM = new JMenuItem(Utils.getResourceString("keys_menu_copy_pem"));
        menuItemCopyPublicJWK = new JMenuItem(Utils.getResourceString("keys_menu_copy_public_jwk"));
        menuItemCopyPublicPEM = new JMenuItem(Utils.getResourceString("keys_menu_copy_public_pem"));
        menuItemCopyPassword = new JMenuItem(Utils.getResourceString("keys_menu_copy_password"));

        // Event handlers that call the presenter for menu item clicks on the right-click menu
        ActionListener popupMenuActionListener = e -> {
            JMenuItem menuItem = (JMenuItem) e.getSource();
            if(menuItem == menuItemDelete){
                presenter.onPopupDelete(tableKeys.getSelectedRows());
            }
            else if(menuItem == menuItemCopyJWK){
                presenter.onPopupCopyJWK(((JTablePopup) tableKeys).getPopupRow());
            }
            else if(menuItem == menuItemCopyPEM){
                presenter.onPopupCopyPEM(((JTablePopup) tableKeys).getPopupRow());
            }
            else if(menuItem == menuItemCopyPublicJWK){
                presenter.onPopupCopyPublicJWK(((JTablePopup) tableKeys).getPopupRow());
            }
            else if(menuItem == menuItemCopyPublicPEM){
                presenter.onPopupCopyPublicPEM(((JTablePopup) tableKeys).getPopupRow());
            }
            else if(menuItem == menuItemCopyPassword){
                presenter.onPopupCopyPassword(((JTablePopup) tableKeys).getPopupRow());
            }
        };

        // Attach the event handler to the right-click menu buttons
        menuItemDelete.addActionListener(popupMenuActionListener);
        menuItemCopyJWK.addActionListener(popupMenuActionListener);
        menuItemCopyPEM.addActionListener(popupMenuActionListener);
        menuItemCopyPublicJWK.addActionListener(popupMenuActionListener);
        menuItemCopyPublicPEM.addActionListener(popupMenuActionListener);
        menuItemCopyPassword.addActionListener(popupMenuActionListener);

        // Add the buttons to the right-click menu
        popupMenu.add(menuItemDelete);
        popupMenu.add(menuItemCopyJWK);
        popupMenu.add(menuItemCopyPEM);
        popupMenu.add(menuItemCopyPublicJWK);
        popupMenu.add(menuItemCopyPublicPEM);
        popupMenu.add(menuItemCopyPassword);

        // Associate the right-click menu to the table
        tableKeys.setComponentPopupMenu(popupMenu);
    }

    public void setTableModel(KeysTableModel model){
        tableKeys.setModel(model);
    }

    /**
     * Get the view's parent JFrame
     * @return parent JFrame
     */
    public JFrame getParent() {
        return parent;
    }

    private static class OneTimeColumnResizeHierarchyListener implements HierarchyListener {
        private final JTable table;

        private OneTimeColumnResizeHierarchyListener(JTable table) {
            this.table = table;
        }

        @Override
        public void hierarchyChanged(HierarchyEvent e) {
            if (e.getChangeFlags() != HierarchyEvent.SHOWING_CHANGED || !e.getComponent().isShowing()) {
                return;
            }

            int width = table.getWidth();
            TableColumnModel columnModel = table.getColumnModel();
            KeysTableColumns[] values = KeysTableColumns.values();

            for (int i = 0; i < values.length; i++) {
                KeysTableColumns tableColumns = values[i];
                TableColumn column = columnModel.getColumn(i);
                int preferredWidth = (int) (tableColumns.widthPercentage * 0.01 * width);
                column.setPreferredWidth(preferredWidth);
            }

            table.removeHierarchyListener(this);
        }
    }

    private static class AlternateRowBackgroundDecoratingTableCellRenderer implements TableCellRenderer {
        private final TableCellRenderer tableCellRenderer;

        AlternateRowBackgroundDecoratingTableCellRenderer(TableCellRenderer tableCellRenderer) {
            this.tableCellRenderer = tableCellRenderer;
        }

        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
            Component component = tableCellRenderer.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

            if (!isSelected && !hasFocus) {
                Color alternateRowColor = UIManager.getColor("Table.alternateRowColor");

                if (alternateRowColor != null && row % 2 != 0) {
                     component.setBackground(alternateRowColor);
                }
            }

            return component;
        }
    }

    private static class RowHeightDecoratingTableCellRenderer implements TableCellRenderer {
        private static final int ADDITIONAL_HEIGHT_PIXELS = 5;

        private final TableCellRenderer tableCellRenderer;

        RowHeightDecoratingTableCellRenderer(TableCellRenderer tableCellRenderer) {
            this.tableCellRenderer = tableCellRenderer;
        }

        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
            Component component = tableCellRenderer.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            int componentHeight = component.getPreferredSize().height;

            if (table.getRowHeight() != componentHeight + ADDITIONAL_HEIGHT_PIXELS) {
                table.setRowHeight(componentHeight + ADDITIONAL_HEIGHT_PIXELS);
            }

            return component;
        }
    }
}
