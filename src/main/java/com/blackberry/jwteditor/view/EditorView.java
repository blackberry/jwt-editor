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

import burp.IExtensionHelpers;
import burp.IMessageEditorTab;
import com.blackberry.jwteditor.utils.Utils;
import com.blackberry.jwteditor.presenter.EditorPresenter;
import com.blackberry.jwteditor.presenter.PresenterStore;
import org.exbin.deltahex.EditationAllowed;
import org.exbin.deltahex.ViewMode;
import org.exbin.deltahex.swing.CodeArea;
import org.exbin.utils.binary_data.ByteArrayEditableData;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.JTextComponent;
import java.awt.*;

/**
 * View class for the Editor tab in standalone and BurpSuite mode
 */
public class EditorView implements IMessageEditorTab {

    public static final int MAX_JOSE_OBJECT_STRING_LENGTH = 55;

    public static final int TAB_JWS = 0;
    public static final int TAB_JWE = 1;

    private IExtensionHelpers helpers;
    private EditorPresenter presenter;
    private RstaFactory rstaFactory;
    private boolean editable;
    private int mode;

    private JFrame parent;
    private JTabbedPane tabbedPane;
    private JComboBox<String> comboBoxJOSEObject;
    private JButton buttonSign;
    private JButton buttonEncrypt;
    private JPanel panel;
    private JPanel panelKey;
    private JPanel panelCiphertext;
    private JPanel panelIV;
    private JPanel panelTag;
    private JPanel panelSignature;
    private RSyntaxTextArea textAreaSerialized;
    private RSyntaxTextArea textAreaJWEHeader;
    private RSyntaxTextArea textAreaJWSHeader;
    private RSyntaxTextArea textAreaPayload;
    private JButton buttonDecrypt;
    private JButton buttonCopy;
    private JButton buttonAttack;
    private JButton buttonVerify;
    private JButton buttonJWSHeaderFormatJSON;
    private JCheckBox checkBoxJWSHeaderCompactJSON;
    private JButton buttonJWEHeaderFormatJSON;
    private JCheckBox checkBoxJWEHeaderCompactJSON;
    private JButton buttonJWSPayloadFormatJSON;
    private JCheckBox checkBoxJWSPayloadCompactJSON;

    private CodeArea codeAreaSignature;
    private CodeArea codeAreaEncryptedKey;
    private CodeArea codeAreaCiphertext;
    private CodeArea codeAreaIV;
    private CodeArea codeAreaTag;

    @Deprecated
    public EditorView() {

    }

    public EditorView(JFrame parent, PresenterStore presenters, RstaFactory rstaFactory) {
        this(parent, presenters, null, rstaFactory, true);
    }

    public EditorView(JFrame parent, PresenterStore presenters, IExtensionHelpers helpers, RstaFactory rstaFactory, boolean editable) {
        this.parent = parent;
        this.rstaFactory = rstaFactory;

        presenter = new EditorPresenter(this, presenters);
        this.helpers = helpers;
        this.editable = editable;

        // Event handler for Header / JWS payload change events
        DocumentListener documentListener = new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                presenter.componentChanged();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                presenter.componentChanged();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                presenter.componentChanged();
            }
        };

        // Attach event handlers for form elements changing, forward to presenter
        textAreaJWSHeader.getDocument().addDocumentListener(documentListener);
        textAreaPayload.getDocument().addDocumentListener(documentListener);
        codeAreaSignature.addDataChangedListener(() -> presenter.componentChanged());

        textAreaJWEHeader.getDocument().addDocumentListener(documentListener);
        codeAreaEncryptedKey.addDataChangedListener(() -> presenter.componentChanged());
        codeAreaCiphertext.addDataChangedListener(() -> presenter.componentChanged());
        codeAreaTag.addDataChangedListener(() -> presenter.componentChanged());
        codeAreaIV.addDataChangedListener(() -> presenter.componentChanged());

        // Compact check box event handler
        checkBoxJWEHeaderCompactJSON.addActionListener(e -> presenter.componentChanged());
        checkBoxJWSHeaderCompactJSON.addActionListener(e -> presenter.componentChanged());
        checkBoxJWSPayloadCompactJSON.addActionListener(e -> presenter.componentChanged());

        // Format check box event handler
        buttonJWEHeaderFormatJSON.addActionListener(e -> presenter.formatJWEHeader());
        buttonJWSHeaderFormatJSON.addActionListener(e -> presenter.formatJWSHeader());
        buttonJWSPayloadFormatJSON.addActionListener(e -> presenter.formatJWSPayload());

        // Button click event handlers
        comboBoxJOSEObject.addActionListener(e -> presenter.onSelectionChanged());
        buttonSign.addActionListener(e -> presenter.onSignClicked());
        buttonVerify.addActionListener(e -> presenter.onVerifyClicked());
        buttonEncrypt.addActionListener(e -> presenter.onEncryptClicked());
        buttonDecrypt.addActionListener(e -> presenter.onDecryptClicked());
        buttonCopy.addActionListener(e -> presenter.onCopyClicked());
    }

    /**
     * Handler for Attack button
     */
    private void onAttackClicked() {
        // Display the attack popup menu
        JPopupMenu popupMenu = buttonAttack.getComponentPopupMenu();
        popupMenu.setVisible(false);
        // Position to above attack button
        buttonAttack.getComponentPopupMenu().show(buttonAttack, buttonAttack.getX(), buttonAttack.getY());
        buttonAttack.getComponentPopupMenu().show(
                buttonAttack,
                buttonAttack.getX(),
                buttonAttack.getY() - buttonAttack.getComponentPopupMenu().getHeight()
        );
    }

    /**
     * Set the JWS header value in the UI
     * @param header value string
     */
    public void setJWSHeader(String header) {
        textAreaJWSHeader.setText(header);
    }

    /**
     * Get the JWS header value from the UI
     * @return value string
     */
    public String getJWSHeader() {
        return textAreaJWSHeader.getText();
    }

    /**
     * Set the payload value in the UI
     * @param payload value string
     */
    public void setPayload(String payload) {
        textAreaPayload.setText(payload);
    }

    /**
     * Get the payload value from the UI
     * @return value string
     */
    public String getPayload() {
        return textAreaPayload.getText();
    }

    /**
     * Set the JWS signature in the UI
     * @param signature signature bytes
     */
    public void setSignature(byte[] signature) {
        codeAreaSignature.setData(new ByteArrayEditableData(signature));
    }

    /**
     * Set the JWE header value in the UI
     * @param header value string
     */
    public void setJWEHeader(String header) {
        textAreaJWEHeader.setText(header);
    }

    /**
     * Get the JWE header value from the UI
     * @return value string
     */
    public String getJWEHeader() {
        return textAreaJWEHeader.getText();
    }

    /**
     * Set the encrypted key in the UI
     * @param encryptionKey value bytes
     */
    public void setEncryptedKey(byte[] encryptionKey) {
        codeAreaEncryptedKey.setData(new ByteArrayEditableData(encryptionKey));
    }

    /**
     * Get the encrypted key from the UI
     * @return encrypted key bytes
     */
    public byte[] getEncryptedKey() {
        return Utils.getCodeAreaData(codeAreaEncryptedKey);
    }

    /**
     * Set the ciphertext in the UI
     * @param ciphertext ciphertext bytes
     */
    public void setCiphertext(byte[] ciphertext) {
        codeAreaCiphertext.setData(new ByteArrayEditableData(ciphertext));
    }

    /**
     * Get the ciphertext from the UI
     * @return ciphertext bytes
     */
    public byte[] getCiphertext() {
        return Utils.getCodeAreaData(codeAreaCiphertext);
    }

    /**
     * Set the tag in the UI
     * @param tag tag bytes
     */
    public void setTag(byte[] tag) {
        codeAreaTag.setData(new ByteArrayEditableData(tag));
    }

    /**
     * Get the tag from the UI
     * @return tag bytes
     */
    public byte[] getTag() {
        return Utils.getCodeAreaData(codeAreaTag);
    }


    /**
     * Set the IV value in the UI
     * @param iv iv bytes
     */
    public void setIV(byte[] iv) {
        codeAreaIV.setData(new ByteArrayEditableData(iv));
    }

    /**
     * Get the IV value from the UI
     * @return iv bytes
     */
    public byte[] getIV() {
        return Utils.getCodeAreaData(codeAreaIV);
    }

    /**
     * Get the signature value from the UI
     * @return signature bytes
     */
    public byte[] getSignature() {

        return Utils.getCodeAreaData(codeAreaSignature);
    }

    /**
     * Set the serialised JWS/JWE in the UI
     * @param text serialised JWE/JWS
     * @param highlight should the text box be highlighted (changed)
     */
    public void setSerialized(String text, boolean highlight) {
        textAreaSerialized.setText(text);

        if (highlight) {
            textAreaSerialized.setForeground(Color.RED);
        } else {
            textAreaSerialized.setForeground(Color.BLACK);
        }
    }

    /**
     * Get the serialised JWS/JWE from the UI
     * @return serialised JWE/JWS
     */
    public String getSerialized() {
        return textAreaSerialized.getText();
    }

    /**
     * Set the JWS/JWEs in the UI dropdown
     * @param joseObjectStrings array of JWS/JWE to display
     */
    public void setJOSEObjects(String[] joseObjectStrings) {
        comboBoxJOSEObject.setModel(new DefaultComboBoxModel<>(joseObjectStrings));
    }

    /**
     * Get the index of the currently selected JWS/JWE
     * @return selected JWS/JWE index
     */
    public int getSelected() {
        return comboBoxJOSEObject.getSelectedIndex();
    }

    /**
     * Set the index of the selected JWS/JWE
     * @param index JWS/JWE index to select
     */
    public void setSelected(int index) {
        comboBoxJOSEObject.setSelectedIndex(index);
    }

    /**
     * Get the UI mode - JWS or JWE
     * @return UI mode value
     */
    public int getMode() {
        return mode;
    }

    /**
     * Set the UI to JWS mode
     */
    public void setJWSMode() {
        mode = TAB_JWS;
        tabbedPane.setSelectedIndex(TAB_JWS);
        tabbedPane.setEnabledAt(TAB_JWS, true);
        tabbedPane.setEnabledAt(TAB_JWE, false);
        buttonAttack.setEnabled(editable);
        buttonSign.setEnabled(editable);
        buttonVerify.setEnabled(true);
        buttonEncrypt.setEnabled(editable);
        buttonDecrypt.setEnabled(false);
        buttonJWEHeaderFormatJSON.setEnabled(false);
        buttonJWSHeaderFormatJSON.setEnabled(editable);
        buttonJWSPayloadFormatJSON.setEnabled(editable);
        checkBoxJWEHeaderCompactJSON.setEnabled(false);
        checkBoxJWSHeaderCompactJSON.setEnabled(editable);
        checkBoxJWSPayloadCompactJSON.setEnabled(editable);
        textAreaJWSHeader.setEditable(editable);
        textAreaPayload.setEditable(editable);
        codeAreaSignature.setEditationAllowed(editable ? EditationAllowed.ALLOWED : EditationAllowed.READ_ONLY);
    }

    /**
     * Set the UI to JWE mode
     */
    public void setJWEMode() {
        mode = TAB_JWE;
        tabbedPane.setSelectedIndex(TAB_JWE);
        tabbedPane.setEnabledAt(TAB_JWS, false);
        tabbedPane.setEnabledAt(TAB_JWE, true);
        buttonAttack.setEnabled(false);
        buttonSign.setEnabled(false);
        buttonVerify.setEnabled(false);
        buttonEncrypt.setEnabled(false);
        buttonDecrypt.setEnabled(editable);
        buttonJWEHeaderFormatJSON.setEnabled(editable);
        buttonJWSHeaderFormatJSON.setEnabled(false);
        buttonJWSPayloadFormatJSON.setEnabled(false);
        checkBoxJWEHeaderCompactJSON.setEnabled(editable);
        checkBoxJWSHeaderCompactJSON.setEnabled(false);
        checkBoxJWSPayloadCompactJSON.setEnabled(false);

        textAreaJWEHeader.setEditable(editable);
        textAreaJWEHeader.setEnabled(editable);

        codeAreaEncryptedKey.setEditationAllowed(editable ? EditationAllowed.ALLOWED : EditationAllowed.READ_ONLY);
        codeAreaIV.setEditationAllowed(editable ? EditationAllowed.ALLOWED : EditationAllowed.READ_ONLY);
        codeAreaCiphertext.setEditationAllowed(editable ? EditationAllowed.ALLOWED : EditationAllowed.READ_ONLY);
        codeAreaTag.setEditationAllowed(editable ? EditationAllowed.ALLOWED : EditationAllowed.READ_ONLY);
    }

    /**
     * Set the Compact checkbox for the JWS header
     * @param compact the compact value
     */
    public void setJWSHeaderCompact(boolean compact) {
        checkBoxJWSHeaderCompactJSON.setSelected(compact);
    }

    /**
     * Get the Compact checkbox for the JWS header
     * @return the compact value
     */
    public boolean getJWSHeaderCompact() {
        return checkBoxJWSHeaderCompactJSON.isSelected();
    }

    /**
     * Set the Compact checkbox for the JWS payload
     * @param compact the compact value
     */
    public void setJWSPayloadCompact(boolean compact) {
        checkBoxJWSPayloadCompactJSON.setSelected(compact);
    }

    /**
     * Get the Compact checkbox for the JWS payload
     * @return the compact value
     */
    public boolean getJWSPayloadCompact() {
        return checkBoxJWSPayloadCompactJSON.isSelected();
    }

    /**
     * Set the Compact checkbox for the JWE header
     * @param compact the compact value
     */
    public void setJWEHeaderCompact(boolean compact) {
        checkBoxJWEHeaderCompactJSON.setSelected(compact);
    }

    /**
     * Get the Compact checkbox for the JWE header
     * @return the compact value
     */
    public boolean getJWEHeaderCompact() {
        return checkBoxJWEHeaderCompactJSON.isSelected();
    }

    /**
     * Get the view
     * @return view JPanel
     */
    public JPanel getPanel() {
        return panel;
    }

    /**
     * Get the value to display for the tab in the Burp HTTP editor
     * @return the tab name
     */
    @Override
    public String getTabCaption() {
        return Utils.getResourceString("burp_editor_tab");
    }

    /**
     * Get the view to display in Burp
     * @return view component
     */
    @Override
    public Component getUiComponent() {
        return getPanel();
    }

    /**
     * Returns true/false if the HTTP content contains a JWS/JWE that can be edited by the extension
     * @param content The message that is about to be displayed, or a zero-length
     * array if the existing message is to be cleared.
     * @param isRequest Indicates whether the message is a request or a
     * response.
     * @return true if the HTTP message contains a JWS/JWE
     */
    public boolean isEnabled(byte[] content, boolean isRequest) {
        return presenter.isEnabled(helpers.bytesToString(content));
    }

    /**
     * Set the content of the view from Burp
     * @param content The message that is to be displayed, or
     * <code>null</code> if the tab should clear its contents and disable any
     * editable controls.
     * @param isRequest Indicates whether the message is a request or a
     */
    public void setMessage(byte[] content, boolean isRequest) {
        presenter.setMessage(helpers.bytesToString(content));
    }

    /**
     * Get the modified HTTP message for Burp
     * @return the modified HTTP message
     */
    public byte[] getMessage() {
        return helpers.stringToBytes(presenter.getMessage());
    }

    /**
     * Has the HTTP message been altered by the extension
     * @return true if the extension has altered the message
     */
    public boolean isModified() {
        return presenter.isModified();
    }

    /**
     * Burp IMessageEditor method to return data selected by user. Not used.
     * @return null
     */
    public byte[] getSelectedData() {
        return null;
    }

    /**
     * Get the view's parent JFrame
     * @return parent JFrame
     */
    public JFrame getParent() {
        return parent;
    }

    /**
     * Custom view initialisation
     */
    private void createUIComponents() {
        // Create CodeAreas for byte[] inputs. The form editor cannot handle these, so create manually

        // Create a CodeArea for the signature
        panelSignature = new JPanel();
        panelSignature.setLayout(new GridLayout());
        codeAreaSignature = new CodeArea();
        codeAreaSignature.setCommandHandler(new HexCodeAreaCommandHandler(codeAreaSignature));
        codeAreaSignature.setShowHeader(false);
        codeAreaSignature.setShowLineNumbers(false);
        codeAreaSignature.setViewMode(ViewMode.CODE_MATRIX);
        codeAreaSignature.setData(new ByteArrayEditableData(new byte[0]));
        panelSignature.add(codeAreaSignature);

        // Create a CodeArea for the encrypted key
        panelKey = new JPanel();
        panelKey.setLayout(new GridLayout());
        codeAreaEncryptedKey = new CodeArea();
        codeAreaEncryptedKey.setCommandHandler(new HexCodeAreaCommandHandler(codeAreaEncryptedKey));
        codeAreaEncryptedKey.setShowHeader(false);
        codeAreaEncryptedKey.setShowLineNumbers(false);
        codeAreaEncryptedKey.setViewMode(ViewMode.CODE_MATRIX);
        codeAreaEncryptedKey.setData(new ByteArrayEditableData(new byte[0]));
        panelKey.add(codeAreaEncryptedKey);

        // Create a CodeArea for the ciphertext
        panelCiphertext = new JPanel();
        panelCiphertext.setLayout(new GridLayout());
        codeAreaCiphertext = new CodeArea();
        codeAreaCiphertext.setCommandHandler(new HexCodeAreaCommandHandler(codeAreaCiphertext));
        codeAreaCiphertext.setShowHeader(false);
        codeAreaCiphertext.setShowLineNumbers(false);
        codeAreaCiphertext.setViewMode(ViewMode.CODE_MATRIX);
        codeAreaCiphertext.setData(new ByteArrayEditableData(new byte[0]));
        panelCiphertext.add(codeAreaCiphertext);

        // Create a CodeArea for the IV
        panelIV = new JPanel();
        panelIV.setLayout(new GridLayout());
        codeAreaIV = new CodeArea();
        codeAreaIV.setCommandHandler(new HexCodeAreaCommandHandler(codeAreaIV));
        codeAreaIV.setShowHeader(false);
        codeAreaIV.setShowLineNumbers(false);
        codeAreaIV.setViewMode(ViewMode.CODE_MATRIX);
        codeAreaIV.setData(new ByteArrayEditableData());
        panelIV.add(codeAreaIV);

        // Create a CodeArea for the tag
        panelTag = new JPanel();
        panelTag.setLayout(new GridLayout());
        codeAreaTag = new CodeArea();
        codeAreaTag.setCommandHandler(new HexCodeAreaCommandHandler(codeAreaTag));
        codeAreaTag.setShowHeader(false);
        codeAreaTag.setShowLineNumbers(false);
        codeAreaTag.setViewMode(ViewMode.CODE_MATRIX);
        codeAreaTag.setData(new ByteArrayEditableData(new byte[0]));
        codeAreaTag.setBackground(Color.WHITE);
        panelTag.add(codeAreaTag);

        // https://github.com/bobbylight/RSyntaxTextArea/issues/269#issuecomment-776329702 - Fix keypresses in Repeater
        JTextComponent.removeKeymap("RTextAreaKeymap");
        UIManager.put("RSyntaxTextAreaUI.actionMap", null);
        UIManager.put("RSyntaxTextAreaUI.inputMap", null);
        UIManager.put("RTextAreaUI.actionMap", null);
        UIManager.put("RTextAreaUI.inputMap", null);

        // Create the Attack popup menu
        JPopupMenu popupMenuAttack = new JPopupMenu();
        JMenuItem menuItemAttackEmbedJWK = new JMenuItem(Utils.getResourceString("editor_view_button_attack_embed_jwk"));
        JMenuItem menuItemAttackSignNone = new JMenuItem(Utils.getResourceString("editor_view_button_attack_sign_none"));
        JMenuItem menuItemAttackKeyConfusion = new JMenuItem(Utils.getResourceString("editor_view_button_attack_key_confusion"));

        // Attach the event handlers to the popup menu click events
        menuItemAttackEmbedJWK.addActionListener(e -> presenter.onAttackEmbedJWKClicked());
        menuItemAttackKeyConfusion.addActionListener(e -> presenter.onAttackKeyConfusionClicked());
        menuItemAttackSignNone.addActionListener(e -> presenter.onAttackSignNoneClicked());

        // Add the buttons to the popup menu
        popupMenuAttack.add(menuItemAttackEmbedJWK);
        popupMenuAttack.add(menuItemAttackSignNone);
        popupMenuAttack.add(menuItemAttackKeyConfusion);

        // Associate the popup menu to the Attack button
        buttonAttack = new JButton();
        buttonAttack.setComponentPopupMenu(popupMenuAttack);
        buttonAttack.addActionListener(e -> onAttackClicked());
        textAreaSerialized = rstaFactory.build();
        textAreaJWEHeader = rstaFactory.build();
        textAreaJWSHeader = rstaFactory.build();
        textAreaPayload = rstaFactory.build();
    }
}
