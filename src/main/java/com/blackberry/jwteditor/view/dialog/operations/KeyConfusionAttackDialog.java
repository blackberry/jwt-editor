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

package com.blackberry.jwteditor.view.dialog.operations;

import com.blackberry.jwteditor.operations.Attacks;
import com.blackberry.jwteditor.utils.Utils;
import com.blackberry.jwteditor.utils.CryptoUtils;
import com.blackberry.jwteditor.utils.PEMUtils;
import com.blackberry.jwteditor.model.jose.JWS;
import com.blackberry.jwteditor.model.keys.JWKKey;
import com.blackberry.jwteditor.model.keys.Key;
import com.nimbusds.jose.JWSAlgorithm;

import javax.swing.*;
import java.awt.event.*;
import java.util.List;

/**
 * Attack > HMAC Key Confusion dialog from the Editor tab
 */
public class KeyConfusionAttackDialog extends JDialog {
    private JPanel contentPane;
    private JButton buttonOK;
    private JButton buttonCancel;
    private JComboBox<Key> comboBoxSigningKey;
    private JComboBox<JWSAlgorithm> comboBoxSigningAlgorithm;
    private JCheckBox checkBoxTrailingNewline;

    private JWS jws;

    /**
     * Show the HMAC Key Confusion attack dialog
     * @param signingKeys the signing keys available
     * @param jws the content to sign
     */
    public KeyConfusionAttackDialog(JFrame parent, List<Key> signingKeys, JWS jws) {
        super(parent);
        this.jws = jws;

        setContentPane(contentPane);
        setModal(true);
        getRootPane().setDefaultButton(buttonOK);

        setTitle(Utils.getResourceString("key_confusion_attack_dialog_title"));

        buttonOK.addActionListener(e -> onOK());

        buttonCancel.addActionListener(e -> onCancel());

        // call onCancel() when cross is clicked
        setDefaultCloseOperation(DO_NOTHING_ON_CLOSE);
        addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent e) {
                onCancel();
            }
        });

        // call onCancel() on ESCAPE
        contentPane.registerKeyboardAction(e -> onCancel(), KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT);

        // Convert the signingKeys List to an Array
        Key[] signingKeysArray = new Key[signingKeys.size()];
        signingKeys.toArray(signingKeysArray);

        // Populate the dropdown with the signing keys
        comboBoxSigningKey.setModel(new DefaultComboBoxModel<>(signingKeysArray));

        // Populate the Signing Algorithm dropdown
        comboBoxSigningAlgorithm.setModel(new DefaultComboBoxModel<>(new JWSAlgorithm[] {JWSAlgorithm.HS256, JWSAlgorithm.HS384, JWSAlgorithm.HS512}));

        // Select the first signing key
        comboBoxSigningKey.setSelectedIndex(0);
    }

    /**
     * Handler for OK button press - perform the attack
     */
    @SuppressWarnings("ConstantConditions")
    private void onOK() {
        // Get the selected key and algorithm
        JWKKey selectedKey = (JWKKey) comboBoxSigningKey.getSelectedItem();
        JWSAlgorithm selectedAlgorithm = (JWSAlgorithm) comboBoxSigningAlgorithm.getSelectedItem();

        // Try to perform the attack, show dialog if this fails
        try{
            jws = Attacks.hmacKeyConfusion(jws, selectedKey, selectedAlgorithm, checkBoxTrailingNewline.isSelected());
        } catch (CryptoUtils.SigningException | PEMUtils.PemException | Key.UnsupportedKeyException e) {
            jws = null;
            JOptionPane.showMessageDialog(this, e.getMessage(), Utils.getResourceString("error_title_unable_to_sign"), JOptionPane.WARNING_MESSAGE);
        }

        dispose();
    }

    /**
     * Called when the Cancel or X button is pressed. Destroy the window
     */
    private void onCancel() {
        dispose();
    }

    /**
     * Get the result of the dialog
     * @return the JWS modified by the attack
     */
    public JWS getJWS(){
        return jws;
    }
}
