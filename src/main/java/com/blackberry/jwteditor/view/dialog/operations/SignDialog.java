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
import com.blackberry.jwteditor.operations.Operations;
import com.blackberry.jwteditor.utils.Utils;
import com.blackberry.jwteditor.utils.CryptoUtils;
import com.blackberry.jwteditor.model.jose.JWS;
import com.blackberry.jwteditor.model.keys.JWKKey;
import com.blackberry.jwteditor.model.keys.Key;
import com.nimbusds.jose.*;

import javax.swing.*;
import java.awt.event.*;
import java.util.List;

/**
 * Sign and Attack > Embedded JWK dialog from the Editor tab
 */
public class SignDialog extends JDialog {

    public enum Mode {
        NORMAL("sign_dialog_title"),
        EMBED_JWK("embed_jwk_attack_dialog_title");

        private final String titleResourceId;

        Mode(String titleResourceId) {
            this.titleResourceId = titleResourceId;
        }
    }

    private JPanel contentPane;
    private JButton buttonOK;
    private JButton buttonCancel;
    private JComboBox<Key> comboBoxSigningKey;
    private JComboBox<JWSAlgorithm> comboBoxSigningAlgorithm;
    private JPanel panelOptions;
    private JRadioButton radioButtonUpdateGenerateAlg;
    private JRadioButton radioButtonUpdateGenerateJWT;
    private JRadioButton radioButtonUpdateGenerateNone;

    private final Mode mode;
    private JWS jws;


    /**
     * Show the signing dialog
     * @param signingKeys the signing keys available
     * @param jws the content to sign
     * @param mode whether the dialog should be used for normal signing, or the embedded JWK attack
     */
    public SignDialog(JFrame parent, List<Key> signingKeys, JWS jws, Mode mode) {
        super(parent);
        this.jws = jws;
        this.mode = mode;

        setContentPane(contentPane);
        setModal(true);
        getRootPane().setDefaultButton(buttonOK);

        setTitle(Utils.getResourceString(mode.titleResourceId));

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

        // Conver the signingKeys from a List to an Array
        Key[] signingKeysArray = new Key[signingKeys.size()];
        signingKeys.toArray(signingKeysArray);

        // Populate the signing keys dropdown
        comboBoxSigningKey.setModel(new DefaultComboBoxModel<>(signingKeysArray));

        // Set an event handler to update the signing algorithms dropdown when the selected key changes
        comboBoxSigningKey.addActionListener(e -> {
            Key selectedKey = (Key) comboBoxSigningKey.getSelectedItem();
            //noinspection ConstantConditions
            comboBoxSigningAlgorithm.setModel(new DefaultComboBoxModel<>(selectedKey.getSigningAlgorithms()));
            buttonOK.setEnabled(true);
        });

        // Set the signing key to the first entry, also triggering the event handler
        comboBoxSigningKey.setSelectedIndex(0);

        // If the dialog is being used for the embeded JWK attack, hide the Header Options
        if(mode != Mode.NORMAL){
            panelOptions.setVisible(false);
        }
    }

    /**
     * Get the result of the dialog
     * @return the header/payload as a signed JWS
     */
    public JWS getJWS(){
        return jws;
    }

    /**
     * Handler for OK button pressed. Sign the editor content with the selected parameters
     */
    @SuppressWarnings("ConstantConditions")
    private void onOK() {
        // Get the selected signing key and algorithm
        JWKKey selectedKey = (JWKKey) comboBoxSigningKey.getSelectedItem();
        JWSAlgorithm selectedAlgorithm = (JWSAlgorithm) comboBoxSigningAlgorithm.getSelectedItem();

        // Get the header update mode based on the selected radio button, convert to the associated enum value
        Operations.SigningUpdateMode signingUpdateMode;
        if(radioButtonUpdateGenerateAlg.isSelected()){
            signingUpdateMode = Operations.SigningUpdateMode.ALG;
        }
        else if(radioButtonUpdateGenerateJWT.isSelected()){
            signingUpdateMode = Operations.SigningUpdateMode.JWT;
        }
        else{
            signingUpdateMode = Operations.SigningUpdateMode.NONE;
        }

        // Perform a signing operation or the embedded JWK attack based on the dialog mode
        try{
            if(mode == Mode.NORMAL){
                jws = Operations.sign(jws, selectedKey, selectedAlgorithm, signingUpdateMode);
            }
            else if (mode == Mode.EMBED_JWK) {
                jws = Attacks.embeddedJWK(jws, selectedKey, selectedAlgorithm);
            }
        } catch (CryptoUtils.SigningException | NoSuchFieldException | IllegalAccessException e) {
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
}
