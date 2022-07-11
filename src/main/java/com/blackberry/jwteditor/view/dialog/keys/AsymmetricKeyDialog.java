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

package com.blackberry.jwteditor.view.dialog.keys;

import com.blackberry.jwteditor.cryptography.okp.OKPGenerator;
import com.blackberry.jwteditor.presenter.PresenterStore;
import com.blackberry.jwteditor.utils.Utils;
import com.blackberry.jwteditor.utils.PEMUtils;
import com.blackberry.jwteditor.model.keys.JWKKey;
import com.blackberry.jwteditor.model.keys.Key;
import com.blackberry.jwteditor.view.RstaFactory;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.event.*;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.text.ParseException;
import java.util.UUID;
import java.util.concurrent.ExecutionException;

/**
 * "New RSA Key /EC Key /OKP " dialog for Keys tab
 */
public class AsymmetricKeyDialog extends KeyDialog {
    private Color textAreaKeyInitialBackgroundColor;
    private Color textAreaKeyInitialCurrentLineHighlightColor;
    private JPanel contentPane;
    private JButton buttonOK;
    private JButton buttonCancel;
    private JComboBox<Object> comboBoxKeySize;
    private JButton buttonGenerate;
    private RSyntaxTextArea textAreaKey;
    private JRadioButton radioButtonJWK;
    private JRadioButton radioButtonPEM;
    private JLabel labelError;
    private JTextField textFieldKeyId;
    private JPanel panelKeyId;

    public enum Mode {
        EC(KeyType.EC),
        RSA(KeyType.RSA),
        OKP(KeyType.OKP);

        private final KeyType keyType;

        Mode(KeyType keyType){
            this.keyType = keyType;
        }
    }

    private final Mode mode;
    private final RstaFactory rstaFactory;
    private JWK jwk;

    public AsymmetricKeyDialog(JFrame parent, PresenterStore presenters, RstaFactory rstaFactory, RSAKey rsaKey){
        this(parent, presenters, Mode.RSA, rstaFactory, rsaKey);
    }

    public AsymmetricKeyDialog(JFrame parent, PresenterStore presenters, RstaFactory rstaFactory, ECKey ecKey){
        this(parent, presenters, Mode.EC, rstaFactory, ecKey);
    }

    public AsymmetricKeyDialog(JFrame parent, PresenterStore presenters, RstaFactory rstaFactory, OctetKeyPair octetKeyPair){
        this(parent, presenters, Mode.OKP, rstaFactory, octetKeyPair);
    }

    public AsymmetricKeyDialog(JFrame parent, PresenterStore presenters, RstaFactory rstaFactory, Mode mode){
        this(parent, presenters, mode, rstaFactory, null);
    }

    private AsymmetricKeyDialog(JFrame parent, PresenterStore presenters, Mode mode, RstaFactory rstaFactory, JWK jwk) {
        super(parent);
        this.mode = mode;
        this.rstaFactory = rstaFactory;
        this.jwk = jwk;
        this.presenters = presenters;

        if(jwk != null) {
            originalId = jwk.getKeyID();
        }

        setContentPane(contentPane);
        setModal(true);
        getRootPane().setDefaultButton(buttonOK);

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

        // Set the window title and key combobox options based on the key type
        switch (mode){
            case EC: {
                setTitle(Utils.getResourceString("keys_new_title_ec"));
                comboBoxKeySize.setModel(new DefaultComboBoxModel<>(new Curve[]{
                        Curve.P_256,
                        Curve.SECP256K1,
                        Curve.P_384,
                        Curve.P_521
                }));

                Curve selectedCurve = jwk == null ? Curve.P_256 : ((ECKey) jwk).getCurve();
                comboBoxKeySize.setSelectedItem(selectedCurve);

                break;
            }

            case RSA: {
                setTitle(Utils.getResourceString("keys_new_title_rsa"));
                comboBoxKeySize.setModel(new DefaultComboBoxModel<>(new Integer[]{
                        512,
                        1024,
                        2048,
                        3072,
                        4096
                }));

                int selectedKeySize = jwk == null ? 2048 : jwk.size();
                comboBoxKeySize.setSelectedItem(selectedKeySize);

                break;
            }

            case OKP: {
                setTitle(Utils.getResourceString("keys_new_title_okp"));
                comboBoxKeySize.setModel(new DefaultComboBoxModel<>(new Curve[]{
                        Curve.X25519,
                        Curve.Ed25519,
                        Curve.X448,
                        Curve.Ed448,
                }));

                Curve selectedCurve = jwk == null ? Curve.X25519 : ((OctetKeyPair) jwk).getCurve();
                comboBoxKeySize.setSelectedItem(selectedCurve);
            }
        }

        // Add event listeners for the generate button being pressed, the key format radio button changing, or the text
        // content being updated
        radioButtonJWK.addChangeListener(e -> onKeyFormatChanged());
        buttonGenerate.addActionListener(e -> generate());

        DocumentListener documentListener = new DocumentListener() {
            public void insertUpdate(DocumentEvent e) {
                checkInput();
            }

            public void removeUpdate(DocumentEvent e) {
                checkInput();
            }

            public void changedUpdate(DocumentEvent e) {
                checkInput();
            }
        };

        textAreaKey.getDocument().addDocumentListener(documentListener);
        textFieldKeyId.getDocument().addDocumentListener(documentListener);

        // If not in edit mode setting the contents of the text field before the window has opened causes the horizontal
        // scroll pane not to initialize properly, so do this after the window open event
        addWindowListener(new WindowAdapter() {
            @Override
            public void windowOpened(WindowEvent e) {
                onKeyFormatChanged();
            }
        });
    }

    /**
     * Enable/disable the OK button
     * @param enabled whether the OK button should be enabled
     */
    private void setFormEnabled(boolean enabled){
        buttonOK.setEnabled(enabled);
    }

    /**
     * Check the contents of the text input
     */
    private void checkInput(){
        if(textAreaKeyInitialBackgroundColor == null) {
            textAreaKeyInitialBackgroundColor = textAreaKey.getBackground();
            textAreaKeyInitialCurrentLineHighlightColor = textAreaKey.getCurrentLineHighlightColor();
        }

        JWK tempJWK = null;

        // Get the text contents
        String key = textAreaKey.getText();

        // Clear any error formatting
        setFormEnabled(true);
        textAreaKey.setBackground(textAreaKeyInitialBackgroundColor);
        textAreaKey.setCurrentLineHighlightColor(textAreaKeyInitialCurrentLineHighlightColor);
        textFieldKeyId.setBackground(textAreaKeyInitialBackgroundColor);
        labelError.setText(" ");

        boolean keyError = false;
        boolean keyIDError = false;
        if(key.length() == 0) {
            // Disable OK if the text entry is empty
            setFormEnabled(false);
        }
        else{
            try {
                // If JWK is selected, try to parse as a JWK
                if(radioButtonJWK.isSelected()){
                    tempJWK = JWK.parse(key);

                    if(tempJWK.getKeyID() == null){
                        keyError = true;
                        labelError.setText(Utils.getResourceString("error_missing_kid"));
                    }

                    // Restricting RSA private keys to their full form at the moment as there is an issue with PEM parsing these keys
                    if(tempJWK instanceof RSAKey && tempJWK.isPrivate() && ((RSAKey)tempJWK).getFirstPrimeFactor() == null){
                        keyError = true;
                        labelError.setText(Utils.getResourceString("error_invalid_key"));
                    }
                }
                // If not, try to parse the PEM and convert to a JWK
                else {
                    switch (mode){
                        case EC:
                            tempJWK = PEMUtils.pemToECKey(key, textFieldKeyId.getText());
                            break;
                        case RSA:
                            tempJWK = PEMUtils.pemToRSAKey(key, textFieldKeyId.getText());
                            break;
                        case OKP:
                            tempJWK = PEMUtils.pemToOctetKeyPair(key, textFieldKeyId.getText());
                            break;
                    }

                    // Check the key id entry is set in PEM mode
                    if(textFieldKeyId.getText().length() == 0) {
                        keyIDError = true;
                        labelError.setText(Utils.getResourceString("error_missing_kid"));
                    }
                }

                // Check the parsed JWK is the correct type for the window mode
                if(!(tempJWK.getKeyType() == mode.keyType)){
                    keyError = true;
                    labelError.setText(Utils.getResourceString("error_invalid_key_type"));
                }

            } catch (ParseException | IllegalArgumentException | PEMUtils.PemException e) {
                // Set the error state if any parse errors are encountered
                keyError = true;
                if(textFieldKeyId.getText().length() == 0) {
                    keyIDError = true;
                }
                labelError.setText(Utils.getResourceString("error_invalid_key"));
            }

        }

        // If the key ID is invalid, disable OK and highlight the key id text entry
        if(keyIDError){
            setFormEnabled(false);
            textFieldKeyId.setBackground(Color.PINK);
        }

        // If the key text is invalid, disable OK and highlight the key text entry
        if(keyError){
            setFormEnabled(false);
            textAreaKey.setBackground(Color.PINK);
            textAreaKey.setCurrentLineHighlightColor(Color.PINK);
        }

        // Set the parsed JWK if there are no errors, set to null otherwise
        if(keyError || keyIDError){
            jwk = null;
        }
        else{
            jwk = tempJWK;
        }
    }

    /**
     * Handler for the key format radio button changing
     */
    private void onKeyFormatChanged(){
        // Change from PEM to JWK
        if(radioButtonJWK.isSelected()){
            if(jwk == null) {
                // If the PEM has not been parsed to a JWK, clear the JWK entry
                textAreaKey.setText("");
            }
            else{
                // Otherwise, serialized the JWK to JSON and set the contents of the text box
                textAreaKey.setText(Utils.prettyPrintJSON(jwk.toJSONString()));
            }

            // Ordering is important here, these must come after the conversion above, otherwise they will trigger the
            // event handlers and clear the stored jwk
            textAreaKey.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JSON);
            panelKeyId.setVisible(false);
        }
        // Change from JWK to PEM
        else {
            if(jwk == null) {
                // If the JWK has not been parsed, clear the PEM entry and key id text box
                textFieldKeyId.setText("");
                textAreaKey.setText("");
            }
            else {
                // Otherwise, serialized the JWK to PEM and set the contents of the text box
                try {
                    // Store a temporary copy of the JWK as setting the first field will overwrite the stored JWK
                    JWK tempJWK = jwk;
                    textFieldKeyId.setText(tempJWK.getKeyID());
                    textAreaKey.setText(PEMUtils.jwkToPem(tempJWK));
                }
                catch (PEMUtils.PemException e){
                    textFieldKeyId.setText("");
                    textAreaKey.setText("");
                }
            }

            // Ordering is important here, these must come after the conversion above, otherwise they will clear the
            // event handlers and clear the stored jwk
            textAreaKey.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_NONE);
            panelKeyId.setVisible(true);
        }
    }

    /**
     * Handle clicks to the Generate button
     */
    private void generate(){
        // Get the selected key size
        Object parameters = comboBoxKeySize.getSelectedItem();

        // Disable the form controls during keygen
        comboBoxKeySize.setEnabled(false);
        buttonGenerate.setEnabled(false);
        textAreaKey.setEnabled(false);
        textFieldKeyId.setEnabled(false);
        buttonOK.setEnabled(false);
        radioButtonJWK.setEnabled(false);
        radioButtonPEM.setEnabled(false);

        // Generate the new key on a background thread as this may be long running
        SwingWorker<JWK, Void> generateTask = new SwingWorker<JWK, Void>() {
            @Override
            protected JWK doInBackground() throws Exception {
                // Generate a random key id
                String kid = UUID.randomUUID().toString();

                // Force using the BC provider, but fall-back to default if this fails
                KeyStore keyStore = null;
                Provider provider = Security.getProvider("BC");
                if(provider != null){
                    keyStore = KeyStore.getInstance(KeyStore.getDefaultType(), provider);
                }

                // Select the key generator and generate based on the dialog mode
                switch(mode){
                    case EC:
                        //noinspection ConstantConditions
                        return new ECKeyGenerator((Curve) parameters).keyStore(keyStore).keyID(kid).generate();
                    case RSA:
                        //noinspection ConstantConditions
                        return new RSAKeyGenerator((Integer) parameters, true).keyStore(keyStore).keyID(kid).generate();
                    case OKP:
                        return new OKPGenerator((Curve) parameters).keyStore(keyStore).keyID(kid).generate();
                    default:
                        throw new IllegalStateException("Can't happen - invalid mode");
                }
            }

            /**
             * Called when doInBackground has finished
             */
            @Override
            protected void done() {
                try {
                    // Get the return value of doInBackground
                    JWK jwk = get();

                    // Set the key text fields based on whether JWK/PEM is selected in the radio button
                    if(radioButtonJWK.isSelected()) {
                        textAreaKey.setText(Utils.prettyPrintJSON(jwk.toJSONString()));
                    }
                    else {
                        textFieldKeyId.setText(jwk.getKeyID());
                        textAreaKey.setText(PEMUtils.jwkToPem(jwk));
                    }
                } catch (PEMUtils.PemException | InterruptedException | ExecutionException e) {
                    labelError.setText(Utils.getResourceString("error_key_generation"));
                }

                // Re-enable the form
                comboBoxKeySize.setEnabled(true);
                buttonGenerate.setEnabled(true);
                textAreaKey.setEnabled(true);
                textFieldKeyId.setEnabled(true);
                buttonOK.setEnabled(true);
                radioButtonJWK.setEnabled(true);
                radioButtonPEM.setEnabled(true);
            }
        };

        generateTask.execute();
    }

    /**
     * Get the new/modified key resulting from the operations of this dialog
     * @return the new/modified JWK
     */
    public Key getKey(){
        if(jwk == null){
            return null;
        }
        else {
            try{
                return new JWKKey(jwk);
            }
            catch (Key.UnsupportedKeyException e){
                return null;
            }

        }
    }

    /**
     * Called when the Cancel or X button is pressed. Set the changed key to null and destroy the window
     */
    private void onCancel() {
        jwk = null;
        dispose();
    }

    private void createUIComponents() {
        textAreaKey = rstaFactory.build();
    }
}
