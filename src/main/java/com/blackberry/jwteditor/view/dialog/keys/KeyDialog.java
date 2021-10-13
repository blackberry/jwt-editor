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

import com.blackberry.jwteditor.model.keys.Key;
import com.blackberry.jwteditor.presenter.KeysPresenter;
import com.blackberry.jwteditor.presenter.PresenterStore;
import com.blackberry.jwteditor.utils.Utils;

import javax.swing.*;

/**
 * Abstract class to be extended by dialogs for key editing/generation on the Keys tab
 */
public abstract class KeyDialog extends JDialog {

    protected PresenterStore presenters;
    protected String originalId;

    public KeyDialog(JFrame parent){
        super(parent);
    }

    /**
     * Get the key generated/edited by the dialog
     * @return the new/modified key
     */
    public abstract Key getKey();

    /**
     * Handler for OK button click
     */
    protected void onOK() {
        KeysPresenter keyPresenter = (KeysPresenter) presenters.get(KeysPresenter.class);
        Key newKey = getKey();

        // Handle overwrites if a key already exists with the same kid
        if(keyPresenter.keyExists(newKey.getID())){
            // If the new and original key ids match, then this is an update
            if(originalId != null && originalId.equals(newKey.getID())){
                dispose();
                return;
            }
            else{
                // Otherwise, saving the key could overwrite an existing kid, so show a dialog to confirm
                int result = JOptionPane.showConfirmDialog(this, Utils.getResourceString("keys_confirm_overwrite"), Utils.getResourceString("keys_confirm_overwrite_title"), JOptionPane.OK_CANCEL_OPTION);
                if(result == 0){
                    dispose();
                }
                else {
                    return;
                }
            }
        }

        dispose();
    }

}
