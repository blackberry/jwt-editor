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

import com.blackberry.jwteditor.presenter.*;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

/**
 * View class for the Entry tab in standalone mode
 */
public class EntryView {

    private JFrame parent;
    private EntryPresenter presenter;
    private JPanel panel;
    private RSyntaxTextArea textAreaEntry;
    private RstaFactory rstaFactory;

    @Deprecated
    public EntryView(){

    }

    public EntryView(JFrame parent, PresenterStore presenters, RstaFactory rstaFactory) {
        this.parent = parent;
        this.rstaFactory = rstaFactory;

        // Initialise the presenter
        presenter = new EntryPresenter(this, presenters);

        // Create an attach a listener for changes to the entry text box
        DocumentListener documentListener = new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                presenter.onTextAreaChanged();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                presenter.onTextAreaChanged();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                presenter.onTextAreaChanged();
            }
        };

        textAreaEntry.getDocument().addDocumentListener(documentListener);
    }

    /**
     * Get the contents of the entry text box
     * @return entry text box contents
     */
    public String getText() {
        return textAreaEntry.getText();
    }

    /**
     * Set the contents of the entry text box
     * @param text new entry text box contents
     */
    public void setText(String text) {
        textAreaEntry.setText(text);
    }

    /**
     * Get the view's parent JFrame
     * @return parent JFrame
     */
    @SuppressWarnings("unused")
    public JFrame getParent() {
        return parent;
    }

    private void createUIComponents() {
        textAreaEntry = rstaFactory.build();
    }
}
