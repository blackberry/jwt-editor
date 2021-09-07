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

package com.blackberry.jwteditor.presenter;

import com.blackberry.jwteditor.view.StandaloneView;

/**
 * Standalone presenter to control views when running in standalone mode
 */
public class StandalonePresenter extends Presenter{

    private final PresenterStore presenters;
    private final StandaloneView view;

    private int activeTab = StandaloneView.TAB_ENTRY;

    public StandalonePresenter(StandaloneView view, PresenterStore presenters) {
        this.view = view;
        this.presenters = presenters;
        presenters.register(this);
    }

    /**
     * Set the editor tab to enabled/disabled
     *
     * @param enabled editor tab enabled
     */
    public void setEditorEnabled(boolean enabled) {
        view.setEditorTabEnabled(enabled);
    }

    /**
     * Callback for the Entry tab text changing
     * @param text entry tab text view contents
     */
    public void onEntryTextAreaChanged(String text) {
        EditorPresenter editorPresenter = (EditorPresenter) presenters.get(EditorPresenter.class);
        // Check that the contents of the editor tab contains a JWE/JWS using the editor presenter
        // Enable the tab if a JWE/JWS is present
        setEditorEnabled(editorPresenter.isEnabled(text));
    }

    /**
     * Callback called whenever the user switches between tabs in standalone mode.
     *
     * Called after the tab has changed
     */
    public void onTabChanged() {
        // Get the destination tab
        int newTab = view.getActiveTab();

        EditorPresenter editorPresenter = (EditorPresenter) presenters.get(EditorPresenter.class);
        EntryPresenter entryPresenter = (EntryPresenter) presenters.get(EntryPresenter.class);

        if(activeTab == StandaloneView.TAB_ENTRY) {
            // Leaving the entry tab, set the editor tab to the entry tab contents
            editorPresenter.setMessage(entryPresenter.getText());
        }
        else if(newTab == StandaloneView.TAB_ENTRY){
            // Arriving to the entry tab, set the entry tab as the set of changes from the editor tab
            entryPresenter.setText(editorPresenter.getMessage());
        }

        // Update the current tab
        activeTab = newTab;
    }
}
