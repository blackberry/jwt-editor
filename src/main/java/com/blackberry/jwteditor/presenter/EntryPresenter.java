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

import com.blackberry.jwteditor.view.EntryView;

/**
 * Presenter for the Entry tab in standalone mode
 */
public class EntryPresenter extends Presenter {

    private final EntryView view;
    private final PresenterStore presenters;

    public EntryPresenter(EntryView view, PresenterStore presenters) {
        this.view = view;
        this.presenters = presenters;
        presenters.register(this);
    }

    /**
     * Callback called when the text entry changes
     */
    public void onTextAreaChanged() {
        // Pass the text up to the standalone presenter
        StandalonePresenter standalonePresenter = (StandalonePresenter) presenters.get(StandalonePresenter.class);
        standalonePresenter.onEntryTextAreaChanged(view.getText());
    }

    /**
     * Get the text from the entry view
     *
     * @return entry view text
     */
    public String getText() {
        return view.getText();
    }

    /**
     * Set the entry view text
     *
     * @param text text to set
     */
    public void setText(String text) {
        view.setText(text);
    }
}
