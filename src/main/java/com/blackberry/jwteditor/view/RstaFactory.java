/*
Author : Dolph Flynn

Copyright 2022 Dolph Flynn

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
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.Theme;

import javax.swing.*;
import java.awt.event.HierarchyEvent;
import java.io.IOException;
import java.util.function.Consumer;

import static java.awt.Color.WHITE;

public interface RstaFactory {
    RSyntaxTextArea build();

    class DefaultRstaFactory implements RstaFactory {
        @Override
        public RSyntaxTextArea build() {
            return new RSyntaxTextArea();
        }
    }

    class BurpThemeAwareRstaFactory implements RstaFactory {
        private final ThemeDetector themeDetector;
        private final Consumer<String> errorLogger;

        public BurpThemeAwareRstaFactory(IBurpExtenderCallbacks callbacks) {
            this.themeDetector = new ThemeDetector(callbacks);
            this.errorLogger = callbacks::printError;
        }

        @Override
        public RSyntaxTextArea build() {
            return new BurpThemeAwareRSyntaxTextArea(themeDetector, errorLogger);
        }

        private static class BurpThemeAwareRSyntaxTextArea extends RSyntaxTextArea {
            private static final String DARK_THEME = "/org/fife/ui/rsyntaxtextarea/themes/dark.xml";
            private static final String LIGHT_THEME = "/org/fife/ui/rsyntaxtextarea/themes/default.xml";

            private final ThemeDetector themeDetector;
            private final Consumer<String> errorLogger;

            private BurpThemeAwareRSyntaxTextArea(ThemeDetector themeDetector, Consumer<String> errorLogger) {
                this.themeDetector = themeDetector;
                this.errorLogger = errorLogger;

                this.addHierarchyListener(e -> {
                    if (e.getChangeFlags() == HierarchyEvent.SHOWING_CHANGED && e.getComponent().isShowing()) {
                        applyTheme();
                    }
                });
            }

            @Override
            public void setSyntaxEditingStyle(String styleKey) {
                super.setSyntaxEditingStyle(styleKey);
                applyTheme();
            }

            @Override
            public void updateUI() {
                super.updateUI();
                applyTheme();
            }

            private void applyTheme() {
                if (themeDetector == null) {
                    return;
                }

                String themeResource = themeDetector.isLightTheme() ? LIGHT_THEME : DARK_THEME;

                try {
                    Theme theme = Theme.load(getClass().getResourceAsStream(themeResource));
                    theme.apply(this);
                } catch (IOException e) {
                    errorLogger.accept(e.getMessage());
                }
            }
        }

        private static class ThemeDetector {
            private final IBurpExtenderCallbacks callbacks;

            private ThemeDetector(IBurpExtenderCallbacks callbacks) {
                this.callbacks = callbacks;
            }

            boolean isLightTheme() {
                JLabel label = new JLabel();
                callbacks.customizeUiComponent(label);

                return label.getBackground().equals(WHITE);
            }
        }
    }
}
