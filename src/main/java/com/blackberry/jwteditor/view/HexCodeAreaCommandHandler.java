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

import com.blackberry.jwteditor.utils.Utils;
import com.nimbusds.jose.util.Base64URL;
import org.apache.commons.codec.DecoderException;
import org.exbin.deltahex.EditationMode;
import org.exbin.deltahex.swing.CodeArea;
import org.exbin.deltahex.swing.CodeAreaCaret;
import org.exbin.deltahex.swing.DefaultCodeAreaCommandHandler;
import org.exbin.utils.binary_data.EditableBinaryData;

import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.io.IOException;

import static org.apache.commons.codec.binary.Hex.decodeHex;
import static org.apache.commons.codec.binary.Hex.encodeHex;

/**
 * Class to handle copy and paste from a CodeArea to/from hexadecimal strings
 *
 * Modified from https://github.com/exbin/bined-lib-java/blob/5abc397f3091cf2471057e9c7a9943bb19deeb32/modules/bined-swt/src/main/java/org/exbin/bined/swt/basic/DefaultCodeAreaCommandHandler.java
 *
 * Copyright (C) ExBin Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
public class HexCodeAreaCommandHandler extends DefaultCodeAreaCommandHandler {

    private final CodeArea codeArea;

    public HexCodeAreaCommandHandler(CodeArea codeArea) {
        super(codeArea);
        this.codeArea = codeArea;
    }

    /**
     * Copy the contents of the CodeArea to the clipboard as a hexadecimal string
     */
    @Override
    public void copy() {
        byte[] data = Utils.getCodeAreaData(codeArea);
        Utils.copyToClipboard(String.valueOf(encodeHex(data)));
    }

    /**
     * Cut the contents of the CodeArea to the clipboard as a hexadecimal string
     */
    @Override
    public void cut() {
        byte[] data = Utils.getCodeAreaData(codeArea);
        super.cut();
        Utils.copyToClipboard(String.valueOf(encodeHex(data)));
    }

    /**
     * Paste an array of bytes into the CodeArea
     * @param bytes bytes to paste
     */
    private void pasteByteArray(byte[] bytes){
        CodeAreaCaret caret = codeArea.getCaret();
        long dataPosition = caret.getDataPosition();
        int length = bytes.length;
        if (this.codeArea.getEditationMode() == EditationMode.OVERWRITE) {
            long toRemove = length;
            if (dataPosition + toRemove > this.codeArea.getDataSize()) {
                toRemove = this.codeArea.getDataSize() - dataPosition;
            }

            ((EditableBinaryData)this.codeArea.getData()).remove(dataPosition, toRemove);
        }

        ((EditableBinaryData)this.codeArea.getData()).insert(this.codeArea.getDataPosition(), bytes);
        this.codeArea.notifyDataChanged();
        caret.setCaretPosition(caret.getDataPosition() + (long)length);
        caret.setCodeOffset(0);
        this.codeArea.updateScrollBars();
        this.codeArea.notifyCaretMoved();
        this.codeArea.revealCursor();
    }

    /**
     * Paste to the contents of the CodeArea from the clipboard, which can be binary, base64 or hexadecimal
     */
    @Override
    public void paste() {
        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
        try {
            if(clipboard.isDataFlavorAvailable(DataFlavor.stringFlavor)){
                String clipboardData = (String) clipboard.getData(DataFlavor.stringFlavor);

                if(Utils.isHex(clipboardData)){
                    pasteByteArray(decodeHex(clipboardData.toCharArray()));
                }
                else if(Utils.isBase64URL(clipboardData)){
                    pasteByteArray(Base64URL.from(clipboardData).decode());
                }
                else {
                    super.paste();
                }
            }
        } catch (UnsupportedFlavorException | IOException | DecoderException e) {
            super.paste();
        }
    }
}
