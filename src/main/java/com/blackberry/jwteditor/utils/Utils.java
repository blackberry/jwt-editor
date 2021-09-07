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

package com.blackberry.jwteditor.utils;

import com.blackberry.jwteditor.model.jose.JOSEObjectPair;
import com.blackberry.jwteditor.model.jose.JWE;
import com.blackberry.jwteditor.model.jose.JWS;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSObject;
import org.apache.commons.lang3.StringUtils;
import org.exbin.deltahex.swing.CodeArea;
import org.exbin.utils.binary_data.BinaryData;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.ResourceBundle;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Class containing general util methods used throughout the other classes
 */
public class Utils {

    private static final String RESOURCE_BUNDLE = "strings"; //NON-NLS

    // Regular expressions for JWS/JWE extraction
    private static final String BASE64_REGEX = "[A-Za-z0-9-_]"; //NON-NLS
    private static final String JWS_REGEX = String.format("e%s*\\.%s+\\.%s*", BASE64_REGEX, BASE64_REGEX, BASE64_REGEX); //NON-NLS
    private static final String JWE_REGEX = String.format("e%s*\\.%s*\\.%s+\\.%s+\\.%s+", BASE64_REGEX, BASE64_REGEX, BASE64_REGEX, BASE64_REGEX, BASE64_REGEX); //NON-NLS
    private static final Pattern JOSE_OBJECT_PATTERN = Pattern.compile(String.format("(%s)|(%s)", JWE_REGEX, JWS_REGEX)); //NON-NLS
    private static final Pattern HEX_PATTERN = Pattern.compile("^([0-9a-fA-F]{2})+$"); //NON-NLS
    private static final Pattern BASE64_PATTERN = Pattern.compile(String.format("^%s+$", BASE64_REGEX)); //NON-NLS

    // On-disk storage constants
    private static final String KEYS_DIR = ".jwt-editor"; //NON-NLS
    private static final String KEYS_FILE = "keys.json"; //NON-NLS

    /**
     * Pretty print a string containing JSON using standard indentation
     *
     * @param json String containing JSON to pretty print
     * @return String containing pretty printed JSON
     */
    public static String prettyPrintJSON(String json){
        return prettyPrintJSON(json, 4);
    }

    /**
     * Pretty print a string containing JSON
     *
     * @param json String containing JSON to pretty print
     * @param indentation number of spaces to use for each indentation level
     * @return String containing pretty printed JSON
     */
    public static String prettyPrintJSON(String json, int indentation){
        // Strip any whitespace from the JSON string, also ensures the string actually contains valid JSON
        json = compactJSON(json);

        StringBuilder stringBuilder = new StringBuilder();

        // Simple pretty printer that increases indentation for every new Object or Array and places each key/value pair on a new line
        int indentationLevel = 0;
        boolean stringContext = false;
        for(char c: json.toCharArray()) {

            if(stringContext){
                stringBuilder.append(c);
            }
            else {
                if (c == '{' || c == '[') {
                    indentationLevel++;
                    stringBuilder.append(c);
                    stringBuilder.append('\n');
                    stringBuilder.append(StringUtils.repeat(' ', indentationLevel * indentation));
                }
                else if (c == '}' || c == ']') {
                    indentationLevel--;
                    stringBuilder.append('\n');
                    stringBuilder.append(StringUtils.repeat(' ', indentationLevel * indentation));
                    stringBuilder.append(c);
                }
                else if (c == ':') {
                    stringBuilder.append(": ");
                }
                else if (c == ',') {
                    stringBuilder.append(",\n");
                    stringBuilder.append(StringUtils.repeat(' ', indentationLevel * indentation));
                }
                else {
                    stringBuilder.append(c);
                }
            }

            if(c == '"'){
                stringContext = !stringContext;
            }
        }
        return stringBuilder.toString();
    }

    /**
     * Strip the whitespace from a string containing JSON
     *
     * @param json JSON string containing whitespace
     * @return JSON string without whitespace
     */
    public static String compactJSON(String json) {

        // Use JSONObject or JSONArray to perform an initial parse to check the content of the string is JSON
        try {
            new JSONObject(json);
        }
        catch (JSONException e) {
            try {
                new JSONArray(json);
            }
            catch (JSONException e2){
                throw e;
            }
        }

        StringBuilder stringBuilder = new StringBuilder();
        // Whitespace in JSON is four characters that are not inside a matched pair of double quotes
        boolean stringContext = false;
        for(char c: json.toCharArray()){
            if (!stringContext && (c == 0x20 || c == 0x0A || c == 0x0D || c == 0x09)) {
                continue;
            }

            stringBuilder.append(c);

            if(c == '"'){
                stringContext = !stringContext;
            }
        }
        return stringBuilder.toString();
    }

    /**
     * Remove all instances of the specified byte from the end of a byte array
     *
     * @param byteArray array of bytes to trim
     * @param trailingByte byte to remove
     * @return trimmed byte array
     */
    public static byte[] trimTrailingBytes(byte[] byteArray, byte trailingByte){
        // Find the earliest position from the end of the continuous sequence of trailingByte
        int i;
        for(i= byteArray.length - 1; i > 0; i--){
            if(byteArray[i] != trailingByte){
                break;
            }
        }

        // Return the subarray to the index
        return Arrays.copyOfRange(byteArray, 0, i);
    }

    /**
     * Copy a String to the default system clipboard
     *
     * @param text String to copy to the clipboard
     */
    public static void copyToClipboard(String text) {
        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
        clipboard.setContents(new StringSelection(text), null);
    }

    /**
     * Does a string contain valid hexadecimal
     *
     * @param string string to check
     * @return true if the string contains a valid sequence of hex characters
     */
    public static boolean isHex(String string){
        return HEX_PATTERN.matcher(string).matches();
    }

    /**
     * Does a string contain only valid base64url characters
     *
     * @param string string to check
     * @return true if the string contains a valid sequence of characters that may be base64url encoded
     */
    public static boolean isBase64URL(String string){
        return BASE64_PATTERN.matcher(string).matches();
    }

    /**
     * Get a localised string from the resource bundle
     *
     * @param id resource bundle id
     * @return corresponding string
     */
    public static String getResourceString(String id){
        return ResourceBundle.getBundle(RESOURCE_BUNDLE).getString(id);
    }

    /**
     * Helper to extract the matched strings from a match object
     * @param m match object
     * @return set of matched strings
     */
    private static HashSet<String> extractStrings(Matcher m){
        HashSet<String> strings = new HashSet<>();

        while(m.find()){
            String token = m.group();
            strings.add(token);
        }

        return strings;
    }

    /**
     * Extract a list of JOSEObjectPairs from a block of text that may contain JWE/JWS in compact form
     *
     * @param text text block
     * @return list of JOSEObjectPairs
     */
    public static ArrayList<JOSEObjectPair> extractJOSEObjects(String text){
        ArrayList<JOSEObjectPair> joseObjects = new ArrayList<>();

        // Get a list of potential matches from the text using a regular expression
        Matcher m = JOSE_OBJECT_PATTERN.matcher(text);

        // Convert the match to a set of strings
        for(String joseObjectCandidate : extractStrings(m)){
            // Try to parse each as both a JWE and a JWS, if this succeeds, add to the list
            try {
                JWEObject.parse(joseObjectCandidate);
                joseObjects.add(new JOSEObjectPair(joseObjectCandidate, JWE.parse(joseObjectCandidate)));
                continue;
            } catch (ParseException e) {
                // Not a JWE
            }

            try {
                JWSObject.parse(joseObjectCandidate);
                joseObjects.add(new JOSEObjectPair(joseObjectCandidate, JWS.parse(joseObjectCandidate)));
            } catch (ParseException e) {
                // Not a JWS
            }
        }
        return joseObjects;
    }

    /**
     * Get data from a deltahex CodeArea as a byte[]
     *
     * @param codeArea CodeArea to extract bytes from
     * @return byte[] contents of the CodeArea
     */
    public static byte[] getCodeAreaData(CodeArea codeArea){
        BinaryData binaryData = codeArea.getData();
        int size = (int) binaryData.getDataSize();
        byte[] data = new byte[size];
        binaryData.copyToArray(0L, data, 0, size);
        return data;
    }

    /**
     * Get the filesystem folder for the key store
     *
     * @return Path to key store folder
     */
    public static Path getKeysDir(){
        return Paths.get(System.getProperty("user.home"), KEYS_DIR);
    }

    /**
     * Get the file on the filesystem for the key store
     *
     * @return Path to the key store
     */
    public static Path getKeysFile(){
        return Paths.get(getKeysDir().toString(), KEYS_FILE);
    }
}
