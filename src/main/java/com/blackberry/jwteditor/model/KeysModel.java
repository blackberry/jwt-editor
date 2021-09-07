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

package com.blackberry.jwteditor.model;

import com.blackberry.jwteditor.model.keys.Key;
import com.blackberry.jwteditor.presenter.KeysPresenter;
import org.json.JSONArray;
import org.json.JSONObject;

import java.util.*;

/**
 * A container class for Key objects
 */
public class KeysModel implements Iterable<Key>{

    // Underlying hashmap - use LinkedHashMap to preserve insertion order
    final LinkedHashMap<String, Key> keys;
    KeysPresenter presenter = null;

    /**
     * Iterator to pass through to the underlying hashmap
     */
    @Override
    public Iterator<Key> iterator() {
        return new KeyModelIterator();
    }



    class KeyModelIterator implements Iterator<Key>{

        final Iterator<String> hashMapIterator;

        public KeyModelIterator() {
            hashMapIterator = keys.keySet().iterator();
        }

        @Override
        public boolean hasNext() {
            return hashMapIterator.hasNext();
        }

        @Override
        public Key next() {
            return keys.get(hashMapIterator.next());
        }
    }

    /**
     * Create an empty KeysModel
     */
    public KeysModel(){
        keys = new LinkedHashMap<>();
    }

    /**
     * Parse a JSON string to a KeysModel
     *
     * @param json JSON string containing encoded keys
     * @return the KeysModel parsed from the JSON
     * @throws java.text.ParseException if parsing fails
     */
    public static KeysModel parse(String json) throws java.text.ParseException {
        KeysModel keysModel = new KeysModel();
        try {
            JSONArray savedKeys = new JSONArray(json);

            for (Object savedKey : savedKeys) {
                Key key = Key.fromJSONObject((JSONObject) savedKey);
                keysModel.addKey(key);
            }

        } catch (Key.UnsupportedKeyException | java.text.ParseException e) {
            throw new java.text.ParseException(e.getMessage(), 0);
        }
        return keysModel;
    }

    /**
     * Convert the KeysModel to a JSON string
     *
     * @return JSON string representation of the KeysModel
     */
    public String serialize(){
        JSONArray jsonArray = new JSONArray();

        for(Key key: this){
            jsonArray.put(key.toJSONObject());
        }

        return jsonArray.toString();
    }

    /**
     * Associate a UI presenter with this model that will be notified when the model changes
     *
     * @param presenter presenter to associate
     */
    public void setPresenter(KeysPresenter presenter){
        this.presenter = presenter;
    }

    /**
     * Get a list of all signing capable keys
     *
     * @return key list
     */
    public List<Key> getSigningKeys() {
        List<Key> keyList = new ArrayList<>();
        for(Key k: this){
            if(k.canSign()){
                keyList.add(k);
            }
        }
        return keyList;
    }

    /**
     * Get a list of all verification capable keys
     *
     * @return key list
     */
    public List<Key> getVerificationKeys() {
        List<Key> keyList = new ArrayList<>();
        for(Key k: this){
            if(k.canVerify()){
                keyList.add(k);
            }
        }
        return keyList;
    }

    /**
     * Get a list of all encryption capable keys
     *
     * @return key list
     */
    public List<Key> getEncryptionKeys() {
        List<Key> keyList = new ArrayList<>();
        for(Key k: this){
            if(k.canEncrypt()){
                keyList.add(k);
            }
        }
        return keyList;
    }

    /**
     * Get a list of all decryption capable keys
     *
     * @return key list
     */
    public List<Key> getDecryptionKeys() {
        List<Key> keyList = new ArrayList<>();
        for(Key k: this){
            if(k.canDecrypt()){
                keyList.add(k);
            }
        }
        return keyList;
    }

    /**
     * Add a key to the model
     *
     * @param key key to add
     */
    public void addKey(Key key){
        keys.put(key.getID(), key);
        if(presenter != null){
            presenter.onModelUpdated();
        }
    }

    /**
     * Remove a key from the model by id
     *
     * @param keyId key id to remove
     */
    public void deleteKey(String keyId){
        keys.remove(keyId);
        if(presenter != null){
            presenter.onModelUpdated();
        }
    }

    /**
     * Remove a set of keys from the model by id
     *
     * @param indicies indicies of keys to remove
     */
    public void deleteKeys(int[] indicies) {
        List<String> toDelete = new ArrayList<>();
        for(int index: indicies){
            toDelete.add(getKey(index).getID());
        }
        for(String keyId: toDelete){
            deleteKey(keyId);
        }
    }

    /**
     * Remove a key from the model by index
     *
     * @param index index of key to remove
     */
    @SuppressWarnings("unused")
    public void deleteKey(int index) {
        deleteKey(getKey(index).getID());
    }

    /**
     * Get a key from the model by index
     *
     * @param index index of key to retrieve
     * @return retrieved key
     */
    public Key getKey(int index){
        String key = (String) keys.keySet().toArray()[index];
        return keys.get(key);
    }

    /**
     * Get a key from the model by index
     *
     * @param keyId ID of key to retrieve
     * @return retrieved key
     */
    public Key getKey(String keyId) {
        return keys.get(keyId);
    }
 }
