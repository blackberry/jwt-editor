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

package com.blackberry.jwteditor.model.keys;

import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.JWK;
import org.json.JSONObject;


import java.text.ParseException;

/**
 * Abstract class containing common elements for all keys
 */
public abstract class Key {

    public abstract String getID();
    public abstract String getDescription();
    public abstract String toString();

    public abstract boolean isPublic();
    public abstract boolean isPrivate();
    public abstract boolean canSign();
    public abstract boolean canVerify();
    public abstract boolean canEncrypt();
    public abstract boolean canDecrypt();

    public abstract boolean hasJWK();
    public abstract boolean hasPEM();


    public abstract JWSAlgorithm[] getSigningAlgorithms();
    public abstract JWEAlgorithm[] getKeyEncryptionKeyAlgorithms();
    public abstract EncryptionMethod[] getContentEncryptionKeyAlgorithms(JWEAlgorithm keyEncryptionKeyAlgorithm);

    public abstract JWSSigner getSigner() throws JOSEException;
    public abstract JWSVerifier getVerifier() throws JOSEException;
    public abstract JWEEncrypter getEncrypter(JWEAlgorithm kekAlgorithm) throws JOSEException;
    public abstract JWEDecrypter getDecrypter(JWEAlgorithm kekAlgorithm) throws JOSEException;

    public abstract JSONObject toJSONObject();

    /**
     * Parse a password or JWK from a JSON object
     * @param jsonObject JSON containing the JWK/ serialized password object
     * @return the parsed Key
     * @throws ParseException if parsing fails
     * @throws UnsupportedKeyException if the key construction fails
     */
    public static Key fromJSONObject(JSONObject jsonObject) throws ParseException, UnsupportedKeyException {

        if( jsonObject.has("key_id") &&  //NON-NLS
            jsonObject.has("password") && //NON-NLS
            jsonObject.has("salt_length") && //NON-NLS
            jsonObject.has("iterations") //NON-NLS
        ){
            String key_id = (String) jsonObject.get("key_id");  //NON-NLS
            String password = (String) jsonObject.get("password");  //NON-NLS
            Integer salt_length = (Integer) jsonObject.get("salt_length");  //NON-NLS
            Integer iterations = (Integer) jsonObject.get("iterations");  //NON-NLS
            return new PasswordKey(key_id, password, salt_length, iterations);
        }
        else {
            return new JWKKey(JWK.parse(jsonObject.toString()));
        }
    }


    public static class UnsupportedKeyException extends Exception{

    }
}
