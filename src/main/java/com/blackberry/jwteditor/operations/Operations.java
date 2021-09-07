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

package com.blackberry.jwteditor.operations;

import com.blackberry.jwteditor.utils.CryptoUtils;
import com.blackberry.jwteditor.model.jose.JWE;
import com.blackberry.jwteditor.model.jose.JWS;
import com.blackberry.jwteditor.model.keys.JWKKey;
import com.blackberry.jwteditor.model.keys.Key;
import com.nimbusds.jose.*;
import com.nimbusds.jose.util.Base64URL;
import org.json.JSONException;
import org.json.JSONObject;

import java.text.ParseException;
import java.util.List;

/**
 * High-level operations on JWE/JWS
 */
public class Operations {

    public enum SigningUpdateMode {
        NONE,
        ALG,
        JWT
    }

    /**
     * Sign a JWS with a JWK
     *
     * @param jws the JWS to sign
     * @param key the JWK to sign the JWS with
     * @param algorithm the algorithm to sign with
     * @param signingUpdateMode the header update mode
     * @return the signed JWS
     * @throws CryptoUtils.SigningException if signing fails
     */
    public static JWS sign(JWS jws, JWKKey key, JWSAlgorithm algorithm, SigningUpdateMode signingUpdateMode) throws CryptoUtils.SigningException {

        // Build a new JWS header with the algorithm to use for signing
        JWSHeader signingInfo = new JWSHeader.Builder(algorithm).build();

        Base64URL encodedHeader;
        JSONObject jsonHeader;
        switch(signingUpdateMode){
            // Don't update the header
            case NONE:
                encodedHeader = jws.getEncodedHeader();
                break;
            // Update or insert the 'alg' field
            case ALG:
                try {
                    jsonHeader = new JSONObject(jws.getHeader());
                }
                catch (JSONException e) {
                    jsonHeader = new JSONObject();
                }
                jsonHeader.put("alg", algorithm.getName()); //NON-NLS
                encodedHeader = Base64URL.encode(jsonHeader.toString());
                break;
            // Update or insert 'alg', 'typ' and 'kid'
            case JWT:
                try {
                    jsonHeader = new JSONObject(jws.getHeader());
                }
                catch (JSONException e) {
                    jsonHeader = new JSONObject();
                }
                jsonHeader.put("alg", algorithm.getName()); //NON-NLS
                jsonHeader.put("typ", "JWT"); //NON-NLS
                jsonHeader.put("kid", key.getID()); //NON-NLS
                encodedHeader = Base64URL.encode(jsonHeader.toString());
                break;
            default:
                throw new IllegalStateException("Unexpected value: " + signingUpdateMode);
        }
        // Do the signing operation
        return CryptoUtils.sign(encodedHeader, jws.getEncodedPayload(), key, signingInfo);
    }

    /**
     * Attempt to verify a JWS with a list of JWKs
     *
     * @param jws the JWS to verify
     * @param keys a list of JWKs to attempt verification with
     * @return true if verification successful
     */
    public static boolean verify(JWS jws, List<Key> keys) {
        for(Key key: keys){
            for(JWSAlgorithm signingAlgorithm: key.getSigningAlgorithms()) {
                JWSHeader verificationInfo = new JWSHeader.Builder(signingAlgorithm).build();
                try {
                    if (CryptoUtils.verify(jws, key, verificationInfo)) {
                        return true;
                    }
                } catch (CryptoUtils.VerificationException e) {
                    // Verification failed for this key & algorithm pair
                }
            }
        }
        return false;
    }

    /**
     * Encrypt a JWS with a JWK
     *
     * @param jws the JWS to encrypt
     * @param selectedKey the JWK to use for encryption
     * @param selectedKek the key encryption algorithm
     * @param selectedCek the content encryption algorithm
     * @return the encrypted JWS as a JWE
     * @throws CryptoUtils.EncryptionException if encryption fails
     */
    public static JWE encrypt(JWS jws, Key selectedKey, JWEAlgorithm selectedKek, EncryptionMethod selectedCek) throws CryptoUtils.EncryptionException {
        return CryptoUtils.encrypt(jws, selectedKey, selectedKek, selectedCek);
    }

    /**
     * Attempt to decrypt a JWE with a set of JWKs
     *
     * @param jwe the JWE to decrypt
     * @param keys a list of JWKs to attempt decryption with
     * @return the decrypted JWS or null if all keys fail
     * @throws ParseException if parsing a decrypted JWE as a JWS fails
     */
    public static JWS decrypt(JWE jwe, List<Key> keys) throws ParseException {
        for(Key key: keys){
            try {
                return CryptoUtils.decrypt(jwe, key);
            } catch (CryptoUtils.DecryptionException e) {
                //Decryption failed for this key
            }
        }
        return null;
    }

}
