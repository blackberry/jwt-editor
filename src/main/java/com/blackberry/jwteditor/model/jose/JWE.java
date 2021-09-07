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

package com.blackberry.jwteditor.model.jose;

import com.nimbusds.jose.util.Base64URL;
import org.apache.commons.lang3.StringUtils;

import java.text.ParseException;

/**
 * Class representing a JWE
 */
public class JWE extends JOSEObject {

    private final Base64URL encryptedKey;
    private final Base64URL iv;
    private final Base64URL ciphertext;
    private final Base64URL tag;

    /**
     * Construct a JWE from encoded components
     *
     * @param header base64 encoded header
     * @param encryptedKey base64 encoded encrypted key
     * @param iv base64 encoded iv
     * @param ciphertext base64 encoded ciphertext
     * @param tag base64 encoded tag
     */
    public JWE(Base64URL header, Base64URL encryptedKey, Base64URL iv, Base64URL ciphertext, Base64URL tag) {
        this.header = header;
        this.encryptedKey = encryptedKey;
        this.iv = iv;
        this.ciphertext = ciphertext;
        this.tag = tag;
    }

    /**
     * Parse a JWE from compact serialization
     *
     * @param compactJWE JWE in compact serialization form
     * @return a parsed JWE object
     * @throws ParseException if the value is not a valid JWE
     */
    public static JWE parse(String compactJWE) throws ParseException {
        if(StringUtils.countMatches(compactJWE, ".") != 4){
            throw new ParseException("Invalid number of encoded fields", 0);
        }

        Base64URL[] parts = com.nimbusds.jose.JOSEObject.split(compactJWE);

        boolean allEmpty = true;
        for(Base64URL part: parts){
            if(part.decodeToString().length() > 0){
                allEmpty = false;
            }
        }

        if(allEmpty){
            throw new ParseException("All sections empty", 0);
        }

        return new JWE(parts[0], parts[1], parts[2], parts[3], parts[4]);
    }

    /**
     * Serialize the JWE to compact form
     *
     * @return String containing the JWE in compact serialization
     */
    @Override
    public String serialize() {
        return String.format("%s.%s.%s.%s.%s", header.toString(), encryptedKey.toString(), iv.toString(), ciphertext.toString(), tag.toString()); //NON-NLS
    }

    /**
     * Get the encrypted key component as bytes
     *
     * @return the decoded encrypted key
     */
    public byte[] getEncryptedKey(){
        if(encryptedKey == null){
            return new byte[0];
        }
        else {
            return encryptedKey.decode();
        }
    }

    /**
     * Get the encrypted key as base64
     *
     * @return the encoded encrypted key
     */
    public Base64URL getEncodedEncryptedKey(){
        return encryptedKey;
    }

    /**
     * Get the ciphertext component as bytes
     *
     * @return the decoded ciphertext
     */
    public byte[] getCiphertext(){
        return ciphertext.decode();
    }

    /**
     * Get the ciphertext as base64
     *
     * @return the encoded ciphertext
     */
    public Base64URL getEncodedCiphertext(){
        return ciphertext;
    }

    /**
     * Get the tag component as bytes
     *
     * @return the decoded tag
     */
    public byte[] getTag(){
        return tag.decode();
    }

    /**
     * Get the tag as base64
     *
     * @return the encoded tag
     */
    public Base64URL getEncodedTag(){
        return tag;
    }

    /**
     * Get the iv as bytes
     *
     * @return the decoded iv
     */
    public byte[] getIV(){
        return iv.decode();
    }

    /**
     * Get the iv as base64
     *
     * @return the encoded iv
     */
    public Base64URL getEncodedIV(){
        return iv;
    }

}
