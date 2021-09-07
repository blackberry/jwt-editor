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

package com.blackberry.jwteditor;

import com.blackberry.jwteditor.utils.CryptoUtils;
import com.blackberry.jwteditor.utils.PEMUtils;
import com.blackberry.jwteditor.model.jose.JWE;
import com.blackberry.jwteditor.model.jose.JWS;
import com.blackberry.jwteditor.model.keys.JWKKey;
import com.blackberry.jwteditor.model.keys.Key;
import com.blackberry.jwteditor.model.keys.PasswordKey;
import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import org.junit.jupiter.api.Test;

import java.text.ParseException;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class EncryptionTests {

    final String TEST_JWS = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJUZXN0In0.WVLalefVZ5Rj991Cjgh0qBjKSIQaqC_CgN3b-30GKpQ";

    @Test
    void rsaEncryption() throws PEMUtils.PemException, Key.UnsupportedKeyException, ParseException, CryptoUtils.EncryptionException, CryptoUtils.DecryptionException {
        boolean atLeastOne = false;

        JWS jwsObject = JWS.parse(TEST_JWS);

        String[][] pemCollections = new String[][]{PEMToJWKTests.RSAPublic, PEMToJWKTests.RSAPrivate};
        for (String[] pemCollection: pemCollections) {
            for (String pem : pemCollection) {
                RSAKey rsaKey = PEMUtils.pemToRSAKey(pem);
                JWKKey key = new JWKKey(rsaKey);
                if (key.canEncrypt()) {
                    for (JWEAlgorithm kek : key.getKeyEncryptionKeyAlgorithms()) {
                        for (EncryptionMethod cek : key.getContentEncryptionKeyAlgorithms(kek)) {
                            JWE jwe = CryptoUtils.encrypt(jwsObject, key, kek, cek);

                            if(key.canDecrypt()){
                                CryptoUtils.decrypt(jwe, key);
                            }
                            atLeastOne = true;
                        }
                    }
                }
            }
        }
        assertTrue(atLeastOne);
    }

    @Test
    void ecEncryption() throws PEMUtils.PemException, Key.UnsupportedKeyException, ParseException, CryptoUtils.EncryptionException, CryptoUtils.DecryptionException {
        boolean atLeastOne = false;
        JWS jwsObject = JWS.parse(TEST_JWS);

        String[][] pemCollections = new String[][]{PEMToJWKTests.ECPublic, PEMToJWKTests.ECPrivate};

        for (String[] pemCollection: pemCollections) {
            for (String pem : pemCollection) {
                ECKey ecKey = PEMUtils.pemToECKey(pem);
                JWKKey key = new JWKKey(ecKey);
                if (key.canEncrypt()) {
                    for (JWEAlgorithm kek : key.getKeyEncryptionKeyAlgorithms()) {
                        for (EncryptionMethod cek : key.getContentEncryptionKeyAlgorithms(kek)) {
                            JWE jwe = CryptoUtils.encrypt(jwsObject, key, kek, cek);
                            if(key.canDecrypt()) {
                                CryptoUtils.decrypt(jwe, key);
                            }
                            atLeastOne = true;
                        }
                    }
                }
            }
        }
        assertTrue(atLeastOne);
    }

    @Test
    void okpEncryption() throws PEMUtils.PemException, Key.UnsupportedKeyException, ParseException, CryptoUtils.EncryptionException {
        boolean atLeastOne = false;

        JWS jwsObject = JWS.parse(TEST_JWS);

        String[][] pemCollections = new String[][]{PEMToJWKTests.OKPPublic, PEMToJWKTests.OKPPrivate};

        for (String[] pemCollection: pemCollections) {
            for (String pem : pemCollection) {
                OctetKeyPair octetKeyPair = PEMUtils.pemToOctetKeyPair(pem);
                JWKKey key = new JWKKey(octetKeyPair);
                if (key.canEncrypt()) {
                    for (JWEAlgorithm kek : key.getKeyEncryptionKeyAlgorithms()) {
                        for (EncryptionMethod cek : key.getContentEncryptionKeyAlgorithms(kek)) {
                            if(key.canDecrypt()){
                                CryptoUtils.encrypt(jwsObject, key, kek, cek);
                            }
                            atLeastOne = true;
                        }
                    }
                }
            }
        }
        assertTrue(atLeastOne);
    }

    @Test
    void octEncryption() throws Key.UnsupportedKeyException, ParseException, CryptoUtils.EncryptionException, JOSEException, CryptoUtils.DecryptionException {
        boolean atLeastOne = false;

        OctetSequenceKey[] octetSequenceKeys = new OctetSequenceKey[]{
                new OctetSequenceKeyGenerator(128).generate(),
                new OctetSequenceKeyGenerator(192).generate(),
                new OctetSequenceKeyGenerator(256).generate(),
                new OctetSequenceKeyGenerator(384).generate(),
                new OctetSequenceKeyGenerator(512).generate(),
        };

        JWS jwsObject = JWS.parse(TEST_JWS);

        for(OctetSequenceKey octetSequenceKey: octetSequenceKeys){
            JWKKey key = new JWKKey(octetSequenceKey);
            if(key.canEncrypt()) {
                for (JWEAlgorithm kek : key.getKeyEncryptionKeyAlgorithms()) {
                    for (EncryptionMethod cek : key.getContentEncryptionKeyAlgorithms(kek)) {
                        JWE jwe = CryptoUtils.encrypt(jwsObject, key, kek, cek);
                        CryptoUtils.decrypt(jwe, key);
                        atLeastOne = true;
                    }
                }
            }
        }
        assertTrue(atLeastOne);
    }

    @Test
    void passwordEncryption() throws ParseException, CryptoUtils.EncryptionException, CryptoUtils.DecryptionException {
        boolean atLeastOne = false;
        JWS jwsObject = JWS.parse(TEST_JWS);

        PasswordKey key = new PasswordKey("Test", "Test", 8, 1000);
        if(key.canEncrypt()) {
            for (JWEAlgorithm kek : key.getKeyEncryptionKeyAlgorithms()) {
                for (EncryptionMethod cek : key.getContentEncryptionKeyAlgorithms(kek)) {
                    JWE jwe = CryptoUtils.encrypt(jwsObject, key, kek, cek);
                    CryptoUtils.decrypt(jwe, key);
                    atLeastOne = true;
                }
            }
        }
        assertTrue(atLeastOne);
    }

}
