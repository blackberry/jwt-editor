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

import com.blackberry.jwteditor.model.jose.JWS;
import com.blackberry.jwteditor.model.keys.JWKKey;
import com.blackberry.jwteditor.model.keys.Key;
import com.blackberry.jwteditor.model.keys.PasswordKey;
import com.blackberry.jwteditor.utils.CryptoUtils;
import com.blackberry.jwteditor.utils.PEMUtils;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import org.junit.jupiter.api.Test;

import java.text.ParseException;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;


public class SigningTests {

    private static JWS TEST_JWS = new JWS(
            Base64URL.encode("{\"typ\":\"JWT\",\"alg\":\"HS256\"}"), //NON-NLS
            Base64URL.encode("{\"sub\":\"Test\"}"), //NON-NLS
            Base64URL.encode(new byte[0])
        );

    @Test
    void rsaSigning() throws PEMUtils.PemException, Key.UnsupportedKeyException, CryptoUtils.SigningException, ParseException, CryptoUtils.VerificationException {
        boolean atLeastOne = false;

        for (String pem : PEMToJWKTests.RSAPrivate) {
            RSAKey rsaKey = PEMUtils.pemToRSAKey(pem);
            JWKKey key = new JWKKey(rsaKey);
            if(key.canSign()) {
                for (JWSAlgorithm algorithm : key.getSigningAlgorithms()) {
                    JWSHeader signingInfo = new JWSHeader.Builder(algorithm).build();
                    JWS jws = CryptoUtils.sign(signingInfo.toBase64URL(), TEST_JWS.getEncodedPayload(), key, signingInfo);
                    assertTrue(CryptoUtils.verify(jws, key, signingInfo));
                    atLeastOne = true;
                }
            }
        }
        assertTrue(atLeastOne);
    }

    @Test
    void ecSigning() throws PEMUtils.PemException, Key.UnsupportedKeyException, CryptoUtils.SigningException, ParseException, CryptoUtils.VerificationException {
        boolean atLeastOne = false;

        for (String pem : PEMToJWKTests.ECPrivate){
            ECKey ecKey = PEMUtils.pemToECKey(pem);
            JWKKey key = new JWKKey(ecKey);
            if(key.canSign()) {
                for (JWSAlgorithm algorithm : key.getSigningAlgorithms()) {
                    JWSHeader signingInfo = new JWSHeader.Builder(algorithm).build();
                    JWS jws = CryptoUtils.sign(signingInfo.toBase64URL(), TEST_JWS.getEncodedPayload(), key, signingInfo);
                    assertTrue(CryptoUtils.verify(jws, key, signingInfo));
                    atLeastOne = true;
                }
            }
        }
        assertTrue(atLeastOne);
    }

    @Test
    void okpSigning() throws PEMUtils.PemException, Key.UnsupportedKeyException, CryptoUtils.SigningException, ParseException, CryptoUtils.VerificationException {
        boolean atLeastOne = false;

        for (String pem : PEMToJWKTests.OKPPrivate){
            OctetKeyPair octetKeyPair = PEMUtils.pemToOctetKeyPair(pem);
            JWKKey privateKey = new JWKKey(octetKeyPair);
            JWKKey publicKey = new JWKKey(octetKeyPair.toPublicJWK());
            if(privateKey.canSign()) {
                for (JWSAlgorithm algorithm : privateKey.getSigningAlgorithms()) {
                    JWSHeader signingInfo = new JWSHeader.Builder(algorithm).build();
                    JWS jws = CryptoUtils.sign(signingInfo.toBase64URL(), TEST_JWS.getEncodedPayload(), privateKey, signingInfo);
                    assertTrue(CryptoUtils.verify(jws, publicKey, signingInfo));
                    atLeastOne = true;
                }
            }
        }
        assertTrue(atLeastOne);
    }

    @Test
    void octSigning() throws JOSEException, Key.UnsupportedKeyException, CryptoUtils.SigningException, ParseException, CryptoUtils.VerificationException {
        boolean atLeastOne = false;

        OctetSequenceKey[] octetSequenceKeys = new OctetSequenceKey[]{
                new OctetSequenceKeyGenerator(128).generate(),
                new OctetSequenceKeyGenerator(192).generate(),
                new OctetSequenceKeyGenerator(256).generate(),
                new OctetSequenceKeyGenerator(384).generate(),
                new OctetSequenceKeyGenerator(512).generate(),
                new OctetSequenceKey.Builder("secret123".getBytes()).build(),
        };

        for(OctetSequenceKey octetSequenceKey: octetSequenceKeys){
            JWKKey key = new JWKKey(octetSequenceKey);
            assertTrue(key.canSign()); //any key should be able to sign

            for (JWSAlgorithm algorithm : key.getSigningAlgorithms()) {
                JWSHeader signingInfo = new JWSHeader.Builder(algorithm).build();
                JWS jws = CryptoUtils.sign(signingInfo.toBase64URL(), TEST_JWS.getEncodedPayload(), key, signingInfo);
                //we should be able to sign and verify with any supported algorithm
                assertTrue(CryptoUtils.verify(jws, key, signingInfo));
                atLeastOne = true;
            }
        }
        assertTrue(atLeastOne);
    }

    @Test
    void passwordSigning() {
        PasswordKey key = new PasswordKey("Test", "Test", 8, 1000); //NON-NLS
        assertFalse(key.canSign());
        assertFalse(key.canVerify());
    }
}
