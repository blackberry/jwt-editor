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

import com.blackberry.jwteditor.utils.PEMUtils;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.Test;

import java.text.ParseException;

import static org.junit.jupiter.api.Assertions.*;

public class RoundTripTests {


    @Test
    void rsaPEMtoJWK() throws PEMUtils.PemException {
        for(String pem: PEMToJWKTests.RSAPrivate) {
            RSAKey rsaKey = PEMUtils.pemToRSAKey(pem);
            String newPem = PEMUtils.jwkToPem(rsaKey);
            assertEquals(pem, newPem);
        }

        for(String pem: PEMToJWKTests.RSAPublic) {
            RSAKey rsaKey = PEMUtils.pemToRSAKey(pem);
            String newPem = PEMUtils.jwkToPem(rsaKey);
            assertEquals(pem, newPem);
        }
    }

    @Test
    void rsaJWKtoPEM() throws PEMUtils.PemException, ParseException {
        for(String jwkString: JWKToPEMTests.RSAPrivate) {
            RSAKey rsaKey = RSAKey.parse(jwkString);
            String pem = PEMUtils.jwkToPem(rsaKey);
            PEMUtils.pemToRSAKey(pem);
        }

        for(String jwkString: JWKToPEMTests.RSAPublic) {
            RSAKey rsaKey = RSAKey.parse(jwkString);
            String pem = PEMUtils.jwkToPem(rsaKey);
            PEMUtils.pemToRSAKey(pem);
        }
    }

    @Test
    void ecKeyPEMtoJWK() throws PEMUtils.PemException {
        for(String pem: PEMToJWKTests.ECPrivate) {
            ECKey ecKey = PEMUtils.pemToECKey(pem);
            String newPem = PEMUtils.jwkToPem(ecKey);
            //assertEquals(pem, newPem);
        }

        for(String pem: PEMToJWKTests.ECPublic) {
            ECKey ecKey = PEMUtils.pemToECKey(pem);
            String newPem = PEMUtils.jwkToPem(ecKey);
            assertEquals(pem, newPem);
        }
    }

    @Test
    void ecJWKtoPEM() throws PEMUtils.PemException, ParseException {
        for(String jwkString: JWKToPEMTests.ECPrivate) {
            ECKey ecKey = ECKey.parse(jwkString);
            String pem = PEMUtils.jwkToPem(ecKey);
            ECKey newKey = PEMUtils.pemToECKey(pem);
        }

        for(String jwkString: JWKToPEMTests.ECPublic) {
            ECKey ecKey = ECKey.parse(jwkString);
            String pem = PEMUtils.jwkToPem(ecKey);
            ECKey newKey = PEMUtils.pemToECKey(pem);
        }
    }

    @Test
    void octetKeyPairPEMtoJWK() throws PEMUtils.PemException {
        for(String pem: PEMToJWKTests.OKPPrivate) {
            OctetKeyPair octetKeyPair = PEMUtils.pemToOctetKeyPair(pem);
            String newPem = PEMUtils.jwkToPem(octetKeyPair);
        }

        for(String pem: PEMToJWKTests.OKPPublic) {
            OctetKeyPair octetKeyPair = PEMUtils.pemToOctetKeyPair(pem);
            String newPem = PEMUtils.jwkToPem(octetKeyPair);
        }
    }

    @Test
    void octetKeyPairJWKtoPEM() throws PEMUtils.PemException, ParseException {
        for(String jwkString: JWKToPEMTests.OKPPrivate) {
            OctetKeyPair octetKeyPair = OctetKeyPair.parse(jwkString);
            String pem = PEMUtils.jwkToPem(octetKeyPair);
            OctetKeyPair newKey = PEMUtils.pemToOctetKeyPair(pem);
        }

        for(String jwkString: JWKToPEMTests.OKPPublic) {
            OctetKeyPair octetKeyPair = OctetKeyPair.parse(jwkString);
            String pem = PEMUtils.jwkToPem(octetKeyPair);
            OctetKeyPair newKey = PEMUtils.pemToOctetKeyPair(pem);
        }
    }

}
