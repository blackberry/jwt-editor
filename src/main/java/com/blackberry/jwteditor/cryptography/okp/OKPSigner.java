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

package com.blackberry.jwteditor.cryptography.okp;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.impl.EdDSAProvider;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.util.Base64URL;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed448PrivateKeyParameters;

/**
    Signer for Ed25519/Ed448 keys

    Modified from com.nimbusds.jose.crypto.Ed25519Signer;
    https://bitbucket.org/connect2id/nimbus-jose-jwt/src/b795131a0f9b6ae18772482360a38d394de490bd/src/main/java/com/nimbusds/jose/crypto/Ed25519Signer.java
    * nimbus-jose-jwt
    *
    * Copyright 2012-2018, Connect2id Ltd.
    *
    * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
    * this file except in compliance with the License. You may obtain a copy of the
    * License at
    *
    *    http://www.apache.org/licenses/LICENSE-2.0
    *
    * Unless required by applicable law or agreed to in writing, software distributed
    * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
    * CONDITIONS OF ANY KIND, either express or implied. See the License for the
    * specific language governing permissions and limitations under the License.
 */
public class OKPSigner extends EdDSAProvider implements JWSSigner {

    private final OctetKeyPair key;

    public OKPSigner(OctetKeyPair key) throws JOSEException {
        if (!key.isPrivate()) {
            throw new JOSEException("OctetKeyPair doesn't contain a private key");
        }

        if (!(key.getCurve().equals(Curve.Ed25519) || key.getCurve().equals(Curve.Ed448))) {
            throw new JOSEException("Curve is not valid for OctetKeyPair signing");
        }

        this.key = key;
    }

    /**
     * Sign a payload with this signer
     * @param jwsHeader the JWS header
     * @param bytes the payload bytes
     * @return an encoded payload signed using the key
     */
    @Override
    public Base64URL sign(JWSHeader jwsHeader, byte[] bytes) {
        byte[] signature;

        if(key.getCurve().equals(Curve.Ed25519)){
            Ed25519PrivateKeyParameters privateKey = new Ed25519PrivateKeyParameters(key.getDecodedD(), 0);
            org.bouncycastle.crypto.signers.Ed25519Signer signer = new org.bouncycastle.crypto.signers.Ed25519Signer();
            signer.init(true, privateKey);
            signer.update(bytes, 0, bytes.length);
            signature = signer.generateSignature();
        }
        else {
            Ed448PrivateKeyParameters privateKey = new Ed448PrivateKeyParameters(key.getDecodedD(), 0);
            org.bouncycastle.crypto.signers.Ed448Signer signer = new org.bouncycastle.crypto.signers.Ed448Signer(new byte[0]);
            signer.init(true, privateKey);
            signer.update(bytes, 0, bytes.length);
            signature = signer.generateSignature();
        }
        return Base64URL.encode(signature);
    }
}
