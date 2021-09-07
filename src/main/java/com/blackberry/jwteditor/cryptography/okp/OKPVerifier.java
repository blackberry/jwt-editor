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
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.impl.EdDSAProvider;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.util.Base64URL;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.Ed448PublicKeyParameters;

/**
    Verifier for Ed25519/Ed448 keys

    Modified from com.nimbusds.jose.crypto.Ed25519Verifier;
    https://bitbucket.org/connect2id/nimbus-jose-jwt/src/b795131a0f9b6ae18772482360a38d394de490bd/src/main/java/com/nimbusds/jose/crypto/Ed25519Verifier.java
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
public class OKPVerifier extends EdDSAProvider implements JWSVerifier {

    private final OctetKeyPair key;

    public OKPVerifier(OctetKeyPair key) throws JOSEException {
        if (key.isPrivate()) {
            throw new JOSEException("OKPVerifier requires a public key, use OctetKeyPair.toPublicJWK()");
        }
        if (!(key.getCurve().equals(Curve.Ed25519) || key.getCurve().equals(Curve.Ed448))) {
            throw new JOSEException("Curve is not valid for OctetKeyPair signing");
        }
        this.key = key;
    }

    /**
     * Verify a JWS using this verifier
     * @param jwsHeader the JWS header
     * @param message the message to verify
     * @param signature the signature of the message
     * @return true if signature verfication succeeds, false otherwise
     */
    @Override
    public boolean verify(JWSHeader jwsHeader, byte[] message, Base64URL signature) {

        if(key.getCurve().equals(Curve.Ed25519)){
            Ed25519PublicKeyParameters publicKey = new Ed25519PublicKeyParameters(key.getDecodedX(), 0);
            org.bouncycastle.crypto.signers.Ed25519Signer verifier = new org.bouncycastle.crypto.signers.Ed25519Signer();
            verifier.init(false, publicKey);
            verifier.update(message, 0, message.length);
            return verifier.verifySignature(signature.decode());
        }
        else {
            Ed448PublicKeyParameters publicKey = new Ed448PublicKeyParameters(key.getDecodedX(), 0);
            org.bouncycastle.crypto.signers.Ed448Signer verifier = new org.bouncycastle.crypto.signers.Ed448Signer(new byte[0]);
            verifier.init(false, publicKey);
            verifier.update(message, 0, message.length);
            return verifier.verifySignature(signature.decode());
        }
    }
}
