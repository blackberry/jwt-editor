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
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.JWKGenerator;
import com.nimbusds.jose.util.Base64URL;
import org.bouncycastle.crypto.params.*;

import java.security.SecureRandom;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/**
    Generator for X25519/X448/Ed25519/Ed448 keys

    Modified from com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
    https://bitbucket.org/connect2id/nimbus-jose-jwt/src/b795131a0f9b6ae18772482360a38d394de490bd/src/main/java/com/nimbusds/jose/jwk/gen/OctetKeyPairGenerator.java
    * nimbus-jose-jwt
    *
    * Copyright 2012-2018, Connect2id Ltd and contributors.
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
public class OKPGenerator extends JWKGenerator<OctetKeyPair> {

    private final Curve crv;
    public static final Set<Curve> SUPPORTED_CURVES;

    public OKPGenerator(Curve crv) {
        if (crv == null) {
            throw new IllegalArgumentException("The curve must not be null");
        } else if (!SUPPORTED_CURVES.contains(crv)) {
            throw new IllegalArgumentException("Curve not supported for OKP generation");
        } else {
            this.crv = crv;
        }
    }

    /**
     * Generate a new Octet Key Pair
     * @return the generated key
     * @throws JOSEException if key generation fails
     */
    @Override
    public OctetKeyPair generate() throws JOSEException {
        byte[] d;
        byte[] x;

        SecureRandom secureRandom = new SecureRandom();

        if(crv.equals(Curve.X25519)){
            X25519PrivateKeyParameters D = new X25519PrivateKeyParameters(secureRandom);
            X25519PublicKeyParameters X = D.generatePublicKey();
            d = D.getEncoded();
            x = X.getEncoded();
        }
        else if(crv.equals(Curve.X448)){
            X448PrivateKeyParameters D = new X448PrivateKeyParameters(secureRandom);
            X448PublicKeyParameters X = D.generatePublicKey();
            d = D.getEncoded();
            x = X.getEncoded();
        }
        else if(crv.equals(Curve.Ed25519)){
            Ed25519PrivateKeyParameters D = new Ed25519PrivateKeyParameters(secureRandom);
            Ed25519PublicKeyParameters X = D.generatePublicKey();
            d = D.getEncoded();
            x = X.getEncoded();
        }
        else {
            Ed448PrivateKeyParameters D = new Ed448PrivateKeyParameters(secureRandom);
            Ed448PublicKeyParameters X = D.generatePublicKey();
            d = D.getEncoded();
            x = X.getEncoded();
        }

        OctetKeyPair.Builder builder = (new OctetKeyPair.Builder(this.crv, Base64URL.encode(x))).d(Base64URL.encode(d)).keyUse(this.use).keyOperations(this.ops).algorithm(this.alg);
        if (this.x5tKid) {
            builder.keyIDFromThumbprint();
        } else {
            builder.keyID(this.kid);
        }

        return builder.build();
    }

    static {
        Set<Curve> curves = new LinkedHashSet<>();
        curves.add(Curve.X25519);
        curves.add(Curve.X448);
        curves.add(Curve.Ed25519);
        curves.add(Curve.Ed448);
        SUPPORTED_CURVES = Collections.unmodifiableSet(curves);
    }
}
