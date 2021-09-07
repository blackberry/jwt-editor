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
import com.nimbusds.jose.JWECryptoParts;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.impl.ECDHCryptoProvider;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.util.Base64URL;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X448PrivateKeyParameters;
import org.bouncycastle.crypto.params.X448PublicKeyParameters;
import org.bouncycastle.math.ec.rfc7748.X25519;
import org.bouncycastle.math.ec.rfc7748.X448;

import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.HashSet;
import java.util.Set;

/**
    Encrypter for X25519/X448 keys

    Modified from com.nimbusds.jose.crypto.X25519Encrypter
    https://bitbucket.org/connect2id/nimbus-jose-jwt/src/b795131a0f9b6ae18772482360a38d394de490bd/src/main/java/com/nimbusds/jose/crypto/X25519Encrypter.java

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
public class OKPEncrypter extends ECDHCryptoProvider implements JWEEncrypter {

    private final OctetKeyPair key;

    public OKPEncrypter(OctetKeyPair key) throws JOSEException {
        super(key.getCurve());

        if (!(key.getCurve().equals(Curve.X25519) || key.getCurve().equals(Curve.X448))) {
            throw new JOSEException("Curve is not valid for OctetKeyPair encryption");
        }

        if (key.isPrivate()) {
            throw new JOSEException("OKPEncrypter requires a public key, use OctetKeyPair.toPublicJWK()");
        }

        this.key = key;
    }

    /**
     * Get the set of elliptic curves supported by this decrypter
     *
     * @return elliptic curves supported by this decrypter
     */
    public Set<Curve> supportedEllipticCurves() {
        HashSet<Curve> set = new HashSet<>();
        set.add(Curve.X25519);
        set.add(Curve.X448);
        return set;
    }

    /**
     * Encrypt a plaintext with this decrypter
     * @param header the JWE header
     * @param plaintext the plaintext to encrypt
     * @return the JWE components
     * @throws JOSEException if encryption fails
     */
    public JWECryptoParts encrypt(JWEHeader header, byte[] plaintext) throws JOSEException {
        SecureRandom secureRandom = new SecureRandom();

        byte[] z;
        byte[] epkX;
        if (key.getCurve().equals(Curve.X25519)) {
            // Get the private key and ephemeral public key
            X25519PublicKeyParameters X = new X25519PublicKeyParameters(key.getDecodedX(), 0);
            X25519PrivateKeyParameters epkD = new X25519PrivateKeyParameters(secureRandom);
            epkX = epkD.generatePublicKey().getEncoded();

            // Do the key agreement
            z = new byte[X25519.POINT_SIZE];
            epkD.generateSecret(X, z, 0);
        }
        else {
            // Get the private key and ephemeral public key
            X448PublicKeyParameters X = new X448PublicKeyParameters(key.getDecodedX(), 0);
            X448PrivateKeyParameters epkD = new X448PrivateKeyParameters(secureRandom);
            epkX = epkD.generatePublicKey().getEncoded();

            // Do the key agreement
            z = new byte[X448.POINT_SIZE];
            epkD.generateSecret(X, z, 0);
        }

        // Build a JWK for the ephemeral key and add to the JWE header
        OctetKeyPair epk = (new OctetKeyPair.Builder(this.getCurve(), Base64URL.encode(epkX))).build();
        JWEHeader updatedHeader = (new com.nimbusds.jose.JWEHeader.Builder(header)).ephemeralPublicKey(epk).build();
        // Encrypt the plaintext using the updated header and derived key
        return this.encryptWithZ(updatedHeader, new SecretKeySpec(z, "AES"), plaintext);
    }

}
