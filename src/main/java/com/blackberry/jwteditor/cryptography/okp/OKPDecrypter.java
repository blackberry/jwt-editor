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
import com.nimbusds.jose.JWEDecrypter;
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
import java.util.HashSet;
import java.util.Set;

/**
    Decrypter for X25519/X448 keys

    Modified from com.nimbusds.jose.crypto.X25519Decrypter
    https://bitbucket.org/connect2id/nimbus-jose-jwt/src/b795131a0f9b6ae18772482360a38d394de490bd/src/main/java/com/nimbusds/jose/crypto/X25519Decrypter.java

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
public class OKPDecrypter extends ECDHCryptoProvider implements JWEDecrypter {
    private final OctetKeyPair key;

    public OKPDecrypter(OctetKeyPair key) throws JOSEException {
        super(key.getCurve());

        if (!(key.getCurve().equals(Curve.X25519) || key.getCurve().equals(Curve.X448))) {
            throw new JOSEException("Curve is not valid for OctetKeyPair decryption");
        }

        if (!key.isPrivate()) {
            throw new JOSEException("OKPEncrypter requires a private key");
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
     * Decrypt a JWE using this decrypter
     *
     * @param header JWE header
     * @param encryptedKey JWE encrypted key
     * @param iv JWE iv
     * @param cipherText JWE ciphertext
     * @param authTag JWE tag
     * @return the decrypted ciphertext
     * @throws JOSEException if decryption fails
     */
    public byte[] decrypt(JWEHeader header, Base64URL encryptedKey, Base64URL iv, Base64URL cipherText, Base64URL authTag) throws JOSEException {
        OctetKeyPair ephemeralPublicKey = (OctetKeyPair)header.getEphemeralPublicKey();
        if (ephemeralPublicKey == null) {
            throw new JOSEException("Missing ephemeral public key \"epk\" JWE header parameter");
        }

        if (!this.key.getCurve().equals(ephemeralPublicKey.getCurve())) {
            throw new JOSEException("Curve of ephemeral public key does not match curve of private key");
        }

        byte[] z;
        if (key.getCurve().equals(Curve.X25519)) {
            // Get the private key and ephemeral public key
            X25519PrivateKeyParameters D = new X25519PrivateKeyParameters(key.getDecodedD(), 0);
            X25519PublicKeyParameters epkX = new X25519PublicKeyParameters(ephemeralPublicKey.getDecodedX(), 0);

            // Do the key agreement
            z = new byte[X25519.POINT_SIZE];
            D.generateSecret(epkX, z, 0);
        }
        else {
            // Get the private key and ephemeral public key
            X448PrivateKeyParameters D = new X448PrivateKeyParameters(key.getDecodedD(), 0);
            X448PublicKeyParameters epkX = new X448PublicKeyParameters(ephemeralPublicKey.getDecodedX(), 0);

            // Do the key agreement
            z = new byte[X448.POINT_SIZE];
            D.generateSecret(epkX, z, 0);
        }

        // Decrypt using the agreed key
        return this.decryptWithZ(header, new SecretKeySpec(z, "AES"), encryptedKey, iv, cipherText, authTag);
    }

}
