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

package com.blackberry.jwteditor.model.keys;

import com.blackberry.jwteditor.cryptography.okp.OKPDecrypter;
import com.blackberry.jwteditor.cryptography.okp.OKPEncrypter;
import com.blackberry.jwteditor.cryptography.okp.OKPSigner;
import com.blackberry.jwteditor.cryptography.okp.OKPVerifier;
import com.blackberry.jwteditor.utils.Utils;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.*;
import org.json.JSONObject;

import java.util.Map;

/**
 * Class for secrets that can be represented as a JWK
 */
public class JWKKey extends Key {

    private final JWK jwk;
    private final KeyType keyType;

    /**
     * Construct a JWKKey from a nimbus-jose JWK object
     * @param jwk JWK
     * @throws UnsupportedKeyException if the key type is not supported
     */
    public JWKKey(JWK jwk) throws UnsupportedKeyException {
        this.jwk = jwk;

        if(jwk instanceof RSAKey){
            keyType = KeyType.RSA;
        }
        else if(jwk instanceof ECKey){
            keyType = KeyType.EC;
        }
        else if(jwk instanceof OctetKeyPair){
            keyType = KeyType.OKP;
        }
        else if(jwk instanceof OctetSequenceKey){
            keyType = KeyType.OCT;
        }
        else {
            throw new UnsupportedKeyException();
        }
    }

    /**
     * Get the nimbus-jose JWK
     *
     * @return the JWK object
     */
    public JWK getJWK() {
        return jwk;
    }

    /**
     * Get the type of key
     *
     * @return the key type
     */
    public KeyType getKeyType() {
        return keyType;
    }

    /**
     * Get the key identifier
     * @return JWK 'kid' value
     */
    @Override
    public String getID() {
        return jwk.getKeyID();
    }

    /**
     * Get a String description of the key
     *
     * @return the key description
     */
    @Override
    public String getDescription() {
        switch (keyType) {
            case RSA:
                return String.format("RSA %d", jwk.size()); //NON-NLS
            case EC:
                return ((ECKey) jwk).getCurve().getName();
            case OKP:
                return ((OctetKeyPair) jwk).getCurve().getName();
            case OCT:
                return String.format("%s %d", "OCT", jwk.size()); //NON-NLS
            default:
                throw new IllegalStateException("Unreachable - handled by PasswordKey");
        }
    }

    /**
     * Is the key a public key
     *
     * @return true if the key has a non-secret
     */
    @Override
    public boolean isPublic() {
        return keyType != KeyType.OCT;
    }

    /**
     * Is the key a private key
     *
     * @return true if the key has a secret component
     */
    @Override
    public boolean isPrivate() {
        return jwk.isPrivate();
    }

    /**
     * Is the key able to sign a payload
     *
     * @return true if the key is capable of signing
     */
    @Override
    public boolean canSign() {
        switch(keyType){
            case RSA:
            case EC:
                // Asymmetric signing requires a private key
                return jwk.isPrivate();
            case OKP:
                switch(((OctetKeyPair)jwk).getCurve().getStdName()){
                    // Signing with OKP requires an Edwards Curve private key
                    case "Ed25519": //NON-NLS
                    case "Ed448": //NON-NLS
                        return jwk.isPrivate();
                    default:
                        return false;
                }
            case OCT:
                // nimbus-jose requires the key size to match the algorithm
                switch(jwk.size()){
                    case 256:
                    case 384:
                    case 512:
                        return true;
                    default:
                        return false;
                }
            default:
                throw new IllegalStateException("Unreachable - handled by PasswordKey");
        }
    }

    /**
     * Is the key able to verify a payload
     *
     * @return true if the key is capable of verification
     */
    @Override
    public boolean canVerify() {
        switch(keyType){
            case RSA:
            case EC:
                return true;
            case OKP:
                switch(((OctetKeyPair)jwk).getCurve().getStdName()){
                    // Verification with OKP requires an Edwards Curve key
                    case "Ed25519": //NON-NLS
                    case "Ed448": //NON-NLS
                        return true;
                    default:
                        return false;
                }
            case OCT:
                switch(jwk.size()){
                    // nimbus-jose requires the key size to match the algorithm
                    case 256:
                    case 384:
                    case 512:
                        return true;
                    default:
                        return false;
                }
            default:
                throw new IllegalStateException("Unreachable - handled by PasswordKey");
        }
    }

    /**
     * Is the key able to encrypt a payload
     *
     * @return true if the key is capable of encryption
     */
    @Override
    public boolean canEncrypt() {
        switch (keyType) {
            case RSA:
                // nimbus-jose requires a key size of at least 2048 bits
                return jwk.size() >= 2048;
            case OCT:
                // Can encrypt with all symmetric keys
                return true;
            case EC:
                // Can encrypt with all EC curves other than secp256k1
                return !((ECKey) jwk).getCurve().getStdName().equals("secp256k1"); //NON-NLS
            case OKP:
                switch (((OctetKeyPair) jwk).getCurve().getStdName()) {
                    // X25519/X448 required for OKP encryption
                    case "X25519": //NON-NLS
                    case "X448": //NON-NLS
                        return true;
                    default:
                        return false;
                }
            default:
                throw new IllegalStateException("Unreachable - handled by PasswordKey");
        }
    }

    /**
     * Is the key able to decrypt a payload
     *
     * @return true if the key is capable of decryption
     */
    @Override
    public boolean canDecrypt() {
        return canEncrypt() && isPrivate();
    }

    /**
     * Does the key have a JWK representation
     *
     * @return always true for JWKKeys
     */
    @Override
    public boolean hasJWK() {
        return true;
    }

    /**
     * Does the key have a PEM representation
     *
     * @return true if the key can be encoded as a PEM
     */
    @Override
    public boolean hasPEM() {
        switch(keyType){
            case RSA:
            case EC:
            case OKP:
                return true;
            case OCT:
            case PASSWORD:
                return false;
        }
        return false;
    }

    /**
     * Get the signing algorithms that can be used with this key
     *
     * @return list of allowed signing algorithms
     */
    public JWSAlgorithm[] getSigningAlgorithms(){
        switch (keyType){
            case RSA:
                switch(jwk.size()){
                    case 512:
                        return new JWSAlgorithm[]{JWSAlgorithm.RS256};
                    case 1024:
                        return new JWSAlgorithm[]{
                            JWSAlgorithm.RS256,
                            JWSAlgorithm.RS384,
                            JWSAlgorithm.RS512,
                            JWSAlgorithm.PS256,
                            JWSAlgorithm.PS384
                        };
                    default:
                        return new JWSAlgorithm[]{
                            JWSAlgorithm.RS256,
                            JWSAlgorithm.RS384,
                            JWSAlgorithm.RS512,
                            JWSAlgorithm.PS256,
                            JWSAlgorithm.PS384,
                            JWSAlgorithm.PS512
                        };
                }
            case EC:
                switch(((ECKey) jwk).getCurve().getName()){
                    case "P-256": //NON-NLS
                        return new JWSAlgorithm[]{JWSAlgorithm.ES256};
                    case "secp256k1": //NON-NLS
                        return new JWSAlgorithm[]{JWSAlgorithm.ES256K}; //NON-NLS
                    case "P-384": //NON-NLS
                        return new JWSAlgorithm[]{JWSAlgorithm.ES384}; //NON-NLS
                    case "P-521": //NON-NLS
                        return new JWSAlgorithm[]{JWSAlgorithm.ES512};
                }
            case OKP:
                //noinspection ConstantConditions
                switch(((OctetKeyPair) jwk).getCurve().getStdName()){
                    case "Ed25519": //NON-NLS
                    case "Ed448": //NON-NLS
                        return new JWSAlgorithm[]{JWSAlgorithm.EdDSA};
                    default:
                        return new JWSAlgorithm[0];
                }
            case OCT:
                switch(jwk.size()){
                    // nimbus-jose requires the key size to match the algorithm
                    case 256:
                        return new JWSAlgorithm[]{JWSAlgorithm.HS256};
                    case 384:
                        return new JWSAlgorithm[]{JWSAlgorithm.HS384};
                    case 512:
                        return new JWSAlgorithm[]{JWSAlgorithm.HS512};
                    default:
                        return new JWSAlgorithm[0];
                }
            default:
                return new JWSAlgorithm[0];
        }
    }

    /**
     * Get the key encryption algorithms that can be used with this key
     *
     * @return list of allowed key encryption algorithms
     */
    public JWEAlgorithm[] getKeyEncryptionKeyAlgorithms(){
        switch (keyType){
            case RSA:
                //noinspection deprecation
                return new JWEAlgorithm[]{JWEAlgorithm.RSA1_5, JWEAlgorithm.RSA_OAEP, JWEAlgorithm.RSA_OAEP_256};
            case EC:
                return new JWEAlgorithm[]{JWEAlgorithm.ECDH_ES, JWEAlgorithm.ECDH_ES_A128KW, JWEAlgorithm.ECDH_ES_A192KW, JWEAlgorithm.ECDH_ES_A256KW};
            case OKP:
                return new JWEAlgorithm[]{JWEAlgorithm.ECDH_ES};
            case OCT:
                // OCT key encryption algorithms are dependant on the key size
                switch(jwk.size()){
                    case 128:
                        return new JWEAlgorithm[]{JWEAlgorithm.DIR, JWEAlgorithm.A128KW, JWEAlgorithm.A128GCMKW};
                    case 192:
                        return new JWEAlgorithm[]{JWEAlgorithm.DIR, JWEAlgorithm.A192KW, JWEAlgorithm.A192GCMKW};
                    case 256:
                        return new JWEAlgorithm[]{JWEAlgorithm.DIR, JWEAlgorithm.A256KW, JWEAlgorithm.A256GCMKW};
                    case 384:
                    case 512:
                        return new JWEAlgorithm[]{JWEAlgorithm.DIR};
                    default:
                        return new JWEAlgorithm[0];
                }
            default:
                return new JWEAlgorithm[0];
        }
    }

    /**
     * Get the content encryption algorithms that can be used with this key
     *
     * @return list of allowed key encryption algorithms
     */
    @Override
    public EncryptionMethod[] getContentEncryptionKeyAlgorithms(JWEAlgorithm keyEncryptionKeyAlgorithm) {
        switch(keyType){
            case OCT: //NON-NLS
                // dir content encryption requires specific key sizes
                if(keyEncryptionKeyAlgorithm.getName().equals("dir")){ //NON-NLS
                    switch(jwk.size()){
                        // A128GCM, A192GCM, A256GCM modes require the equivalent size key
                        case 128:
                            return new EncryptionMethod[]{EncryptionMethod.A128GCM};
                        case 192:
                            return new EncryptionMethod[]{EncryptionMethod.A192GCM};
                        // A128CBC_HS256, A192CBC_HS384, A256CBC_HS512 require double the key length as the key is split
                        // into two halves, one for AES, the other for HMAC
                        case 256:
                            return new EncryptionMethod[]{
                                    EncryptionMethod.A256GCM,
                                    EncryptionMethod.A128CBC_HS256
                            };
                        case 384:
                            return new EncryptionMethod[]{EncryptionMethod.A192CBC_HS384};
                        case 512:
                            return new EncryptionMethod[]{EncryptionMethod.A256CBC_HS512};
                    }
                }
                // Fall through here - all other modes use key wrapping, which can encrypt an arbitrary size key
            case EC:
            case OKP:
            case RSA:
                return new EncryptionMethod[]{
                        EncryptionMethod.A128GCM,
                        EncryptionMethod.A192GCM,
                        EncryptionMethod.A256GCM,
                        EncryptionMethod.A128CBC_HS256,
                        EncryptionMethod.A192CBC_HS384,
                        EncryptionMethod.A192CBC_HS384,
                        EncryptionMethod.A256CBC_HS512,
                };
            case PASSWORD:
            default:
                throw new IllegalStateException("Unreachable - handled by PasswordKey");
        }
    }

    /**
     * Get the appropriate signer for the key type
     *
     * @return the nimbus-jose JWSSigner to perform the signing operation
     */
    public JWSSigner getSigner() throws JOSEException {
        switch (keyType){
            case RSA:
                // Allow < 2048 bit keys
                return new RSASSASigner(((RSAKey)jwk).toRSAPrivateKey(), true);
            case EC:
                return new ECDSASigner(((ECKey)jwk).toECPrivateKey());
            case OKP:
                return new OKPSigner((OctetKeyPair) jwk);
            case OCT:
                return new MACSigner(((OctetSequenceKey) jwk).toSecretKey().getEncoded());
            case PASSWORD:
            default:
                throw new IllegalStateException("Unreachable - handled by PasswordKey");
        }
    }

    /**
     * Get the appropriate verifier for the key type
     *
     * @return the nimbus-jose JWSVerifier to perform the verification operation
     */
    public JWSVerifier getVerifier() throws JOSEException {
        switch (keyType){
            case RSA:
                return new RSASSAVerifier(((RSAKey)jwk).toRSAPublicKey());
            case EC:
                return new ECDSAVerifier(((ECKey)jwk).toECPublicKey());
            case OKP:
                return new OKPVerifier((OctetKeyPair) jwk.toPublicJWK());
            case OCT:
                return new MACVerifier(((OctetSequenceKey) jwk).toSecretKey().getEncoded());
            case PASSWORD:
            default:
                throw new IllegalStateException("Unreachable - handled by PasswordKey");
        }
    }

    /**
     * Get the appropriate encrypter for the key type
     *
     * @return the nimbus-jose JWEEncrypter to perform the encryption operation
     */
    public JWEEncrypter getEncrypter(JWEAlgorithm kekAlgorithm) throws JOSEException {
        switch(keyType){
            case RSA:
                return new RSAEncrypter(((RSAKey) jwk).toRSAPublicKey());
            case EC:
                return new ECDHEncrypter(((ECKey) jwk).toECPublicKey());
            case OKP:
                return new OKPEncrypter(((OctetKeyPair) jwk).toPublicJWK()); //NON-NLS
            case OCT:
                if(kekAlgorithm.getName().equals("dir")){ //NON-NLS
                    return new DirectEncrypter((OctetSequenceKey) jwk);
                }
                else{
                    return new AESEncrypter((OctetSequenceKey) jwk);
                }
            case PASSWORD:
            default:
                throw new IllegalStateException("Unreachable - handled by PasswordKey");
        }
    }

    /**
     * Get the appropriate decrypter for the key type
     *
     * @return the nimbus-jose JWEDecrypter to perform the decryption operation
     */
    public JWEDecrypter getDecrypter(JWEAlgorithm kekAlgorithm) throws JOSEException {
        switch(keyType){
            case RSA:
                return new RSADecrypter(((RSAKey) jwk).toRSAPrivateKey());
            case EC:
                return new ECDHDecrypter(((ECKey) jwk).toECPrivateKey());
            case OKP:
                return new OKPDecrypter(((OctetKeyPair) jwk));
            case OCT:
                if(kekAlgorithm.getName().equals("dir")){ //NON-NLS
                    return new DirectDecrypter((OctetSequenceKey) jwk);
                }
                else{
                    return new AESDecrypter((OctetSequenceKey) jwk);
                }
            case PASSWORD:
            default:
                throw new IllegalStateException("Unreachable - handled by PasswordKey");
        }
    }

    /**
     * Get the key as a JWK JSON object
     * @return a JSONObject representing the key
     */
    @Override
    public JSONObject toJSONObject() {
        JSONObject jsonObject = new JSONObject();
        Map<String, Object> jwkMap = jwk.toJSONObject();

        for(String k : jwkMap.keySet()){
            jsonObject.put(k, jwkMap.get(k));
        }

        return jsonObject;
    }

    /**
     * Get a string representation of the key
     * @return a String representing the key
     */
    public String toString() {
        return String.format("%s (%s)", getID(), getDescription()); //NON-NLS
    }
}
