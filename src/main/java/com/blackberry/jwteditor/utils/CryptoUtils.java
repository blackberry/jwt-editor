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

package com.blackberry.jwteditor.utils;

import com.blackberry.jwteditor.model.jose.JWE;
import com.blackberry.jwteditor.model.jose.JWS;
import com.blackberry.jwteditor.model.keys.Key;
import com.nimbusds.jose.*;
import com.nimbusds.jose.util.Base64URL;

import java.nio.charset.StandardCharsets;
import java.security.Provider;
import java.security.Security;
import java.text.ParseException;

/**
 * Crypto operations on JWS/JWE
 */
public class CryptoUtils {

    public static class SigningException extends Exception {
        public SigningException(String msg){
            super(msg);
        }
    }

    public static class VerificationException extends Exception {
        public VerificationException(String msg){
            super(msg);
        }
    }

    public static class EncryptionException extends Exception {
        public EncryptionException(String msg){
            super(msg);
        }
    }

    public static class DecryptionException extends Exception {
        public DecryptionException(String msg){
            super(msg);
        }
    }


    /**
     * Sign a header and payload with a JWK using an algorithm
     *
     * @param header encoded header bytes to sign
     * @param payload encoded payload bytes to sign
     * @param key JWK to sign with
     * @param signingInfo JWSHeader containing the signing algorithm
     * @return a signed JWS
     * @throws SigningException if signing fails
     */
    public static JWS sign(Base64URL header, Base64URL payload, Key key, JWSHeader signingInfo) throws SigningException {

        // Get the signer based on the key type
        JWSSigner signer;
        try {
            signer = key.getSigner();
        } catch (JOSEException e) {
            throw new SigningException(e.getMessage());
        }

        // Try to use the BouncyCastle provider, but fall-back to default if this fails
        Provider provider = Security.getProvider("BC");
        if(provider != null){
            signer.getJCAContext().setProvider(provider);
        }

        // Build the signing input
        // JWS signature input is the ASCII bytes of the base64 encoded header and payload concatenated with a '.'
        byte[] headerBytes = header.toString().getBytes(StandardCharsets.US_ASCII);
        byte[] payloadBytes = payload.toString().getBytes(StandardCharsets.US_ASCII);
        byte[] signingInput = new byte[headerBytes.length + 1 + payloadBytes.length];
        System.arraycopy(headerBytes, 0, signingInput, 0, headerBytes.length);
        signingInput[headerBytes.length] = '.';
        System.arraycopy(payloadBytes, 0, signingInput, headerBytes.length + 1, payloadBytes.length);

        // Sign the payload with the key and the algorithm provided
        Base64URL encodedSignature;
        try {
            encodedSignature = signer.sign(signingInfo, signingInput);
        }
        catch (JOSEException e){
            throw new SigningException(e.getMessage());
        }

        // Return a new JWS consisting of the three components
        return new JWS(header, payload, encodedSignature);
    }

    /**
     * Verify a JWS with a JWK and an algorithm
     * @param jws JWS to verify
     * @param key JWK for verification
     * @param verificationInfo JWSHeader containing verification algorithm
     * @return result of signature verification
     * @throws VerificationException if verification process fails
     */
    public static boolean verify(JWS jws, Key key, JWSHeader verificationInfo) throws VerificationException {

        // Get the verifier based on the key type
        JWSVerifier verifier;
        try{
            verifier = key.getVerifier();
        } catch (JOSEException e) {
            throw new VerificationException(e.getMessage());
        }

        // Try to use the BouncyCastle provider, but fall-back to default if this fails
        Provider provider = Security.getProvider("BC");
        if(provider != null){
            verifier.getJCAContext().setProvider(provider);
        }

        // Build the signing input
        // JWS signature input is the ASCII bytes of the base64 encoded header and payload concatenated with a '.'
        byte[] headerBytes = jws.getEncodedHeader().toString().getBytes(StandardCharsets.US_ASCII);
        byte[] payloadBytes = jws.getEncodedPayload().toString().getBytes(StandardCharsets.US_ASCII);
        byte[] signingInput = new byte[headerBytes.length + 1 + payloadBytes.length];
        System.arraycopy(headerBytes, 0, signingInput, 0, headerBytes.length);
        signingInput[headerBytes.length] = '.';
        System.arraycopy(payloadBytes, 0, signingInput, headerBytes.length + 1, payloadBytes.length);

        // Verify the payload with the key and the algorithm provided
        try {
            return verifier.verify(verificationInfo, signingInput, jws.getEncodedSignature());
        } catch (JOSEException e) {
            throw new VerificationException(e.getMessage());
        }
    }

    /**
     * Encrypt a JWS using a JWK to produce a JWE
     * @param jws JWS to encrypt
     * @param key JWK to encrypt with
     * @param kek Key encryption algorithm to use
     * @param cek Content encryption algorithm to use
     * @return result of the encryption as a JWE
     * @throws EncryptionException if encryption fails
     */
    public static JWE encrypt(JWS jws, Key key, JWEAlgorithm kek, EncryptionMethod cek) throws EncryptionException {
        JWEHeader header = new JWEHeader(kek, cek);

        // Get the encrypter based on the key type
        JWEEncrypter encrypter;
        try {
             encrypter = key.getEncrypter(kek);
        } catch (JOSEException e) {
            throw new EncryptionException("Invalid key type for encryption algorithm");
        }

        // Try to use the BouncyCastle provider, but fall-back to default if this fails
        Provider provider = Security.getProvider("BC");
        if(provider != null){
            encrypter.getJCAContext().setProvider(provider);
        }

        // Encrypt the JWS with the key to get a set of Base64 encoded parts
        JWECryptoParts jweCryptoParts;
        try {
            jweCryptoParts = encrypter.encrypt(header, jws.serialize().getBytes(StandardCharsets.US_ASCII));
        } catch (JOSEException e) {
            throw new EncryptionException(e.getMessage());
        }

        // Use the returned parts to construct a JWE
        return new JWE(
                jweCryptoParts.getHeader().toBase64URL(),
                jweCryptoParts.getEncryptedKey(),
                jweCryptoParts.getInitializationVector(),
                jweCryptoParts.getCipherText(),
                jweCryptoParts.getAuthenticationTag()
        );
    }

    /**
     * Decrypt a JWE to a JWS using a JWK
     * @param jwe JWE to decrypt
     * @param key JWK to decrypt with
     * @return result of the decryption as a JWS
     * @throws DecryptionException if decryption fails
     * @throws ParseException if parsing of plaintext as a JWS fails
     */
    public static JWS decrypt(JWE jwe, Key key) throws DecryptionException, ParseException {

        // Parse the JWE header to get the decryption algorithms
        JWEHeader header = JWEHeader.parse(jwe.getHeader());
        try {
            // Create a new decrypter with the header algs
            JWEDecrypter decrypter = key.getDecrypter(header.getAlgorithm());

            // Try to use the BouncyCastle provider, but fall-back to default if this fails
            Provider provider = Security.getProvider("BC");
            if(provider != null){
                decrypter.getJCAContext().setProvider(provider);
            }

            // Get the encrypted key component, or null if "dir" encryption
            Base64URL encryptedKey = jwe.getEncodedEncryptedKey();
            if(header.getAlgorithm().getName().equals("dir")){ //NON-NLS
                encryptedKey = null;
            }

            // Decrypt the ciphertext component using the parsed algorithms and JWK
            byte[] plaintext = decrypter.decrypt(
                    header,
                    encryptedKey,
                    jwe.getEncodedIV(),
                    jwe.getEncodedCiphertext(),
                    jwe.getEncodedTag()
            );
            // Try to parse the result as a JWS and return
            return JWS.parse(new String(plaintext));
        } catch (ParseException e) {
            throw new DecryptionException("JWE contents are not a JWS");
        } catch (Exception e) {
            throw new DecryptionException("Unable to decrypt JWE");
        }
    }

}
