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

import com.blackberry.jwteditor.model.keys.JWKKey;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.util.Base64URL;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Map;

/**
 * Class containing utilities to convert between PEM and nimbus-jose JWK formats
 */
public class PEMUtils {

    private static final int X25519_KEY_LENGTH = 32;
    private static final int X448_KEY_LENGTH = 56;
    private static final int ED25519_KEY_LENGTH = 32;
    private static final int ED448_KEY_LENGTH = 57;

    public static class PemException extends Exception{
        public PemException(String msg) {
            super(msg);
        }
    }

    /**
     * Convert a sequence of DER bytes to a PEM string
     * @param header the PEM header ("e.g RSA PRIVATE KEY")
     * @param der_bytes the DER bytes to encode
     * @return a PEM string
     * @throws IOException if conversion fails
     */
    private static String derToPEMString(String header, byte[] der_bytes) throws IOException {
        StringWriter stringWriter = new StringWriter();
        PemWriter pemWriter = new PemWriter(stringWriter);
        PemObject pemObject = new PemObject(header, der_bytes);
        pemWriter.writeObject(pemObject);
        pemWriter.close();
        stringWriter.close();
        return stringWriter.toString();
    }

    /**
     * Convert a BouncyCastle PemObject to its String representation
     * @param pemObject the PemObject
     * @return a PEM string
     * @throws IOException if conversion fails
     */
    private static String pemObjectToString(PemObject pemObject) throws IOException {
        StringWriter stringWriter = new StringWriter();
        PemWriter pemWriter = new PemWriter(stringWriter);
        pemWriter.writeObject(pemObject);
        pemWriter.close();
        stringWriter.close();
        return stringWriter.toString();
    }

    /**
     * Trim a byte[] to an expected length
     * @param bytes input byte[]
     * @param expectedLength expected length
     * @return trimmed byte[]
     */
    private static byte[] trimByteArray(byte[] bytes, int expectedLength){
        return Arrays.copyOfRange(bytes, 0, expectedLength);
    }

    /**
     * Convert a JWK object to its PEM representation
     * @param jwk JWK to convert
     * @return a PEM string
     * @throws PemException if PEM conversion fails
     */
    public static String jwkToPem(JWK jwk) throws PemException {
        try {
            JWKKey jwkKey = new JWKKey(jwk);

            switch (jwkKey.getKeyType()){
                case RSA:
                    return rsaKeyToPem((RSAKey) jwk);
                case EC:
                    return ecKeyToPem((ECKey) jwk);
                case OKP:
                    return octetKeyPairToPem((OctetKeyPair) jwk);
                default:
                    throw new PemException("Invalid JWK type for PEM conversions");
            }
        } catch (com.blackberry.jwteditor.model.keys.Key.UnsupportedKeyException e) {
            throw new PemException("Invalid JWK type for PEM conversions");
        }
    }

    /**
     * Convert an Elliptic Curve key to PEM
     * @param ecKey the EC key
     * @return a PEM string
     * @throws PemException if PEM conversion fails
     */
    public static String ecKeyToPem(ECKey ecKey) throws PemException {
        try {
            if (ecKey.isPrivate()) {
                JcaPKCS8Generator jcaPKCS8Generator = new JcaPKCS8Generator(ecKey.toECPrivateKey(), null);
                return pemObjectToString(jcaPKCS8Generator.generate());
            } else {
                return derToPEMString("PUBLIC KEY", ecKey.toECPublicKey().getEncoded()); //NON-NLS
            }
        } catch (IOException | JOSEException e) {
            throw new PemException("PEM conversion error");
        }
    }

    /**
     * Convert an RSA key to PEM
     * @param rsaKey the RSA key
     * @return a PEM string
     * @throws PemException if PEM conversion fails
     */
    public static String rsaKeyToPem(RSAKey rsaKey) throws PemException {
        try {
            if (rsaKey.isPrivate()) {
                PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(rsaKey.toRSAPrivateKey().getEncoded());
                ASN1Encodable asn1Encodable = privateKeyInfo.parsePrivateKey();
                ASN1Primitive asn1Primitive = asn1Encodable.toASN1Primitive();
                byte[] privateKeyPKCS8 = asn1Primitive.getEncoded(ASN1Encoding.DER);
                return derToPEMString("RSA PRIVATE KEY", privateKeyPKCS8); //NON-NLS
            } else {
                return derToPEMString("PUBLIC KEY", rsaKey.toPublicKey().getEncoded()); //NON-NLS
            }
        } catch (IOException | JOSEException e) {
            throw new PemException("PEM conversion error");
        }
    }

    /**
     * Convert an OKP to PEM
     * @param octetKeyPair the OKP
     * @return a PEM string
     * @throws PemException if PEM conversion fails
     */
    public static String octetKeyPairToPem(OctetKeyPair octetKeyPair) throws PemException {
        try {
            ASN1ObjectIdentifier algorithmIdentifier;
            int keyLength;

            // Set the ASN.1 algorithm id and key length based on the curve type
            switch(octetKeyPair.getCurve().getStdName()){
                case "X25519": //NON-NLS
                    keyLength = X25519_KEY_LENGTH;
                    algorithmIdentifier = new ASN1ObjectIdentifier("1.3.101.110");
                    break; //NON-NLS
                case "X448": //NON-NLS
                    keyLength = X448_KEY_LENGTH;
                    algorithmIdentifier = new ASN1ObjectIdentifier("1.3.101.111");
                    break;
                case "Ed25519": //NON-NLS
                    keyLength = ED25519_KEY_LENGTH;
                    algorithmIdentifier = new ASN1ObjectIdentifier("1.3.101.112");
                    break;
                case "Ed448": //NON-NLS
                    keyLength = ED448_KEY_LENGTH;
                    algorithmIdentifier = new ASN1ObjectIdentifier("1.3.101.113");
                    break;
                default:
                    throw new PemException("Invalid curve");
            }

            // Build a sequence for the algorithm id
            DLSequence algorithmSequence = new DLSequence(algorithmIdentifier);

            if(octetKeyPair.isPrivate()){
                // Build a DER sequence for the private key bytes
                byte[] privateKeyBytes = octetKeyPair.getD().decode();

                DEROctetString innerOctetString = new DEROctetString(privateKeyBytes);
                DEROctetString outerOctetString = new DEROctetString(innerOctetString.getEncoded());
                ASN1Integer integer = new ASN1Integer(0);

                DLSequence outerSequence = new DLSequence(new ASN1Encodable[] {integer, algorithmSequence, outerOctetString});

                return derToPEMString("PRIVATE KEY", outerSequence.getEncoded()); //NON-NLS
            }
            else{
                // Build a DER sequence for the public key bytes
                byte[] publicKeyBytes = trimByteArray(octetKeyPair.getX().decode(), keyLength);
                DERBitString bitString = new DERBitString(publicKeyBytes);
                DLSequence outerSequence = new DLSequence(new ASN1Encodable[]{algorithmSequence, bitString});
                return derToPEMString("PUBLIC KEY", outerSequence.getEncoded()); //NON-NLS
            }

        } catch (IOException e) {
            throw new PemException("PEM conversion error");
        }
    }

    /**
     * Update the 'kid' header in a JWK
     * @param jwk the JWK to update
     * @param keyId the 'kid' value to set
     * @return the updated JWK
     * @throws PemException if updating the header fails
     */
    private static JWK embedKid(JWK jwk, String keyId) throws PemException {
        try {
            Map<String, Object> jsonKey = jwk.toJSONObject(); //NON-NLS
            jsonKey.put("kid", keyId); //NON-NLS
            return JWK.parse(jsonKey);
        } catch (ParseException e) {
            throw new PemException("Unable to embed key id");
        }
    }

    /**
     * Convert a RSA key PEM to a JWK RSAKey
     * @param pem the RSA key in PEM form
     * @param keyId the 'kid' value to use for the converted JWK
     * @return the RSAKey
     * @throws PemException if conversion fails
     */
    public static RSAKey pemToRSAKey(String pem, String keyId) throws PemException {
        return (RSAKey) embedKid(pemToRSAKey(pem), keyId);
    }

    /**
     * Convert a RSA key PEM to a JWK RSAKey
     * @param pem the RSA key in PEM form
     * @return the RSAKey
     * @throws PemException if conversion fails
     */
    public static RSAKey pemToRSAKey(String pem) throws PemException {
        JWK rsaKey;
        try {
            rsaKey = RSAKey.parseFromPEMEncodedObjects(pem);
        } catch (JOSEException e) {
            throw new PemException("Invalid RSA key PEM");
        }

        if (!(rsaKey instanceof RSAKey)) {
            throw new PemException("Invalid key type");
        }

        return (RSAKey) rsaKey;

    }

    /**
     * Convert an Elliptic Curve key PEM to a JWK ECKey
     * @param pem the EC key in PEM form
     * @param keyId the 'kid' value to use for the converted JWK
     * @return the ECKey
     * @throws PemException if conversion fails
     */
    public static ECKey pemToECKey(String pem, String keyId) throws PemException {
        return (ECKey) embedKid(pemToECKey(pem), keyId);
    }

    /**
     * Convert an Elliptic Curve key PEM to a JWK ECKey
     * @param pem the EC key in PEM form
     * @return the ECKey
     * @throws PemException if conversion fails
     */
    public static ECKey pemToECKey(String pem) throws PemException {
        JWK ecKey = null;
        boolean parsed;

        try {
            ecKey = ECKey.parseFromPEMEncodedObjects(pem);
            parsed = true;
        } catch (JOSEException e) {
            parsed = false;
        }

        // ECKey.parseFromPEMEncodedObjects does not handle PKCS8 formatted EC keys, build this manually
        if (!parsed) {
            try {
                // Read the PEM file
                InputStream inputStream = new ByteArrayInputStream(pem.getBytes());
                InputStreamReader inputStreamReader = new InputStreamReader(inputStream);
                PEMParser pemParser = new PEMParser(inputStreamReader);
                Object pemObject = pemParser.readObject();

                // The PKCS8 PEM object is a PrivateKeyInfo
                if (pemObject instanceof PrivateKeyInfo) {
                    // Get the private key
                    JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC"); //NON-NLS
                    PrivateKey privateKey = converter.getPrivateKey((PrivateKeyInfo) pemObject);

                    if (privateKey instanceof BCECPrivateKey) {
                        BCECPrivateKey ecPrivateKey = (BCECPrivateKey) privateKey;

                        // Derive a public key from the private key
                        BigInteger d = ecPrivateKey.getD();
                        ECParameterSpec ecParameterSpec = ecPrivateKey.getParameters();
                        ECPoint Q = ecPrivateKey.getParameters().getG().multiply(d);
                        ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(Q, ecParameterSpec); //NON-NLS //NON-NLS
                        KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC"); //NON-NLS //NON-NLS
                        ECPublicKey publicKey = (ECPublicKey) keyFactory.generatePublic(ecPublicKeySpec);

                        // Use public and private key to construct a JWK object
                        return new ECKey.Builder(Curve.forECParameterSpec(publicKey.getParams()), publicKey).privateKey(privateKey).build();
                    } else {
                        throw new PemException("Invalid PEM type");
                    }
                } else {
                    throw new PemException("Invalid PEM type");
                }
            } catch (IOException | NoSuchProviderException | NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new PemException("Invalid PEM");
            }
        }

        if (!(ecKey instanceof ECKey)) {
            throw new PemException("Invalid key type");
        }

        return (ECKey) ecKey;
    }

    /**
     * Convert an OKP PEM to a JWK OctetKeyPair
     * @param pem the OKP in PEM form
     * @param keyId the 'kid' value to use for the converted JWK
     * @return the OctetKeyPair
     * @throws PemException if conversion fails
     */
    public static OctetKeyPair pemToOctetKeyPair(String pem, String keyId) throws PemException {
        return (OctetKeyPair) embedKid(pemToOctetKeyPair(pem), keyId);
    }

    /**
     * Convert an OKP PEM to a JWK OctetKeyPair
     * @param pem the OKP in PEM form
     * @return the OctetKeyPair
     * @throws PemException if conversion fails
     */
    public static OctetKeyPair pemToOctetKeyPair(String pem) throws PemException {
        try {
            InputStream inputStream = new ByteArrayInputStream(pem.getBytes());
            InputStreamReader inputStreamReader = new InputStreamReader(inputStream);
            PEMParser pemParser = new PEMParser(inputStreamReader);
            PemObject pemObject = pemParser.readPemObject();

            if(pemObject == null){
                throw new PemException("Invalid PEM");
            }

            DLSequence outerSequence = (DLSequence) ASN1Primitive.fromByteArray(pemObject.getContent());

            ASN1Encodable integerOrSequencePrimitive = outerSequence.getObjectAt(0);

            // Private key
            if(integerOrSequencePrimitive instanceof ASN1Integer){
                ASN1Integer i = (ASN1Integer) integerOrSequencePrimitive;
                DLSequence algorithmSequence = (DLSequence) outerSequence.getObjectAt(1);
                DEROctetString outerOctetString = (DEROctetString) outerSequence.getObjectAt(2);

                ASN1ObjectIdentifier algorithmIdentifier = (ASN1ObjectIdentifier) algorithmSequence.getObjectAt(0);

                if(i.intValueExact() != 0) {
                    throw new PemException("Invalid integer value");
                }

                ASN1OctetString innerOctetString = (ASN1OctetString) ASN1Primitive.fromByteArray(outerOctetString.getOctets());

                Curve curve;
                Base64URL x, d;
                switch(algorithmIdentifier.getId()){
                    case "1.3.101.110":
                        if(innerOctetString.getOctets().length != X25519_KEY_LENGTH) throw new PemException("Invalid key length");
                        curve = Curve.X25519;
                        X25519PrivateKeyParameters x25519PrivateKeyParameters = new X25519PrivateKeyParameters(innerOctetString.getOctets(), 0);
                        X25519PublicKeyParameters x25519PublicKeyParameters = x25519PrivateKeyParameters.generatePublicKey();
                        d = Base64URL.encode(innerOctetString.getOctets());
                        x = Base64URL.encode(x25519PublicKeyParameters.getEncoded());
                        break;
                    case "1.3.101.111":
                        if(innerOctetString.getOctets().length != X448_KEY_LENGTH) throw new PemException("Invalid key length");
                        curve = Curve.X448;
                        X448PrivateKeyParameters x448PrivateKeyParameters = new X448PrivateKeyParameters(innerOctetString.getOctets(), 0);
                        X448PublicKeyParameters x448PublicKeyParameters = x448PrivateKeyParameters.generatePublicKey();
                        d = Base64URL.encode(innerOctetString.getOctets());
                        x = Base64URL.encode(x448PublicKeyParameters.getEncoded());
                        break;
                    case "1.3.101.112":
                        if(innerOctetString.getOctets().length != ED25519_KEY_LENGTH) throw new PemException("Invalid key length");
                        curve = Curve.Ed25519;
                        Ed25519PrivateKeyParameters ed25519PrivateKeyParameters = new Ed25519PrivateKeyParameters(innerOctetString.getOctets(), 0);
                        Ed25519PublicKeyParameters ed25519PublicKeyParameters = ed25519PrivateKeyParameters.generatePublicKey();
                        d = Base64URL.encode(innerOctetString.getOctets());
                        x = Base64URL.encode(ed25519PublicKeyParameters.getEncoded());
                        break;
                    case "1.3.101.113":
                        if(innerOctetString.getOctets().length != ED448_KEY_LENGTH) throw new PemException("Invalid key length");
                        curve = Curve.Ed448;
                        Ed448PrivateKeyParameters ed448PrivateKeyParameters = new Ed448PrivateKeyParameters(innerOctetString.getOctets(), 0);
                        Ed448PublicKeyParameters ed448PublicKeyParameters = ed448PrivateKeyParameters.generatePublicKey();
                        d = Base64URL.encode(innerOctetString.getOctets());
                        x = Base64URL.encode(ed448PublicKeyParameters.getEncoded());
                        break;
                    default:
                        throw new PemException("Invalid curve");
                }

                return new OctetKeyPair.Builder(curve, x).d(d).build();

            }
            // Public key
            else if (integerOrSequencePrimitive instanceof ASN1Sequence){
                DLSequence algorithmSequence = (DLSequence) outerSequence.getObjectAt(0);
                ASN1ObjectIdentifier algorithmIdentifer = (ASN1ObjectIdentifier) algorithmSequence.getObjectAt(0);
                DERBitString bitString = (DERBitString) outerSequence.getObjectAt(1);

                byte[] keyBytes = Arrays.copyOfRange(bitString.getBytes(), 0, bitString.getEncoded().length);

                Curve curve;
                int keyLength;
                switch(algorithmIdentifer.getId()){
                    case "1.3.101.110":
                        curve = Curve.X25519;
                        keyLength = X25519_KEY_LENGTH;
                        break;
                    case "1.3.101.111":
                        curve = Curve.X448;
                        keyLength = X448_KEY_LENGTH;
                        break;
                    case "1.3.101.112":
                        curve = Curve.Ed25519;
                        keyLength = ED25519_KEY_LENGTH;
                        break;
                    case "1.3.101.113":
                        curve = Curve.Ed448;
                        keyLength = ED448_KEY_LENGTH;
                        break;
                    default:
                        throw new PemException("Invalid curve");
                }

                Base64URL d = Base64URL.encode(trimByteArray(keyBytes, keyLength));
                return new OctetKeyPair.Builder(curve, d).build();
            }
            else{
                throw new PemException("Invalid PEM");
            }

        } catch (IOException e) {
            throw new PemException("Error reading PEM");
        } catch (ArrayIndexOutOfBoundsException e) {
            throw new PemException("Invalid number of ASN1 objects");
        } catch (ClassCastException e){
            throw new PemException("Invalid ASN1");
        }
    }
}
