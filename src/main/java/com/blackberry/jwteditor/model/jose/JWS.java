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

package com.blackberry.jwteditor.model.jose;

import com.nimbusds.jose.util.Base64URL;
import org.apache.commons.lang3.StringUtils;

import java.text.ParseException;

/**
 * Class representing a JWS
 */
public class JWS extends JOSEObject {

    final Base64URL payload;
    final Base64URL signature;

    /**
     * Construct a JWS from encoded components
     * @param header the encoded header
     * @param payload the encoded payload
     * @param signature the encoded signature
     */
    public JWS(Base64URL header, Base64URL payload, Base64URL signature) {
        this.header = header;
        this.payload = payload;
        this.signature = signature;
    }

    /**
     * Parse a JWS from compact serialization
     *
     * @param compactJWS the JWS in compact serialization
     * @return the parsed JWS
     * @throws ParseException if parsing fails
     */
    public static JWS parse(String compactJWS) throws ParseException {
        if (StringUtils.countMatches(compactJWS, ".") != 2) {
            throw new ParseException("Invalid number of encoded sections", 0);
        }

        Base64URL[] parts = com.nimbusds.jose.JOSEObject.split(compactJWS);

        boolean allEmpty = true;
        for(Base64URL part: parts){
            if(part.decodeToString().length() > 0){
                allEmpty = false;
            }
        }

        if(allEmpty){
            throw new ParseException("All sections empty", 0);
        }

        return new JWS(parts[0], parts[1], parts[2]);
    }

    /**
     * Get the payload as a String
     *
     * @return the decoded payload
     */
    public String getPayload() {
        return payload.decodeToString();
    }

    /**
     * Get the encoded payload
     *
     * @return the base64 encoded payload
     */
    public Base64URL getEncodedPayload() { return payload; }

    public byte[] getSignature() {
        return signature.decode();
    }

    /**
     * Get the encoded signature
     *
     * @return the base64 encoded signature
     */
    public Base64URL getEncodedSignature() { return signature; }


    /**
     * Serialize the JWS to compact form
     *
     * @return the JWS in compact form
     */
    @Override
    public String serialize() {
        return String.format("%s.%s.%s", header.toString(), payload.toString(), signature.toString()); //NON-NLS
    }
}
