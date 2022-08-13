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

import com.blackberry.jwteditor.model.jose.JWS;
import com.blackberry.jwteditor.model.keys.JWKKey;
import com.blackberry.jwteditor.model.keys.Key;
import com.blackberry.jwteditor.operations.Attacks;
import com.blackberry.jwteditor.utils.CryptoUtils;
import com.blackberry.jwteditor.utils.PEMUtils;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.text.ParseException;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class AttackTests {

    // Using values from https://www.nccgroup.com/ae/about-us/newsroom-and-events/blogs/2019/january/jwt-attack-walk-through/ to verify
    private static final String HMAC_KEY_CONFUSION_JWS = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOlwvXC9kZW1vLnNqb2VyZGxhbmdrZW1wZXIubmxcLyIsImlhdCI6MTU0NzcyOTY2MiwiZXhwIjoxNTQ3Nzk5OTk5LCJkYXRhIjp7Ik5DQyI6InRlc3QifX0.";
    private static final String HMAC_KEY_CONFUSION_EXPECTED_JWS = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOlwvXC9kZW1vLnNqb2VyZGxhbmdrZW1wZXIubmxcLyIsImlhdCI6MTU0NzcyOTY2MiwiZXhwIjoxNTQ3Nzk5OTk5LCJkYXRhIjp7Ik5DQyI6InRlc3QifX0.2zobdg7sgeApcEaR9ngMTRZT1dkWiMJOWYkelzQu5Z8";
    private static final String HMAC_KEY_CONFUSION_PEM = "-----BEGIN PUBLIC KEY-----\n" +
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqi8TnuQBGXOGx/Lfn4JF\n" +
            "NYOH2V1qemfs83stWc1ZBQFCQAZmUr/sgbPypYzy229pFl6bGeqpiRHrSufHug7c\n" +
            "1LCyalyUEP+OzeqbEhSSuUss/XyfzybIusbqIDEQJ+Yex3CdgwC/hAF3xptV/2t+\n" +
            "H6y0Gdh1weVKRM8+QaeWUxMGOgzJYAlUcRAP5dRkEOUtSKHBFOFhEwNBXrfLd76f\n" +
            "ZXPNgyN0TzNLQjPQOy/tJ/VFq8CQGE4/K5ElRSDlj4kswxonWXYAUVxnqRN1LGHw\n" +
            "2G5QRE2D13sKHCC8ZrZXJzj67Hrq5h2SADKzVzhA8AW3WZlPLrlFT3t1+iZ6m+aF\n" +
            "KwIDAQAB\n" +
            "-----END PUBLIC KEY----";

    private static final String EMBEDDED_JWK_KEY = "{\"p\":\"6g4o__Z8GnI2UtRz6AJdD0dVRmZqq1bONXWq6ee70eVHmu-fZ2XQCYj6miF1DT-QHDA1eb7QxKnb5b-HZ2L-OXf6OLtu6xNBmQjT1ZcGHe8YHmNfJN4CP-nxG4EYJRoInZOvQwBEWfXIrqvw0HhGXTrfC8GGHtb1uCP733cITaU\",\"kty\":\"RSA\",\"q\":\"tvQO0f6XevKrWzHDfjfQ_dQohOIpRYMIuiEohAMqphgeVh3VUJHAnigWkHllvJN6wsJcZM9TfXiKFjdEtgl_L9igTJ8BTAJD2yLl_qfnjpODLR7A--AnyFEEFtgO-FfnFRQlBC50-Bfz4JxF5K7hXAYs1X5GHp0j6SyjO7wSaFU\",\"d\":\"SWgkfMybZJ6zFZgVpgLMgjTHWfvrC4MRvtjmif2haSiYHQRB0IgY5_kSUKvp00reb4Xa_Asx1gjq6lrfd8iIt_OSJNkS7Od3s_K6pP_o7WAtl3UUuMqSdZSmJXiPzlkCBldnjsHRU1kqolfiT07m9zCS972ZTilYoErVk9eOCcazPvEihUcyDGTcx2H7cXrZaqrlliQNUpTCWw6SHspq2V4FLGZrioFDCOkbAL1rgD5mg2mANMLv1UY7JWVueuvzs8jnvsGnhRQlnhf7QgSFXUUfhoy-Ej2rWrfYZ5_i17tuGkjqiq0vzAA1U28REZEBHjDQ4p_8vCtHgz3Lc-75UQ\",\"e\":\"AQAB\",\"kid\":\"dfc6a9df-916c-406d-84de-ce5b49d50ad0\",\"qi\":\"Pl4ANTrzCLGsE5IE3jkJiqeOq6Z3HXrQsv39NXQNriLAyghQPgrcnN4rGLaBRi1DKFElU4qmCLXzwaylox-vJd_W4WD-2UFvaSD4h_EUjGSfpcfEPTONECF5WTRHwDCNRVu7XaK53jp0nadsiFaa8a1SmP58uZwl869Bp0Hskks\",\"dp\":\"lLJSUeuihJqy8ISQ7oEx5hcHkiZW9mu7rjMHVnsm0_66MzCxMNt6A9TGgU1oM_aB86adEq-rqoXPcnLv7zrxEEms6oYJvccKEdON4VCFTlcsF4JCXAW_oCNcToEBefDEMHg3DHYK9qwzxuTtpUQEUA6qzakxMD6Y9VfHGP1ihRE\",\"dq\":\"nnRItbXUCsdMhEJYd-Pt3Tm4EkcyyaKQl2yKg7OeZ5ZyB9H048Ao3JIJ4P1TkP0GkNH3ZdRvEjepGU6q8yLMhmsPgu0gGW3IyW2zV1ii48h9D0IYkM32hrcsXICqjorLeGUnHjUCV7GfJoUSv9p7EtHCWPHx1yfwZ06i3eSo6LU\",\"n\":\"p0U0MdHFLPovX5j91oH-dc54oeJDIDapuPDM9gYHjhX2Bwj4fFhqvaAfIhn-w7zm-6HZsH-VxPCngl7GkWxx1F7Cobkg8TOD4UusFFo8srSFDExWCQ4MRFDRcLN9bmfXeiR-MvGE1tHZNJCOnxsx32-ueF0T2xo880-073skum8sS9vi7RuNhaCY_liJNkrznqQCEbNLR_-V_-IQaFG_obDNqEHroKC3lxz34s4CPpUwen8IFJm8_vbcFiI_jZrw_VTwJM4Il5Hr2uJLv_ahsZTLomumJmabvXulgQFBK4hEd-FH4c72glbFfFLEkzRQz-ozCzySudbRG9UvhubPyQ\"}";
    private static final String EMBEDDED_JWK_EXPECTED_JWS = "eyJraWQiOiJkZmM2YTlkZi05MTZjLTQwNmQtODRkZS1jZTViNDlkNTBhZDAiLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImp3ayI6eyJrdHkiOiJSU0EiLCJlIjoiQVFBQiIsImtpZCI6ImRmYzZhOWRmLTkxNmMtNDA2ZC04NGRlLWNlNWI0OWQ1MGFkMCIsIm4iOiJwMFUwTWRIRkxQb3ZYNWo5MW9ILWRjNTRvZUpESURhcHVQRE05Z1lIamhYMkJ3ajRmRmhxdmFBZklobi13N3ptLTZIWnNILVZ4UENuZ2w3R2tXeHgxRjdDb2JrZzhUT0Q0VXVzRkZvOHNyU0ZERXhXQ1E0TVJGRFJjTE45Ym1mWGVpUi1NdkdFMXRIWk5KQ09ueHN4MzItdWVGMFQyeG84ODAtMDczc2t1bThzUzl2aTdSdU5oYUNZX2xpSk5rcnpucVFDRWJOTFJfLVZfLUlRYUZHX29iRE5xRUhyb0tDM2x4ejM0czRDUHBVd2VuOElGSm04X3ZiY0ZpSV9qWnJ3X1ZUd0pNNElsNUhyMnVKTHZfYWhzWlRMb211bUptYWJ2WHVsZ1FGQks0aEVkLUZINGM3MmdsYkZmRkxFa3pSUXotb3pDenlTdWRiUkc5VXZodWJQeVEifX0.eyJpc3MiOiJodHRwOlwvXC9kZW1vLnNqb2VyZGxhbmdrZW1wZXIubmxcLyIsImlhdCI6MTU0NzcyOTY2MiwiZXhwIjoxNTQ3Nzk5OTk5LCJkYXRhIjp7Ik5DQyI6InRlc3QifX0.Fte7ISfZ15DGtYwql8Ej1rou0Kf5Lut3qpxUS2zcp5UsRapQTyU5nehvVZD5BKq_xKRkG0SEVlRbF6Z2FAsG7Al3NXKc257xKc1djt_toh7nsDZPWycfj91FrLVJW5dN06PNgDjkCVlcdM2x_awesc3bApLg7bmcEkxsMoPqUjDBLxo6h-AHEo_7F-0R7mOAC5cSUCsCosEnnwMG7ihC_bPkD9cGUwq5UEPjzVCToavIXXWjNRpHXSob9aGuKUlYao92VoYIuOH51YcyAspzXD3lDViG8ZxOPVTf3T7ZDUmfy161XDRyvmRxeUVSRSUzAt3-WdMjmP8YRylYCC36Ew";

    @ParameterizedTest
    @ValueSource(strings = {"none", "None", "NONE", "nOnE"})
    void testSigningKeyNone(String algorithm) throws ParseException {
        JWS jws = JWS.parse(HMAC_KEY_CONFUSION_JWS);
        JWS modifiedJWS = Attacks.noneSigning(jws, algorithm);

        assertEquals(modifiedJWS.getHeader(), String.format("{\"typ\":\"JWT\",\"alg\":\"%s\"}", algorithm));
        assertEquals(modifiedJWS.getEncodedPayload().toString(), HMAC_KEY_CONFUSION_JWS.split("\\.")[1]);
        assertEquals(modifiedJWS.getSignature().length, 0);
    }

    @Test
    void testHMACKeyConfusion() throws ParseException, PEMUtils.PemException, Key.UnsupportedKeyException, CryptoUtils.SigningException {
        JWS jws = JWS.parse(HMAC_KEY_CONFUSION_JWS);
        JWS expectedJWS = JWS.parse(HMAC_KEY_CONFUSION_EXPECTED_JWS);
        JWKKey key = new JWKKey(PEMUtils.pemToRSAKey(HMAC_KEY_CONFUSION_PEM));

        JWS modifiedJWS  = Attacks.hmacKeyConfusion(jws, key, JWSAlgorithm.HS256, false);

        assertArrayEquals(modifiedJWS.getSignature(), expectedJWS.getSignature());
    }

    @Test
    // Test the Embedded JWK attack produces a known-good value
    void testEmbeddedJWKKnown() throws ParseException, Key.UnsupportedKeyException, CryptoUtils.SigningException, NoSuchFieldException, IllegalAccessException {
        JWS jws = JWS.parse(HMAC_KEY_CONFUSION_JWS);
        JWKKey jwk = new JWKKey(JWK.parse(EMBEDDED_JWK_KEY));

        JWS modifiedJWS = Attacks.embeddedJWK(jws, jwk, JWSAlgorithm.RS256);

        assertEquals(modifiedJWS.serialize(), EMBEDDED_JWK_EXPECTED_JWS);
    }


    @Test
    // Test the Embedded JWK attack with all signing key types
    void testEmbeddedJWKAll() throws ParseException, Key.UnsupportedKeyException, CryptoUtils.SigningException, JOSEException, PEMUtils.PemException, NoSuchFieldException, IllegalAccessException {
        JWS jws = JWS.parse(HMAC_KEY_CONFUSION_JWS);

        for (String pem : PEMToJWKTests.RSAPrivate) {
            RSAKey rsaKey = PEMUtils.pemToRSAKey(pem);
            JWKKey jwk = new JWKKey(rsaKey);
            for (JWSAlgorithm alg : jwk.getSigningAlgorithms()) {
                Attacks.embeddedJWK(jws, jwk, alg);
            }
        }

        for (String pem : PEMToJWKTests.ECPrivate) {
            ECKey ecKey = PEMUtils.pemToECKey(pem);
            JWKKey jwk = new JWKKey(ecKey);
            for (JWSAlgorithm alg : jwk.getSigningAlgorithms()) {
                Attacks.embeddedJWK(jws, jwk, alg);
            }
        }

        for (String pem : PEMToJWKTests.OKPPrivate) {
            OctetKeyPair octetKeyPair = PEMUtils.pemToOctetKeyPair(pem);
            JWKKey jwk = new JWKKey(octetKeyPair);
            for (JWSAlgorithm alg : jwk.getSigningAlgorithms()) {
                Attacks.embeddedJWK(jws, jwk, alg);
            }
        }

        OctetSequenceKey[] octetSequenceKeys = new OctetSequenceKey[]{
                new OctetSequenceKeyGenerator(128).generate(),
                new OctetSequenceKeyGenerator(192).generate(),
                new OctetSequenceKeyGenerator(256).generate(),
                new OctetSequenceKeyGenerator(384).generate(),
                new OctetSequenceKeyGenerator(512).generate(),
                new OctetSequenceKey.Builder("secret123".getBytes()).build(),
        };

        for(OctetSequenceKey octetSequenceKey: octetSequenceKeys) {
            JWKKey jwk = new JWKKey(octetSequenceKey);
            for (JWSAlgorithm alg : jwk.getSigningAlgorithms()) {
                Attacks.embeddedJWK(jws, jwk, alg);
            }
        }
    }
}
