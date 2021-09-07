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

import com.blackberry.jwteditor.model.jose.JOSEObjectPair;
import com.blackberry.jwteditor.model.jose.JWE;
import com.blackberry.jwteditor.model.jose.JWS;
import com.blackberry.jwteditor.utils.Utils;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JOSEParserTests {

    private static final String[] VALID_JWS = new String[]{
            // JWS
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJUZXN0In0.Nabf3xakZubPnCzHT-fx0vG1iuNPeJKuSzHxUiQKf-8",
            // JWS without signature
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJUZXN0In0.",
            // JWS with preceding text
            "asdasdasdeyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJUZXN0In0.Nabf3xakZubPnCzHT-fx0vG1iuNPeJKuSzHxUiQKf-8",
            // JWS without signature preceding text
            "asdasdasdasdeyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJUZXN0In0.Nabf3xakZubPnCzHT-fx0vG1iuNPeJKuSzHxUiQKf-8"
    };

    private static final String[] INVALID_JWS = new String[]{
            // No header
            ".eyJzdWIiOiJUZXN0In0.Nabf3xakZubPnCzHT-fx0vG1iuNPeJKuSzHxUiQKf-8",
            // No payload
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..Nabf3xakZubPnCzHT-fx0vG1iuNPeJKuSzHxUiQKf-8",
            // Empty
            "..",
            //URL
            "www.blackberry.com",
    };
    private static final String[] VALID_JWE = new String[]{
            //JWE with encrypted key
            "eyJlbmMiOiJBMTI4R0NNIiwiYWxnIjoiQTEyOEtXIn0.H3X6mT5HLgcFfzLoe4ku6Knhh9Ofv1eL.qF5-N_7K8VQ4yMSz.WXUNY6eg5fR4tc8Hqf5XDRM9ALGwcQyYG4IYwwg8Ctkx1UuxoV7t6UnemjzCj2sOYUqi3KYpDzrKVJpzokz0vcIem4lFe5N_ds8FAMpW0GSF9ePA8qvV99WaP0N2ECVPmgihvL6qwNhdptlLKtxcOpE41U5LnU22voPK55VF4_1j0WmTgWgZ7DwLDysp6EIDjrrt-DY.febBmP71KADmKRVfeSnv_g",
            //JWE with dir encryption
            "eyJlbmMiOiJBMTI4R0NNIiwiYWxnIjoiZGlyIn0..FofRkmAUlKShyhYp.1AjXmQsKwV36LSxZ5YJq7xPPTTUS_e9FyLbd-CWdX72ESWMttHm2xGDWUl-Sp9grmcINWLNwsKezYnJVncfir2o9Uq9vcXENIypU2Qwmymn5q5gJwkR4Wx_RLae9Zm8xP76LJFQe8FssUVHx65Zzvd1I6GbV6FjfbkLF1Z_Ka-olubtWCilFDjIVN7WRUAxmV8syJaM.P0XjuL8_8nK50paY09mB6g",
            //JWE with encrypted key with preceding text
            "asdasdasdaseyJlbmMiOiJBMTI4R0NNIiwiYWxnIjoiQTEyOEtXIn0.H3X6mT5HLgcFfzLoe4ku6Knhh9Ofv1eL.qF5-N_7K8VQ4yMSz.WXUNY6eg5fR4tc8Hqf5XDRM9ALGwcQyYG4IYwwg8Ctkx1UuxoV7t6UnemjzCj2sOYUqi3KYpDzrKVJpzokz0vcIem4lFe5N_ds8FAMpW0GSF9ePA8qvV99WaP0N2ECVPmgihvL6qwNhdptlLKtxcOpE41U5LnU22voPK55VF4_1j0WmTgWgZ7DwLDysp6EIDjrrt-DY.febBmP71KADmKRVfeSnv_g",
            //JWE with dir encryption with preceding text
            "asdasdasdeyJlbmMiOiJBMTI4R0NNIiwiYWxnIjoiZGlyIn0..FofRkmAUlKShyhYp.1AjXmQsKwV36LSxZ5YJq7xPPTTUS_e9FyLbd-CWdX72ESWMttHm2xGDWUl-Sp9grmcINWLNwsKezYnJVncfir2o9Uq9vcXENIypU2Qwmymn5q5gJwkR4Wx_RLae9Zm8xP76LJFQe8FssUVHx65Zzvd1I6GbV6FjfbkLF1Z_Ka-olubtWCilFDjIVN7WRUAxmV8syJaM.P0XjuL8_8nK50paY09mB6g"
    };
    private static final String[] INVALID_JWE = new String[]{
            //No header
            ".H3X6mT5HLgcFfzLoe4ku6Knhh9Ofv1eL.qF5-N_7K8VQ4yMSz.WXUNY6eg5fR4tc8Hqf5XDRM9ALGwcQyYG4IYwwg8Ctkx1UuxoV7t6UnemjzCj2sOYUqi3KYpDzrKVJpzokz0vcIem4lFe5N_ds8FAMpW0GSF9ePA8qvV99WaP0N2ECVPmgihvL6qwNhdptlLKtxcOpE41U5LnU22voPK55VF4_1j0WmTgWgZ7DwLDysp6EIDjrrt-DY.febBmP71KADmKRVfeSnv_g",
            //No IV
            "eyJlbmMiOiJBMTI4R0NNIiwiYWxnIjoiQTEyOEtXIn0.H3X6mT5HLgcFfzLoe4ku6Knhh9Ofv1eL..WXUNY6eg5fR4tc8Hqf5XDRM9ALGwcQyYG4IYwwg8Ctkx1UuxoV7t6UnemjzCj2sOYUqi3KYpDzrKVJpzokz0vcIem4lFe5N_ds8FAMpW0GSF9ePA8qvV99WaP0N2ECVPmgihvL6qwNhdptlLKtxcOpE41U5LnU22voPK55VF4_1j0WmTgWgZ7DwLDysp6EIDjrrt-DY.febBmP71KADmKRVfeSnv_g",
            //No Ciphertext
            "eyJlbmMiOiJBMTI4R0NNIiwiYWxnIjoiQTEyOEtXIn0.H3X6mT5HLgcFfzLoe4ku6Knhh9Ofv1eL.qF5-N_7K8VQ4yMSz..febBmP71KADmKRVfeSnv_g",
            //No Tag
            "eyJlbmMiOiJBMTI4R0NNIiwiYWxnIjoiQTEyOEtXIn0.H3X6mT5HLgcFfzLoe4ku6Knhh9Ofv1eL.qF5-N_7K8VQ4yMSz.WXUNY6eg5fR4tc8Hqf5XDRM9ALGwcQyYG4IYwwg8Ctkx1UuxoV7t6UnemjzCj2sOYUqi3KYpDzrKVJpzokz0vcIem4lFe5N_ds8FAMpW0GSF9ePA8qvV99WaP0N2ECVPmgihvL6qwNhdptlLKtxcOpE41U5LnU22voPK55VF4_1j0WmTgWgZ7DwLDysp6EIDjrrt-DY.",
            //Empty
            "....",
            "1.2.www.blackberry.com",
    };


    @Test
    void testValidJWS(){
        for(String joseObjectString: VALID_JWS){
            ArrayList<JOSEObjectPair> joseObjects = Utils.extractJOSEObjects(joseObjectString);
            assertEquals(1, joseObjects.size());
            assertTrue(joseObjects.get(0).getModified() instanceof JWS);
        }
    }

    @Test
    void testInvalidJWS(){
        for(String joseObjectString: INVALID_JWS){
            ArrayList<JOSEObjectPair> joseObjects = Utils.extractJOSEObjects(joseObjectString);
            assertEquals(0, joseObjects.size());
        }
    }

    @Test
    void testValidJWE(){
        for(String joseObjectString: VALID_JWE){
            ArrayList<JOSEObjectPair> joseObjects = Utils.extractJOSEObjects(joseObjectString);
            assertEquals(1, joseObjects.size());
            assertTrue(joseObjects.get(0).getModified() instanceof JWE);
        }
    }

    @Test
    void testInvalidJWE(){
        for(String joseObjectString: INVALID_JWE){
            ArrayList<JOSEObjectPair> joseObjects = Utils.extractJOSEObjects(joseObjectString);
            assertEquals(0, joseObjects.size());
        }
    }

}
