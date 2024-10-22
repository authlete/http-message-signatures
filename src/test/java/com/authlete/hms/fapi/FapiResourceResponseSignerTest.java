/*
 * Copyright (C) 2024 Authlete, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.authlete.hms.fapi;


import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.net.URI;
import java.security.SignatureException;
import java.text.ParseException;
import java.time.Instant;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import com.authlete.hms.SignatureInfo;
import com.authlete.hms.impl.JoseHttpVerifier;
import com.nimbusds.jose.jwk.JWK;


public class FapiResourceResponseSignerTest
{
    private static final String SIGNING_KEY =
            "{\n" +
            "  \"kty\": \"EC\",\n" +
            "  \"alg\": \"ES256\",\n" +
            "  \"crv\": \"P-256\",\n" +
            "  \"x\": \"R-z3wlMAAQ73arr3JkxfP04woVLm1zHJXX2IGCm7z5c\",\n" +
            "  \"y\": \"zs5TKDbreY-5rUqx1xiMc1aKP9CWq3dL6wZJ3wVTf50\",\n" +
            "  \"d\": \"E67QqVgry3Y7vlMyuEID4CRbubQON9Bf-PLaB3lIdFs\",\n" +
            "  \"kid\": \"snIZq-_NvzkKV-IdiM348BCz_RKdwmufnrPubsKKyio\",\n" +
            "  \"use\": \"sig\"\n" +
            "}";

    // The content-digest value for testing; sha-256 of "{}".
    private static final String CONTENT_DIGEST =
            "sha-256=:RBNvo1WzZ4oRRq0W9+hknpT7T8If536DEMBg9hyq/4o=:";


    @Test
    public void test() throws ParseException, IllegalStateException, SignatureException
    {
        JWK signingKey      = JWK.parse(SIGNING_KEY);
        JWK verificationKey = signingKey.toPublicJWK();
        Instant created     = Instant.now();

        FapiResourceResponseSigner signer = new FapiResourceResponseSigner()
                .setMethod("GET")
                .setTargetUri(URI.create("https://example.com/path?key=value"))
                .setRequestContentDigest(CONTENT_DIGEST)
                .setStatus(200)
                .setResponseContentDigest(CONTENT_DIGEST)
                .setCreated(created)
                .setSigningKey(signingKey)
                ;

        // Sign
        SignatureInfo info = signer.sign();

        // Signature metadata, which is used as part of the Signature-Input HTTP field value.
        String expectedMetadata = String.format(
                "(\"@method\";req \"@target-uri\";req \"content-digest\";req \"@status\" \"content-digest\")" +
                ";created=%d;keyid=\"snIZq-_NvzkKV-IdiM348BCz_RKdwmufnrPubsKKyio\";tag=\"fapi-2-response\"",
                created.getEpochSecond());
        String actualMetadata = info.getSerializedSignatureMetadata();
        assertEquals(expectedMetadata, actualMetadata);

        // Verify the signature.
        byte[] signature = info.getSignature();
        boolean verified = info.getSignatureBase().verify(new JoseHttpVerifier(verificationKey), signature);
        assertTrue(verified, "Signature verification unexpectedly failed.");

        // Serialized signature, which is used as part of the Signature HTTP field value.
        String expectedSerializedSignature = String.format(":%s:",
                Base64.getEncoder().encodeToString(signature));
        String actualSerializedSignature = info.getSerializedSignature();
        assertEquals(expectedSerializedSignature, actualSerializedSignature);
    }
}
