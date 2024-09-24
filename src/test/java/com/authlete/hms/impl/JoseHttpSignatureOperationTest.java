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
package com.authlete.hms.impl;


import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.security.SignatureException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import com.authlete.hms.ComponentIdentifier;
import com.authlete.hms.ComponentIdentifierParameters;
import com.authlete.hms.HttpSigner;
import com.authlete.hms.HttpVerifier;
import com.authlete.hms.SignatureBase;
import com.authlete.hms.SignatureBaseBuilder;
import com.authlete.hms.SignatureContext;
import com.authlete.hms.SignatureMetadata;
import com.authlete.hms.SignatureMetadataParameters;
import com.authlete.hms.TestSignatureContext;
import com.nimbusds.jose.jwk.JWK;


public class JoseHttpSignatureOperationTest
{
    private static final String KEY_ES256 =
            "{\n" +
            "  \"kty\": \"EC\",\n" +
            "  \"alg\": \"ES256\",\n" +
            "  \"crv\": \"P-256\",\n" +
            "  \"x\": \"FQRPPveG_JcbafEXx3QjZyf3sKu1l9IC_QA-43Dn814\",\n" +
            "  \"y\": \"2ApqjsFr0FgCCAhTAse3gUwBlIqepYXQH5dVp_LvgSo\",\n" +
            "  \"d\": \"mxBMW0wYKiJqVwZUk1sqfVUSWZlzckf5eSF1L-p8LL4\"\n" +
            "}";


    @Test
    public void test() throws Exception
    {
        // Prepare a pair of private key and public key.
        JWK priKey = createPrivateKey();
        JWK pubKey = priKey.toPublicJWK();

        // Prepare a signer and a verifier.
        HttpSigner   signer   = new JoseHttpSigner(priKey);
        HttpVerifier verifier = new JoseHttpVerifier(pubKey);

        // Prepare a signature base.
        SignatureBase base = createSignatureBase();

        // Sign the signature base (= create a signature).
        byte[] signature = base.sign(signer);
        assertNotNull(signature);

        // Verify the signature.
        boolean verified = base.verify(verifier, signature);
        assertTrue(verified, "Signature verification unexpectedly failed.");

        // Prepare an invalid signature.
        byte[] invalidSignature = createInvalidSignature(signature);

        verified = false;

        try
        {
            // Confirm that signature verification fails.
            verified = base.verify(verifier, invalidSignature);
        }
        catch (SignatureException cause)
        {
            // The signature verification expectedly failed.
            // (It seems that the verifier implementation throws an exception
            // when the signature is invalid.)
            return;
        }

        assertFalse(verified, "Signature verification unexpectedly succeeded.");
    }


    private static JWK createPrivateKey() throws ParseException
    {
        return JWK.parse(KEY_ES256);
    }


    private static SignatureBase createSignatureBase() throws SignatureException
    {
        // Component identifiers with optional parameters.
        List<ComponentIdentifier> identifiers = new ArrayList<>();
        identifiers.add(new ComponentIdentifier("@method"));
        identifiers.add(new ComponentIdentifier("my-field",
                new ComponentIdentifierParameters().setSf(true)));

        // Signature metadata with optional parameters.
        SignatureMetadata metadata = new SignatureMetadata(
                identifiers, new SignatureMetadataParameters().setTag("my_tag"));

        SignatureContext context = new TestSignatureContext();
        SignatureBaseBuilder builder = new SignatureBaseBuilder(context);

        return builder.build(metadata);
    }


    private static byte[] createInvalidSignature(byte[] originalSignature)
    {
        byte[] invalidSignature = new byte[originalSignature.length];

        // Copy the original signature.
        System.arraycopy(originalSignature, 0, invalidSignature, 0, originalSignature.length);

        // The first byte of the signature.
        byte first = invalidSignature[0];

        // Change the first byte.
        invalidSignature[0] = (byte)~first;

        return invalidSignature;
    }
}
