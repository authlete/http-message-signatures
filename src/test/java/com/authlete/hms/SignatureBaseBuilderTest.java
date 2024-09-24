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
package com.authlete.hms;


import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;


public class SignatureBaseBuilderTest
{
    @Test
    public void test_normal() throws Exception
    {
        // Component identifiers with optional parameters.
        List<ComponentIdentifier> identifiers = new ArrayList<>();
        identifiers.add(new ComponentIdentifier("@method"));
        identifiers.add(new ComponentIdentifier("my-field",
                new ComponentIdentifierParameters().setSf(true)));

        // Signature metadata with optional parameters.
        SignatureMetadata metadata = new SignatureMetadata(
                identifiers, new SignatureMetadataParameters().setTag("my_tag"));

        assertEquals("(\"@method\" \"my-field\";sf);tag=\"my_tag\"", metadata.serialize());

        // Create a signature base builder.
        SignatureContext context = new TestSignatureContext();
        SignatureBaseBuilder builder = new SignatureBaseBuilder(context);

        // Create a signature base.
        SignatureBase base = builder.build(metadata);

        String expectedSerializedBase =
                "\"@method\": POST\n" +
                "\"my-field\";sf: my-field-value\n" +
                "\"@signature-params\": (\"@method\" \"my-field\";sf);tag=\"my_tag\"";

        assertEquals(expectedSerializedBase, base.serialize());
    }


    @Test
    public void test_normal_component_unavailable() throws Exception
    {
        // Component identifiers.
        List<ComponentIdentifier> identifiers = new ArrayList<>();
        identifiers.add(new ComponentIdentifier("unknown-field"));

        // Signature metadata.
        SignatureMetadata metadata = new SignatureMetadata(identifiers);

        // Create a signature base builder.
        SignatureContext context = new TestSignatureContext();
        SignatureBaseBuilder builder = new SignatureBaseBuilder(context);

        // Create a signature base.
        SignatureBase base = builder.build(metadata);

        String expectedSerializedBase =
                "\"unknown-field\": \n" +
                "\"@signature-params\": (\"unknown-field\")";

        assertEquals(expectedSerializedBase, base.serialize());
    }


    @Test
    public void test_derived_component_unavailable() throws Exception
    {
        // Component identifiers.
        List<ComponentIdentifier> identifiers = new ArrayList<>();
        identifiers.add(new ComponentIdentifier("@method"));

        // Signature metadata.
        SignatureMetadata metadata = new SignatureMetadata(identifiers);

        // Prepare a signature context that always returns null.
        SignatureContext context = new SignatureContext() {
            @Override
            public String getComponentValue(
                    SignatureMetadata metadata, ComponentIdentifier identifier) throws SignatureException
            {
                return null;
            }
        };

        // Create a signature base builder.
        SignatureBaseBuilder builder = new SignatureBaseBuilder(context);

        // When the value for a derived component is unavailable,
        // an error must be produced.
        assertThrows(SignatureException.class, () -> builder.build(metadata));
    }
}
