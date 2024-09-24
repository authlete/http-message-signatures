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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.security.SignatureException;
import org.junit.jupiter.api.Test;


public class SignatureInputFieldTest
{
    @Test
    public void test_not_dictionary()
    {
        // A field value that is not a dictionary.
        final String fieldValue = "hello";

        assertThrows(SignatureException.class, () -> SignatureInputField.parse(fieldValue));
    }


    @Test
    public void test_not_inner_list()
    {
        // A field value that is a dictionary, but a member value is not an inner list.
        final String fieldValue = "sig=\"hello\"";

        assertThrows(SignatureException.class, () -> SignatureInputField.parse(fieldValue));
    }


    @Test
    public void test_empty_dictionary() throws Exception
    {
        // A field value that is an empty dictionary.
        final String fieldValue = "";

        SignatureInputField field = SignatureInputField.parse(fieldValue);
        assertNotNull(field);
        assertEquals(0, field.size());
    }


    @Test
    public void test_empty_inner_list() throws Exception
    {
        // A field value that is a dictionary having a member whose value is an empty inner list..
        final String fieldValue = "sig=()";

        SignatureInputField field = SignatureInputField.parse(fieldValue);
        assertNotNull(field);
        assertEquals(1, field.size());

        SignatureMetadata metadata = field.get("sig");
        assertNotNull(metadata);
        assertEquals(0, metadata.size());
    }


    @Test
    public void test_component_name_including_uppercase()
    {
        final String fieldValue = "sig=(\"MyField\")";

        // Normal component names must not include uppercase characters.
        assertThrows(SignatureException.class, () -> SignatureInputField.parse(fieldValue));
    }


    @Test
    public void test_unknown_derived_component_name()
    {
        final String fieldValue = "sig=(\"@unknown\")";

        // Derived component names must have been pre-registered.
        assertThrows(SignatureException.class, () -> SignatureInputField.parse(fieldValue));
    }


    @Test
    public void test_correct_component_names() throws Exception
    {
        final String fieldValue = "sig=(\"authorization\" \"@method\")";

        SignatureInputField field = SignatureInputField.parse(fieldValue);
        assertNotNull(field);
        assertEquals(1, field.size());

        SignatureMetadata metadata = field.get("sig");
        assertNotNull(metadata);
        assertEquals(2, metadata.size());

        assertEquals("authorization", metadata.get(0).getComponentName());
        assertEquals("@method", metadata.get(1).getComponentName());
    }


    @Test
    public void test_signature_metadata_parameters_empty() throws Exception
    {
        final String fieldValue = "sig=()";

        SignatureInputField field = SignatureInputField.parse(fieldValue);
        assertNotNull(field);

        SignatureMetadata metadata = field.get("sig");
        assertNotNull(metadata);

        SignatureMetadataParameters params = metadata.getParameters();
        assertNotNull(params);

        assertNull(params.getAlg());
        assertNull(params.getCreated());
        assertNull(params.getExpires());
        assertNull(params.getKeyid());
        assertNull(params.getNonce());
        assertNull(params.getTag());
    }


    @Test
    public void test_signature_metadata_parameters() throws Exception
    {
        final String fieldValue =
                "sig=();alg=\"ed25519\";created=1714921200;expires=1714921260" +
                ";keyid=\"my_keyid\";nonce=\"my_nonce\";tag=\"my_tag\"";

        SignatureInputField field = SignatureInputField.parse(fieldValue);
        assertNotNull(field);

        SignatureMetadata metadata = field.get("sig");
        assertNotNull(metadata);

        SignatureMetadataParameters params = metadata.getParameters();
        assertNotNull(params);

        assertEquals("ed25519",  params.getAlg());
        assertEquals(1714921200, params.getCreated().getEpochSecond());
        assertEquals(1714921260, params.getExpires().getEpochSecond());
        assertEquals("my_keyid", params.getKeyid());
        assertEquals("my_nonce", params.getNonce());
        assertEquals("my_tag",   params.getTag());
    }


    @Test
    public void test_component_identifier_parameters_empty() throws Exception
    {
        final String fieldValue = "sig=(\"my-field\")";

        SignatureInputField field = SignatureInputField.parse(fieldValue);
        assertNotNull(field);

        SignatureMetadata metadata = field.get("sig");
        assertNotNull(metadata);

        ComponentIdentifier identifier = metadata.get(0);
        assertNotNull(identifier);

        ComponentIdentifierParameters params = identifier.getParameters();
        assertNotNull(params);

        assertFalse(params.isBs());
        assertNull( params.getKey());
        assertNull( params.getName());
        assertFalse(params.isReq());
        assertFalse(params.isSf());
        assertFalse(params.isTr());
    }


    @Test
    public void test_component_identifier_parameters_bs() throws Exception
    {
        final String fieldValue = "sig=(\"my-field\";bs)";

        SignatureInputField field = SignatureInputField.parse(fieldValue);
        assertNotNull(field);

        SignatureMetadata metadata = field.get("sig");
        assertNotNull(metadata);

        ComponentIdentifier identifier = metadata.get(0);
        assertNotNull(identifier);

        ComponentIdentifierParameters params = identifier.getParameters();
        assertNotNull(params);

        assertTrue(params.isBs());
    }


    @Test
    public void test_component_identifier_parameters_bs_sf() throws Exception
    {
        final String fieldValue = "sig=(\"my-field\";bs;sf)";

        // The 'bs' flag and 'sf' flag are mutually exclusive.
        assertThrows(SignatureException.class, () -> SignatureInputField.parse(fieldValue));
    }


    @Test
    public void test_component_identifier_parameters_bs_key() throws Exception
    {
        final String fieldValue = "sig=(\"my-field\";bs;key=\"my_key\")";

        // The 'bs' flag and 'key' parameter are mutually exclusive.
        assertThrows(SignatureException.class, () -> SignatureInputField.parse(fieldValue));
    }


    @Test
    public void test_component_identifier_parameters() throws Exception
    {
        final String fieldValue = "sig=(\"my-field\";key=\"my_key\";req;sf;tr)";

        SignatureInputField field = SignatureInputField.parse(fieldValue);
        assertNotNull(field);

        SignatureMetadata metadata = field.get("sig");
        assertNotNull(metadata);

        ComponentIdentifier identifier = metadata.get(0);
        assertNotNull(identifier);

        ComponentIdentifierParameters params = identifier.getParameters();
        assertNotNull(params);

        assertFalse(params.isBs());
        assertEquals("my_key", params.getKey());
        assertNull(params.getName());
        assertTrue(params.isReq());
        assertTrue(params.isSf());
        assertTrue(params.isTr());
    }


    @Test
    public void test_component_identifier_query_param_missing_name() throws Exception
    {
        final String fieldValue = "sig=(\"@query-param\")";

        // The '@query-param' derived component must always have the 'name' parameter.
        assertThrows(SignatureException.class, () -> SignatureInputField.parse(fieldValue));
    }


    @Test
    public void test_component_identifier_query_param() throws Exception
    {
        final String fieldValue = "sig=(\"@query-param\";name=\"my_name\")";

        SignatureInputField field = SignatureInputField.parse(fieldValue);
        assertNotNull(field);

        SignatureMetadata metadata = field.get("sig");
        assertNotNull(metadata);

        ComponentIdentifier identifier = metadata.get(0);
        assertNotNull(identifier);

        assertEquals("@query-param", identifier.getComponentName());

        ComponentIdentifierParameters params = identifier.getParameters();
        assertNotNull(params);

        assertEquals("my_name", params.getName());
    }


    @Test
    public void test_component_identifier_signature_params() throws Exception
    {
        final String fieldValue = "sig=(\"@signature-params\")";

        // The '@signature-params' derived component must not be included.
        assertThrows(SignatureException.class, () -> SignatureInputField.parse(fieldValue));
    }


    @Test
    public void test_multiple_members() throws Exception
    {
        final String fieldValue = "sig1=(\"my-field-1\"), sig2=(\"my-field-2\")";

        SignatureInputField field = SignatureInputField.parse(fieldValue);
        assertNotNull(field);
        assertEquals(2, field.size());

        SignatureMetadata metadata1 = field.get("sig1");
        assertNotNull(metadata1);
        assertEquals(1, metadata1.size());
        assertEquals("my-field-1", metadata1.get(0).getComponentName());

        SignatureMetadata metadata2 = field.get("sig2");
        assertNotNull(metadata2);
        assertEquals(1, metadata2.size());
        assertEquals("my-field-2", metadata2.get(0).getComponentName());
    }
}
