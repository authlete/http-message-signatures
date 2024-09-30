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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;


public class NormalComponentValueProviderTest
{
    @Test
    public void test_obs_fold() throws SignatureException
    {
        // RFC 9421, 2.1. HTTP Fields
        String fieldValueRaw = "Obsolete\r\n    line folding.";
        String fieldValue    = "Obsolete line folding.";

        NormalComponentValueProvider provider = new NormalComponentValueProvider();

        // headers
        Map<String, List<String>> headers = new HashMap<>();
        provider.setHeaders(headers);
        headers.put("X-Obs-Fold-Header", Arrays.asList(fieldValueRaw));

        // "x-obs-fold-header"
        assertEquals(fieldValue, provider.getComponentValue(
                new ComponentIdentifier("x-obs-fold-header")));
    }


    @Test
    public void test_multiple_fields() throws SignatureException
    {
        // RFC 9421, 2.1. HTTP Fields
        List<String> fieldValueRaw = Arrays.asList("max-age=60", "   must-revalidate");
        String       fieldValue    = "max-age=60, must-revalidate";

        NormalComponentValueProvider provider = new NormalComponentValueProvider();

        // headers
        Map<String, List<String>> headers = new HashMap<>();
        provider.setHeaders(headers);
        headers.put("Cache-Control", fieldValueRaw);

        // "cache-control"
        assertEquals(fieldValue, provider.getComponentValue(
                new ComponentIdentifier("cache-control")));
    }


    @Test
    public void test_sf() throws SignatureException
    {
        // RFC 9421, Section 2.1.1. Strict Serialization of HTTP Structured Fields
        String fieldValueRaw = " a=1,    b=2;x=1;y=2,   c=(a   b   c)";
        String fieldValue    = "a=1,    b=2;x=1;y=2,   c=(a   b   c)";
        String fieldValueSf  = "a=1, b=2;x=1;y=2, c=(a b c)";

        NormalComponentValueProvider provider = new NormalComponentValueProvider();

        // headers
        Map<String, List<String>> headers = new HashMap<>();
        provider.setHeaders(headers);
        headers.put("Example-Dict", Arrays.asList(fieldValueRaw));

        // "example-dict"
        assertEquals(fieldValue, provider.getComponentValue(
                new ComponentIdentifier("example-dict")));

        // "example-dict;sf"
        assertEquals(fieldValueSf, provider.getComponentValue(
                new ComponentIdentifier("example-dict",
                        new ComponentIdentifierParameters().setSf(true))));
    }


    @Test
    public void test_key() throws SignatureException
    {
        // RFC 9421, Section 2.1.2. Dictionary Structured Field Members
        String fieldValueRaw = " a=1, b=2;x=1;y=2, c=(a   b    c), d";
        String fieldValueA   = "1";
        String fieldValueB   = "2;x=1;y=2";
        String fieldValueC   = "(a b c)";
        String fieldValueD   = "?1";

        NormalComponentValueProvider provider = new NormalComponentValueProvider();

        // headers
        Map<String, List<String>> headers = new HashMap<>();
        provider.setHeaders(headers);
        headers.put("Example-Dict", Arrays.asList(fieldValueRaw));

        // "example-dict";key="a"
        assertEquals(fieldValueA, provider.getComponentValue(
                new ComponentIdentifier("example-dict",
                        new ComponentIdentifierParameters().setKey("a"))));

        // "example-dict";key="b"
        assertEquals(fieldValueB, provider.getComponentValue(
                new ComponentIdentifier("example-dict",
                        new ComponentIdentifierParameters().setKey("b"))));

        // "example-dict";key="c"
        assertEquals(fieldValueC, provider.getComponentValue(
                new ComponentIdentifier("example-dict",
                        new ComponentIdentifierParameters().setKey("c"))));

        // "example-dict";key="d"
        assertEquals(fieldValueD, provider.getComponentValue(
                new ComponentIdentifier("example-dict",
                        new ComponentIdentifierParameters().setKey("d"))));
    }


    @Test
    public void test_bs_1() throws SignatureException
    {
        // RFC 9421, Section 2.1.3. Binary-Wrapped HTTP Fields
        List<String> fieldValueRaw = Arrays.asList("value, with, lots", "of, commas");
        String       fieldValue    = "value, with, lots, of, commas";
        String       fieldValueBs  = ":dmFsdWUsIHdpdGgsIGxvdHM=:, :b2YsIGNvbW1hcw==:";

        NormalComponentValueProvider provider = new NormalComponentValueProvider();

        // headers
        Map<String, List<String>> headers = new HashMap<>();
        provider.setHeaders(headers);
        headers.put("Example-Header", fieldValueRaw);

        // "example-header"
        assertEquals(fieldValue, provider.getComponentValue(
                new ComponentIdentifier("example-header")));

        // "example-header";bs
        assertEquals(fieldValueBs, provider.getComponentValue(
                new ComponentIdentifier("example-header",
                        new ComponentIdentifierParameters().setBs(true))));
    }


    @Test
    public void test_bs_2() throws SignatureException
    {
        // RFC 9421, Section 2.1.3. Binary-Wrapped HTTP Fields
        List<String> fieldValueRaw = Arrays.asList("value, with, lots, of, commas");
        String       fieldValue    = "value, with, lots, of, commas";
        String       fieldValueBs  = ":dmFsdWUsIHdpdGgsIGxvdHMsIG9mLCBjb21tYXM=:";

        NormalComponentValueProvider provider = new NormalComponentValueProvider();

        // headers
        Map<String, List<String>> headers = new HashMap<>();
        provider.setHeaders(headers);
        headers.put("Example-Header", fieldValueRaw);

        // "example-header"
        assertEquals(fieldValue, provider.getComponentValue(
                new ComponentIdentifier("example-header")));

        // "example-header";bs
        assertEquals(fieldValueBs, provider.getComponentValue(
                new ComponentIdentifier("example-header",
                        new ComponentIdentifierParameters().setBs(true))));
    }


    @Test
    public void test_tr() throws SignatureException
    {
        // RFC 9421, Section 2.1.4. Trailer Fields
        String fieldValueRaw = "Wed, 9 Nov 2022 07:28:00 GMT";
        String fieldValueTr  = "Wed, 9 Nov 2022 07:28:00 GMT";

        NormalComponentValueProvider provider = new NormalComponentValueProvider();

        // trailers
        Map<String, List<String>> trailers = new HashMap<>();
        provider.setTrailers(trailers);
        trailers.put("Expires", Arrays.asList(fieldValueRaw));

        // "expires"
        assertNull(provider.getComponentValue(new ComponentIdentifier("expires")));

        // "expires";tr
        assertEquals(fieldValueTr, provider.getComponentValue(
                new ComponentIdentifier("expires",
                        new ComponentIdentifierParameters().setTr(true))));
    }


    @Test
    public void test_req_tr_combinations() throws SignatureException
    {
        NormalComponentValueProvider provider = new NormalComponentValueProvider();

        // headers
        Map<String, List<String>> headers = new HashMap<>();
        provider.setHeaders(headers);
        headers.put("my-field", Arrays.asList("header"));

        // trailers
        Map<String, List<String>> trailers = new HashMap<>();
        provider.setTrailers(trailers);
        trailers.put("my-field", Arrays.asList("trailer"));

        // headers in request
        Map<String, List<String>> headersInRequest = new HashMap<>();
        provider.setHeadersInRequest(headersInRequest);
        headersInRequest.put("my-field", Arrays.asList("headerInRequest"));

        // trailers in request
        Map<String, List<String>> trailersInRequest = new HashMap<>();
        provider.setTrailersInRequest(trailersInRequest);
        trailersInRequest.put("my-field", Arrays.asList("trailerInRequest"));

        // "my-field"
        assertEquals("header", provider.getComponentValue(
                new ComponentIdentifier("my-field")));

        // "my-field";tr
        assertEquals("trailer", provider.getComponentValue(
                new ComponentIdentifier("my-field",
                        new ComponentIdentifierParameters().setTr(true))));

        // "my-field";req
        assertEquals("headerInRequest", provider.getComponentValue(
                new ComponentIdentifier("my-field",
                        new ComponentIdentifierParameters().setReq(true))));

        // "my-field";req;tr
        assertEquals("trailerInRequest", provider.getComponentValue(
                new ComponentIdentifier("my-field",
                        new ComponentIdentifierParameters().setReq(true).setTr(true))));
    }


    @Test
    public void test_unknown_data_type_sf_list() throws SignatureException
    {
        String fieldName = "my-list-field";

        // "my-list-field";sf
        ComponentIdentifier identifier = new ComponentIdentifier(fieldName,
                new ComponentIdentifierParameters().setSf(true));

        NormalComponentValueProvider provider = new NormalComponentValueProvider();

        // headers
        Map<String, List<String>> headers = new HashMap<>();
        provider.setHeaders(headers);
        headers.put(fieldName, Arrays.asList("a, b"));

        // When the 'sf' flag is set, the data type of the field must be known.
        assertThrows(SignatureException.class, () -> provider.getComponentValue(identifier));

        // Give the provider information about the data type of the field.
        provider.addDataTypeMapping(fieldName, StructuredDataType.LIST);

        assertEquals("a, b", provider.getComponentValue(identifier));
    }


    @Test
    public void test_unknown_data_type_sf_item() throws SignatureException
    {
        String fieldName = "my-item-field";

        // "my-item-field";sf
        ComponentIdentifier identifier = new ComponentIdentifier(fieldName,
                new ComponentIdentifierParameters().setSf(true));

        NormalComponentValueProvider provider = new NormalComponentValueProvider();

        // headers
        Map<String, List<String>> headers = new HashMap<>();
        provider.setHeaders(headers);
        headers.put(fieldName, Arrays.asList("123"));

        // When the 'sf' flag is set, the data type of the field must be known.
        assertThrows(SignatureException.class, () -> provider.getComponentValue(identifier));

        // Give the provider information about the data type of the field.
        provider.addDataTypeMapping(fieldName, StructuredDataType.ITEM);

        assertEquals("123", provider.getComponentValue(identifier));
    }


    @Test
    public void test_unknown_data_type_sf_dictionary() throws SignatureException
    {
        String fieldName = "my-dictionary-field";

        // "my-dictionary-field";sf
        ComponentIdentifier identifier = new ComponentIdentifier(fieldName,
                new ComponentIdentifierParameters().setSf(true));

        NormalComponentValueProvider provider = new NormalComponentValueProvider();

        // headers
        Map<String, List<String>> headers = new HashMap<>();
        provider.setHeaders(headers);
        headers.put(fieldName, Arrays.asList("a=\"b\""));

        // When the 'sf' flag is set, the data type of the field must be known.
        assertThrows(SignatureException.class, () -> provider.getComponentValue(identifier));

        // Give the provider information about the data type of the field.
        provider.addDataTypeMapping(fieldName, StructuredDataType.DICTIONARY);

        assertEquals("a=\"b\"", provider.getComponentValue(identifier));
    }


    @Test
    public void test_unavailable_dictionary() throws SignatureException
    {
        NormalComponentValueProvider provider = new NormalComponentValueProvider();

        // headers
        Map<String, List<String>> headers = new HashMap<>();
        provider.setHeaders(headers);
        headers.put("my-dictionary-field", Arrays.asList("a=\"b\""));

        // When the 'key' flag is set, the specified field must exist.
        assertThrows(SignatureException.class, () -> provider.getComponentValue(
                new ComponentIdentifier("unknown-dictionary-field",
                        new ComponentIdentifierParameters().setKey("a"))));
    }


    @Test
    public void test_unavailable_dictionary_member() throws SignatureException
    {
        NormalComponentValueProvider provider = new NormalComponentValueProvider();

        // headers
        Map<String, List<String>> headers = new HashMap<>();
        provider.setHeaders(headers);
        headers.put("my-dictionary-field", Arrays.asList("a=\"b\""));

        // When the 'key' flag is set, the specified key must exist.
        assertThrows(SignatureException.class, () -> provider.getComponentValue(
                new ComponentIdentifier("my-dictionary-field",
                        new ComponentIdentifierParameters().setKey("nonexistent"))));
    }
}
