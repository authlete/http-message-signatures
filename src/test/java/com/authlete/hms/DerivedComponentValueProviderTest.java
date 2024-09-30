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
import java.net.URI;
import java.security.SignatureException;
import org.junit.jupiter.api.Test;


public class DerivedComponentValueProviderTest
{
    @Test
    public void test_authority_1() throws SignatureException
    {
        URI uri = URI.create("https://WWW.EXAMPLE.COM");

        DerivedComponentValueProvider provider = new DerivedComponentValueProvider();
        provider.setTargetUri(uri);

        // The host part must be lowercase.
        assertEquals("www.example.com",
                provider.getComponentValue(new ComponentIdentifier("@authority")));
    }


    @Test
    public void test_authority_2() throws SignatureException
    {
        URI uri = URI.create("https://WWW.EXAMPLE.COM:443");

        DerivedComponentValueProvider provider = new DerivedComponentValueProvider();
        provider.setTargetUri(uri);

        // The default port number must be omitted.
        assertEquals("www.example.com",
                provider.getComponentValue(new ComponentIdentifier("@authority")));
    }


    @Test
    public void test_authority_3() throws SignatureException
    {
        URI uri = URI.create("https://WWW.EXAMPLE.COM:8443");

        DerivedComponentValueProvider provider = new DerivedComponentValueProvider();
        provider.setTargetUri(uri);

        // The non-default port number must appear in the value.
        assertEquals("www.example.com:8443",
                provider.getComponentValue(new ComponentIdentifier("@authority")));
    }


    @Test
    public void test_authority_4() throws SignatureException
    {
        URI uri = URI.create("http://WWW.EXAMPLE.COM:80");

        DerivedComponentValueProvider provider = new DerivedComponentValueProvider();
        provider.setTargetUri(uri);

        // The default port number must be omitted.
        assertEquals("www.example.com",
                provider.getComponentValue(new ComponentIdentifier("@authority")));
    }


    @Test
    public void test_authority_5() throws SignatureException
    {
        URI uri = URI.create("http://WWW.EXAMPLE.COM:8080");

        DerivedComponentValueProvider provider = new DerivedComponentValueProvider();
        provider.setTargetUri(uri);

        // The non-default port number must appear in the value.
        assertEquals("www.example.com:8080",
                provider.getComponentValue(new ComponentIdentifier("@authority")));
    }


    @Test
    public void test_authority_6() throws SignatureException
    {
        URI uri = URI.create("https://UserInfo@WWW.EXAMPLE.COM");

        DerivedComponentValueProvider provider = new DerivedComponentValueProvider();
        provider.setTargetUri(uri);

        // The host part must be lowercase.
        assertEquals("UserInfo@www.example.com",
                provider.getComponentValue(new ComponentIdentifier("@authority")));
    }


    @Test
    public void test_scheme() throws SignatureException
    {
        URI uri = URI.create("HTTP://example.com");

        DerivedComponentValueProvider provider = new DerivedComponentValueProvider();
        provider.setTargetUri(uri);

        // The scheme part must be lowercase.
        assertEquals("http", provider.getComponentValue(new ComponentIdentifier("@scheme")));
    }


    @Test
    public void test_path_empty() throws SignatureException
    {
        URI uri = URI.create("https://example.com");

        DerivedComponentValueProvider provider = new DerivedComponentValueProvider();
        provider.setTargetUri(uri);

        // "@path"
        assertEquals("/", provider.getComponentValue(new ComponentIdentifier("@path")));
    }


    @Test
    public void test_path_root() throws SignatureException
    {
        URI uri = URI.create("https://example.com/");

        DerivedComponentValueProvider provider = new DerivedComponentValueProvider();
        provider.setTargetUri(uri);

        // "@path"
        assertEquals("/", provider.getComponentValue(new ComponentIdentifier("@path")));
    }


    @Test
    public void test_query_1() throws SignatureException
    {
        // RFC 9421, Section 2.2.7. Query
        URI uri = URI.create("https://www.example.com/path?param=value&foo=bar&baz=bat%2Dman");

        DerivedComponentValueProvider provider = new DerivedComponentValueProvider();
        provider.setTargetUri(uri);

        // "@query"
        assertEquals("?param=value&foo=bar&baz=bat%2Dman",
                provider.getComponentValue(new ComponentIdentifier("@query")));
    }


    @Test
    public void test_query_2() throws SignatureException
    {
        // RFC 9421, Section 2.2.7. Query
        URI uri = URI.create("https://www.example.com/path?queryString");

        DerivedComponentValueProvider provider = new DerivedComponentValueProvider();
        provider.setTargetUri(uri);

        // "@query"
        assertEquals("?queryString",
                provider.getComponentValue(new ComponentIdentifier("@query")));
    }


    @Test
    public void test_query_3() throws SignatureException
    {
        // RFC 9421, Section 2.2.7. Query
        URI uri = URI.create("https://www.example.com/path");

        DerivedComponentValueProvider provider = new DerivedComponentValueProvider();
        provider.setTargetUri(uri);

        // "@query"
        assertEquals("?",
                provider.getComponentValue(new ComponentIdentifier("@query")));
    }


    @Test
    public void test_query_4() throws SignatureException
    {
        // RFC 9421, Section 2.2.7. Query
        URI uri = URI.create("https://www.example.com/path?");

        DerivedComponentValueProvider provider = new DerivedComponentValueProvider();
        provider.setTargetUri(uri);

        // "@query"
        assertEquals("?",
                provider.getComponentValue(new ComponentIdentifier("@query")));
    }


    @Test
    public void test_query_5() throws SignatureException
    {
        // RFC 9421, Section 2.2.7. Query
        URI uri = URI.create("https://www.example.com/path?");

        DerivedComponentValueProvider provider = new DerivedComponentValueProvider();
        provider.setTargetUri(uri);

        // "@query"
        assertEquals("?",
                provider.getComponentValue(new ComponentIdentifier("@query")));
    }


    @Test
    public void test_query_param_1() throws SignatureException
    {
        // RFC 9421, Section 2.2.8. Query Parameters
        URI uri = URI.create("https://www.example.com/path?param=value&foo=bar&baz=batman&qux=");

        DerivedComponentValueProvider provider = new DerivedComponentValueProvider();
        provider.setTargetUri(uri);

        // "@query-param";name="baz"
        assertEquals("batman", provider.getComponentValue(
                new ComponentIdentifier("@query-param",
                        new ComponentIdentifierParameters().setName("baz"))));

        // "@query-param";name="qux"
        assertEquals("", provider.getComponentValue(
                new ComponentIdentifier("@query-param",
                        new ComponentIdentifierParameters().setName("qux"))));

        // "@query-param";name="param"
        assertEquals("value", provider.getComponentValue(
                new ComponentIdentifier("@query-param",
                        new ComponentIdentifierParameters().setName("param"))));
    }


    @Test
    public void test_query_param_2() throws SignatureException
    {
        // RFC 9421, Section 2.2.8. Query Parameters
        URI uri = URI.create(
                "https://www.example.com/parameters?var=this%20is%20a%20big%0Amultiline%20value&" +
                "bar=with+plus+whitespace&fa%C3%A7ade%22%3A%20=something");

        DerivedComponentValueProvider provider = new DerivedComponentValueProvider();
        provider.setTargetUri(uri);

        // "@query-param";name="var"
        assertEquals("this%20is%20a%20big%0Amultiline%20value", provider.getComponentValue(
                new ComponentIdentifier("@query-param",
                        new ComponentIdentifierParameters().setName("var"))));

        // "@query-param";name="bar"
        assertEquals("with%20plus%20whitespace", provider.getComponentValue(
                new ComponentIdentifier("@query-param",
                        new ComponentIdentifierParameters().setName("bar"))));

        // "@query-param";name="fa%C3%A7ade%22%3A%20"
        assertEquals("something", provider.getComponentValue(
                new ComponentIdentifier("@query-param",
                        new ComponentIdentifierParameters().setName("fa%C3%A7ade%22%3A%20"))));
    }


    @Test
    public void test_status_string_valid()
    {
        DerivedComponentValueProvider provider = new DerivedComponentValueProvider();
        provider.setStatus("200");

        // "@status"
        assertEquals("200", provider.getComponentValue(new ComponentIdentifier("@status")));
    }


    @Test
    public void test_status_string_invalid()
    {
        DerivedComponentValueProvider provider = new DerivedComponentValueProvider();

        // The string must represent a three-digit positive integer.
        assertThrows(IllegalArgumentException.class, () -> provider.setStatus("20"));
    }


    @Test
    public void test_status_integer_valid()
    {
        DerivedComponentValueProvider provider = new DerivedComponentValueProvider();
        provider.setStatus(200);

        // "@status"
        assertEquals("200", provider.getComponentValue(new ComponentIdentifier("@status")));
    }


    @Test
    public void test_status_integer_invalid()
    {
        DerivedComponentValueProvider provider = new DerivedComponentValueProvider();

        // The integer must be a three-digit positive integer.
        assertThrows(IllegalArgumentException.class, () -> provider.setStatus(20));
    }
}
