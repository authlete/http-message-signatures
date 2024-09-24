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


import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import java.nio.charset.StandardCharsets;
import java.security.SignatureException;
import java.util.Base64;
import org.junit.jupiter.api.Test;


public class SignatureFieldTest
{
    @Test
    public void test_not_dictionary()
    {
        // A field value that is not a dictionary.
        final String fieldValue = "hello";

        assertThrows(SignatureException.class, () -> SignatureField.parse(fieldValue));
    }


    @Test
    public void test_not_byte_sequence()
    {
        // A field value that is a dictionary, but a member value is not a byte sequence.
        final String fieldValue = "sig=\"hello\"";

        assertThrows(SignatureException.class, () -> SignatureField.parse(fieldValue));
    }


    @Test
    public void test_empty_dictionary() throws Exception
    {
        // A field value that is an empty dictionary.
        final String fieldValue = "";

        SignatureField field = SignatureField.parse(fieldValue);
        assertNotNull(field);
        assertEquals(0, field.size());
    }


    @Test
    public void test_byte_sequence() throws Exception
    {
        byte[] bytes  = "Hello, world!".getBytes(StandardCharsets.UTF_8);
        String base64 = Base64.getEncoder().encodeToString(bytes); // SGVsbG8sIHdvcmxkIQ==
        String fieldValue = String.format("sig=:%s:", base64);

        SignatureField field = SignatureField.parse(fieldValue);
        assertNotNull(field);
        assertEquals(1, field.size());

        byte[] actualBytes = field.get("sig");
        assertNotNull(actualBytes);

        assertArrayEquals(bytes, actualBytes);
    }
}
