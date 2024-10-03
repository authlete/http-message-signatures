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
import org.junit.jupiter.api.Test;


public class StructuredFieldTokenTest
{
    private static void testToken(String token)
    {
        StructuredFieldToken sfToken = new StructuredFieldToken(token);

        assertEquals(token, sfToken.getToken());
    }


    @Test
    public void test_asterisk()
    {
        testToken("*");
    }


    @Test
    public void test_not_starting_alpha()
    {
        assertThrows(IllegalArgumentException.class, () -> testToken("123"));
    }


    @Test
    public void test_all_tchars()
    {
        testToken("A!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXZYabcdefghijklmnopqrstuvwxyz");
    }


    @Test
    public void test_colon()
    {
        testToken("a:b");
    }


    @Test
    public void test_slash()
    {
        // RFC 8941 Structured Field Values for HTTP, Section 3.3.4. Tokens
        testToken("foo123/456");
    }


    @Test
    public void test_not_tchar()
    {
        assertThrows(IllegalArgumentException.class, () -> testToken("a\"b"));
    }
}
