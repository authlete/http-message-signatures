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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import org.junit.jupiter.api.Test;


public class ComponentIdentifierTest
{
    @Test
    public void test_equality_same_name()
    {
        ComponentIdentifier id1 = new ComponentIdentifier("my-field");
        ComponentIdentifier id2 = new ComponentIdentifier("my-field");

        assertEquals(id1, id2);
    }


    @Test
    public void test_equality_different_name()
    {
        ComponentIdentifier id1 = new ComponentIdentifier("my-field-1");
        ComponentIdentifier id2 = new ComponentIdentifier("my-field-2");

        assertNotEquals(id1, id2);
    }


    @Test
    public void test_equality_different_parameter()
    {
        ComponentIdentifier id1 = new ComponentIdentifier("my-field");
        ComponentIdentifier id2 = new ComponentIdentifier("my-field", new ComponentIdentifierParameters().setSf(true));

        assertNotEquals(id1, id2);
    }


    @Test
    public void test_equality_same_name_and_parameters()
    {
        ComponentIdentifier id1 = new ComponentIdentifier("my-field",
                new ComponentIdentifierParameters().setSf(true).setReq(true));
        ComponentIdentifier id2 = new ComponentIdentifier("my-field",
                new ComponentIdentifierParameters().setSf(true).setReq(true));

        assertEquals(id1, id2);
    }


    @Test
    public void test_equality_same_name_and_parameters_in_different_order()
    {
        ComponentIdentifier id1 = new ComponentIdentifier("my-field",
                new ComponentIdentifierParameters().setSf(true).setReq(true));
        ComponentIdentifier id2 = new ComponentIdentifier("my-field",
                new ComponentIdentifierParameters().setReq(true).setSf(true));

        assertEquals("\"my-field\";sf;req", id1.serialize());
        assertEquals("\"my-field\";req;sf", id2.serialize());

        // RFC 9421 HTTP Message Signatures
        // 2. HTTP Message Components
        //
        //   Multiple component identifiers having the same component name MAY
        //   be included if they have parameters that make them distinct, such
        //   as `"foo";bar` and `"foo";baz`. The order of parameters MUST be
        //   preserved when processing a component identifier (such as when
        //   parsing during verification), but the order of parameters is not
        //   significant when comparing two component identifiers for equality
        //   checks. That is to say, `"foo";bar;baz` cannot be in the same
        //   message as `"foo";baz;bar`, since these two component identifiers
        //   are equivalent, but a system processing one form is not allowed to
        //   transform it into the other form.
        //
        assertEquals(id1, id2);
    }


    @Test
    public void test_equality_same_key()
    {
        ComponentIdentifier id1 = new ComponentIdentifier("my-field",
                new ComponentIdentifierParameters().setKey("my_key"));
        ComponentIdentifier id2 = new ComponentIdentifier("my-field",
                new ComponentIdentifierParameters().setKey("my_key"));

        assertEquals(id1, id2);
    }


    @Test
    public void test_equality_different_key()
    {
        ComponentIdentifier id1 = new ComponentIdentifier("my-field",
                new ComponentIdentifierParameters().setKey("my_key_1"));
        ComponentIdentifier id2 = new ComponentIdentifier("my-field",
                new ComponentIdentifierParameters().setKey("my_key_2"));

        assertEquals("\"my-field\";key=\"my_key_1\"", id1.serialize());
        assertEquals("\"my-field\";key=\"my_key_2\"", id2.serialize());

        assertNotEquals(id1, id2);
    }
}
