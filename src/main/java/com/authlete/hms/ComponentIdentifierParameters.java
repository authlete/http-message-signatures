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


import org.greenbytes.http.sfv.Parameters;


/**
 * HTTP Signature Component Parameters.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.1"
 *      >RFC 9421 HTTP Message Signatures, Section 2.1. HTTP Fields</a>
 *
 * @see <a href="https://www.iana.org/assignments/http-message-signature/http-message-signature.xhtml#component-parameters"
 *      >IANA: HTTP Message Signature / HTTP Signature Component Parameters</a>
 */
public class ComponentIdentifierParameters extends BasicParameters
{
    /**
     * {@code "bs"}: Byte Sequence wrapping indicator.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.1.3"
     *      >RFC 9421 HTTP Message Signatures, Section 2.1.3.
     *       Binary-Wrapped HTTP Fields</a>
     */
    public static final String BS = "bs";


    /**
     * {@code "key"}: Single key value of Dictionary Structured Fields.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.1.2"
     *      >RFC 9421 HTTP Message Signatures, Section 2.1.2.
     *       Dictionary Structured Field Members</a>
     */
    public static final String KEY = "key";


    /**
     * {@code "name"}: Single named query parameter.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2.8"
     *      >RFC 9421 HTTP Message Signatures, Section 2.2.8.
     *       Query Parameters</a>
     */
    public static final String NAME = "name";


    /**
     * {@code "req"}: Related request indicator.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.4"
     *      >RFC 9421 HTTP Message Signatures, Section 2.4.
     *       Signing Request Components in a Response Message</a>
     */
    public static final String REQ = "req";


    /**
     * {@code "sf"}: Strict Structured Field serialization.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.1.1"
     *      >RFC 9421 HTTP Message Signatures, Section 2.1.1.
     *       Strict Serialization of HTTP Structured Fields</a>
     */
    public static final String SF = "sf";


    /**
     * {@code "tr"}: Trailer.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.1.4"
     *      >RFC 9421 HTTP Message Signatures, Section 2.1.4.
     *       Trailer Fields</a>
     */
    public static final String TR = "tr";


    private static final long serialVersionUID = 1L;


    /**
     * The default constructor.
     */
    public ComponentIdentifierParameters()
    {
    }


    ComponentIdentifierParameters(Parameters parameters)
    {
        super(parameters);
    }


    /**
     * Get the flag indicating whether the {@code bs} flag is set.
     *
     * @return
     *         True if the {@code bs} flag is set.
     *
     * @throws IllegalStateException
     *         The parameter value identified by the key {@code "bs"} is not
     *         null, but it is not an instance of {@code Boolean}.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.1.3"
     *      >RFC 9421 HTTP Message Signatures, Section 2.1.3.
     *       Binary-Wrapped HTTP Fields</a>
     */
    public boolean isBs()
    {
        return getAsPrimitiveBoolean(BS);
    }


    /**
     * Set the flag indicating whether the {@code bs} flag is set.
     *
     * @param bs
     *         True to indicate that the {@code bs} flag is set.
     *
     * @return
     *         {@code this} object.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.1.3"
     *      >RFC 9421 HTTP Message Signatures, Section 2.1.3.
     *       Binary-Wrapped HTTP Fields</a>
     */
    public ComponentIdentifierParameters setBs(Boolean bs)
    {
        put(BS, bs);

        return this;
    }


    /**
     * Get the value of the {@code key} parameter.
     *
     * @return
     *         The value of the {@code key} parameter.
     *
     * @throws IllegalStateException
     *         The parameter value identified by the key {@code "key"} is
     *         not null, but it is not an instance of {@code String}.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.1.2"
     *      >RFC 9421 HTTP Message Signatures, Section 2.1.2.
     *       Dictionary Structured Field Members</a>
     */
    public String getKey()
    {
        return getAsString(KEY);
    }


    /**
     * Set the value of the {@code key} parameter.
     *
     * @param key
     *         The value of the {@code key} parameter.
     *
     * @return
     *         {@code this} object.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.1.2"
     *      >RFC 9421 HTTP Message Signatures, Section 2.1.2.
     *       Dictionary Structured Field Members</a>
     */
    public ComponentIdentifierParameters setKey(String key)
    {
        put(KEY, key);

        return this;
    }


    /**
     * Get the value of the {@code name} parameter.
     *
     * @return
     *         The value of the {@code name} parameter.
     *
     * @throws IllegalStateException
     *         The parameter value identified by the key {@code "name"} is
     *         not null, but it is not an instance of {@code String}.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2.8"
     *      >RFC 9421 HTTP Message Signatures, Section 2.2.8.
     *       Query Parameters</a>
     */
    public String getName()
    {
        return getAsString(NAME);
    }


    /**
     * Set the value of the {@code name} parameter.
     *
     * @param name
     *         The value of the {@code name} parameter.
     *
     * @return
     *         {@code this} object.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2.8"
     *      >RFC 9421 HTTP Message Signatures, Section 2.2.8.
     *       Query Parameters</a>
     */
    public ComponentIdentifierParameters setName(String name)
    {
        put(NAME, name);

        return this;
    }


    /**
     * Get the flag indicating whether the {@code req} flag is set.
     *
     * @return
     *         True if the {@code req} flag is set.
     *
     * @throws IllegalStateException
     *         The parameter value identified by the key {@code "req"} is not
     *         null, but it is not an instance of {@code Boolean}.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.4"
     *      >RFC 9421 HTTP Message Signatures, Section 2.4.
     *       Signing Request Components in a Response Message</a>
     */
    public boolean isReq()
    {
        return getAsPrimitiveBoolean(REQ);
    }


    /**
     * Set the flag indicating whether the {@code req} flag is set.
     *
     * @param req
     *         True to indicate that the {@code req} flag is set.
     *
     * @return
     *         {@code this} object.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.4"
     *      >RFC 9421 HTTP Message Signatures, Section 2.4.
     *       Signing Request Components in a Response Message</a>
     */
    public ComponentIdentifierParameters setReq(Boolean req)
    {
        put(REQ, req);

        return this;
    }


    /**
     * Get the flag indicating whether the {@code sf} flag is set.
     *
     * @return
     *         True if the {@code sf} flag is set.
     *
     * @throws IllegalStateException
     *         The parameter value identified by the key {@code "sf"} is not
     *         null, but it is not an instance of {@code Boolean}.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.1.1"
     *      >RFC 9421 HTTP Message Signatures, Section 2.1.1.
     *       Strict Serialization of HTTP Structured Fields</a>
     */
    public boolean isSf()
    {
        return getAsPrimitiveBoolean(SF);
    }


    /**
     * Set the flag indicating whether the {@code sf} flag is set.
     *
     * @param sf
     *         True to indicate that the {@code sf} flag is set.
     *
     * @return
     *         {@code this} object.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.1.1"
     *      >RFC 9421 HTTP Message Signatures, Section 2.1.1.
     *       Strict Serialization of HTTP Structured Fields</a>
     */
    public ComponentIdentifierParameters setSf(Boolean sf)
    {
        put(SF, sf);

        return this;
    }


    /**
     * Get the flag indicating whether the {@code tr} flag is set.
     *
     * @return
     *         True if the {@code tr} flag is set.
     *
     * @throws IllegalStateException
     *         The parameter value identified by the key {@code "tr"} is not
     *         null, but it is not an instance of {@code Boolean}.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.1.1"
     *      >RFC 9421 HTTP Message Signatures, Section 2.1.1.
     *       Strict Serialization of HTTP Structured Fields</a>
     */
    public boolean isTr()
    {
        return getAsPrimitiveBoolean(TR);
    }


    /**
     * Set the flag indicating whether the {@code tr} flag is set.
     *
     * @param tr
     *         True to indicate that the {@code tr} flag is set.
     *
     * @return
     *         {@code this} object.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.1.1"
     *      >RFC 9421 HTTP Message Signatures, Section 2.1.1.
     *       Strict Serialization of HTTP Structured Fields</a>
     */
    public ComponentIdentifierParameters setTr(Boolean tr)
    {
        put(TR, tr);

        return this;
    }
}
