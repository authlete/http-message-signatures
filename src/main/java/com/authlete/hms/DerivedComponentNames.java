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


import java.util.LinkedHashSet;
import java.util.Set;


/**
 * Names of derived components.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2"
 *      >RFC 9421 HTTP Message Signatures, Section 2.2. Derived Components</a>
 *
 * @see <a href="https://www.iana.org/assignments/http-message-signature/http-message-signature.xhtml#signature-derived-component-names"
 *      >IANA: HTTP Message Signature / HTTP Signature Derived Component Names</a>
 */
final class DerivedComponentNames
{
    /**
     * {@code "@authority"}: The HTTP authority, or target host.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2.3"
     *      >RFC 9421 HTTP Message Signatures, Section 2.2.3. Authority</a>
     */
    public static final String AUTHORITY = "@authority";


    /**
     * {@code "@method"}: The HTTP request method.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2.1"
     *      >RFC 9421 HTTP Message Signatures, Section 2.2.1. Method</a>
     */
    public static final String METHOD = "@method";


    /**
     * {@code "@path"}: The full path of the request URI.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2.6"
     *      >RFC 9421 HTTP Message Signatures, Section 2.2.6. Path</a>
     */
    public static final String PATH = "@path";


    /**
     * {@code "@query"}: The full query of the request URI.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2.7"
     *      >RFC 9421 HTTP Message Signatures, Section 2.2.7. Query</a>
     */
    public static final String QUERY = "@query";


    /**
     * {@code "@query-param"}: A single named query parameter.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2.8"
     *      >RFC 9421 HTTP Message Signatures, Section 2.2.8. Query Parameters</a>
     */
    public static final String QUERY_PARAM = "@query-param";


    /**
     * {@code "@request-target"}: The request target of the request.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2.5"
     *      >RFC 9421 HTTP Message Signatures, Section 2.2.5. Request Target</a>
     */
    public static final String REQUEST_TARGET = "@request-target";


    /**
     * {@code "@scheme"}: The URI scheme of the request URI.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2.4"
     *      >RFC 9421 HTTP Message Signatures, Section 2.2.4. Scheme</a>
     */
    public static final String SCHEME = "@scheme";


    /**
     * {@code "@signature-params"}: Reserved for signature parameters line in signature base.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.3"
     *      >RFC 9421 HTTP Message Signatures, Section 2.3. Signature Parameters</a>
     */
    public static final String SIGNATURE_PARAMS = "@signature-params";


    /**
     * {@code "@status"}: The status code of the response.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2.9"
     *      >RFC 9421 HTTP Message Signatures, Section 2.2.9. Status Code</a>
     */
    public static final String STATUS = "@status";


    /**
     * {@code "@target-uri"}: The full target URI of the request.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2.2"
     *      >RFC 9421 HTTP Message Signatures, Section 2.2.2. Target URI</a>
     */
    public static final String TARGET_URI = "@target-uri";


    /**
     * Registered derived component names.
     */
    private static final Set<String> REGISTERED_DERIVED_COMPONENTS;


    static
    {
        Set<String> components = new LinkedHashSet<>();

        components.add(AUTHORITY);
        components.add(METHOD);
        components.add(PATH);
        components.add(QUERY);
        components.add(QUERY_PARAM);
        components.add(REQUEST_TARGET);
        components.add(SCHEME);
        components.add(SIGNATURE_PARAMS);
        components.add(STATUS);
        components.add(TARGET_URI);

        REGISTERED_DERIVED_COMPONENTS = components;
    }


    private DerivedComponentNames()
    {
    }


    /**
     * Check whether the passed component name is a derived component name.
     *
     * @param derivedComponentName
     *         The name of a derived component name, such as {@code "@method"}.
     *
     * @return
     *         True if the passed component name is a derived component name.
     *         When null is passed, false is returned.
     */
    public static boolean isRegistered(String derivedComponentName)
    {
        if (derivedComponentName == null)
        {
            return false;
        }

        return REGISTERED_DERIVED_COMPONENTS.contains(derivedComponentName);
    }
}
