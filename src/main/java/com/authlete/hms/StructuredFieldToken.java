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


import java.util.Objects;
import java.util.regex.Pattern;


/**
 * A class representing {@code sf-token} defined in RFC 8941 Structured Field
 * Values for HTTP, Section 3&#x2E;3&#x2E;4&#x2E; Tokens.
 *
 * <pre>
 * sf-token = ( ALPHA / "*" ) *( tchar / ":" / "/" )
 * </pre>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc8941.html#section-3.3.4"
 *      >RFC 8941 Structured Field Values for HTTP, Section 3.3.4. Tokens</a>
 */
public class StructuredFieldToken
{
    /**
     * The pattern for sf-token.
     *
     * <pre>
     * sf-token = ( ALPHA / "*" ) *( tchar / ":" / "/" )
     * </pre>
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc8941.html#section-3.3.4"
     *      >RFC 8941 Structured Field Values for HTTP, Section 3.3.4. Tokens</a>
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7230.html#section-3.2.6"
     *      >RFC 7230 Hypertext Transfer Protocol (HTTP/1.1): Message Syntax
     *       and Routing, Section 3.2.6. Field Value Components</a>
     */
    private static final Pattern PATTERN_SF_TOKEN =
            Pattern.compile("^[A-Za-z*][!#$%&'*+.^_`|~0-9A-Za-z:/-]*$");


    private final String token;


    /**
     * A constructor with a string that conforms to the sf-token format.
     *
     * @param token
     *         A string that conforms to the sf-token format as specified in
     *         RFC 8941 Structured Field Values for HTTP, Section 3.3.4.
     *
     * @throws IllegalArgumentException
     *         The token is null or does not conform to the sf-token format as
     *         specified in RFC 8941 Structured Field Values for HTTP, Section
     *         3.3.4. Tokens.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc8941.html#section-3.3.4"
     *      >RFC 8941 Structured Field Values for HTTP, Section 3.3.4. Tokens</a>
     */
    public StructuredFieldToken(String token)
    {
        validateToken("token", token);

        this.token = token;
    }


    @Override
    public boolean equals(Object obj)
    {
        if (obj == null)
        {
            return false;
        }

        if (this == obj)
        {
            return true;
        }

        if (getClass() != obj.getClass())
        {
            return false;
        }

        StructuredFieldToken that = (StructuredFieldToken)obj;

        return Objects.equals(token, that.token);
    }


    @Override
    public int hashCode()
    {
        return Objects.hash(token);
    }


    @Override
    public String toString()
    {
        return token;
    }


    /**
     * Get the token passed to the constructor.
     *
     * @return
     *         The token.
     */
    public String getToken()
    {
        return token;
    }


    /**
     * Validate an sf-token.
     */
    private static void validateToken(String argumentName, String token)
    {
        Arguments.ensureNonNull(argumentName, token);

        if (!PATTERN_SF_TOKEN.matcher(token).matches())
        {
            throw new IllegalArgumentException(String.format(
                    "The value of the '%s' argument does not conform to the sf-token format " +
                    "as specified in RFC 8941, Section 3.3.4.", argumentName));
        }
    }
}
