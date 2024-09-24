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


/**
 * A class representing {@code signature-base-line} defined in RFC 9421
 * HTTP Message Signatures, <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.5"
 * >Section 2&#x2E;5&#x2E; Creating the Signature Base</a>.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.5"
 *      >RFC 9421 HTTP Message Signatures, 2.5. Creating the Signature Base</a>
 */
public class SignatureBaseLine
{
    private final ComponentIdentifier componentIdentifier;
    private final String componentValue;


    /**
     * A constructor with a component identifier and a component value.
     *
     * @param identifier
     *         A component identifier.
     *
     * @param value
     *         A component value. This should not be null when the identifier
     *         refers to a derived component.
     *
     * @throws IllegalArgumentException
     *         The identifier is null.
     */
    public SignatureBaseLine(ComponentIdentifier identifier, String value)
    {
        this.componentIdentifier = Arguments.ensureNonNull("identifier", identifier);
        this.componentValue      = value;
    }


    /**
     * Get the string representation of this instance, which is the serialized
     * signature base line returned by the {@link #serialize()} method.
     *
     * @return
     *         The string representation of this instance.
     */
    @Override
    public String toString()
    {
        return serialize();
    }


    /**
     * Serialize the signature base line represented by this instance, and
     * return the resulting string.
     *
     * @return
     *         The serialized signature base line represented by this
     *         instance.
     */
    public String serialize()
    {
        return serializeTo(new StringBuilder()).toString();
    }


    /**
     * Serialize the signature base line represented by this instance, and write
     * the resulting string into the specified string builder.
     *
     * <p>
     * The ABNF for signature base line from RFC 9421 HTTP Message Signatures,
     * <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.5">2.5.
     * Creating the Signature Base</a>:
     * </p>
     *
     * <pre>
     * signature-base-line = component-identifier ":" SP
     *     ( derived-component-value / *field-content )
     *     ; no obs-fold nor obs-text
     * </pre>
     *
     * @param sb
     *         A string builder into which the resulting string is written.
     *
     * @return
     *         The same string builder that was passed as the argument.
     */
    public StringBuilder serializeTo(StringBuilder sb)
    {
        // RFC 9421 HTTP Message Signatures
        // 2.5. Creating the Signature Base
        //
        //   signature-base-line = component-identifier ":" SP
        //       ( derived-component-value / *field-content )
        //       ; no obs-fold nor obs-text
        //

        // Append "component-identifier: ".
        getComponentIdentifier().serializeTo(sb);
        sb.append(": ");

        // The component value.
        String value = getComponentValue();

        // If the component value is available.
        if (value != null)
        {
            // Append the component value.
            sb.append(value);
        }

        return sb;
    }


    /**
     * Get the component identifier.
     *
     * @return
     *         The component identifier.
     */
    public ComponentIdentifier getComponentIdentifier()
    {
        return componentIdentifier;
    }


    /**
     * Get the component value.
     *
     * @return
     *         The component value.
     */
    public String getComponentValue()
    {
        return componentValue;
    }
}
