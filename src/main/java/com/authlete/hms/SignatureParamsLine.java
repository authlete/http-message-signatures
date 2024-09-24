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
 * A class representing {@code signature-params-line} defined in RFC 9421
 * HTTP Message Signatures, <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.5"
 * >Section 2&#x2E;5&#x2E; Creating the Signature Base</a>.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.5"
 *      >RFC 9421 HTTP Message Signatures, 2.5. Creating the Signature Base</a>
 */
public class SignatureParamsLine
{
    private final SignatureMetadata metadata;


    /**
     * A constructor with signature metadata.
     *
     * @param metadata
     *         Signature metadata.
     *
     * @throws IllegalArgumentException
     *         The signature metadata is null.
     */
    public SignatureParamsLine(SignatureMetadata metadata)
    {
        this.metadata = Arguments.ensureNonNull("metadata", metadata);
    }


    /**
     * Get the string representation of this instance, which is the serialized
     * signature params line returned by the {@link #serialize()} method.
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
     * Serialize the signature params line represented by this instance, and
     * return the resulting string.
     *
     * @return
     *         The serialized signature params line represented by this
     *         instance.
     */
    public String serialize()
    {
        return serializeTo(new StringBuilder()).toString();
    }


    /**
     * Serialize the signature params line represented by this instance, and
     * write the resulting string into the specified string builder.
     *
     * <p>
     * The ABNF for signature params line from RFC 9421 HTTP Message Signatures,
     * <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.5">2.5.
     * Creating the Signature Base</a>:
     * </p>
     *
     * <pre>
     * signature-params-line = DQUOTE "@signature-params" DQUOTE
     *      ":" SP inner-list
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
        //   signature-params-line = DQUOTE "@signature-params" DQUOTE
        //        ":" SP inner-list
        //

        sb.append("\"@signature-params\": ");
        getMetadata().serializeTo(sb);

        return sb;
    }


    /**
     * Get the signature metadata that has been passed to the constructor.
     *
     * @return
     *         The signature metadata.
     */
    public SignatureMetadata getMetadata()
    {
        return metadata;
    }
}
