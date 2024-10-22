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
 * Structured data types.
 *
 * @since 1.1
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc8941.html#section-3"
 *      >RFC 8941 Structured Field Values for HTTP, Section 3. Structured Data Types</a>
 *
 * @see <a href="https://www.iana.org/assignments/http-fields/http-fields.xhtml"
 *      >IANA Hypertext Transfer Protocol (HTTP) Field Name Registry</a>
 */
public enum StructuredDataType
{
    /**
     * List.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc8941.html#section-3.1"
     *      >RFC 8941 Structured Field Values for HTTP, Section 3.1. Lists</a>
     */
    LIST,


    /**
     * Dictionary.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc8941.html#section-3.2"
     *      >RFC 8941 Structured Field Values for HTTP, Section 3.2. Dictionaries</a>
     */
    DICTIONARY,


    /**
     * Item.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc8941.html#section-3.3"
     *      >RFC 8941 Structured Field Values for HTTP, Section 3.3. Items</a>
     */
    ITEM,
    ;


    /**
     * Get the structured data type of the specified field.
     *
     * @param fieldName
     *         A field name.
     *
     * @return
     *         The data type of the specified field.
     *         If unknown, null is returned.
     */
    public static StructuredDataType getByFieldName(String fieldName)
    {
        if (fieldName == null)
        {
            return null;
        }

        // Convert the given value to lowercase.
        String lowercase = fieldName.toLowerCase();

        // The IANA Hypertext Transfer Protocol (HTTP) Field Name Registry
        // includes information about the structured type of certain HTTP fields.

        switch (lowercase)
        {
            // Standard HTTP fields.

            case "accept-ch":
                return LIST;

            case "cache-status":
                return LIST;

            case "cdn-cache-control":
                return DICTIONARY;

            // Client-Cert, defined in RFC 9440: Client-Cert HTTP Field.
            case "client-cert":
                return ITEM;

            // Client-Cert-Chain, defined in RFC 9440: Client-Cert HTTP Field.
            case "client-cert-chain":
                return LIST;

            // Content-Digest, defined in RFC 9530: Digest Fields.
            case "content-digest":
                return DICTIONARY;

            case "cross-origin-embedder-policy":
                return ITEM;

            case "cross-origin-embedder-policy-report-only":
                return ITEM;

            case "cross-origin-opener-policy":
                return ITEM;

            case "cross-origin-opener-policy-report-only":
                return ITEM;

            case "origin-agent-cluster":
                return ITEM;

            case "priority":
                return DICTIONARY;

            case "proxy-status":
                return LIST;

            // Repr-Digest, defined in RFC 9530: Digest Fields.
            case "repr-digest":
                return DICTIONARY;

            // Signature, defined in RFC 9421: HTTP Message Signatures.
            case "signature":
                return DICTIONARY;

            // Signature-Input, defined in RFC 9421: HTTP Message Signatures.
            case "signature-input":
                return DICTIONARY;

            // Want-Content-Digest, defined in RFC 9530: Digest Fields.
            case "want-content-digest":
                return DICTIONARY;

            // Want-Repr-Digest, defined in RFC 9530: Digest Fields.
            case "want-repr-digest":
                return DICTIONARY;

            // HTTP fields used in RFC 8941 used for examples.

            case "example-boolean":
                return ITEM;

            case "example-bytesequence":
                return ITEM;

            case "example-decimal":
                return ITEM;

            case "example-dict":
                return DICTIONARY;

            case "example-integer":
                return ITEM;

            case "example-list":
                return LIST;

            case "example-string":
                return ITEM;

            case "example-token":
                return ITEM;

            // Unknown

            default:
                return null;
        }
    }
}
