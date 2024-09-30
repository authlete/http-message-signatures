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


import java.nio.charset.StandardCharsets;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.greenbytes.http.sfv.ByteSequenceItem;
import org.greenbytes.http.sfv.Dictionary;
import org.greenbytes.http.sfv.ListElement;
import org.greenbytes.http.sfv.Parser;


/**
 * A utility for constructing component values of normal components
 * (non-derived components).
 *
 * @since 1.1
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.1"
 *      >RFC 9421 HTTP Message Signatures, Section 2.1. HTTP Fields</a>
 */
class NormalComponentValueProvider
{
    // The regular expression representing "obs-fold", which is defined
    // as follows in RFC 9112 HTTP/1.1, Section 5.2. Obsolete Line Folding.
    //
    //   obs-fold = OWS CRLF RWS
    //            ; obsolete line folding
    //
    private static final String OBS_FOLD_REGEX = "[\\s\\t]*\\r\\n[\\s\\t]+";


    private Map<String, List<String>> headers;
    private Map<String, List<String>> trailers;
    private Map<String, List<String>> headersInRequest;
    private Map<String, List<String>> trailersInRequest;
    private Map<String, StructuredDataType> dataTypeMappings;


    /**
     * The default constructor.
     */
    public NormalComponentValueProvider()
    {
        dataTypeMappings = new HashMap<>();
    }


    /**
     * Get the pool of the HTTP header fields.
     *
     * @return
     *         The pool of the HTTP header fields.
     */
    public Map<String, List<String>> getHeaders()
    {
        return headers;
    }


    /**
     * Set the pool of the HTTP header fields.
     *
     * @param headers
     *         The pool of the HTTP header fields.
     *
     * @return
     *         {@code this} object.
     */
    public NormalComponentValueProvider setHeaders(Map<String, List<String>> headers)
    {
        this.headers = headers;

        return this;
    }


    /**
     * Get the pool of the HTTP trailer fields.
     *
     * @return
     *         The pool of the HTTP trailer fields.
     */
    public Map<String, List<String>> getTrailers()
    {
        return trailers;
    }


    /**
     * Set the pool of the HTTP trailer fields.
     *
     * @param trailers
     *         The pool of the HTTP trailer fields.
     *
     * @return
     *         {@code this} object.
     */
    public NormalComponentValueProvider setTrailers(Map<String, List<String>> trailers)
    {
        this.trailers = trailers;

        return this;
    }


    /**
     * Get the pool of the HTTP header fields in the request.
     *
     * @return
     *         The pool of the HTTP header fields in the request.
     */
    public Map<String, List<String>> getHeadersInRequest()
    {
        return headersInRequest;
    }


    /**
     * Set the pool of the HTTP header fields in the request.
     *
     * @param headersInRequest
     *         The pool of the HTTP header fields in the request.
     *
     * @return
     *         {@code this} object.
     */
    public NormalComponentValueProvider setHeadersInRequest(Map<String, List<String>> headersInRequest)
    {
        this.headersInRequest = headersInRequest;

        return this;
    }


    /**
     * Get the pool of the HTTP trailer fields in the request.
     *
     * @return
     *         The pool of the HTTP trailer fields in the request.
     */
    public Map<String, List<String>> getTrailersInRequest()
    {
        return trailersInRequest;
    }


    /**
     * Set the pool of the HTTP trailer fields in the request.
     *
     * @param trailersInRequest
     *         The pool of the HTTP trailer fields in the request.
     *
     * @return
     *         {@code this} object.
     */
    public NormalComponentValueProvider setTrailersInRequest(Map<String, List<String>> trailersInRequest)
    {
        this.trailersInRequest = trailersInRequest;

        return this;
    }


    /**
     * Get the {@code Map} instance that manages additional mappings between
     * field names and their structured data types. The mappings managed by
     * the instance are referenced when processing the {@code sf} flag
     * (<a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.1.1"
     * >RFC 9421, Section 2.1.1. Strict Serialization of HTTP Structured
     * Fields</a>).
     *
     * <p>
     * This class implementation refers to the default mappings maintained
     * within the {@link StructuredDataType} class when the mapping for a
     * field name, specified as a component name with the {@code sf} flag,
     * is not found in the additional mappings.
     * </p>
     *
     * @return
     *         The {@code Map} instance that manages additional mappings.
     */
    public Map<String, StructuredDataType> getDataTypeMappings()
    {
        return dataTypeMappings;
    }


    /**
     * Add an additional mapping between a field name and its structured data
     * type. This mapping is referenced when processing the {@code sf} flag
     * (<a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.1.1"
     * >RFC 9421, Section 2.1.1. Strict Serialization of HTTP Structured
     * Fields</a>).
     *
     * <p>
     * This class implementation refers to the default mappings maintained
     * within the {@link StructuredDataType} class when the mapping for a
     * field name, specified as a component name with the {@code sf} flag,
     * is not found in the additional mappings.
     * </p>
     *
     * @param fieldName
     *         A field name. The given value is converted to lowercase before
     *         being added.
     *
     * @param dataType
     *         A data type.
     *
     * @return
     *         {@code this} object.
     */
    public NormalComponentValueProvider addDataTypeMapping(
            String fieldName, StructuredDataType dataType)
    {
        // Convert the given field name into lowercase, then register it
        // to the additional mappings.
        getDataTypeMappings().put(fieldName.toLowerCase(), dataType);

        return this;
    }


    /**
     * Get the value of the component specified by the component identifier.
     *
     * @param identifier
     *         A component identifier.
     *
     * @return
     *         The value of the component specified by the component identifier.
     *         If the value is unavailable, {@code null} is returned.
     *
     * @throws SignatureException
     *         (1)
     *         The component identifier includes the {@code key} parameter,
     *         but the HTTP field value is either missing, cannot be parsed
     *         as a dictionary, or contains no entry with the specified key.
     *         (2)
     *         The component identifier includes the {@code sf} parameter,
     *         but the data type of the HTTP field is either unknown or its
     *         value cannot be parsed as the expected data type.
     */
    public String getComponentValue(ComponentIdentifier identifier) throws SignatureException
    {
        if (identifier == null)
        {
            return null;
        }

        // The component name.
        String componentName = identifier.getComponentName();

        // The parameters.
        ComponentIdentifierParameters parameters = identifier.getParameters();

        // Determine the source of component values.
        Map<String, List<String>> source = determineSource(parameters);

        // RFC 9421
        // 2.1. HTTP Fields
        //
        //   bs
        //     A Boolean flag indicating that individual field values are
        //     encoded using Byte Sequence data structures before being
        //     combined into the component value (Section 2.1.3).
        //
        if (parameters.isBs())
        {
            return extractFieldValue(source, componentName, /*bs*/true);
        }

        // RFC 9421
        // 2.1. HTTP Fields
        //
        //   key
        //     A String parameter used to select a single member value from
        //     a Dictionary Structured Field (Section 2.1.2).
        //
        if (parameters.getKey() != null)
        {
            return extractDictionaryMemberValue(
                    source, componentName, parameters.getKey());
        }

        // RFC 9421
        // 2.1. HTTP Fields
        //
        //   sf
        //     A Boolean flag indicating that the component value is serialized
        //     using strict encoding of the Structured Field value (Section 2.1.1).
        //
        if (parameters.isSf())
        {
            return extractStructuredFieldValue(
                    source, componentName, getDataTypeMappings());
        }

        return extractFieldValue(source, componentName);
    }


    private Map<String, List<String>> determineSource(
            ComponentIdentifierParameters parameters)
    {
        // RFC 9421 HTTP Message Signatures
        // 2.1. HTTP Fields
        //
        //   req
        //     A Boolean flag for signed responses indicating that the
        //     component value is derived from the request that triggered
        //     this response message and not from the response message
        //     directly. Note that this parameter can also be applied to
        //     any derived component identifiers that target the request
        //     (Section 2.4).
        //
        boolean req = parameters.isReq();

        // RFC 9421 HTTP Message Signatures
        // 2.1. HTTP Fields
        //
        //   tr
        //     A Boolean flag indicating that the field value is taken
        //     from the trailers of the message as defined in Section 6.5
        //     of [HTTP]. If this flag is absent, the field value is taken
        //     from the header fields of the message as defined in Section
        //     6.3 of [HTTP] (Section 2.1.4).
        //
        boolean tr = parameters.isTr();

        // Determine the source based on the 'req' and 'tr' flags.
        if (req)
        {
            if (tr)
            {
                // Component values are sourced from the pool of trailers
                // in the request.
                return getTrailersInRequest();
            }
            else
            {
                // Component values are sourced from the pool of headers
                // in the request.
                return getHeadersInRequest();
            }
        }
        else
        {
            if (tr)
            {
                // Component values are sourced from the pool of trailers.
                return getTrailers();
            }
            else
            {
                // Component values are sourced from the pool of headers.
                return getHeaders();
            }
        }
    }


    private static String extractFieldValue(
            Map<String, List<String>> source, String fieldName)
    {
        return extractFieldValue(source, fieldName, /*bs*/false);
    }


    private static String extractFieldValue(
            Map<String, List<String>> source, String fieldName, boolean bs)
    {
        // Values of the HTTP field.
        List<String> fieldValues = extractFieldValues(source, fieldName, bs);

        if (fieldValues == null)
        {
            return null;
        }

        // RFC 9421 HTTP Message Signatures
        // 2.1. HTTP Fields
        //
        //   Unless overridden by additional parameters and rules, HTTP field
        //   values MUST be combined into a single value as defined in Section
        //   5.2 of [HTTP] to create the component value. Specifically, HTTP
        //   fields sent as multiple fields MUST be combined by concatenating
        //   the values using a single comma and a single space as a separator
        //   ("," + " ").
        //

        // RFC 9110 HTTP Semantics
        // 5.2. Field Lines and Combined Field Value
        //
        //   When a field name is repeated within a section, its combined field
        //   value consists of the list of corresponding field line values
        //   within that section, concatenated in order, with each field line
        //   value separated by a comma.
        //

        // RFC 9110 HTTP Semantics
        // 5.3. Field Order
        //
        //   A recipient MAY combine multiple field lines within a field section
        //   that have the same field name into one field line, without changing
        //   the semantics of the message, by appending each subsequent field
        //   line value to the initial field line value in order, separated by a
        //   comma (",") and optional whitespace (OWS, defined in Section 5.6.3).
        //   For consistency, use comma SP.
        //

        // Concatenate multiple values into one using ", " as delimiters.
        return fieldValues.stream().collect(Collectors.joining(", "));
    }


    private static List<String> extractFieldValues(
            Map<String, List<String>> source, String fieldName, boolean bs)
    {
        if (source == null)
        {
            // Values of the HTTP field are unavailable.
            return null;
        }

        List<String> values = null;

        // For each HTTP field.
        for (Map.Entry<String, List<String>> entry : source.entrySet())
        {
            // The name of the HTTP field.
            String name = entry.getKey();

            // If the HTTP field name matches the expected one.
            if (name.equalsIgnoreCase(fieldName))
            {
                values = entry.getValue();
                break;
            }
        }

        // If the HTTP field with the name was not found.
        if (values == null)
        {
            // Values of the HTTP field are unavailable.
            return null;
        }

        // Canonicalized field values.
        List<String> fieldValues = new ArrayList<>();

        for (String value : values)
        {
            // Canonicalize the value.
            value = canonicalizeFieldValue(value);

            if (value == null || value.isEmpty())
            {
                continue;
            }

            // RFC 9421
            // 2.1. HTTP Fields
            //
            //   bs
            //     A Boolean flag indicating that individual field values are
            //     encoded using Byte Sequence data structures before being
            //     combined into the component value (Section 2.1.3).
            //
            if (bs)
            {
                // Convert the value into a serialized byte sequence.
                value = convertToByteSequence(value);
            }

            fieldValues.add(value);
        }

        if (fieldValues.size() == 0)
        {
            // Values of the HTTP field are unavailable.
            return null;
        }

        return fieldValues;
    }


    private static String canonicalizeFieldValue(String value)
    {
        if (value == null)
        {
            return null;
        }

        // RFC 9421 HTTP Message Signatures
        // 2.1. HTTP Fields
        //
        //   2. Strip leading and trailing whitespace from each item in the
        //      list. Note that since HTTP field values are not allowed to
        //      contain leading and trailing whitespace, this would be a
        //      no-op in a compliant implementation.
        //

        // Remove all leading and trailing spaces.
        value = value.trim();

        // RFC 9421 HTTP Message Signatures
        // 2.1. HTTP Fields
        //
        //   3. Remove any obsolete line folding within the line, and replace
        //      it with a single space (" "), as discussed in Section 5.2 of
        //      [HTTP/1.1]. Note that this behavior is specific to HTTP/1.1
        //      and does not apply to other versions of the HTTP specification,
        //      which do not allow internal line folding.
        //

        // RFC 9112 HTTP/1.1
        // 5.2. Obsolete Line Folding
        //
        //   obs-fold = OWS CRLF RWS
        //            ; obsolete line folding
        //

        // RFC 9110 HTTP Semantics
        // 5.6.3. Whitespace
        //
        //   OWS = *( SP / HTAB )
        //       ; optional whitespace
        //   RWS = 1*( SP / HTAB )
        //       ; required whitespace
        //

        // Replace all obs-fold into a single space.
        value = value.replaceAll(OBS_FOLD_REGEX, " ");

        return value;
    }


    private static String convertToByteSequence(String input)
    {
        // Convert the String instance into a byte array.
        byte[] inputBytes = input.getBytes(StandardCharsets.UTF_8);

        // Serialize the byte array into a byte sequence as defined in RFC 8941.
        return ByteSequenceItem.valueOf(inputBytes).serialize();
    }


    private static String extractDictionaryMemberValue(
            Map<String, List<String>> source, String fieldName, String key) throws SignatureException
    {
        // RFC 9421 HTTP Message Signatures
        // 2.1.2. Dictionary Structured Field Members
        //
        //   If a Dictionary key is named as a covered component but it does
        //   not occur in the Dictionary, this MUST cause an error in the
        //   signature base generation.
        //

        // Extract the field value.
        String fieldValue = extractFieldValue(source, fieldName);

        // If the value of the field is unavailable.
        if (fieldValue == null)
        {
            throw new SignatureException(String.format(
                    "The '%s' HTTP field is part of the signature base for an " +
                    "HTTP message signature, but it is missing.", fieldName));
        }

        Dictionary dictionary;

        try
        {
            // Parse the field value as dictionary.
            dictionary = Parser.parseDictionary(fieldValue);
        }
        catch (Exception cause)
        {
            throw new SignatureException(String.format(
                    "The '%s' HTTP field is part of the signature base for an " +
                    "HTTP message signature, and its value is expected to be " +
                    "a dictionary. However, the value could not be parsed as " +
                    "a dictionary.", fieldValue));
        }

        // Extract the value of the member with the key.
        ListElement<?> element = dictionary.get().get(key);

        // If the value of the member is unavailable.
        if (element == null)
        {
            throw new SignatureException(String.format(
                    "The dictionary entry with the key '%s' in the '%s' HTTP " +
                    "field is part of the signature base for an HTTP message " +
                    "signature, but no such entry exists.", key, fieldName));
        }

        // The serialized form of the element.
        return element.serialize();
    }


    private static String extractStructuredFieldValue(
            Map<String, List<String>> source, String fieldName,
            Map<String, StructuredDataType> mappings) throws SignatureException
    {
        // The data type of the field.
        StructuredDataType type = mappings.get(fieldName);

        if (type == null)
        {
            // Search the default mappings for the specified field name.
            type = StructuredDataType.getByFieldName(fieldName);
        }

        // If the data type is unknown.
        if (type == null)
        {
            // RFC 9421 HTTP Message Signatures
            // 2.1.1. Strict Serialization of HTTP Structured Fields.
            //
            //   If the application does not know the type of the field or does
            //   not know how to serialize the type of the field, the use of
            //   this flag will produce an error.
            //
            throw new SignatureException(String.format(
                    "The '%s' HTTP field is specified as part of the signature " +
                    "base for an HTTP message signature with the 'sf' flag, but " +
                    "its data type is unknown.", fieldName));
        }

        // Extract the field value.
        String fieldValue = extractFieldValue(source, fieldName);

        // If the field value is unavailable.
        if (fieldValue == null)
        {
            return null;
        }

        switch (type)
        {
            case LIST:
                return extractListFieldValue(fieldName, fieldValue);

            case DICTIONARY:
                return extractDictionaryFieldValue(fieldName, fieldValue);

            case ITEM:
                return extractItemFieldValue(fieldName, fieldValue);

            default:
                // This never happens.
                return null;
        }
    }


    private static String extractListFieldValue(
            String fieldName, String fieldValue) throws SignatureException
    {
        try
        {
            // Parse the field value as List.
            return Parser.parseList(fieldValue).serialize();
        }
        catch (RuntimeException cause)
        {
            throw new SignatureException(String.format(
                    "The '%s' HTTP field is specified as part of the signature " +
                    "base for an HTTP message signature with the 'sf' flag, but " +
                    "its value could not be parsed as List.", fieldName));
        }
    }


    private static String extractDictionaryFieldValue(
            String fieldName, String fieldValue) throws SignatureException
    {
        try
        {
            // Parse the field value as Dictionary.
            return Parser.parseDictionary(fieldValue).serialize();
        }
        catch (RuntimeException cause)
        {
            throw new SignatureException(String.format(
                    "The '%s' HTTP field is specified as part of the signature " +
                    "base for an HTTP message signature with the 'sf' flag, but " +
                    "its value could not be parsed as Dictionary.", fieldName));
        }
    }


    private static String extractItemFieldValue(
            String fieldName, String fieldValue) throws SignatureException
    {
        try
        {
            // Parse the field value as Item.
            return Parser.parseItem(fieldValue).serialize();
        }
        catch (RuntimeException cause)
        {
            throw new SignatureException(String.format(
                    "The '%s' HTTP field is specified as part of the signature " +
                    "base for an HTTP message signature with the 'sf' flag, but " +
                    "its value could not be parsed as Item.", fieldName));
        }
    }
}
