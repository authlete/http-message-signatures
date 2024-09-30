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


import java.net.URI;
import java.security.SignatureException;
import java.util.List;
import java.util.Map;


/**
 * A utility to provide component values.
 *
 * @since 1.1
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2"
 *      >RFC 9421 HTTP Message Signatures, 2. HTTP Message Components</a>
 */
public class ComponentValueProvider implements SignatureContext
{
    private final NormalComponentValueProvider normalComponentValueProvider;
    private final DerivedComponentValueProvider derivedComponentValueProvider;


    /**
     * The default constructor.
     */
    public ComponentValueProvider()
    {
        normalComponentValueProvider  = new NormalComponentValueProvider();
        derivedComponentValueProvider = new DerivedComponentValueProvider();
    }


    @Override
    public String getComponentValue(
            SignatureMetadata metadata, ComponentIdentifier identifier) throws SignatureException
    {
        return getComponentValue(identifier);
    }


    /**
     * Get the pool of the HTTP header fields.
     *
     * @return
     *         The pool of the HTTP header fields.
     */
    public Map<String, List<String>> getHeaders()
    {
        return getNormalProvider().getHeaders();
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
    public ComponentValueProvider setHeaders(Map<String, List<String>> headers)
    {
        getNormalProvider().setHeaders(headers);

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
        return getNormalProvider().getTrailers();
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
    public ComponentValueProvider setTrailers(Map<String, List<String>> trailers)
    {
        getNormalProvider().setTrailers(trailers);

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
        return getNormalProvider().getHeadersInRequest();
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
    public ComponentValueProvider setHeadersInRequest(Map<String, List<String>> headersInRequest)
    {
        getNormalProvider().setHeadersInRequest(headersInRequest);

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
        return getNormalProvider().getTrailersInRequest();
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
    public ComponentValueProvider setTrailersInRequest(Map<String, List<String>> trailersInRequest)
    {
        getNormalProvider().setTrailersInRequest(trailersInRequest);

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
        return getNormalProvider().getDataTypeMappings();
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
    public ComponentValueProvider addDataTypeMapping(
            String fieldName, StructuredDataType dataType)
    {
        getNormalProvider().addDataTypeMapping(fieldName, dataType);

        return this;
    }


    /**
     * Get the HTTP method of a request message. This is used as the value of
     * the {@code "@method"} derived component.
     *
     * @return
     *         The HTTP method of a request message.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2.1"
     *      >RFC 9421 HTTP Message Signatures, Section 2.2.1. Method</a>
     */
    public String getMethod()
    {
        return getDerivedProvider().getMethod();
    }


    /**
     * Set the HTTP method of a request message. This is used as the value of
     * the {@code "@method"} derived component.
     *
     * @param method
     *         The HTTP method of a request message.
     *
     * @return
     *         {@code this} object.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2.1"
     *      >RFC 9421 HTTP Message Signatures, Section 2.2.1. Method</a>
     */
    public ComponentValueProvider setMethod(String method)
    {
        getDerivedProvider().setMethod(method);

        return this;
    }


    /**
     * Get the target URI of a request message. This is used as the value of
     * the {@code "@target-uri"} derived component.
     *
     * @return
     *         The target URI of a request message.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2.2"
     *      >RFC 9421 HTTP Message Signatures, Section 2.2.2. Target URI</a>
     */
    public String getTargetUri()
    {
        return getDerivedProvider().getTargetUri();
    }


    /**
     * Set the target URI of a request message. This is used as the value of
     * the {@code "@target-uri"} derived component.
     *
     * @param uri
     *         The target URI of a request message.
     *
     * @return
     *         {@code this} object.
     *
     * @throws IllegalArgumentException
     *         The given string violates <a href=
     *         "https://www.rfc-editor.org/rfc/rfc2396.html">RFC 2396 Uniform
     *         Resource Identifiers (URI): Generic Syntax</a>.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2.2"
     *      >RFC 9421 HTTP Message Signatures, Section 2.2.2. Target URI</a>
     */
    public ComponentValueProvider setTargetUri(String uri)
    {
        getDerivedProvider().setTargetUri(uri);

        return this;
    }


    /**
     * Set the target URI of a request message. This is used as the value of
     * the {@code "@target-uri"} derived component.
     *
     * @param uri
     *         The target URI of a request message.
     *
     * @return
     *         {@code this} object.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2.2"
     *      >RFC 9421 HTTP Message Signatures, Section 2.2.2. Target URI</a>
     */
    public ComponentValueProvider setTargetUri(URI uri)
    {
        getDerivedProvider().setTargetUri(uri);

        return this;
    }


    /**
     * Get the authority component of the target URI of the HTTP request
     * message. This is used as the value of the {@code "@authority"} derived
     * component.
     *
     * <p>
     * The value of this derived component is computed based on the target URI
     * set by the {@code setTargetUri} method.
     * </p>
     *
     * @return
     *         The authority component of the target URI of the HTTP request
     *         message.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2.3"
     *      >RFC 9421 HTTP Message Signatures, Section 2.2.3. Authority</a>
     */
    public String getAuthority()
    {
        return getDerivedProvider().getAuthority();
    }


    /**
     * Get the scheme of the target URL of the HTTP request message. This is
     * used as the value of the {@code "@scheme"} derived component.
     *
     * <p>
     * The value of this derived component is computed based on the target URI
     * set by the {@code setTargetUri} method.
     * </p>
     *
     * @return
     *         The scheme of the target URL of the HTTP request message.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2.4"
     *      >RFC 9421 HTTP Message Signatures, Section 2.2.4. Scheme</a>
     */
    public String getScheme()
    {
        return getDerivedProvider().getScheme();
    }


    /**
     * Get the full request target of the HTTP request message. This is used
     * as the value of the {@code "@request-target"} derived component.
     *
     * @return
     *         The full request target of the HTTP request message.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2.5"
     *      >RFC 9421 HTTP Message Signatures, Section 2.2.5. Request Target</a>
     */
    public String getRequestTarget()
    {
        return getDerivedProvider().getRequestTarget();
    }


    /**
     * Set the full request target of the HTTP request message. This is used
     * as the value of the {@code "@request-target"} derived component.
     *
     * @param requestTarget
     *         The full request target of the HTTP request message.
     *
     * @return
     *         {@code this} object.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2.5"
     *      >RFC 9421 HTTP Message Signatures, Section 2.2.5. Request Target</a>
     */
    public ComponentValueProvider setRequestTarget(String requestTarget)
    {
        getDerivedProvider().setRequestTarget(requestTarget);

        return this;
    }


    /**
     * Get the target path of the HTTP request message. This is used as the
     * value of the {@code "@path"} derived component.
     *
     * <p>
     * The value of this derived component is computed based on the target URI
     * set by the {@code setTargetUri} method.
     * </p>
     *
     * @return
     *         The target path of the HTTP request message.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2.6"
     *      >RFC 9421 HTTP Message Signatures, Section 2.2.6. Path</a>
     */
    public String getPath()
    {
        return getDerivedProvider().getPath();
    }


    /**
     * Get the query component of the HTTP request message. This is used as
     * the value of the {@code "@query"} derived component.
     *
     * <p>
     * The value of this derived component is computed based on the target URI
     * set by the {@code setTargetUri} method.
     * </p>
     *
     * @return
     *         The query component of the HTTP request message.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2.7"
     *      >RFC 9421 HTTP Message Signatures, Section 2.2.7. Query</a>
     */
    public String getQuery()
    {
        return getDerivedProvider().getQuery();
    }


    /**
     * Get the value of a query parameter in the HTTP request message. This is
     * used as the value of the <code>"@query-param";name="<i>name</i>"</code>
     * derived component.
     *
     * <p>
     * The value of this derived component is computed based on the target URI
     * set by the {@code setTargetUri} method.
     * </p>
     *
     * @param name
     *         The name of a query parameter.
     *
     * @return
     *         The value of a query parameter in the HTTP request message.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2.8"
     *      >RFC 9421 HTTP Message Signatures, Section 2.2.8. Query Parameters</a>
     */
    public String getQueryParam(String name)
    {
        return getDerivedProvider().getQueryParam(name);
    }


    /**
     * Get the three-digit numeric HTTP status code of a response message.
     * This is used as the {@code "@status"} derived component.
     *
     * @return
     *         The three-digit numeric HTTP status code of a response message.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2.9"
     *      >RFC 9421 HTTP Message Signatures, Section 2.2.9. Status Code</a>
     */
    public String getStatus()
    {
        return getDerivedProvider().getStatus();
    }


    /**
     * Set the three-digit numeric HTTP status code of a response message.
     * This is used as the {@code "@status"} derived component.
     *
     * @param status
     *         The three-digit numeric HTTP status code of a response message.
     *
     * @return
     *         {@code this} object.
     *
     * @throws IllegalArgumentException
     *         The value of {@code status} does not represent a three-digit
     *         positive integer.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2.9"
     *      >RFC 9421 HTTP Message Signatures, Section 2.2.9. Status Code</a>
     */
    public ComponentValueProvider setStatus(String status)
    {
        getDerivedProvider().setStatus(status);

        return this;
    }


    /**
     * Set the three-digit numeric HTTP status code of a response message.
     * This is used as the {@code "@status"} derived component.
     *
     * @param status
     *         The three-digit numeric HTTP status code of a response message.
     *
     * @return
     *         {@code this} object.
     *
     * @throws IllegalArgumentException
     *         The value of {@code status} is not a three-digit positive integer.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2.9"
     *      >RFC 9421 HTTP Message Signatures, Section 2.2.9. Status Code</a>
     */
    public ComponentValueProvider setStatus(int status)
    {
        getDerivedProvider().setStatus(status);

        return this;
    }


    /**
     * Get the value of the component specified by the component identifier.
     *
     * @param identifier
     *         A component identifier.
     *
     * @return
     *         The value of the specified component. If the value is
     *         unavailable, {@code null} is returned.
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

        // If the component identifier indicates that the component is
        // a derived component.
        if (identifier.isDerivedComponent())
        {
            // Derived component
            return getDerivedProvider().getComponentValue(identifier);
        }
        else
        {
            // Normal component
            return getNormalProvider().getComponentValue(identifier);
        }
    }


    /**
     * Get the value of the component specified by the component name.
     *
     * @param componentName
     *         A component name.
     *
     * @return
     *         The value of the specified component. If the value is
     *         unavailable, {@code null} is returned.
     *
     * @throws SignatureException
     */
    public String getComponentValue(String componentName) throws SignatureException
    {
        if (componentName == null)
        {
            return null;
        }

        return getComponentValue(new ComponentIdentifier(componentName));
    }


    private NormalComponentValueProvider getNormalProvider()
    {
        return normalComponentValueProvider;
    }


    private DerivedComponentValueProvider getDerivedProvider()
    {
        return derivedComponentValueProvider;
    }
}
