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


import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;


/**
 * A utility to provide values of derived components.
 *
 * @since 1.1
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2"
 *      >RFC 9421 HTTP Message Signatures, Section 2.2. Derived Components</a>
 */
class DerivedComponentValueProvider
{
    // The pattern for the HTTP status code.
    private static final Pattern STATUS_CODE_PATTERN = Pattern.compile("^[1-9][0-9][0-9]$");


    private String method;
    private String targetUri;
    private String requestTarget;
    private String status;
    private URI parsedTargetUri;
    private String parsedAuthority;
    private String parsedScheme;
    private String parsedPath;
    private String parsedQuery;
    private Map<String, String> parsedQueryParams;


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
        return method;
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
    public DerivedComponentValueProvider setMethod(String method)
    {
        this.method = method;

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
        return targetUri;
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
    public DerivedComponentValueProvider setTargetUri(String uri)
    {
        this.targetUri = uri;

        if (uri != null)
        {
            parsedTargetUri = URI.create(uri);
        }
        else
        {
            parsedTargetUri = null;
        }

        return setupByTargetUri(parsedTargetUri);
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
    public DerivedComponentValueProvider setTargetUri(URI uri)
    {
        this.parsedTargetUri = uri;

        if (uri != null)
        {
            targetUri = uri.toASCIIString();
        }
        else
        {
            targetUri = null;
        }

        return setupByTargetUri(parsedTargetUri);
    }


    private DerivedComponentValueProvider setupByTargetUri(URI uri)
    {
        parsedAuthority   = parseAuthority(uri);
        parsedScheme      = parseScheme(uri);
        parsedPath        = parsePath(uri);
        parsedQuery       = parseQuery(uri);
        parsedQueryParams = parseQueryParams(uri);

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
        return parsedAuthority;
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
        return parsedScheme;
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
        return requestTarget;
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
    public DerivedComponentValueProvider setRequestTarget(String requestTarget)
    {
        this.requestTarget = requestTarget;

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
        return parsedPath;
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
        return parsedQuery;
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
        if (name == null)
        {
            return null;
        }

        if (parsedQueryParams == null)
        {
            return null;
        }

        return parsedQueryParams.get(name);
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
        return status;
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
    public DerivedComponentValueProvider setStatus(String status)
    {
        if (status != null)
        {
            // If the passed string does not match the status code pattern.
            if (!STATUS_CODE_PATTERN.matcher(status).matches())
            {
                throw new IllegalArgumentException(
                        "The value of the 'status' argument must represent " +
                        "a three-digit positive integer.");
            }
        }

        this.status = status;

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
    public DerivedComponentValueProvider setStatus(int status)
    {
        if (status < 100 || 1000 <= status)
        {
            throw new IllegalArgumentException(
                    "The value of the 'status' argument must be a three-digit " +
                    "positive integer.");
        }

        this.status = String.valueOf(status);

        return this;
    }


    /**
     * Get the value of the component specified by the component identifier.
     *
     * @param identifier
     *         A component identifier.
     *
     * @return
     *         The value of the specified component. If the value is unavailable,
     *         {@code null} is returned.
     */
    public String getComponentValue(ComponentIdentifier identifier)
    {
        if (identifier == null)
        {
            return null;
        }

        // The component name.
        String componentName = identifier.getComponentName();

        switch (componentName)
        {
            // @method
            case DerivedComponentNames.METHOD:
                return getMethod();

            // @target-uri
            case DerivedComponentNames.TARGET_URI:
                return getTargetUri();

            // @authority
            case DerivedComponentNames.AUTHORITY:
                return getAuthority();

            // @scheme
            case DerivedComponentNames.SCHEME:
                return getScheme();

            // @request-target
            case DerivedComponentNames.REQUEST_TARGET:
                return getRequestTarget();

            // @path
            case DerivedComponentNames.PATH:
                return getPath();

            // @query
            case DerivedComponentNames.QUERY:
                return getQuery();

            // @query-param
            case DerivedComponentNames.QUERY_PARAM:
                return getQueryParam(identifier.getParameters().getName());

            // @status
            case DerivedComponentNames.STATUS:
                return getStatus();

            default:
                return null;
        }
    }


    private static String parseAuthority(URI uri)
    {
        // RFC 9421
        // 2.2.3. Authority
        //
        //   The component value MUST be normalized according to the rules
        //   provided in [HTTP], Section 4.2.3. Namely, the hostname is
        //   normalized to lowercase, and the default port is omitted.
        //

        if (uri == null)
        {
            return null;
        }

        String scheme   = uri.getScheme();
        String userinfo = uri.getUserInfo();
        String host     = uri.getHost();
        int    port     = uri.getPort();

        if (host == null)
        {
            host = "";
        }
        else
        {
            host = encode(host.toLowerCase());
        }

        boolean portOmitted = (port == -1)
                || ("http" .equalsIgnoreCase(scheme) && port == 80)
                || ("https".equalsIgnoreCase(scheme) && port == 443);

        StringBuilder sb = new StringBuilder();

        if (userinfo != null)
        {
            sb.append(userinfo);
            sb.append('@');
        }

        sb.append(host);

        if (!portOmitted)
        {
            sb.append(':');
            sb.append(port);
        }

        return sb.toString();
    }


    private static String parseScheme(URI uri)
    {
        if (uri == null)
        {
            return null;
        }

        String scheme = uri.getScheme();

        if (scheme == null)
        {
            return null;
        }

        // RFC 9421
        // 2.2.4. Scheme
        //
        //   The @scheme derived component refers to the scheme of the target
        //   URL of the HTTP request message. The component value is the scheme
        //   as a lowercase string as defined in [HTTP], Section 4.2. While the
        //   scheme itself is case insensitive, it MUST be normalized to
        //   lowercase for inclusion in the signature base.
        //

        return scheme.toLowerCase();
    }


    private static String parsePath(URI uri)
    {
        // RFC 9421
        // 2.2.6. Path
        //
        //   Namely, an empty path string is normalized as a single slash (/) character.
        //

        if (uri == null)
        {
            return "/";
        }

        String path = uri.getRawPath();

        if (path == null || path.isEmpty())
        {
            return "/";
        }

        return path;
    }


    private static String parseQuery(URI uri)
    {
        // RFC 9421
        // 2.2.7. Query
        //
        //   Just like including an empty path component, the signer can
        //   include an empty query component to indicate that this component
        //   is not used in the message. If the query string is absent from
        //   the request message, the component value is the leading ?
        //   character alone:
        //
        //     ?
        //

        if (uri == null)
        {
            return "?";
        }

        String rawQuery = uri.getRawQuery();

        if (rawQuery == null)
        {
            return "?";
        }

        return "?" + rawQuery;
    }


    private static Map<String, String> parseQueryParams(URI uri)
    {
        // Parse the query part as a list of name=value pairs.
        List<List<String>> queryParams = parseQueryParamsAsList(uri);

        if (queryParams == null)
        {
            return null;
        }

        Map<String, String> map = new LinkedHashMap<>();

        // For each name-value pair.
        for (List<String> pair : queryParams)
        {
            // Add the name-value pair. During this process, any entry
            // with a duplicate name will be overwritten.
            map.put(pair.get(0), pair.get(1));
        }

        return map;
    }


    private static List<List<String>> parseQueryParamsAsList(URI uri)
    {
        if (uri == null)
        {
            return null;
        }

        String queryParams = uri.getRawQuery();

        if (queryParams == null)
        {
            return null;
        }

        List<List<String>> list = new ArrayList<>();

        // Split the query part into name-value pairs.
        String[] nameValues = queryParams.split("&");

        // For each name-value pair.
        for (int i = 0; i < nameValues.length; i++)
        {
            // Split the pair into the name and the value.
            String[] nameValue = nameValues[i].split("=", 2);

            switch (nameValue.length)
            {
                case 2:
                    // Add the name-value pair.
                    list.add(Arrays.asList(encode(nameValue[0]), encode(nameValue[1])));
                    break;

                case 1:
                    // Add the name-value pair with an empty string as the value.
                    list.add(Arrays.asList(encode(nameValue[0]), ""));
                    break;

                default:
                    break;
            }
        }

        return list;
    }


    private static String encode(String input)
    {
        try
        {
            String decoded = URLDecoder.decode(input,   "UTF-8");
            String encoded = URLEncoder.encode(decoded, "UTF-8").replaceAll("[+]", "%20");

            return encoded;
        }
        catch (UnsupportedEncodingException cause)
        {
            // This never happens.
            return input;
        }
    }
}
