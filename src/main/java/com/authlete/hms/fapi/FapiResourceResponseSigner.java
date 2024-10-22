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
package com.authlete.hms.fapi;


import java.net.URI;
import java.security.SignatureException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import com.authlete.hms.ComponentIdentifier;
import com.authlete.hms.ComponentIdentifierParameters;
import com.authlete.hms.SignatureBase;
import com.authlete.hms.SignatureBaseLine;
import com.authlete.hms.SignatureInfo;
import com.authlete.hms.SignatureMetadata;
import com.authlete.hms.SignatureMetadataParameters;
import com.authlete.hms.SignatureParamsLine;
import com.authlete.hms.impl.JoseHttpSigner;
import com.nimbusds.jose.jwk.JWK;


/**
 * A utility for signing a resource response in accordance with
 * the FAPI 2&#x2E;0 Message Signing requirements.
 *
 * <p><b>Sample Code</b></p>
 *
 * <pre>
 * <span style="color: green;">// Create a signer.</span>
 * FapiResourceResponseSigner signer = new FapiResourceResponseSigner()
 *         .setMethod(<span style="color: darkred;">"GET"</span>)
 *         .setTargetUri(URI.create(<span style="color: darkred;"
 *          >"https://example.com/path?key=value"</span>))
 *         .setStatus(200)
 *         .setResponseContentDigest(
 *             <span style="color: darkred;">"sha-256=:RBNvo1WzZ4oRRq0W9+hknpT7<!--
 *             -->T8If536DEMBg9hyq/4o=:"</span>
 *         )
 *         .setCreated(Instant.now())
 *         .setSigningKey(JWK.parse(SIGNING_KEY))
 *         ;
 *
 * <span style="color: green;">// Sign the HTTP response.</span>
 * SignatureInfo info = signer.sign();
 *
 * <span style="color: green;">// Signature HTTP field.</span>
 * String signatureFieldValue = String.format(<span style="color: darkred;"
 *     >"sig=%s"</span>, info.getSerializedSignature());
 *     <span style="color: green;">// e.g. sig=:OXJQdFoyuYsbMfJHl/+bT8WwKv49Pt6<!--
 *     -->fiYz/0bTQSAynaJH+HELTqZVzzm3/pyk/MPrjQ9iPmPxz8rgkkRe5kQ==:</span>
 * responseBuilder.header(<span style="color: darkred;">"Signature"</span>, signatureFieldValue);
 *
 * <span style="color: green;">// Signature-Input HTTP field.</span>
 * String signatureInputFieldValue = String.format(<span style="color: darkred;"
 *     >"sig=%s"</span>, info.getSerializedSignatureMetadata());
 *     <span style="color: green;">// e.g. sig=("@method";req "@target-uri";req <!--
 *     -->"@status" "content-digest");created=1729584639;keyid="snIZq-_NvzkKV-Id<!--
 *     -->iM348BCz_RKdwmufnrPubsKKyio";tag="fapi-2-response"</span>
 * responseBuilder.header(<span style="color: darkred;">"Signature-Input"</span>, signatureInputFieldValue);
 * </pre>
 *
 * @since 1.3
 *
 * @see <a href="https://openid.bitbucket.io/fapi/fapi-2_0-message-signing.html"
 *      >FAPI 2.0 Message Signing</a>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html"
 *      >RFC 9421: HTTP Message Signatures</a>
 */
public class FapiResourceResponseSigner
{
    /**
     * The component identifier, {@code "@method";req}.
     */
    private static final ComponentIdentifier COMP_ID_METHOD_REQ =
            new ComponentIdentifier("@method",
                    new ComponentIdentifierParameters().setReq(true));


    /**
     * The component identifier, {@code "@target-uri";req}.
     */
    private static final ComponentIdentifier COMP_ID_TARGET_URI_REQ =
            new ComponentIdentifier("@target-uri",
                    new ComponentIdentifierParameters().setReq(true));


    /**
     * The component identifier, {@code "content-digest";req}.
     */
    private static final ComponentIdentifier COMP_ID_CONTENT_DIGEST_REQ =
            new ComponentIdentifier("content-digest",
                    new ComponentIdentifierParameters().setReq(true));


    /**
     * The component identifier, {@code "@status"}.
     */
    private static final ComponentIdentifier COMP_ID_STATUS =
            new ComponentIdentifier("@status");


    /**
     * The component identifier, {@code "content-digest"}.
     */
    private static final ComponentIdentifier COMP_ID_CONTENT_DIGEST =
            new ComponentIdentifier("content-digest");


    /**
     * The value of the {@code tag} parameter of the signature metadata.
     */
    private static final String TAG_VALUE_FAPI_2_RESPONSE = "fapi-2-response";


    /**
     * The HTTP method of the request.
     */
    private String method;


    /**
     * The target URI (the original request URL) of the HTTP request.
     */
    private URI targetUri;


    /**
     * The value of the {@code Content-Digest} HTTP field of the request.
     */
    private String requestContentDigest;


    /**
     * The value of the three-digit numeric HTTP status code of the response.
     */
    private int status;


    /**
     * The value of the {@code Content-Digest} HTTP field of the response.
     */
    private String responseContentDigest;


    /**
     * The value of the {@code created} parameter of the signature metadata.
     */
    private Long created;


    /**
     * The private key for signing the signature base.
     */
    private JWK signingKey;


    /**
     * Get the HTTP method of the request. This is used as the value of the
     * {@code "@method";req} derived component.
     *
     * @return
     *         The HTTP method of the request.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2.1"
     *      >RFC 9421: HTTP Message Signatures, Section 2.2.1. Method</a>
     */
    public String getMethod()
    {
        return method;
    }


    /**
     * Set the HTTP method of the request. This is used as the value of the
     * {@code "@method";req} derived component.
     *
     * <p>
     * This must be set before calling the {@link #sign()} method.
     * </p>
     *
     * @param method
     *         The HTTP method of the request.
     *
     * @return
     *         {@code this} object.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2.1"
     *      >RFC 9421: HTTP Message Signatures, Section 2.2.1. Method</a>
     */
    public FapiResourceResponseSigner setMethod(String method)
    {
        this.method = method;

        return this;
    }


    /**
     * Get the target URI (the original request URL) of the HTTP request.
     * This is used as the value of the {@code "@target-uri";req} derived
     * component.
     *
     * @return
     *         The target URI (the original request URL) of the HTTP request.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2.2"
     *      >RFC 9421: HTTP Message Signatures, Section 2.2.2. Target URI</a>
     */
    public URI getTargetUri()
    {
        return targetUri;
    }


    /**
     * Set the target URI (the original request URL) of the HTTP request.
     * This is used as the value of the {@code "@target-uri";req} derived
     * component.
     *
     * <p>
     * This must be set before calling the {@link #sign()} method.
     * </p>
     *
     * @param targetUri
     *         The target URI (the original request URL) of the HTTP request.
     *
     * @return
     *         {@code this} object.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2.2"
     *      >RFC 9421: HTTP Message Signatures, Section 2.2.2. Target URI</a>
     */
    public FapiResourceResponseSigner setTargetUri(URI targetUri)
    {
        this.targetUri = targetUri;

        return this;
    }


    /**
     * Get the value of the {@code Content-Digest} HTTP field of the request.
     * This is used as the value of the {@code "content-digest";req} component.
     *
     * @return
     *         The value of the {@code Content-Digest} HTTP field of the request.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9530.html"
     *      >RFC 9530: Digest Fields</a>
     */
    public String getRequestContentDigest()
    {
        return requestContentDigest;
    }


    /**
     * Set the value of the {@code Content-Digest} HTTP field of the request.
     * This is used as the value of the {@code "content-digest";req} component.
     *
     * <p>
     * If the HTTP request contains a request body, this must be set before
     * calling the {@link #sign()} method.
     * </p>
     *
     * @param contentDigest
     *         The value of the {@code Content-Digest} HTTP field of the request.
     *
     * @return
     *         {@code this} object.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9530.html"
     *      >RFC 9530: Digest Fields</a>
     */
    public FapiResourceResponseSigner setRequestContentDigest(String contentDigest)
    {
        this.requestContentDigest = contentDigest;

        return this;
    }


    /**
     * Get the status code of the HTTP response. This is used as the value of
     * the {@code "@status"} derived component.
     *
     * @return
     *         The status code of the HTTP response.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2.9"
     *      >RFC 9421: HTTP Message Signatures, Section 2.2.9. Status Code</a>
     */
    public int getStatus()
    {
        return status;
    }


    /**
     * Set the status code of the HTTP response. This is used as the value of
     * the {@code "@status"} derived component.
     *
     * <p>
     * This must be set before calling the {@link #sign()} method.
     * </p>
     *
     * @param status
     *         The status code of the HTTP response.
     *
     * @return
     *         {@code this} object.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2.9"
     *      >RFC 9421: HTTP Message Signatures, Section 2.2.9. Status Code</a>
     */
    public FapiResourceResponseSigner setStatus(int status)
    {
        this.status = status;

        return this;
    }


    /**
     * Get the value of the {@code Content-Digest} HTTP field of the response.
     * This is used as the value of the {@code "content-digest"} component.
     *
     * @return
     *         The value of the {@code Content-Digest} HTTP field of the response.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9530.html"
     *      >RFC 9530: Digest Fields</a>
     */
    public String getResponseContentDigest()
    {
        return responseContentDigest;
    }


    /**
     * Set the value of the {@code Content-Digest} HTTP field of the response.
     * This is used as the value of the {@code "content-digest"} component.
     *
     * <p>
     * If the HTTP response contains a request body, this must be set before
     * calling the {@link #sign()} method.
     * </p>
     *
     * @param contentDigest
     *         The value of the {@code Content-Digest} HTTP field of the response.
     *
     * @return
     *         {@code this} object.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9530.html"
     *      >RFC 9530: Digest Fields</a>
     */
    public FapiResourceResponseSigner setResponseContentDigest(String contentDigest)
    {
        this.responseContentDigest = contentDigest;

        return this;
    }


    /**
     * Get the creation time of the signature, represented as seconds since
     * the Unix epoch. This is used as the value of the {@code created}
     * parameter of the signature metadata.
     *
     * @return
     *         The creation time of the signature.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.3"
     *      >RFC 9421: HTTP Message Signatures, Section 2.3. Signature Parameters</a>
     */
    public Long getCreated()
    {
        return created;
    }


    /**
     * Set the creation time of the signature, represented as seconds since
     * the Unix epoch. This is used as the value of the {@code created}
     * parameter of the signature metadata.
     *
     * <p>
     * If this is not set before calling the {@link #sign()} method, the
     * current time at which the method will be executed is used as the
     * signature creation time.
     * </p>
     *
     * @param created
     *         The creation time of the signature.
     *
     * @return
     *         {@code this} object.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.3"
     *      >RFC 9421: HTTP Message Signatures, Section 2.3. Signature Parameters</a>
     */
    public FapiResourceResponseSigner setCreated(Long created)
    {
        this.created = created;

        return this;
    }


    /**
     * Set the creation time of the signature. This is used as the value of
     * the {@code created} parameter of the signature metadata.
     *
     * <p>
     * If this is not set before calling the {@link #sign()} method, the
     * current time at which the method will be executed is used as the
     * signature creation time.
     * </p>
     *
     * @param created
     *         The creation time of the signature.
     *
     * @return
     *         {@code this} object.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.3"
     *      >RFC 9421: HTTP Message Signatures, Section 2.3. Signature Parameters</a>
     */
    public FapiResourceResponseSigner setCreated(Instant created)
    {
        Long timestamp = null;

        if (created != null)
        {
            // Seconds since the Unix epoch.
            timestamp = created.getEpochSecond();
        }

        return setCreated(timestamp);
    }


    private Long getCreatedOrNow()
    {
        // The value of the 'created' parameter held by this instance.
        Long timestamp = getCreated();

        // If the 'created' parameter has not been set.
        if (timestamp == null)
        {
            // The current time (= seconds since the Unix epoch).
            timestamp = Instant.now().getEpochSecond();
        }

        return timestamp;
    }


    /**
     * Get the private key for signing the HTTP response.
     *
     * @return
     *         The private key for signing the HTTP response.
     */
    public JWK getSigningKey()
    {
        return signingKey;
    }


    /**
     * Set the private key for signing the HTTP response.
     *
     * @param signingKey
     *         The private key for signing the HTTP response.
     *
     * @return
     *         {@code this} object.
     */
    public FapiResourceResponseSigner setSigningKey(JWK signingKey)
    {
        this.signingKey = signingKey;

        return this;
    }


    /**
     * Execute HTTP message signing.
     *
     * @return
     *         Information about the signing operation, including the
     *         computed signature base and the generated signature.
     *
     * @throws IllegalStateException
     *         Mandatory input parameters, such as {@code method},
     *         {@code targetUri}, {@code status}, and {@code signingKey},
     *         are not set.
     *
     * @throws SignatureException
     *         Signing failed.
     */
    public SignatureInfo sign() throws IllegalStateException, SignatureException
    {
        // Check if input parameters have been properly set.
        checkParameters();

        // Create the signature base.
        SignatureBase base = createSignatureBase();

        // Sign the signature base with the specified signing key.
        byte[] signature = sign(base);

        // Collect information about the signing operation.
        SignatureInfo info = new SignatureInfo()
                .setSigningKey(getSigningKey())
                .setSignatureBase(base)
                .setSignature(signature)
                ;

        return info;
    }


    private void checkParameters()
    {
        // method
        checkParameter("The HTTP method of the request",
                getMethod(), "setMethod(String)");

        // targetUri
        checkParameter("The target URI (the original request URL) of the HTTP request",
                getTargetUri(), "setTargetUri(URI)");

        // status
        checkParameterStatus(getStatus());

        // signingKey
        checkParameter("A private key for signing the HTTP response",
                getSigningKey(), "setSigningKey(JWK)");
    }


    private static void checkParameter(
            String parameterName, Object parameterValue, String setterMethod)
    {
        // If the parameter value is not null.
        if (parameterValue != null)
        {
            // OK.
            return;
        }

        throw new IllegalStateException(String.format(
                "%s must be set using the %s method before calling the sign() method.",
                parameterName, setterMethod));
    }


    private static void checkParameterStatus(int status)
    {
        // If the status is a three-digit, positive integer.
        if (100 <= status && status < 1000)
        {
            // OK.
            return;
        }

        // The status code value is outside the valid range.

        // If it appears that neither of the setStatus methods has been called.
        if (status == 0)
        {
            throw new IllegalStateException(
                    "The status code of the response must be set using the " +
                    "setStatus(int) or setStatus(Instant) method before calling "+
                    "the sign() method.");
        }

        throw new IllegalStateException(
                "The status code of the response must be a three-digit, positive integer.");
    }


    private SignatureBase createSignatureBase()
    {
        // RFC 9421 HTTP Message Signatures
        // 2.5 Creating the Signature Base
        //
        //   signature-base = *( signature-base-line LF ) signature-params-line
        //

        // signature-base-line's
        List<SignatureBaseLine> baseLines = createSignatureBaseLines();

        // signature-params-line
        SignatureParamsLine paramsLine = createSignatureParamsLine();

        // signature-base
        return new SignatureBase(baseLines, paramsLine);
    }


    private List<SignatureBaseLine> createSignatureBaseLines()
    {
        List<SignatureBaseLine> baseLines = new ArrayList<>();

        // FAPI 2.0 Message Signing
        //
        //   shall cryptographically link the response to the request
        //   by including the request method, request target-uri and
        //   (if applicable) the request content-digest in the response
        //   signature input by means of the req boolean flag defined
        //   in Section 2.4 of [RFC9421];
        //

        // "@method";req
        addBaseLine(baseLines, COMP_ID_METHOD_REQ, getMethod());

        // "@target-uri";req
        addBaseLine(baseLines, COMP_ID_TARGET_URI_REQ, getTargetUri().toASCIIString());

        if (getRequestContentDigest() != null)
        {
            // "content-digest";req
            addBaseLine(baseLines, COMP_ID_CONTENT_DIGEST_REQ, getRequestContentDigest());
        }

        // FAPI 2.0 Message Signing
        //
        //   shall include @status (the status code of the response) in
        //   the signature;
        //

        // "@status"
        addBaseLine(baseLines, COMP_ID_STATUS, String.valueOf(getStatus()));

        // FAPI 2.0 Message Signing
        //
        //   when the response contains a response body, shall include the
        //   content-digest header as defined in [RFC9530] in the response,
        //   and shall include that header in the signature, and should use
        //   content-encoding agnostic digest methods (such as sha-256).
        //

        if (getResponseContentDigest() != null)
        {
            // "content-digest"
            addBaseLine(baseLines, COMP_ID_CONTENT_DIGEST, getResponseContentDigest());
        }

        // The signature baselines.
        return baseLines;
    }


    private static void addBaseLine(
            List<SignatureBaseLine> baseLines, ComponentIdentifier identifier, String value)
    {
        baseLines.add(new SignatureBaseLine(identifier, value));
    }


    private SignatureParamsLine createSignatureParamsLine()
    {
        //-----------------------------------------------------------------
        // Component identifiers included in the signature params line.
        //-----------------------------------------------------------------
        List<ComponentIdentifier> identifiers = new ArrayList<>();

        // "@method";req
        identifiers.add(COMP_ID_METHOD_REQ);

        // "@target-uri";req
        identifiers.add(COMP_ID_TARGET_URI_REQ);

        if (getRequestContentDigest() != null)
        {
            // "content-digest";req
            identifiers.add(COMP_ID_CONTENT_DIGEST_REQ);
        }

        // "@status"
        identifiers.add(COMP_ID_STATUS);

        if (getResponseContentDigest() != null)
        {
            // "content-digest"
            identifiers.add(COMP_ID_CONTENT_DIGEST);
        }

        //-----------------------------------------------------------------
        // Parameters included in the signature params line.
        //-----------------------------------------------------------------
        SignatureMetadataParameters parameters = new SignatureMetadataParameters();

        // FAPI 2.0 Message Signing
        //
        //   shall include the created parameter (the signature creation time)
        //   in the signature;
        //

        // created
        parameters.setCreated(getCreatedOrNow());

        // keyid
        parameters.setKeyid(getSigningKey().getKeyID());

        // FAPI 2.0 Message Signing
        //
        //   shall include the tag parameter with a value of fapi-2-response
        //   in the signature;
        //

        // tag
        parameters.setTag(TAG_VALUE_FAPI_2_RESPONSE);

        //-----------------------------------------------------------------
        // Signature metadata
        //-----------------------------------------------------------------
        SignatureMetadata metadata = new SignatureMetadata(identifiers, parameters);

        // The signature-params-line consists of the signature metadata.
        return new SignatureParamsLine(metadata);
    }


    private byte[] sign(SignatureBase base) throws SignatureException
    {
        // Sign the signature base using the specified signing key.
        return base.sign(new JoseHttpSigner(getSigningKey()));
    }
}
