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


import java.time.Instant;
import org.greenbytes.http.sfv.Parameters;


/**
 * HTTP Signature Metadata Parameters.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.3"
 *      >RFC 9421 HTTP Message Signatures, Section 2.3. Signature Parameters</a>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-6.3"
 *      >RFC 9421 HTTP Message Signatures, Section 6.3. HTTP Signature Metadata Parameters Registry</a>
 *
 * @see <a href="https://www.iana.org/assignments/http-message-signature/http-message-signature.xhtml#signature-metadata-parameters"
 *      >IANA: HTTP Message Signature / HTTP Signature Metadata Parameters</a>
 */
public class SignatureMetadataParameters extends BasicParameters
{
    /**
     * {@code "alg"}: Explicitly declared signature algorithm.
     *
     * @see <a href="https://www.iana.org/assignments/http-message-signature/http-message-signature.xhtml#signature-algorithms"
     *      >IANA: HTTP Message Signature / HTTP Signature Algorithms</a>
     */
    public static final String ALG = "alg";


    /**
     * {@code "created"}: Timestamp of signature creation.
     */
    public static final String CREATED = "created";


    /**
     * {@code "expires"}: Timestamp of proposed signature expiration.
     */
    public static final String EXPIRES = "expires";


    /**
     * {@code "keyid"}: Key identifier for the signing and verification keys used
     * to create this signature.
     */
    public static final String KEYID = "keyid";


    /**
     * {@code "nonce"}: A single-use nonce value.
     */
    public static final String NONCE = "nonce";


    /**
     * {@code "tag"}: An application-specific tag for a signature.
     */
    public static final String TAG = "tag";


    private static final long serialVersionUID = 1L;


    /**
     * The default constructor.
     */
    public SignatureMetadataParameters()
    {
    }


    SignatureMetadataParameters(Parameters parameters)
    {
        super(parameters);
    }


    /**
     * Get the value of the {@code alg} parameter.
     *
     * @return
     *         The value of the {@code alg} parameter. This can be null.
     *
     * @throws IllegalStateException
     *         The parameter value identified by the key {@code "alg"} is not
     *         null, but it is not an instance of {@code String}.
     */
    public String getAlg() throws IllegalStateException
    {
        return getAsString(ALG);
    }


    /**
     * Set the value of the {@code alg} parameter.
     *
     * @param alg
     *         The value of the {@code alg} parameter.
     *
     * @return
     *         {@code this} object.
     */
    public SignatureMetadataParameters setAlg(String alg)
    {
        put(ALG, alg);

        return this;
    }


    /**
     * Get the value of the {@code created} parameter.
     *
     * @return
     *         The value of the {@code created} parameter. This can be null.
     *
     * @throws IllegalStateException
     *         The parameter value identified by the key {@code "created"} is
     *         not null, but it is neither a {@code Long} instance nor an
     *         {@code Integer} instance. Or the number represented by the
     *         value is outside the valid range for 'seconds since the
     *         Unix epoch'.
     */
    public Instant getCreated() throws IllegalStateException
    {
        return getAsEpochSecond(CREATED);
    }


    /**
     * Set the value of the {@code created} parameter.
     *
     * @param created
     *         The value of the {@code created} parameter.
     *
     * @return
     *         {@code this} object.
     */
    public SignatureMetadataParameters setCreated(Long created)
    {
        put(CREATED, created);

        return this;
    }


    /**
     * Set the value of the {@code created} parameter.
     *
     * @param created
     *         The value of the {@code created} parameter.
     *
     * @return
     *         {@code this} object.
     */
    public SignatureMetadataParameters setCreated(Instant created)
    {
        setAsEpochSecond(CREATED, created);

        return this;
    }


    /**
     * Get the value of the {@code expires} parameter.
     *
     * @return
     *         The value of the {@code expires} parameter. This can be null.
     *
     * @throws IllegalStateException
     *         The parameter value identified by the key {@code "expires"} is
     *         not null, but it is neither a {@code Long} instance nor an
     *         {@code Integer} instance. Or the number represented by the
     *         value is outside the valid range for 'seconds since the
     *         Unix epoch'.
     */
    public Instant getExpires() throws IllegalStateException
    {
        return getAsEpochSecond(EXPIRES);
    }


    /**
     * Set the value of the {@code expires} parameter.
     *
     * @param expires
     *         The value of the {@code expires} parameter.
     *
     * @return
     *         {@code this} object.
     */
    public SignatureMetadataParameters setExpires(Long expires)
    {
        put(EXPIRES, expires);

        return this;
    }


    /**
     * Set the value of the {@code expires} parameter.
     *
     * @param expires
     *         The value of the {@code expires} parameter.
     *
     * @return
     *         {@code this} object.
     */
    public SignatureMetadataParameters setExpires(Instant expires)
    {
        setAsEpochSecond(EXPIRES, expires);

        return this;
    }


    /**
     * Get the value of the {@code keyid} parameter.
     *
     * @return
     *         The value of the {@code keyid} parameter. This can be null.
     *
     * @throws IllegalStateException
     *         The parameter value identified by the key {@code "keyid"} is not
     *         null, but it is not an instance of {@code String}.
     */
    public String getKeyid() throws IllegalStateException
    {
        return getAsString(KEYID);
    }


    /**
     * Set the value of the {@code keyid} parameter.
     *
     * @param keyid
     *         The value of the {@code keyid} parameter.
     *
     * @return
     *         {@code this} object.
     */
    public SignatureMetadataParameters setKeyid(String keyid)
    {
        put(KEYID, keyid);

        return this;
    }


    /**
     * Get the value of the {@code nonce} parameter.
     *
     * @return
     *         The value of the {@code nonce} parameter. This can be null.
     *
     * @throws IllegalStateException
     *         The parameter value identified by the key {@code "nonce"} is not
     *         null, but it is not an instance of {@code String}.
     */
    public String getNonce() throws IllegalStateException
    {
        return getAsString(NONCE);
    }


    /**
     * Set the value of the {@code nonce} parameter.
     *
     * @param nonce
     *         The value of the {@code nonce} parameter.
     *
     * @return
     *         {@code this} object.
     */
    public SignatureMetadataParameters setNonce(String nonce)
    {
        put(NONCE, nonce);

        return this;
    }


    /**
     * Get the value of the {@code tag} parameter.
     *
     * @return
     *         The value of the {@code tag} parameter. This can be null.
     *
     * @throws IllegalStateException
     *         The parameter value identified by the key {@code "tag"} is not
     *         null, but it is not an instance of {@code String}.
     */
    public String getTag() throws IllegalStateException
    {
        return getAsString(TAG);
    }


    /**
     * Set the value of the {@code tag} parameter.
     *
     * @param tag
     *         The value of the {@code tag} parameter.
     *
     * @return
     *         {@code this} object.
     */
    public SignatureMetadataParameters setTag(String tag)
    {
        put(TAG, tag);

        return this;
    }
}
