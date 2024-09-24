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


import java.security.SignatureException;


/**
 * The signature context that provides component values.
 *
 * <p>
 * RFC 9421 HTTP Message Signatures, <a href=
 * "https://www.rfc-editor.org/rfc/rfc9421.html#section-1.1">Section 1.1.
 * Conventions and Terminology</a>, explains Signature Context as follows:
 * <p>
 *
 * <blockquote>
 * <p><i>
 * The data source from which the HTTP message component values are drawn.
 * The context includes the target message and any additional information
 * the signer or verifier might have, such as the full target URI of a
 * request or the related request message for a response.
 * </i></p>
 * </blockquote>
 *
 * <p>
 * The {@link SignatureBaseBuilder#SignatureBaseBuilder(SignatureContext)
 * constructor} of the {@link SignatureBaseBuilder} class requires an instance
 * that implements this {@code SignatureContext} interface.
 * </p>
 *
 * @see SignatureBaseBuilder
 */
public interface SignatureContext
{
    /**
     * Get the component value.
     *
     * @param metadata
     *         The signature metadata where the component identifier is
     *         included.
     *
     * @param identifier
     *         The component identifier.
     *
     * @return
     *         The value of the component identified by the component
     *         identifier. null if the component value is not available.
     *
     * @throws SignatureException
     *         Something wrong happened.
     */
    String getComponentValue(
            SignatureMetadata metadata, ComponentIdentifier identifier) throws SignatureException;
}
