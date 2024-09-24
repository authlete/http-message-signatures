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
 * The interface that signature signers must implement.
 *
 * <p>
 * The {@link SignatureBase#sign(HttpSigner) sign} method of the
 * {@link SignatureBase} class requires an instance that implements this
 * {@code HttpSigner} interface.
 * </p>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-3.1"
 *      >RFC 9421 HTTP Message Signatures, Section 3.1. Creating a Signature</a>
 *
 * @see SignatureBase#sign(HttpSigner)
 */
public interface HttpSigner
{
    /**
     * Sign the signature base (= create a signature).
     *
     * @param signatureBase
     *         The signature base to be signed.
     *
     * @return
     *         The resulting signature.
     *
     * @throws SignatureException
     *         An error occurred during the signing process.
     */
    byte[] sign(byte[] signatureBase) throws SignatureException;
}
