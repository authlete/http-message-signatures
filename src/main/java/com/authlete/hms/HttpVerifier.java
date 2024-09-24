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
 * The interface that signature verifiers must implement.
 *
 * <p>
 * The {@link SignatureBase#verify(HttpVerifier, byte[]) verify} method of the
 * {@link SignatureBase} class requires an instance that implements this
 * {@code HttpVerifier} interface.
 * </p>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-3.2"
 *      >RFC 9421 HTTP Message Signatures, Section 3.2. Verifying a Signature</a>
 *
 * @see SignatureBase#verify(HttpVerifier, byte[])
 */
public interface HttpVerifier
{
    /**
     * Verify the signature.
     *
     * @param signatureBase
     *         The signature base used to create the signature.
     *
     * @param signature
     *         The signature to be verified.
     *
     * @return
     *         True when the signature is valid.
     *
     * @throws SignatureException
     *         An error occurred during the verification process, or the
     *         signature is invalid.
     */
    boolean verify(byte[] signatureBase, byte[] signature) throws SignatureException;
}
