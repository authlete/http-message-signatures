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
import java.util.List;


/**
 * A class representing {@code signature-base} defined in RFC 9421
 * HTTP Message Signatures, <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.5"
 * >Section 2&#x2E;5&#x2E; Creating the Signature Base</a>.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.5"
 *      >RFC 9421 HTTP Message Signatures, 2.5. Creating the Signature Base</a>
 */
public class SignatureBase
{
    private final List<SignatureBaseLine> baseLines;
    private final SignatureParamsLine paramsLine;


    /**
     * A constructor with signature base lines and a signature params line.
     *
     * @param baseLines
     *         Signature base lines.
     *
     * @param paramsLine
     *         A signature params line. Must not be null.
     *
     * @throws IllegalArgumentException
     *         The signature params line is null.
     */
    public SignatureBase(List<SignatureBaseLine> baseLines, SignatureParamsLine paramsLine)
    {
        this.baseLines  = Arguments.ensureNonNullElseGet(baseLines, ArrayList<SignatureBaseLine>::new);
        this.paramsLine = Arguments.ensureNonNull("paramsLine", paramsLine);
    }


    /**
     * Get the string representation of this instance, which is the serialized
     * signature base returned by the {@link #serialize()} method.
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
     * Serialize the signature base represented by this instance, and return
     * the resulting string.
     *
     * @return
     *         The serialized signature base represented by this instance.
     */
    public String serialize()
    {
        return serializeTo(new StringBuilder()).toString();
    }


    /**
     * Serialize the signature base represented by this instance, and write
     * the resulting string into the specified string builder.
     *
     * <p>
     * The ABNF for signature base from RFC 9421 HTTP Message Signatures,
     * <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.5">2.5.
     * Creating the Signature Base</a>:
     * </p>
     *
     * <pre>
     * signature-base = *( signature-base-line LF ) signature-params-line
     * signature-base-line = component-identifier ":" SP
     *     ( derived-component-value / *field-content )
     *     ; no obs-fold nor obs-text
     * component-identifier = component-name parameters
     * component-name = sf-string
     * derived-component-value = *( VCHAR / SP )
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
        //   signature-base = *( signature-base-line LF ) signature-params-line
        //

        for (SignatureBaseLine baseLine : getBaseLines())
        {
            baseLine.serializeTo(sb);
            sb.append('\n');
        }

        getParamsLine().serializeTo(sb);

        return sb;
    }


    /**
     * Get the signature base lines included in this signature base.
     *
     * @return
     *         The signature base lines.
     */
    public List<SignatureBaseLine> getBaseLines()
    {
        return baseLines;
    }


    /**
     * Get the signature params line included in this signature base.
     *
     * @return
     *         The signature params line.
     */
    public SignatureParamsLine getParamsLine()
    {
        return paramsLine;
    }


    /**
     * Sign this signature base (= create a signature for this signature base).
     *
     * @param signer
     *         A signer that signs the signature base.
     *
     * @return
     *         A newly generated signature.
     *
     * @throws SignatureException
     *         The signing operation failed.
     */
    public byte[] sign(HttpSigner signer) throws SignatureException
    {
        // The byte array representation of this signature base.
        byte[] signatureBase = toByteArray();

        // Let the signer sign the signature base.
        // (= Let the signer create a signature.)
        return signer.sign(signatureBase);
    }


    /**
     * Verify the signature.
     *
     * @param verifier
     *         A verifier that verifies the signature.
     *
     * @param signature
     *         A signature.
     *
     * @return
     *         True if the signature is valid.
     *
     * @throws SignatureException
     *         Signature verification failed, or the signature is invalid.
     */
    public boolean verify(HttpVerifier verifier, byte[] signature) throws SignatureException
    {
        // The byte array representation of this signature base.
        byte[] signatureBase = toByteArray();

        // Verify the signature.
        return verifier.verify(signatureBase, signature);
    }


    /**
     * Get the byte array representation of this signature base.
     */
    private byte[] toByteArray()
    {
        // The byte array representation of this signature base.
        return serialize().getBytes(StandardCharsets.UTF_8);
    }
}
