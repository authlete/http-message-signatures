/*
 * Copyright (C) 2024 Authlete, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package com.authlete.hms;


import org.greenbytes.http.sfv.ByteSequenceItem;
import com.nimbusds.jose.jwk.JWK;


/**
 * Information about signing operation, including the computed signature base
 * and the generated signature.
 *
 * @since 1.3
 */
public class SignatureInfo
{
    /**
     * The signing key used in the signing operation.
     */
    private JWK signingKey;


    /**
     * The computed signature base.
     */
    private SignatureBase signatureBase;


    /**
     * The generated signature.
     */
    private byte[] signature;


    /**
     * Get the signing key used in the signing operation.
     *
     * @return
     *         The signing key.
     */
    public JWK getSigningKey()
    {
        return signingKey;
    }


    /**
     * Set the signing key used in the signing operation.
     *
     * @param key
     *         The signing key.
     *
     * @return
     *         {@code this} object.
     */
    public SignatureInfo setSigningKey(JWK key)
    {
        this.signingKey = key;

        return this;
    }


    /**
     * Get the computed signature base.
     *
     * @return
     *         The computed signature base.
     */
    public SignatureBase getSignatureBase()
    {
        return signatureBase;
    }


    /**
     * Set the computed signature base.
     *
     * @param base
     *         The computed signature base.
     *
     * @return
     *         {@code this} object.
     */
    public SignatureInfo setSignatureBase(SignatureBase base)
    {
        this.signatureBase = base;

        return this;
    }


    /**
     * Get the signature metadata in the serialized form. The value can be
     * used as part of the {@code Signature-Input} HTTP field value.
     *
     * <p><b>Sample Code</b></p>
     *
     * <pre>
     * String signatureInputFieldValue =
     *     String.format(<span style="color: darkred;">"sig=%s"</span>, <!--
     *     -->info.getSerializedSignatureMetadata());
     *
     * responseBuilder.header(
     *     <span style="color: darkred;">"Signature-Input"</span>, signatureInputFieldValue);
     * </pre>
     *
     * @return
     *         The signature metadata in the serialized form.
     */
    public String getSerializedSignatureMetadata()
    {
        // signature-base
        SignatureBase base = getSignatureBase();

        if (base == null)
        {
            return null;
        }

        // signature-params-line
        SignatureParamsLine paramsLine = base.getParamsLine();

        if (paramsLine == null)
        {
            return null;
        }

        // The value of the signature-params-line (= signature metadata)
        SignatureMetadata metadata = paramsLine.getMetadata();

        if (metadata == null)
        {
            return null;
        }

        // Signature metadata in the serialized form.
        return metadata.serialize();
    }


    /**
     * Get the generated signature.
     *
     * @return
     *         The generated signature.
     */
    public byte[] getSignature()
    {
        return signature;
    }


    /**
     * Set the generated signature.
     *
     * @param signature
     *         The generated signature.
     *
     * @return
     *         {@code this} object.
     */
    public SignatureInfo setSignature(byte[] signature)
    {
        this.signature = signature;

        return this;
    }


    /**
     * Get the signature in the serialized form. The value can be used as
     * part of the {@code Signature} HTTP field value.
     *
     * <p><b>Sample Code</b></p>
     *
     * <pre>
     * String signatureFieldValue =
     *     String.format(<span style="color: darkred;">"sig=%s"</span>, <!--
     *     -->info.getSerializedSignature());
     *
     * responseBuilder.header(
     *     <span style="color: darkred;">"Signature"</span>, signatureFieldValue);
     * </pre>
     *
     * @return
     *         The signature in the serialized form.
     */
    public String getSerializedSignature()
    {
        byte[] sig = getSignature();

        if (sig == null)
        {
            return null;
        }

        // Serialize the byte array into a byte sequence as defined in RFC 8941.
        return ByteSequenceItem.valueOf(sig).serialize();
    }
}
