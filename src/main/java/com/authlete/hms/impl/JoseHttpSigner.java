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
package com.authlete.hms.impl;


import java.security.SignatureException;
import com.authlete.hms.HttpSigner;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.OctetKeyPair;


/**
 * An {@link HttpSigner} implementation for JWS algorithms.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.1"
 *      >RFC 7518 JSON Web Algorithms (JWA), Section 3.1. "alg" (Algorithm)
 *      Header Parameter Values for JWS</a>
 */
public class JoseHttpSigner extends JoseHttpSignatureOperation implements HttpSigner
{
    /**
     * A constructor with a key for signing.
     *
     * <p>
     * An algorithm needs to be specified by the {@code alg} parameter in the JWK.
     * </p>
     *
     * @param key
     *         A signing key. This must be a private key.
     *
     * @throws IllegalArgumentException
     *         The key is null, is not a private key, or does not contain the
     *         {@code alg} parameter.
     */
    public JoseHttpSigner(JWK key)
    {
        super(key);

        ensurePrivateKey(key);
    }


    /**
     * A constructor with a key and algorithm for signing.
     *
     * <p>
     * An algorithm needs to be specified by either the {@code alg} argument
     * passed to this method or the {@code alg} parameter in the JWK. When
     * both means are used, the specified algorithms must be identical.
     * </p>
     *
     * @param key
     *         A signing key. This must be a private key.
     *
     * @param alg
     *         An algorithm for signing.
     *
     * @throws IllegalArgumentException
     *         The key is null, is not a private key, or the {@code alg}
     *         parameter of the key does not match the algorithm specified
     *         by the {@code alg} argument. Or, the key does not contain the
     *         {@code alg} parameter and the {@code alg} argument is null.
     */
    public JoseHttpSigner(JWK key, JWSAlgorithm alg)
    {
        super(key, alg);

        ensurePrivateKey(key);
    }


    /**
     * Check if the passed key is a private key.
     *
     * @param key
     *         A key to check.
     *
     * @throws IllegalArgumentException
     *         The key is not a private key.
     */
    private void ensurePrivateKey(JWK key)
    {
        if (!key.isPrivate())
        {
            throw new IllegalArgumentException(
                    "The value of the 'key' argument must be a private key.");
        }
    }


    @Override
    public byte[] sign(byte[] signatureBase) throws SignatureException
    {
        // Create a signer based on the signing key that has been specified
        // through a constructor.
        JWSSigner signer = createSigner();

        // Create a dummy header, which is required when calling the
        // sign(JWSHeader, byte[]) method of the JWSSigner interface.
        JWSHeader header = createHeader();

        // RFC 9421 HTTP Message Signatures
        // 3.3.7. JSON Web Signature (JWS) Algorithms
        //
        //   For both signing and verification, the HTTP message's signature
        //   base (Section 2.5) is used as the entire "JWS Signing Input".
        //

        try
        {
            // Sign the signature base (= create a signature).
            return signer.sign(header, signatureBase).decode();
        }
        catch (JOSEException cause)
        {
            throw new SignatureException(
                    "Failed to sign the signature base: " + cause.getMessage(), cause);
        }
    }


    private JWSSigner createSigner() throws SignatureException
    {
        try
        {
            // Create a signer based on the signing key.
            return createSigner(getKey());
        }
        catch (JOSEException cause)
        {
            throw new SignatureException(
                    "Failed to create a signer: " + cause.getMessage(), cause);
        }
    }


    private static JWSSigner createSigner(JWK signingKey) throws JOSEException
    {
        // Key Type
        KeyType keyType = signingKey.getKeyType();

        // "kty": "EC"
        if (keyType.equals(KeyType.EC))
        {
            return createSignerEC(signingKey);
        }
        // "kty": "RSA"
        else if (keyType.equals(KeyType.RSA))
        {
            return createSignerRSA(signingKey);
        }
        // "kty": "OKP"
        else if (keyType.equals(KeyType.OKP))
        {
            return createSignerOKP(signingKey);
        }
        // "kty": "OCT"
        else if (keyType.equals(KeyType.OCT))
        {
            return createSignerOCT(signingKey);
        }
        else
        {
            // The key type is not supported.
            throw new JOSEException(String.format(
                    "The key type '%s' is not supported.", keyType.toString()));
        }
    }


    private static JWSSigner createSignerEC(JWK signingKey) throws JOSEException
    {
        // Create an ECDSA signer from the signing key.
        return new ECDSASigner(signingKey.toECKey().toECPrivateKey());
    }


    private static JWSSigner createSignerRSA(JWK signingKey) throws JOSEException
    {
        // Create an RSA signer from the signing key.
        return new RSASSASigner(signingKey.toRSAKey().toRSAPrivateKey());
    }


    private static JWSSigner createSignerOKP(JWK signingKey) throws JOSEException
    {
        OctetKeyPair keyPair = signingKey.toOctetKeyPair();

        Curve curve = keyPair.getCurve();

        if (curve.equals(Curve.Ed25519))
        {
            // Create an Ed25519 signer from the key pair.
            return new Ed25519Signer(keyPair);
        }

        // The curve is not supported.
        throw new JOSEException(String.format(
                "The curve '%s' is not supported.", curve.getName()));
    }


    private static JWSSigner createSignerOCT(JWK signingKey) throws KeyLengthException
    {
        // Create a MAC signer from the signing key.
        return new MACSigner(signingKey.toOctetSequenceKey().toByteArray());
    }
}
