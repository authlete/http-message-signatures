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
import com.authlete.hms.HttpVerifier;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.util.Base64URL;


/**
 * An {@link HttpVerifier} implementation for JWS algorithms.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.1"
 *      >RFC 7518 JSON Web Algorithms (JWA), Section 3.1. "alg" (Algorithm)
 *      Header Parameter Values for JWS</a>
 */
public class JoseHttpVerifier extends JoseHttpSignatureOperation implements HttpVerifier
{
    /**
     * A constructor with a key for verification.
     *
     * <p>
     * An algorithm needs to be specified by the {@code alg} parameter in the JWK.
     * </p>
     *
     * @param key
     *         A verification key.
     *
     * @throws IllegalArgumentException
     *         The key is null, or it does not contain the {@code alg} parameter.
     */
    public JoseHttpVerifier(JWK key)
    {
        super(key);
    }


    /**
     * A constructor with a key and algorithm for verification.
     *
     * <p>
     * An algorithm needs to be specified by either the {@code alg} argument
     * passed to this method or the {@code alg} parameter in the JWK. When
     * both means are used, the specified algorithms must be identical.
     * </p>
     *
     * @param key
     *         A verification key.
     *
     * @param alg
     *         An algorithm for verification.
     *
     * @throws IllegalArgumentException
     *         The key is null, or the {@code alg} parameter of the key does
     *         not match the algorithm specified by the {@code alg} argument.
     *         Or, the key does not contain the {@code alg} parameter and the
     *         {@code alg} argument is null.
     */
    public JoseHttpVerifier(JWK key, JWSAlgorithm alg)
    {
        super(key, alg);
    }


    @Override
    public boolean verify(byte[] signatureBase, byte[] signature) throws SignatureException
    {
        // Create a verifier based on the verification key that has been
        // specified through a constructor.
        JWSVerifier verifier = createVerifier();

        // Create a dummy header, which is required when calling the
        // verify(JWSHeader, byte[], Base64URL) method of the JWSVerifier interface.
        JWSHeader header = createHeader();

        // RFC 9421 HTTP Message Signatures
        // 3.3.7. JSON Web Signature (JWS) Algorithms
        //
        //   For both signing and verification, the HTTP message's signature
        //   base (Section 2.5) is used as the entire "JWS Signing Input".
        //

        try
        {
            // Verify the signature.
            return verifier.verify(header, signatureBase, Base64URL.encode(signature));
        }
        catch (JOSEException cause)
        {
            throw new SignatureException(
                    "Failed to verify the signature: " + cause.getMessage(), cause);
        }
    }


    private JWSVerifier createVerifier() throws SignatureException
    {
        try
        {
            // Create a verifier based on the verification key.
            return createVerifier(getKey());
        }
        catch (JOSEException cause)
        {
            throw new SignatureException(
                    "Failed to create a verifier: " + cause.getMessage(), cause);
        }
    }


    private static JWSVerifier createVerifier(JWK verificationKey) throws JOSEException
    {
        // Key Type
        KeyType keyType = verificationKey.getKeyType();

        // "kty": "EC"
        if (keyType.equals(KeyType.EC))
        {
            return createVerifierEC(verificationKey);
        }
        // "kty": "RSA"
        else if (keyType.equals(KeyType.RSA))
        {
            return createVerifierRSA(verificationKey);
        }
        // "kty": "OKP"
        else if (keyType.equals(KeyType.OKP))
        {
            return createVerifierOKP(verificationKey);
        }
        // "kty": "OCT"
        else if (keyType.equals(KeyType.OCT))
        {
            return createVerifierOCT(verificationKey);
        }
        else
        {
            // The key type is not supported.
            throw new JOSEException(String.format(
                    "The key type '%s' is not supported.", keyType.toString()));
        }
    }


    private static JWSVerifier createVerifierEC(JWK verificationKey) throws JOSEException
    {
        // Create an EC verifier from the verification key.
        return new ECDSAVerifier(verificationKey.toECKey().toECPublicKey());
    }


    private static JWSVerifier createVerifierRSA(JWK verificationKey) throws JOSEException
    {
        // Create an RSA verifier from the verification key.
        return new RSASSAVerifier(verificationKey.toRSAKey().toRSAPublicKey());
    }


    private static JWSVerifier createVerifierOKP(JWK verificationKey) throws JOSEException
    {
        OctetKeyPair keyPair = verificationKey.toOctetKeyPair();

        Curve curve = keyPair.getCurve();

        if (curve.equals(Curve.Ed25519))
        {
            // Create an Ed25519 verifier from the key pair.
            return new Ed25519Verifier(keyPair);
        }

        // The curve is not supported.
        throw new JOSEException(String.format(
                "The curve '%s' is not supported.", curve.getName()));
    }


    private static JWSVerifier createVerifierOCT(JWK verificationKey) throws JOSEException
    {
        // Create a MAC verifier from the verification key.
        return new MACVerifier(verificationKey.toOctetSequenceKey().toByteArray());
    }
}
