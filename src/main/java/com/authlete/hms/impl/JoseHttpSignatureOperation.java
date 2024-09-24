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


import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;


/**
 * The base class providing common functionalities for the implementations of
 * {@link JoseHttpSigner} and {@link JoseHttpVerifier}.
 */
class JoseHttpSignatureOperation
{
    private final JWK key;
    private final JWSAlgorithm alg;


    JoseHttpSignatureOperation(JWK key)
    {
        this.key = validateKey(key);
        this.alg = determineAlg(key);
    }


    JoseHttpSignatureOperation(JWK key, JWSAlgorithm alg)
    {
        this.key = validateKey(key);
        this.alg = determineAlg(key, alg);
    }


    private static JWK validateKey(JWK key)
    {
        if (key == null)
        {
            throw new IllegalArgumentException("The 'key' argument must not be null.");
        }

        return key;
    }


    private static JWSAlgorithm determineAlg(JWK key)
    {
        // The value of the 'alg' parameter in the JWK.
        Algorithm algInJwk = key.getAlgorithm();

        if (algInJwk == null)
        {
            throw new IllegalArgumentException("The JWK is missing the 'alg' parameter.");
        }

        if (algInJwk instanceof JWSAlgorithm)
        {
            return (JWSAlgorithm)algInJwk;
        }
        else
        {
            return JWSAlgorithm.parse(algInJwk.getName());
        }
    }


    private static JWSAlgorithm determineAlg(JWK key, JWSAlgorithm alg)
    {
        // The value of the 'alg' parameter in the JWK.
        Algorithm algInJwk = key.getAlgorithm();

        if (alg == null)
        {
            if (algInJwk == null)
            {
                throw new IllegalArgumentException(
                        "The 'alg' argument must be specified when the JWK is missing the 'alg' parameter.");
            }
            else
            {
                // Choose the algorithm specified by the 'alg' parameter in the JWK.
                return (algInJwk instanceof JWSAlgorithm)
                        ? (JWSAlgorithm)algInJwk : JWSAlgorithm.parse(algInJwk.getName());
            }
        }
        else if (algInJwk == null)
        {
            // Choose the algorithm specified by the 'alg' argument.
            return alg;
        }
        else
        {
            // If the algorithm specified by the 'alg' argument differs from the one
            // specified by the 'alg' parameter in the JWK.
            if (!alg.getName().equals(algInJwk.getName()))
            {
                throw new IllegalArgumentException(
                        "The algorithm specified by the 'alg' argument differs from the one " +
                        "specified by the 'alg' parameter in the JWK.");
            }
            else
            {
                return alg;
            }
        }
    }


    /**
     * Get the key.
     *
     * @return
     *         The key.
     */
    public JWK getKey()
    {
        return key;
    }


    /**
     * Get the algorithm.
     *
     * @return
     *         The algorithm.
     */
    public JWSAlgorithm getAlg()
    {
        return alg;
    }


    JWSHeader createHeader()
    {
        return new JWSHeader(getAlg());
    }
}
