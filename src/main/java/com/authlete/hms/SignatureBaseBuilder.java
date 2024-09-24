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
import java.util.ArrayList;
import java.util.List;


/**
 * A builder for signature base, which is represented by the {@link SignatureBase}
 * class.
 *
 * @see SignatureBase
 */
public class SignatureBaseBuilder
{
    private final SignatureContext context;


    /**
     * A constructor with a signature context.
     *
     * @param context
     *         A signature context.
     *
     * @throws IllegalArgumentException
     *         The signature context is null.
     */
    public SignatureBaseBuilder(SignatureContext context)
    {
        this.context = Arguments.ensureNonNull("context", context);
    }


    /**
     * Get the signature context passed to the constructor.
     *
     * @return
     *         The signature context.
     */
    public SignatureContext getContext()
    {
        return context;
    }


    /**
     * Build a signature base based on the specified signature metadata.
     *
     * @param metadata
     *         Signature metadata.
     *
     * @return
     *         Signature base.
     *
     * @throws SignatureException
     *         Failed to create a signature base.
     *
     * @throws IllegalArgumentException
     *         The signature metadata is null.
     */
    public SignatureBase build(SignatureMetadata metadata) throws SignatureException
    {
        Arguments.ensureNonNull("metadata", metadata);

        // Create a list of signature base lines.
        List<SignatureBaseLine> baseLines = buildBaseLines(metadata);

        // Create a signature params line.
        SignatureParamsLine paramsLine = new SignatureParamsLine(metadata);

        // Create a signature base with the signature base lines and
        // signature params line.
        return new SignatureBase(baseLines, paramsLine);
    }


    private List<SignatureBaseLine> buildBaseLines(SignatureMetadata metadata) throws SignatureException
    {
        List<SignatureBaseLine> baseLines = new ArrayList<>();

        // For each component identifier.
        for (ComponentIdentifier identifier : metadata)
        {
            // Construct a signature base line for the component identifier.
            SignatureBaseLine baseLine = buildBaseLine(metadata, identifier);

            baseLines.add(baseLine);
        }

        return baseLines;
    }


    private SignatureBaseLine buildBaseLine(
            SignatureMetadata metadata, ComponentIdentifier identifier) throws SignatureException
    {
        // Get the value of the component identified by the component identifier.
        String componentValue = getContext().getComponentValue(metadata, identifier);

        if (componentValue == null && identifier.isDerivedComponent())
        {
            // RFC 9421 HTTP Message Signatures
            // 2.5. Creating the Signature Base
            //
            //   If the component name starts with an "at" (@) character, derive
            //   the component's value from the message according to the specific
            //   rules defined for the derived component, as provided in Section
            //   2.2, including processing of any known valid parameters. If the
            //   derived component name is unknown or the value cannot be derived,
            //   produce an error.
            //
            throw new SignatureException(String.format(
                    "The value of the derived component '%s' is not available.",
                    identifier.toString()));
        }

        // Construct a signature base line with the component identifier and
        // component value.
        return new SignatureBaseLine(identifier, componentValue);
    }
}
