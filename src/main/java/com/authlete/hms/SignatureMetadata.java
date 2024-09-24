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
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import org.greenbytes.http.sfv.InnerList;
import org.greenbytes.http.sfv.Item;
import org.greenbytes.http.sfv.Parameters;
import org.greenbytes.http.sfv.StringItem;


/**
 * Signature metadata.
 *
 * <p>
 * From the first paragraph of RFC 9421, <a href=
 * "https://www.rfc-editor.org/rfc/rfc9421.html#section-2.3">Section 2.3.
 * Signature Parameters</a>:
 * </p>
 *
 * <blockquote>
 * <p><i>
 * HTTP message signatures have metadata properties that provide information
 * regarding the signature's generation and verification, consisting of the
 * ordered set of covered components and the ordered set of parameters, where
 * the parameters include a timestamp of signature creation, identifiers for
 * verification key material, and other utilities. This <b>metadata</b> is
 * represented by a special message component in the signature base for
 * signature parameters; this special message component is treated slightly
 * differently from other message components.
 * </i></p>
 * </blockquote>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.3"
 *      >RFC 9421 HTTP Message Signatures, Section 2.3. Signature Parameters</a>
 */
public class SignatureMetadata extends ArrayList<ComponentIdentifier>
{
    private static final long serialVersionUID = 1L;


    private final SignatureMetadataParameters parameters;


    /**
     * The default constructor.
     */
    public SignatureMetadata()
    {
        this((SignatureMetadataParameters)null);
    }


    /**
     * A constructor with signature metadata parameters.
     *
     * @param parameters
     *         Signature metadata parameters.
     */
    public SignatureMetadata(SignatureMetadataParameters parameters)
    {
        this.parameters = Arguments.ensureNonNullElseGet(
                parameters, SignatureMetadataParameters::new);
    }


    /**
     * A constructor with component identifiers.
     *
     * @param identifiers
     *         Component identifiers.
     */
    public SignatureMetadata(
            Collection<? extends ComponentIdentifier> identifiers)
    {
        this(identifiers, (SignatureMetadataParameters)null);
    }


    /**
     * A constructor with component identifiers and signature metadata
     * parameters.
     *
     * @param identifiers
     *         Component identifiers.
     *
     * @param parameters
     *         Signature metadata parameters.
     */
    public SignatureMetadata(
            Collection<? extends ComponentIdentifier> identifiers,
            SignatureMetadataParameters parameters)
    {
        super(identifiers);

        this.parameters = Arguments.ensureNonNullElseGet(
                parameters, SignatureMetadataParameters::new);
    }


    /**
     * Get the string representation of this instance, which is the serialized
     * signature metadata returned by the {@link #serialize()} method.
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
     * Serialize the signature metadata represented by this instance, and return
     * the resulting string.
     *
     * @return
     *         The serialized signature metadata represented by this instance.
     */
    public String serialize()
    {
        return serializeTo(new StringBuilder()).toString();
    }


    /**
     * Serialize the signature metadata represented by this instance, and write
     * the resulting string into the specified string builder.
     *
     * @param sb
     *         A string builder into which the resulting string is written.
     *
     * @return
     *         The same string builder that was passed as the argument.
     */
    public StringBuilder serializeTo(StringBuilder sb)
    {
        sb.append('(');

        // For each component identifier.
        for (int index = 0; index < size(); index++)
        {
            if (index != 0)
            {
                sb.append(' ');
            }

            // Serialize the component identifier.
            get(index).serializeTo(sb);
        }

        sb.append(')');

        // Serialize the parameters.
        parameters.serializeTo(sb);

        return sb;
    }


    /**
     * Get the signature metadata parameters.
     *
     * @return
     *         The signature metadata parameters.
     */
    public SignatureMetadataParameters getParameters()
    {
        return parameters;
    }


    static SignatureMetadata parse(
            String label, InnerList innerList) throws SignatureException
    {
        // Parse the items in the inner list as component identifiers.
        Set<ComponentIdentifier> identifiers =
                parseAsComponentIdentifiers(label, innerList.get());

        // Parse the parameters associated with the inner list as
        // signature metadata parameters.
        SignatureMetadataParameters parameters =
                parseAsSignatureMetadataParameters(label, innerList.getParams());

        // Create a SignatureMetadata instance, consisting of the component
        // identifiers and parameters.
        return new SignatureMetadata(identifiers, parameters);
    }


    private static Set<ComponentIdentifier> parseAsComponentIdentifiers(
            String label, List<Item<?>> items) throws SignatureException
    {
        // The list of parsed component identifiers.
        Set<ComponentIdentifier> identifiers = new LinkedHashSet<>();

        for (int index = 0; index < items.size(); index++)
        {
            // Parse the item in the inner list as ComponentIdentifier.
            ComponentIdentifier identifier =
                    parseAsComponentIdentifier(label, index, items.get(index));

            // RFC 9421 HTTP Message Signatures
            // 2. HTTP Message Components
            //
            //   Within a single list of covered components, each component
            //   identifier MUST occur only once.
            //
            if (identifiers.contains(identifier))
            {
                throw new SignatureException(String.format(
                        "The signature metadata labeled '%s' contain a duplicate " +
                        "component identifier '%s' at index '%d'.", label, identifier, index));
            }

            // Add the component identifier.
            identifiers.add(identifier);
        }

        return identifiers;
    }


    private static ComponentIdentifier parseAsComponentIdentifier(
            String label, int index, Item<?> item) throws SignatureException
    {
        // RFC 9421 HTTP Message Signatures
        // 2.5. Creating the Signature Base
        //
        //   component-identifier = component-name parameters
        //   component-name       = sf-string
        //
        if (!(item instanceof StringItem))
        {
            throw new SignatureException(String.format(
                    "The element at index '%d' in the signature metadata labeled '%s' " +
                    "could not parsed as a string item (see RFC 8941, Section 3.3.3).", index, label));
        }

        // Parse the string item as ComponentIdentifier.
        return ComponentIdentifier.parse(label, index, (StringItem)item);
    }


    private static SignatureMetadataParameters parseAsSignatureMetadataParameters(
            String label, Parameters parameters) throws SignatureException
    {
        // Parse the parameters as SignatureMetadataParameters.
        return new SignatureMetadataParameters(parameters);
    }
}
