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
import java.util.Objects;
import org.greenbytes.http.sfv.StringItem;


/**
 * A class representing a component identifier.
 *
 * <p>
 * RFC 9421 HTTP Message Signatures, <a href=
 * "https://www.rfc-editor.org/rfc/rfc9421.html#section-1.1">Section 1.1.
 * Conventions and Terminology</a>, explains HTTP Message Component Identifier
 * as follows:
 * </p>
 *
 * <blockquote>
 * <p><i>
 * The combination of an HTTP message component name and any parameters.
 * This combination uniquely identifies a specific HTTP message component
 * with respect to a particular HTTP message signature and the HTTP message
 * it applies to.
 * </i></p>
 * </blockquote>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2"
 *      >RFC 9421 HTTP Message Signatures, Section 2. HTTP Message Components</a>
 */
public class ComponentIdentifier
{
    private final String componentName;
    private final ComponentIdentifierParameters parameters;


    /**
     * A constructor with a component name.
     *
     * @param componentName
     *         A component name.
     *
     * @throws IllegalArgumentException
     *         The component name is null.
     */
    public ComponentIdentifier(String componentName)
    {
        this(componentName, (ComponentIdentifierParameters)null);
    }


    /**
     * A constructor with a component name and parameters.
     *
     * @param componentName
     *         A component name.
     *
     * @param parameters
     *         Parameters.
     *
     * @throws IllegalArgumentException
     *         The component name is null.
     */
    public ComponentIdentifier(
            String componentName, ComponentIdentifierParameters parameters)
    {
        this.componentName = Arguments.ensureNonNull("componentName", componentName);
        this.parameters    = Arguments.ensureNonNullElseGet(parameters, ComponentIdentifierParameters::new);
    }


    @Override
    public boolean equals(Object obj)
    {
        if (obj == null)
        {
            return false;
        }

        if (this == obj)
        {
            return true;
        }

        if (getClass() != obj.getClass())
        {
            return false;
        }

        ComponentIdentifier that = (ComponentIdentifier)obj;

        if (!componentName.equals(that.componentName))
        {
            return false;
        }

        // RFC 9421 HTTP Message Signatures
        // 2. HTTP Message Components
        //
        //   Multiple component identifiers having the same component name MAY
        //   be included if they have parameters that make them distinct, such
        //   as `"foo";bar` and `"foo";baz`. The order of parameters MUST be
        //   preserved when processing a component identifier (such as when
        //   parsing during verification), but the order of parameters is not
        //   significant when comparing two component identifiers for equality
        //   checks. That is to say, `"foo";bar;baz` cannot be in the same
        //   message as `"foo";baz;bar`, since these two component identifiers
        //   are equivalent, but a system processing one form is not allowed to
        //   transform it into the other form.
        //
        return parameters.equals(that.parameters);
    }


    @Override
    public int hashCode()
    {
        // Map.hashCode()
        //
        //   Returns the hash code value for this map. The hash code of a map
        //   is defined to be the sum of the hash codes of each entry in the
        //   map's entrySet() view. This ensures that m1.equals(m2) implies
        //   that m1.hashCode()==m2.hashCode() for any two maps m1 and m2, as
        //   required by the general contract of Object.hashCode().
        //

        return Objects.hash(componentName, parameters);
    }


    /**
     * Get the string representation of this instance, which is the serialized
     * component identifier returned by the {@link #serialize()} method.
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
     * Serialize the component identifier represented by this instance, and
     * return the resulting string.
     *
     * @return
     *         The serialized component identifier represented by this instance.
     */
    public String serialize()
    {
        return serializeTo(new StringBuilder()).toString();
    }


    /**
     * Serialize the component identifier represented by this instance, and
     * write the resulting string into the specified string builder.
     *
     * @param sb
     *         A string builder into which the resulting string is written.
     *
     * @return
     *         The same string builder that was passed as the argument.
     */
    public StringBuilder serializeTo(StringBuilder sb)
    {
        StringItem.valueOf(componentName).serializeTo(sb);
        parameters.serializeTo(sb);

        return sb;
    }


    /**
     * Get the component name.
     *
     * @return
     *         The component name.
     */
    public String getComponentName()
    {
        return componentName;
    }


    /**
     * Get the parameters which are part of this component identifier.
     *
     * @return
     *         The parameters.
     */
    public ComponentIdentifierParameters getParameters()
    {
        return parameters;
    }


    /**
     * Get the flag indicating that the component name of this component
     * identifier refers to a derived component.
     *
     * @return
     *         True if the component name refers to a derived component.
     *         In other words, true if the component name starts with
     *         {@code "@"}.
     */
    public boolean isDerivedComponent()
    {
        return isDerivedComponentName(getComponentName());
    }


    static ComponentIdentifier parse(String label, int index, StringItem stringItem) throws SignatureException
    {
        // The value of the string item represents a component name.
        String componentName = stringItem.get();

        // Parse the parameters associated with the string item.
        ComponentIdentifierParameters parameters =
                new ComponentIdentifierParameters(stringItem.getParams());

        // Validate the component name and parameters.
        validate(label, index, componentName, parameters);

        // Create a ComponentIdentifier instance, consisting of the component
        // name and parameters.
        return new ComponentIdentifier(componentName, parameters);
    }


    private static void validate(
            String label, int index, String componentName,
            ComponentIdentifierParameters parameters) throws SignatureException
    {
        // Validate the component name.
        validateComponentName(label, index, componentName);

        // Validate the parameters.
        validateParameters(label, index, componentName, parameters);
    }


    private static String validateComponentName(
            String label, int index, String componentName) throws SignatureException
    {
        // RFC 9421 HTTP Message Signatures
        // 2. HTTP Message Components
        //
        //   Each component name is either an HTTP field name (Section 2.1) or
        //   a registered derived component name (Section 2.2).
        //
        // 2.1. HTTP Fields
        //
        //   The component name for an HTTP field is the lowercased form of its
        //   field name as defined in Section 5.1 of [HTTP]. While HTTP field
        //   names are case insensitive, implementations MUST use lowercased
        //   field names (e.g., content-type, date, etag) when using them as
        //   component names.
        //
        // 2.2. Derived Components
        //
        //   Derived component names MUST start with the "at" (@) character.
        //

        // If the value appears to be a derived component name.
        if (isDerivedComponentName(componentName))
        {
            // Validate the value as a derived component name.
            validateDerivedComponentName(label, index, componentName);
        }
        else
        {
            // Validate the value as a normal component name.
            validateNormalComponentName(label, index, componentName);
        }

        return componentName;
    }


    private static boolean isDerivedComponentName(String componentName)
    {
        return componentName.startsWith("@");
    }


    private static void validateDerivedComponentName(
            String label, int index, String componentName) throws SignatureException
    {
        // If the value is not a registered derived component name.
        if (!DerivedComponentNames.isRegistered(componentName))
        {
            throw new SignatureException(String.format(
                    "The component name at index '%d' in the signature metadata labeled " +
                    "'%s' starts with '@', but it is not a registered derived component name.",
                    index, label));
        }

        // RFC 9421 HTTP Message Signatures
        // 3.1. Creating a Signature
        //
        //   The `@signature-params` derived component identifier MUST NOT be
        //   present in the list of covered component identifiers.
        //
        if (componentName.equals(DerivedComponentNames.SIGNATURE_PARAMS))
        {
            throw new SignatureException(String.format(
                    "The signature metadata labeled '%s' contains '@signature-params', " +
                    "which is prohibited.", label));
        }
    }


    private static void validateNormalComponentName(
            String label, int index, String componentName) throws SignatureException
    {
        // If the value contains one or more uppercase characters.
        if (containsUppercase(componentName))
        {
            throw new SignatureException(String.format(
                    "The component name at index '%d' in the signature metadata labeled " +
                    "'%s' contains one or more uppercase characters.", index, label));
        }
    }


    private static boolean containsUppercase(String string)
    {
        for (char ch : string.toCharArray())
        {
            if (Character.isUpperCase(ch))
            {
                return true;
            }
        }

        return false;
    }


    private static void validateParameters(
            String label, int index, String componentName,
            ComponentIdentifierParameters parameters) throws SignatureException
    {
        // RFC 9421 HTTP Message Signatures
        // 2.1. HTTP Fields
        //
        //   Multiple parameters MAY be specified together, though some
        //   combinations are redundant or incompatible. For example, the `sf`
        //   parameter's functionality is already covered when the `key`
        //   parameter is used on a Dictionary item, since key requires strict
        //   serialization of the value. The `bs` parameter, which requires the
        //   raw bytes of the field values from the message, is not compatible
        //   with the use of the `sf` or `key` parameters, which require the
        //   parsed data structures of the field values after combination.
        //
        if (parameters.isBs() && (parameters.isSf() || parameters.getKey() != null))
        {
            throw new SignatureException(String.format(
                    "The component identifier at index '%d' in the signature metadata " +
                    "labeled '%s' has the 'bs' flag, but using this flag with either " +
                    "the 'sf' flag or the 'key' parameter is prohibited.", index, label));
        }

        // RFC 9421 HTTP Message Signatures
        // 2.2.8. Query Parameters
        //
        //   The REQUIRED `name` parameter of each component identifier contains
        //   the encoded nameString of a single query parameter as a String value.
        //
        if (componentName.equals(DerivedComponentNames.QUERY_PARAM))
        {
            if (parameters.getName() == null)
            {
                throw new SignatureException(String.format(
                        "The '@query-param' at index '%d' in the signature metadata " +
                        "labeled '%s' is missing the 'name' parameter.", index, label));
            }
        }
    }
}
