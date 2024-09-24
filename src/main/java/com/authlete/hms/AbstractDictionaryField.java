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
import java.util.LinkedHashMap;
import java.util.Map;
import org.greenbytes.http.sfv.Dictionary;
import org.greenbytes.http.sfv.Parser;


/**
 * The base class for HTTP fields with values that are dictionaries.
 *
 * @param <T>
 *        The class that represents member values.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc8941.html#section-3.2"
 *      >RFC 8941 Structured Field Values for HTTP, Section 3.2. Dictionaries</a>
 */
abstract class AbstractDictionaryField<T> extends LinkedHashMap<String, T>
{
    private static final long serialVersionUID = 1L;


    AbstractDictionaryField()
    {
    }


    AbstractDictionaryField(Map<String, ? extends T> members)
    {
        super(members);
    }


    /**
     * Get the string representation of this instance, which is the serialized
     * dictionary returned by the {@link #serialize()} method.
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
     * Serialize the dictionary represented by this instance, as defined in
     * <a href="https://www.rfc-editor.org/rfc/rfc8941.html">RFC 8941
     * Structured Field Values for HTTP</a>, and return the resulting string.
     *
     * @return
     *         The serialized dictionary represented by this instance.
     */
    public String serialize()
    {
        return serializeTo(new StringBuilder()).toString();
    }


    /**
     * Serialize the dictionary represented by this instance, as defined in
     * <a href="https://www.rfc-editor.org/rfc/rfc8941.html">RFC 8941
     * Structured Field Values for HTTP</a>, and write the resulting string
     * into the specified string builder.
     *
     * <p>
     * The ABNF for Dictionaries from RFC 8941 Structured Field Values for
     * HTTP, <a href="https://www.rfc-editor.org/rfc/rfc8941.html#section-3.2"
     * >3.2. Dictionaries</a>:
     * </p>
     *
     * <pre>
     * sf-dictionary  = dict-member *( OWS "," OWS dict-member )
     * dict-member    = member-key ( parameters / ( "=" member-value ))
     * member-key     = key
     * member-value   = sf-item / inner-list
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
        boolean first = true;

        for (Map.Entry<String, T> entry : entrySet())
        {
            if (first)
            {
                first = false;
            }
            else
            {
                sb.append(", ");
            }

            sb.append(entry.getKey());
            sb.append('=');

            // Serialize the member value by calling the abstract method which
            // is implemented by the subclass.
            serializeMemberValueTo(entry.getValue(), sb);
        }

        return sb;
    }


    /**
     * Serialize a member value and write the resulting string into the
     * specified string builder.
     *
     * @param value
     *         A member value.
     *
     * @param sb
     *         A string builder into which the resulting string is written.
     */
    abstract void serializeMemberValueTo(T value, StringBuilder sb);


    /**
     * Parse a field value as a dictionary, as defined in RFC 8941 Structured
     * Field Values for HTTP, Section 3&#x2E;2&#x2E; Dictionaries.
     *
     * @param fieldValue
     *         The value of an HTTP field.
     *
     * @return
     *         A dictionary representing the field value.
     *
     * @throws SignatureException
     *         The field value failed to be parsed as a dictionary.
     */
    static Dictionary parseAsDictionary(String fieldValue) throws SignatureException
    {
        try
        {
            // Parse the field value as a Dictionary Structured Field.
            return Parser.parseDictionary(fieldValue);
        }
        catch (Exception cause)
        {
            throw new SignatureException(
                    "The field value could not be parsed as a dictionary " +
                    "(see RFC 8941, Section 3.2).", cause);
        }
    }
}
