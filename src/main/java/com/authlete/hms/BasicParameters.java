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


import java.math.BigDecimal;
import java.time.DateTimeException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import org.greenbytes.http.sfv.BooleanItem;
import org.greenbytes.http.sfv.ByteSequenceItem;
import org.greenbytes.http.sfv.DecimalItem;
import org.greenbytes.http.sfv.IntegerItem;
import org.greenbytes.http.sfv.Item;
import org.greenbytes.http.sfv.Parameters;
import org.greenbytes.http.sfv.StringItem;
import org.greenbytes.http.sfv.TokenItem;


/**
 * The base class for parameters.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc8941.html#section-3.1.2"
 *      >RFC 8941 Structured Field Values for HTTP, Section 3.1.2. Parameters</a>
 */
class BasicParameters extends LinkedHashMap<String, Object>
{
    private static final long serialVersionUID = 1L;


    BasicParameters()
    {
    }


    BasicParameters(Parameters parameters)
    {
        super(convertParametersToMap(parameters));
    }


    /**
     * Convert a {@link Parameters} instance whose member values are
     * {@link Item} instances into a {@code Map} instance whose member
     * values are well-known Java class instances.
     *
     * @param parameters
     *         An instance representing parameters (<a href=
     *         "https://www.rfc-editor.org/rfc/rfc8941.html#section-3.1.2"
     *         >RFC 8941 Structured Field Values for HTTP, Section 3.1.2.
     *         Parameters</a>).
     *
     * @return
     *         A {@code Map} instance representing the parameters.
     */
    private static Map<String, Object> convertParametersToMap(Parameters parameters)
    {
        Map<String, Object> map = new LinkedHashMap<>();

        // For each parameter.
        for (Map.Entry<String, Item<?>> entry : parameters.entrySet())
        {
            String paramKey = entry.getKey();

            // Convert the Item instance into a well-known Java class instance.
            Object paramValue = convertFromItem(entry.getValue());

            map.put(paramKey, paramValue);
        }

        return map;
    }


    /**
     * Get the string representation of this instance, which is the serialized
     * parameters returned by the {@link #serialize()} method.
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
     * Serialize the parameters represented by this instance, as defined in
     * <a href="https://www.rfc-editor.org/rfc/rfc8941.html">RFC 8941
     * Structured Field Values for HTTP</a>, and return the resulting string.
     *
     * @return
     *         The serialized parameters represented by this instance.
     */
    public String serialize()
    {
        return serializeTo(new StringBuilder()).toString();
    }


    /**
     * Serialize the parameters represented by this instance, as defined in
     * <a href="https://www.rfc-editor.org/rfc/rfc8941.html">RFC 8941
     * Structured Field Values for HTTP</a>, and write the resulting string
     * into the specified string builder.
     *
     * <p>
     * The ABNF for Parameters from RFC 8941 Structured Field Values for
     * HTTP, <a href="https://www.rfc-editor.org/rfc/rfc8941.html#section-3.1.2"
     * >3.1.2. Parameters</a>:
     * </p>
     *
     * <pre>
     * parameters    = *( ";" *SP parameter )
     * parameter     = param-key [ "=" param-value ]
     * param-key     = key
     * key           = ( lcalpha / "*" )
     *                 *( lcalpha / DIGIT / "_" / "-" / "." / "*" )
     * lcalpha       = %x61-7A ; a-z
     * param-value   = bare-item
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
        for (Map.Entry<String, Object> entry : entrySet())
        {
            String paramKey   = entry.getKey();
            Object paramValue = entry.getValue();

            // Append ";param-key".
            sb.append(';').append(paramKey);

            // RFC 8941 Structured Field Values for HTTP
            // 3.1.2. Parameters
            //
            //   Parameters whose value is Boolean (see Section 3.3.6) true
            //   MUST omit that value when serialized.
            //
            if (Boolean.TRUE.equals(paramValue))
            {
                // Omit the value.
                continue;
            }

            // Append "=".
            sb.append('=');

            // Append "param-value".
            serializeParamValue(sb, paramKey, paramValue);
        }

        return sb;
    }


    /**
     * Serialize the parameter value and write the resulting string into the
     * specified string builder.
     *
     * @param sb
     *         A string builder into which the resulting string is written.
     *
     * @param paramKey
     *         The parameter name.
     *
     * @param paramValue
     *         The parameter value.
     */
    private static void serializeParamValue(
            StringBuilder sb, String paramKey, Object paramValue)
    {
        // Convert the parameter value into an Item instance.
        Item<?> item = convertToItem(paramValue);

        if (item == null)
        {
            throw new IllegalStateException(String.format(
                    "The type of the value of the parameter '%s' is '%s', but " +
                    "it is not a supported bare item (see RFC 8941, Section 3.3).",
                    paramKey,
                    (paramValue == null) ? "null" : paramValue.getClass().getName()));
        }

        item.serializeTo(sb);
    }


    /**
     * Convert an {@link Item} into a well-known Java class instance.
     *
     * <p>
     * When the passed item is a {@link TokenItem} instance, a new
     * {@link StructuredFieldToken} instance is returned. This behavior is
     * necessary to distinguish tokens (RFC 8941, <a href=
     * "https://www.rfc-editor.org/rfc/rfc8941.html#section-3.3.4">Section
     * 3.3.4. Tokens</a>) from strings (RFC 8941, <a href=
     * "https://www.rfc-editor.org/rfc/rfc8941.html#section-3.3.3">Section
     * 3.3.3. Strings</a>).
     * </p>
     *
     * @param item
     *         An item.
     *
     * @return
     *         A well-known Java class instance corresponding to the passed
     *         item. When the passed item is a {@link TokenItem} instance,
     *         a new {@link StructuredFieldToken} instance is returned.
     */
    private static Object convertFromItem(Item<?> item)
    {
        if (item instanceof TokenItem)
        {
            return new StructuredFieldToken(((TokenItem)item).get());
        }
        else
        {
            return item.get();
        }
    }


    /**
     * Convert a well-known Java class instance into an instance of a subclass
     * of {@link Item}.
     *
     * @param object
     *         An object.
     *
     * @return
     *         An instance of a subclass of {@link Item}. When the type of the
     *         passed object is an unexpected one, null is returned.
     */
    private static Item<?> convertToItem(Object object)
    {
        // RFC 8941 Structured Field Values for HTTP
        // 3.3. Items
        //
        //   bare-item = sf-integer / sf-decimal / sf-string / sf-token
        //               / sf-binary / sf-boolean
        //

        if (object instanceof Integer)
        {
            // sf-integer
            return IntegerItem.valueOf(((Integer)object).longValue());
        }
        else if (object instanceof Long)
        {
            // sf-integer
            return IntegerItem.valueOf(((Long)object).longValue());
        }
        else if (object instanceof BigDecimal)
        {
            // sf-decimal
            return DecimalItem.valueOf((BigDecimal)object);
        }
        else if (object instanceof String)
        {
            // sf-string
            return StringItem.valueOf((String)object);
        }
        else if (object instanceof StructuredFieldToken)
        {
            // sf-token
            return TokenItem.valueOf(((StructuredFieldToken)object).getToken());
        }
        else if (object instanceof byte[])
        {
            // sf-binary
            return ByteSequenceItem.valueOf((byte[])object);
        }
        else if (object instanceof Boolean)
        {
            // sf-boolean
            return BooleanItem.valueOf(((Boolean)object).booleanValue());
        }
        else
        {
            // unsupported
            return null;
        }
    }


    /**
     * Get the parameter value as a string.
     *
     * @param key
     *         The parameter name.
     *
     * @return
     *         The parameter value. This can be null.
     *
     * @throws IllegalStateException
     *         The parameter value is not null, but it is not a
     *         {@code String} instance.
     */
    String getAsString(String key) throws IllegalStateException
    {
        Object value = get(key);

        if (value == null)
        {
            return null;
        }

        if (!(value instanceof String))
        {
            throw new IllegalStateException(String.format(
                    "The type of the value of the parameter '%s' is '%s', but " +
                    "it must be String.", key, value.getClass().getName()));
        }

        return (String)value;
    }


    /**
     * Get the parameter value as a long integer.
     *
     * @param key
     *         The parameter name.
     *
     * @return
     *         The parameter value. This can be null.
     *
     * @throws IllegalStateException
     *         The parameter value is not null, but it is neither a
     *         {@code Long} instance nor an {@code Integer} instance.
     */
    Long getAsLong(String key) throws IllegalStateException
    {
        Object value = get(key);

        if (value == null)
        {
            return null;
        }

        if (value instanceof Long)
        {
            return (Long)value;
        }

        if (value instanceof Integer)
        {
            return Long.valueOf(((Integer)value).longValue());
        }

        throw new IllegalStateException(String.format(
                "The type of the value of the parameter '%s' is '%s', but " +
                "it must be either Long or Integer.", key, value.getClass().getName()));
    }


    /**
     * Interpret the parameter value as the number of seconds since the Unix
     * epoch and return an {@link Instant} instance representing that time.
     *
     * @param key
     *         The parameter name.
     *
     * @return
     *         An {@link Instant} instance representing the time.
     *         This can be null.
     *
     * @throws IllegalStateException
     *         The parameter value is not null, but it is neither a
     *         {@code Long} instance nor an {@code Integer} instance.
     */
    Instant getAsEpochSecond(String key) throws IllegalStateException
    {
        Long value = getAsLong(key);

        if (value == null)
        {
            return null;
        }

        try
        {
            // Interpret the long value as the number of seconds since
            // the Unix epoch.
            return Instant.ofEpochSecond(value);
        }
        catch (DateTimeException cause)
        {
            throw new IllegalStateException(String.format(
                    "The value of '%s', %d, is outside the valid range for " +
                    "'seconds since the Unix epoch'.", key, value), cause);
        }
    }


    /**
     * Store the number of seconds since the Unix epoch represented by the
     * passed {@link Instant} instance as the value of the parameter specified
     * by the key.
     *
     * @param key
     *         The parameter name.
     *
     * @param value
     *         The parameter value.
     */
    void setAsEpochSecond(String key, Instant value)
    {
        if (value == null)
        {
            put(key, null);
        }
        else
        {
            put(key, Long.valueOf(value.getEpochSecond()));
        }
    }


    /**
     * Get the parameter value as a boolean value.
     *
     * @param key
     *         The parameter name.
     *
     * @return
     *         The parameter value. This can be null.
     *
     * @throws IllegalStateException
     *         The parameter value is not null, but it is not a
     *         {@code Boolean} instance.
     */
    Boolean getAsBoolean(String key) throws IllegalStateException
    {
        Object value = get(key);

        if (value == null)
        {
            return null;
        }

        if (!(value instanceof Boolean))
        {
            throw new IllegalStateException(String.format(
                    "The type of the value of the parameter '%s' is '%s', but " +
                    "it must be Boolean.", key, value.getClass().getName()));
        }

        return (Boolean)value;
    }


    /**
     * Get the parameter value as a boolean value.
     *
     * @param key
     *         The parameter name.
     *
     * @return
     *         The parameter value. When the parameter value is not available
     *         or its value is null, false is returned.
     *
     * @throws IllegalStateException
     *         The parameter value is not null, but it is not a
     *         {@code Boolean} instance.
     */
    boolean getAsPrimitiveBoolean(String key) throws IllegalStateException
    {
        Boolean value = getAsBoolean(key);

        if (value == null)
        {
            return false;
        }

        return value;
    }
}
