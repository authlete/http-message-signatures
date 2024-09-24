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
import java.util.Map;
import org.greenbytes.http.sfv.ByteSequenceItem;
import org.greenbytes.http.sfv.Dictionary;
import org.greenbytes.http.sfv.ListElement;


/**
 * The {@code Signature} HTTP Field.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-4.2"
 *      >RFC 9421 HTTP Message Signatures, Section 4.2. The Signature HTTP Field</a>
 */
public class SignatureField extends AbstractDictionaryField<byte[]>
{
    private static final long serialVersionUID = 1L;


    /**
     * The default constructor.
     */
    public SignatureField()
    {
    }


    /**
     * A constructor with dictionary members, each of which represents a pair of
     * label and signature.
     *
     * @param members
     *         Dictionary members in the value of the {@code Signature} HTTP field.
     */
    public SignatureField(Map<String, byte[]> members)
    {
        super(members);
    }


    @Override
    void serializeMemberValueTo(byte[] value, StringBuilder sb)
    {
        ByteSequenceItem.valueOf(value).serializeTo(sb);
    }


    /**
     * Parse the value of the {@code Signature} HTTP field.
     *
     * @param fieldValue
     *         The value of the {@code Signature} HTTP field.
     *         If null is passed, this method returns null.
     *
     * @return
     *         The parsed field value.
     *
     * @throws SignatureException
     *         The passed field value could not be parsed successfully.
     */
    public static SignatureField parse(String fieldValue) throws SignatureException
    {
        if (fieldValue == null)
        {
            return null;
        }

        // Create a SignatureField instance, which will be returned from
        // this method after setup.
        SignatureField instance = new SignatureField();

        // RFC 9421 HTTP Message Signatures
        // 4.2. The Signature HTTP Field
        //
        //   The Signature field is a Dictionary Structured Field (defined
        //   in Section 3.2 of [STRUCTURED-FIELDS]) containing one or more
        //   message signatures generated from the signature context of the
        //   target message.
        //
        Dictionary dictionary = parseAsDictionary(fieldValue);

        // For each member in the dictionary.
        for (Map.Entry<String, ListElement<?>> member : dictionary.get().entrySet())
        {
            // RFC 9421 HTTP Message Signatures
            // 4.2. The Signature HTTP Field
            //
            //   The member's key is the label that uniquely identifies
            //   the message signature within the HTTP message.
            //
            String label = member.getKey();

            // Parse the value of the dictionary member as a byte array.
            byte[] signature = parseAsByteArray(label, member.getValue());

            // Add the pair of label and signature.
            instance.put(label, signature);
        }

        return instance;
    }


    private static byte[] parseAsByteArray(
            String label, ListElement<?> element) throws SignatureException
    {
        // RFC 9421 HTTP Message Signatures
        // 4.2. The Signature HTTP Field
        //
        //   The member's value is a Byte Sequence containing the signature
        //   value for the message signature identified by the label:
        //
        if (!(element instanceof ByteSequenceItem))
        {
            throw new SignatureException(String.format(
                    "The value of the member labeled '%s' could not be parsed " +
                    "as a byte sequence (see RFC 8941, Section 3.3.5).", label));
        }

        // Parse the byte sequence as a byte array.
        return ((ByteSequenceItem)element).get().array();
    }
}
