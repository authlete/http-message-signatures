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
import org.greenbytes.http.sfv.Dictionary;
import org.greenbytes.http.sfv.InnerList;
import org.greenbytes.http.sfv.ListElement;


/**
 * The {@code Signature-Input} HTTP Field.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-4.1"
 *      >RFC 9421 HTTP Message Signatures, Section 4.1. The Signature-Input HTTP Field</a>
 */
public class SignatureInputField extends AbstractDictionaryField<SignatureMetadata>
{
    private static final long serialVersionUID = 1L;


    /**
     * The default constructor.
     */
    public SignatureInputField()
    {
    }


    /**
     * A constructor with dictionary members, each of which represents a pair of
     * label and signature metadata.
     *
     * @param members
     *         Dictionary members in the value of the {@code Signature-Input}
     *         HTTP field.
     */
    public SignatureInputField(Map<String, ? extends SignatureMetadata> members)
    {
        super(members);
    }


    @Override
    void serializeMemberValueTo(SignatureMetadata value, StringBuilder sb)
    {
        value.serializeTo(sb);
    }


    /**
     * Parse the value of the {@code Signature-Input} HTTP field.
     *
     * @param fieldValue
     *         The value of the {@code Signature-Input} HTTP field.
     *         If null is passed, this method returns null.
     *
     * @return
     *         The parsed field value.
     *
     * @throws SignatureException
     *         The passed field value could not be parsed successfully.
     */
    public static SignatureInputField parse(String fieldValue) throws SignatureException
    {
        if (fieldValue == null)
        {
            return null;
        }

        // Create a SignatureInputField instance, which will be returned
        // from this method after setup.
        SignatureInputField instance = new SignatureInputField();

        // RFC 9421 HTTP Message Signatures
        // 4.1. The Signature-Input HTTP Field
        //
        //   The Signature-Input field is a Dictionary Structured Field
        //   (defined in Section 3.2 of [STRUCTURED-FIELDS]) containing
        //   the metadata for one or more message signatures generated
        //   from components within the HTTP message.
        //
        Dictionary dictionary = parseAsDictionary(fieldValue);

        // For each member in the dictionary.
        for (Map.Entry<String, ListElement<?>> member : dictionary.get().entrySet())
        {
            // RFC 9421 HTTP Message Signatures
            // 4.1. The Signature-Input HTTP Field
            //
            //   The member's key is the label that uniquely identifies
            //   the message signature within the HTTP message.
            //
            String label = member.getKey();

            // Parse the value of the dictionary member as SignatureMetadata.
            SignatureMetadata metadata = parseAsSignatureMetadata(label, member.getValue());

            // Add the pair of label and signature metadata.
            instance.put(label, metadata);
        }

        return instance;
    }


    private static SignatureMetadata parseAsSignatureMetadata(
            String label, ListElement<?> element) throws SignatureException
    {
        // RFC 9421 HTTP Message Signatures
        // 4.1. The Signature-Input HTTP Field
        //
        //   The member's value is the covered components ordered set
        //   serialized as an Inner List, including all signature metadata
        //   parameters identified by the label:
        //
        if (!(element instanceof InnerList))
        {
            throw new SignatureException(String.format(
                    "The value of the member labeled '%s' could not be parsed " +
                    "as an inner list (see RFC 8941, Section 3.1.1).", label));
        }

        // Parse the inner list as SignatureMetadata.
        return SignatureMetadata.parse(label, (InnerList)element);
    }
}
