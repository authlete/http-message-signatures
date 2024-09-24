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


import java.util.function.Supplier;


/**
 * Utility for processing method arguments.
 */
class Arguments
{
    private Arguments()
    {
    }


    /**
     * This method returns the argument value if it is not null. Otherwise,
     * it throws an {@link IllegalArgumentException} with the error message:
     * "The '{<i><code>argumentName</code></i>}' argument must not be null."
     *
     * <p>
     * This method is similar to the {@code Objects.requireNonNull}
     * method.
     * </p>
     *
     * @param <T>
     *         The type of the argument value.
     *
     * @param argumentName
     *         The name of the argument.
     *
     * @param argumentValue
     *         The value of the argument.
     *
     * @return
     *         The argument value if it is not null.
     *
     * @throws IllegalArgumentException
     *         The argument value is null.
     */
    public static <T> T ensureNonNull(
            String argumentName, T argumentValue) throws IllegalArgumentException
    {
        if (argumentValue != null)
        {
            return argumentValue;
        }

        throw new IllegalArgumentException(String.format(
                "The '%s' argument must not be null.", argumentName));
    }


    /**
     * This method returns the argument value if it is not null. Otherwise,
     * it invokes {@code supplier.get()} and returns the supplied value.
     *
     * <p>
     * This method is equivalent to the {@code Objects.requireNonNullElseGet}
     * method, available since Java 9.
     * </p>
     *
     * @param <T>
     *         The type of the argument value and return type.
     *
     * @param argumentValue
     *         An object.
     *
     * @param supplier
     *         A supplier invoked when the argument value is null.
     *
     * @return
     *         The argument value if it is not null and otherwise the value
     *         supplied by {@code supplier.get()}.
     */
    public static <T> T ensureNonNullElseGet(T argumentValue, Supplier<? extends T> supplier)
    {
        if (argumentValue != null)
        {
            return argumentValue;
        }

        return supplier.get();
    }
}
