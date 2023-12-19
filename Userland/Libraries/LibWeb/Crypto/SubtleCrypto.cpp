/*
 * Copyright (c) 2021-2022, Linus Groh <linusg@serenityos.org>
 * Copyright (c) 2023, stelar7 <dudedbz@gmail.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibCrypto/Hash/HashManager.h>
#include <LibJS/Runtime/Array.h>
#include <LibJS/Runtime/ArrayBuffer.h>
#include <LibJS/Runtime/Promise.h>
#include <LibWeb/Bindings/Intrinsics.h>
#include <LibWeb/Crypto/SubtleCrypto.h>
#include <LibWeb/WebIDL/AbstractOperations.h>
#include <LibWeb/WebIDL/Buffers.h>
#include <LibWeb/WebIDL/ExceptionOr.h>

namespace Web::Crypto {

JS_DEFINE_ALLOCATOR(SubtleCrypto);

JS::NonnullGCPtr<SubtleCrypto> SubtleCrypto::create(JS::Realm& realm)
{
    return realm.heap().allocate<SubtleCrypto>(realm, realm);
}

SubtleCrypto::SubtleCrypto(JS::Realm& realm)
    : PlatformObject(realm)
{
}

SubtleCrypto::~SubtleCrypto() = default;

void SubtleCrypto::initialize(JS::Realm& realm)
{
    Base::initialize(realm);
    set_prototype(&Bindings::ensure_web_prototype<Bindings::SubtleCryptoPrototype>(realm, "SubtleCrypto"_fly_string));
}

// https://w3c.github.io/webcrypto/#dfn-normalize-an-algorithm
JS::ThrowCompletionOr<Bindings::Algorithm> SubtleCrypto::normalize_an_algorithm(AlgorithmIdentifier const& algorithm, String operation)
{
    auto& realm = this->realm();

    // If alg is an instance of a DOMString:
    if (algorithm.has<String>()) {
        // Return the result of running the normalize an algorithm algorithm,
        // with the alg set to a new Algorithm dictionary whose name attribute is alg, and with the op set to op.
        auto dictionary = JS::make_handle(JS::Object::create(realm, realm.intrinsics().object_prototype()));
        TRY(dictionary->create_data_property("name", JS::PrimitiveString::create(realm.vm(), algorithm.get<String>())));
        TRY(dictionary->create_data_property("op", JS::PrimitiveString::create(realm.vm(), operation)));

        return normalize_an_algorithm(dictionary, operation);
    }

    // If alg is an object:
    // 1. Let registeredAlgorithms be the associative container stored at the op key of supportedAlgorithms.
    // NOTE: There should always be a container at the op key.
    auto internal_object = supported_algorithms();
    auto maybe_registered_algorithms = internal_object.get(operation);
    auto registered_algorithms = maybe_registered_algorithms.value();

    // 2. Let initialAlg be the result of converting the ECMAScript object represented by alg to
    // the IDL dictionary type Algorithm, as defined by [WebIDL].
    auto initial_algorithm = algorithm.get<JS::Handle<JS::Object>>();

    // 3. If an error occurred, return the error and terminate this algorithm.
    auto has_name = TRY(initial_algorithm->has_property("name"));
    if (!has_name) {
        return realm.vm().throw_completion<JS::TypeError>(JS::ErrorType::NotAnObjectOfType, "Algorithm");
    }

    // 4. Let algName be the value of the name attribute of initialAlg.
    auto algorithm_name = TRY(TRY(initial_algorithm->get("name")).to_string(realm.vm()));

    String desired_type;

    // 5. If registeredAlgorithms contains a key that is a case-insensitive string match for algName:
    if (registered_algorithms.contains(algorithm_name)) {
        // 1. Set algName to the value of the matching key.
        auto it = registered_algorithms.find(algorithm_name);
        algorithm_name = (*it).key;

        // 2. Let desiredType be the IDL dictionary type stored at algName in registeredAlgorithms.
        desired_type = (*it).value;
    } else {
        // Otherwise:
        // Return a new NotSupportedError and terminate this algorithm.
        // FIXME: This should be a DOMException
        return realm.vm().throw_completion<JS::TypeError>(JS::ErrorType::NotImplemented, algorithm_name);
    }

    // 8. Let normalizedAlgorithm be the result of converting the ECMAScript object represented by alg
    // to the IDL dictionary type desiredType, as defined by [WebIDL].
    // FIXME: Create a pointer here based on the type of desiredType
    Bindings::Algorithm normalized_algorithm;

    // 9. Set the name attribute of normalizedAlgorithm to algName.
    normalized_algorithm.name = algorithm_name;

    // 10. If an error occurred, return the error and terminate this algorithm.

    // FIXME: 11. Let dictionaries be a list consisting of the IDL dictionary type desiredType
    // and all of desiredType's inherited dictionaries, in order from least to most derived.
    // FIXME: 12. For each dictionary dictionary in dictionaries:

    // 13. Return normalizedAlgorithm.
    return normalized_algorithm;
}

// https://w3c.github.io/webcrypto/#dfn-SubtleCrypto-method-digest
JS::NonnullGCPtr<JS::Promise> SubtleCrypto::digest(AlgorithmIdentifier const& algorithm, JS::Handle<WebIDL::BufferSource> const& data)
{
    auto& realm = this->realm();

    // 1. Let algorithm be the algorithm parameter passed to the digest() method.

    // 2. Let data be the result of getting a copy of the bytes held by the data parameter passed to the digest() method.
    auto data_buffer_or_error = WebIDL::get_buffer_source_copy(*data->raw_object());
    if (data_buffer_or_error.is_error()) {
        auto error = WebIDL::OperationError::create(realm, "Failed to copy bytes from ArrayBuffer"_fly_string);
        auto promise = JS::Promise::create(realm);
        promise->reject(error.ptr());
        return promise;
    }
    auto& data_buffer = data_buffer_or_error.value();

    // 3. Let normalizedAlgorithm be the result of normalizing an algorithm, with alg set to algorithm and op set to "digest".
    auto normalized_algorithm = normalize_an_algorithm(algorithm, "digest"_string);

    // 4. If an error occurred, return a Promise rejected with normalizedAlgorithm.
    if (normalized_algorithm.is_error()) {
        auto promise = JS::Promise::create(realm);
        auto error = normalized_algorithm.release_error();
        auto error_value = error.value().value();
        promise->reject(error_value);
        return promise;
    }

    // 5. Let promise be a new Promise.
    auto promise = JS::Promise::create(realm);

    // 6. Return promise and perform the remaining steps in parallel.
    // FIXME: We don't have a good abstraction for this yet, so we do it in sync.

    // 7. If the following steps or referenced procedures say to throw an error, reject promise with the returned error and then terminate the algorithm.

    // 8. Let result be the result of performing the digest operation specified by normalizedAlgorithm using algorithm, with data as message.
    auto algorithm_object = normalized_algorithm.release_value();
    auto algorithm_name = algorithm_object.name;

    ::Crypto::Hash::HashKind hash_kind;
    if (algorithm_name.equals_ignoring_ascii_case("SHA-1"sv)) {
        hash_kind = ::Crypto::Hash::HashKind::SHA1;
    } else if (algorithm_name.equals_ignoring_ascii_case("SHA-256"sv)) {
        hash_kind = ::Crypto::Hash::HashKind::SHA256;
    } else if (algorithm_name.equals_ignoring_ascii_case("SHA-384"sv)) {
        hash_kind = ::Crypto::Hash::HashKind::SHA384;
    } else if (algorithm_name.equals_ignoring_ascii_case("SHA-512"sv)) {
        hash_kind = ::Crypto::Hash::HashKind::SHA512;
    } else {
        auto error = WebIDL::NotSupportedError::create(realm, MUST(String::formatted("Invalid hash function '{}'", algorithm_name)));
        promise->reject(error.ptr());
        return promise;
    }

    ::Crypto::Hash::Manager hash { hash_kind };
    hash.update(data_buffer);

    auto digest = hash.digest();
    auto result_buffer = ByteBuffer::copy(digest.immutable_data(), hash.digest_size());
    if (result_buffer.is_error()) {
        auto error = WebIDL::OperationError::create(realm, "Failed to create result buffer"_fly_string);
        promise->reject(error.ptr());
        return promise;
    }

    auto result = JS::ArrayBuffer::create(realm, result_buffer.release_value());

    // 9. Resolve promise with result.
    promise->fulfill(result);

    return promise;
}

// https://w3c.github.io/webcrypto/#SubtleCrypto-method-importKey
JS::ThrowCompletionOr<JS::NonnullGCPtr<JS::Promise>> SubtleCrypto::import_key(Bindings::KeyFormat format, KeyDataType key_data, AlgorithmIdentifier algorithm, bool extractable, Vector<Bindings::KeyUsage> key_usages)
{
    auto& realm = this->realm();

    // 1. Let format, algorithm, extractable and usages, be the format, algorithm, extractable
    // and key_usages parameters passed to the importKey() method, respectively.

    Variant<ByteBuffer, Bindings::JsonWebKey, Empty> real_key_data;
    // 2. If format is equal to the string "raw", "pkcs8", or "spki":
    if (format == Bindings::KeyFormat::Raw || format == Bindings::KeyFormat::Pkcs8 || format == Bindings::KeyFormat::Spki) {
        // 1. If the keyData parameter passed to the importKey() method is a JsonWebKey dictionary, throw a TypeError.
        if (key_data.has<Bindings::JsonWebKey>()) {
            return realm.vm().throw_completion<JS::TypeError>(JS::ErrorType::NotAnObjectOfType, "BufferSource");
        }

        // 2. Let keyData be the result of getting a copy of the bytes held by the keyData parameter passed to the importKey() method.
        auto data_buffer_or_error = WebIDL::get_buffer_source_copy(*key_data.get<JS::Handle<WebIDL::BufferSource>>()->raw_object());
        if (data_buffer_or_error.is_error()) {
            auto error = WebIDL::OperationError::create(realm, "Failed to copy bytes from ArrayBuffer"_fly_string);
            auto promise = JS::Promise::create(realm);
            promise->reject(error.ptr());
            return promise;
        }
        real_key_data = data_buffer_or_error.value();
    }

    if (format == Bindings::KeyFormat::Jwk) {
        // 1. If the keyData parameter passed to the importKey() method is not a JsonWebKey dictionary, throw a TypeError.
        if (!key_data.has<Bindings::JsonWebKey>()) {
            return realm.vm().throw_completion<JS::TypeError>(JS::ErrorType::NotAnObjectOfType, "JsonWebKey");
        }

        // 2. Let keyData be the keyData parameter passed to the importKey() method.
        real_key_data = key_data.get<Bindings::JsonWebKey>();
    }

    // NOTE: The spec jumps to 5 here for some reason?
    // 5. Let normalizedAlgorithm be the result of normalizing an algorithm, with alg set to algorithm and op set to "importKey".
    auto normalized_algorithm = normalize_an_algorithm(algorithm, "importKey"_string);

    // 6. If an error occurred, return a Promise rejected with normalizedAlgorithm.
    if (normalized_algorithm.is_error()) {
        auto promise = JS::Promise::create(realm);
        auto error = normalized_algorithm.release_error();
        auto error_value = error.value().value();
        promise->reject(error_value);
        return promise;
    }

    // 7. Let promise be a new Promise.
    auto promise = JS::Promise::create(realm);

    // 8. Return promise and perform the remaining steps in parallel.
    // FIXME: We don't have a good abstraction for this yet, so we do it in sync.

    // 9. If the following steps or referenced procedures say to throw an error, reject promise with the returned error and then terminate the algorithm.

    // 10. Let result be the CryptoKey object that results from performing the import key operation
    // specified by normalizedAlgorithm using keyData, algorithm, format, extractable and usages.
    if (normalized_algorithm.release_value().name != "PBKDF2"sv) {
        auto error = WebIDL::NotSupportedError::create(realm, MUST(String::formatted("Invalid algorithm '{}'", normalized_algorithm.release_value().name)));
        promise->reject(error.ptr());
        return promise;
    }
    auto maybe_result = pbkdf2_import_key(real_key_data, algorithm, format, extractable, key_usages);
    if (maybe_result.is_error()) {
        auto error = maybe_result.release_error();
        auto error_value = error.value().value();
        promise->reject(error_value);
        return promise;
    }

    auto result = maybe_result.release_value();

    // 11. If the [[type]] internal slot of result is "secret" or "private" and usages is empty, then throw a SyntaxError.
    if ((result->type() == Bindings::KeyType::Secret || result->type() == Bindings::KeyType::Private) && key_usages.is_empty()) {
        auto error = WebIDL::SyntaxError::create(realm, "usages must not be empty"_fly_string);
        promise->reject(error.ptr());
        return promise;
    }

    // 12. Set the [[extractable]] internal slot of result to extractable.
    result->set_extractable(extractable);

    // 13. Set the [[usages]] internal slot of result to the normalized value of usages.
    // NOTE: We are always normalized, due to taking a enum as input.
    Vector<JS::Value> key_usages_values;
    key_usages_values.ensure_capacity(key_usages.size());
    for (auto& usage : key_usages) {
        auto primitive = JS::PrimitiveString::create(realm.vm(), idl_enum_to_string(usage));
        key_usages_values.append(JS::Value(primitive));
    }
    auto normalized_usages = JS::Array::create_from(realm, key_usages_values);
    result->set_usages(normalized_usages);

    // 14. Resolve promise with result.
    promise->fulfill(result);

    return promise;
}

// https://w3c.github.io/webcrypto/#SubtleCrypto-method-deriveBits
JS::NonnullGCPtr<JS::Promise> SubtleCrypto::derive_bits(AlgorithmIdentifier algorithm, CryptoKey const& base_key, u32 length)
{
    auto& realm = this->realm();

    // 1. Let algorithm, baseKey and length, be the algorithm, baseKey and length parameters passed to the deriveBits() method, respectively.

    // 2. Let normalizedAlgorithm be the result of normalizing an algorithm, with alg set to algorithm and op set to "deriveBits".
    auto normalized_algorithm = normalize_an_algorithm(algorithm, "deriveBits"_string);

    // 3. If an error occurred, return a Promise rejected with normalizedAlgorithm.
    if (normalized_algorithm.is_error()) {
        auto promise = JS::Promise::create(realm);
        auto error = normalized_algorithm.release_error();
        auto error_value = error.value().value();
        promise->reject(error_value);
        return promise;
    }

    // 4. Let promise be a new Promise object.
    auto promise = JS::Promise::create(realm);

    // 5. Return promise and perform the remaining steps in parallel.
    // FIXME: We don't have a good abstraction for this yet, so we do it in sync.

    // 6. If the following steps or referenced procedures say to throw an error,
    //    reject promise with the returned error and then terminate the algorithm.

    // 7. If the name member of normalizedAlgorithm is not equal to the name attribute of
    //    the [[algorithm]] internal slot of baseKey then throw an InvalidAccessError.
    auto key_algorithm = static_cast<Bindings::KeyAlgorithm const*>(base_key.algorithm());
    if (normalized_algorithm.release_value().name != key_algorithm->name()) {
        auto error = WebIDL::InvalidAccessError::create(realm, "Algorithm mismatch"_fly_string);
        promise->reject(error.ptr());
        return promise;
    }

    // FIXME: 8. If the [[usages]] internal slot of baseKey does not contain an entry that is "deriveBits", then throw an InvalidAccessError.
    /*
    auto key_usages = static_cast<JS::Array const*>(base_key.usages());
    if (!any_of(key_usages, [](auto& usage) { return usage == idl_enum_to_string(Bindings::KeyUsage::Derivebits); })) {
        auto error = WebIDL::InvalidAccessError::create(realm, "Key does not support deriveBits"_fly_string);
        promise->reject(error.ptr());
        return promise;
    }
    */

    // 9. Let result be the result of creating an ArrayBuffer containing the result of performing the derive bits operation
    //    specified by normalizedAlgorithm using baseKey, algorithm and length.
    // NOTE: Spec says to use algorithm here, but PBKDF2 wans the normalizedAlgorithm instead.
    auto algorithm_object = normalized_algorithm.release_value();
    if (algorithm_object.name != "PBKDF2"sv) {
        auto error = WebIDL::NotSupportedError::create(realm, MUST(String::formatted("Invalid algorithm '{}'", normalized_algorithm.release_value().name)));
        promise->reject(error.ptr());
        return promise;
    }

    auto maybe_result = pbkdf2_derive_bits(base_key, algorithm_object, length);
    if (maybe_result.is_error()) {
        auto error = maybe_result.release_error();
        auto error_value = error.value().value();
        promise->reject(error_value);
        return promise;
    }

    // 10. Resolve promise with result.
    promise->fulfill(maybe_result.release_value());

    return promise;
}

SubtleCrypto::SupportedAlgorithmsMap& SubtleCrypto::supported_algorithms_internal()
{
    static SubtleCrypto::SupportedAlgorithmsMap s_supported_algorithms;
    return s_supported_algorithms;
}

// https://w3c.github.io/webcrypto/#algorithm-normalization-internal
SubtleCrypto::SupportedAlgorithmsMap SubtleCrypto::supported_algorithms()
{
    auto& internal_object = supported_algorithms_internal();

    if (!internal_object.is_empty()) {
        return internal_object;
    }

    // 1. For each value, v in the List of supported operations,
    // set the v key of the internal object supportedAlgorithms to a new associative container.
    auto supported_operations = Vector {
        "encrypt"_string,
        "decrypt"_string,
        "sign"_string,
        "verify"_string,
        "digest"_string,
        "deriveBits"_string,
        "wrapKey"_string,
        "unwrapKey"_string,
        "generateKey"_string,
        "importKey"_string,
        "exportKey"_string,
        "get key length"_string,
    };

    for (auto& operation : supported_operations) {
        internal_object.set(operation, {});
    }

    // https://w3c.github.io/webcrypto/#algorithm-conventions
    // https://w3c.github.io/webcrypto/#sha
    define_an_algorithm("digest"_string, "SHA1"_string, ""_string);
    define_an_algorithm("digest"_string, "SHA-256"_string, ""_string);
    define_an_algorithm("digest"_string, "SHA-384"_string, ""_string);
    define_an_algorithm("digest"_string, "SHA-512"_string, ""_string);

    // https://w3c.github.io/webcrypto/#pbkdf2
    define_an_algorithm("importKey"_string, "PBKDF2"_string, ""_string);
    define_an_algorithm("deriveBits"_string, "PBKDF2"_string, "Pbkdf2Params"_string);
    // FIXME: define_an_algorithm("get key length"_string, "PBKDF2"_string, ""_string);

    return internal_object;
}

// https://w3c.github.io/webcrypto/#concept-define-an-algorithm
void SubtleCrypto::define_an_algorithm(String op, String algorithm, String type)
{
    auto& internal_object = supported_algorithms_internal();

    // 1. Let registeredAlgorithms be the associative container stored at the op key of supportedAlgorithms.
    // NOTE: There should always be a container at the op key.
    auto maybe_registered_algorithms = internal_object.get(op);
    auto registered_algorithms = maybe_registered_algorithms.value();

    // 2. Set the alg key of registeredAlgorithms to the IDL dictionary type type.
    registered_algorithms.set(algorithm, type);
    internal_object.set(op, registered_algorithms);
}

// https://w3c.github.io/webcrypto/#pbkdf2-operations
JS::ThrowCompletionOr<JS::NonnullGCPtr<CryptoKey>> SubtleCrypto::pbkdf2_import_key([[maybe_unused]] Variant<ByteBuffer, Bindings::JsonWebKey, Empty> key_data, [[maybe_unused]] AlgorithmIdentifier algorithm_parameter, Bindings::KeyFormat format, bool extractable, Vector<Bindings::KeyUsage> key_usages)
{
    auto& realm = this->realm();

    // 1. If format is not "raw", throw a NotSupportedError
    if (format != Bindings::KeyFormat::Raw) {
        // FIXME: This should be a NotSupportedError
        return realm.vm().throw_completion<JS::TypeError>(JS::ErrorType::NotImplemented, idl_enum_to_string(format));
    }

    // 2. If usages contains a value that is not "deriveKey" or "deriveBits", then throw a SyntaxError.
    for (auto& usage : key_usages) {
        if (usage != Bindings::KeyUsage::Derivekey && usage != Bindings::KeyUsage::Derivebits) {
            return realm.vm().throw_completion<JS::SyntaxError>(MUST(String::formatted("Invalid key usage '{}'", idl_enum_to_string(usage))));
        }
    }

    // 3. If extractable is not false, then throw a SyntaxError.
    if (extractable) {
        return realm.vm().throw_completion<JS::SyntaxError>("extractable must be false"_string);
    }

    // 4. Let key be a new CryptoKey representing keyData.
    auto key = CryptoKey::create(realm);

    // 5. Set the [[type]] internal slot of key to "secret".
    key->set_type(Bindings::KeyType::Secret);

    // 6. Set the [[extractable]] internal slot of key to false.
    key->set_extractable(false);

    // 7. Let algorithm be a new KeyAlgorithm object.
    auto algorithm = Bindings::KeyAlgorithm::create(realm);

    // 8. Set the name attribute of algorithm to "PBKDF2".
    algorithm->set_name("PBKDF2"_string);

    // 9. Set the [[algorithm]] internal slot of key to algorithm.
    key->set_algorithm(algorithm);

    // 10. Return key.
    return key;
}

JS::ThrowCompletionOr<JS::NonnullGCPtr<JS::ArrayBuffer>> SubtleCrypto::pbkdf2_derive_bits(CryptoKey const& base_key, Bindings::Pbkdf2Params* normalized_algorithm, u32 length)
{
    auto& realm = this->realm();

    // 1. If length is null or zero, or is not a multiple of 8, then throw an OperationError.
    if (length == 0 || length % 8 != 0) {
        return WebIDL::OperationError::create(realm, "Length must be a multiple of 8"_fly_string);
    }

    // 2. If the iterations member of normalizedAlgorithm is zero, then throw an OperationError.
    if (normalized_algorithm->iterations == 0) {
        return WebIDL::OperationError::create(realm, "Iterations must not be zero"_fly_string);
    }

    // FIXME: 3. Let prf be the MAC Generation function described in Section 4 of [FIPS-198-1]
    //    using the hash function described by the hash member of normalizedAlgorithm.

    // FIXME: 4. Let result be the result of performing the PBKDF2 operation defined in Section 5.2 of [RFC8018]
    //        using prf as the pseudo-random function, PRF,
    //        the password represented by [[handle]] internal slot of key as the password, P,
    //        the contents of the salt attribute of normalizedAlgorithm as the salt, S,
    //        the value of the iterations attribute of normalizedAlgorithm as the iteration count, c,
    //        and length divided by 8 as the intended key length, dkLen.
    auto maybe_result_buffer = ByteBuffer::create_uninitialized(length / 8);

    // 5. If the key derivation operation fails, then throw an OperationError.
    if (maybe_result_buffer.is_error()) {
        return WebIDL::OperationError::create(realm, "Failed to create result buffer"_fly_string);
    }

    auto output = JS::ArrayBuffer::create(realm, maybe_result_buffer.release_value());

    // 6. Return result
    return output;
}

}
