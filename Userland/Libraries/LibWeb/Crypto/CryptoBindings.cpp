/*
 * Copyright (c) 2023, stelar7 <dudedbz@gmail.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibJS/Runtime/AbstractOperations.h>
#include <LibJS/Runtime/GlobalObject.h>
#include <LibWeb/Crypto/CryptoBindings.h>

namespace Web::Bindings {

JS_DEFINE_ALLOCATOR(KeyAlgorithm);

JS::NonnullGCPtr<KeyAlgorithm> KeyAlgorithm::create(JS::Realm& realm)
{
    return realm.heap().allocate<KeyAlgorithm>(realm, realm.intrinsics().object_prototype());
}

KeyAlgorithm::KeyAlgorithm(Object& prototype)
    : Object(ConstructWithPrototypeTag::Tag, prototype)
{
}

};
