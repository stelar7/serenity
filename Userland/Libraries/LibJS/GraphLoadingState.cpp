/*
 * Copyright (c) 2023, stelar7 <dudedbz@gmail.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibJS/GraphLoadingState.h>

namespace JS {

GraphLoadingState::GraphLoadingState(GCPtr<PromiseCapability> capability, bool is_loading, u32 pending_modules_count, Vector<NonnullGCPtr<Module>> visited, GCPtr<FetchState> host_defined)
    : m_capability(capability)
    , m_is_loading(is_loading)
    , m_pending_modules_count(pending_modules_count)
    , m_visited(visited)
    , m_host_defined(host_defined)
{
}

}
