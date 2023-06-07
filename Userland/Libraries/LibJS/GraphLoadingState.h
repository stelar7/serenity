/*
 * Copyright (c) 2023, stelar7 <dudedbz@gmail.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <LibJS/FetchState.h>
#include <LibJS/Forward.h>
#include <LibJS/Heap/Cell.h>
#include <LibJS/Script.h>

namespace JS {

// 16.2.1.5, Table 44, GraphLoadingState Record, https://tc39.es/ecma262/multipage/ecmascript-language-scripts-and-modules.html#graphloadingstate-record
class GraphLoadingState : public Cell {
    JS_CELL(GraphLoadingState, Cell);

public:
    GraphLoadingState(GCPtr<PromiseCapability> capability, bool is_loading, u32 pending_modules_count, Vector<NonnullGCPtr<Module>> visited, GCPtr<FetchState> host_defined);

    bool is_loading() const { return m_is_loading; }
    bool is_visited(GCPtr<Module> module) const
    {
        for (auto& visited_module : m_visited) {
            if (visited_module == module)
                return true;
        }

        return false;
    }

    Vector<NonnullGCPtr<Module>> const& visited() const { return m_visited; }
    void add_visited(NonnullGCPtr<Module> module) { m_visited.append(module); }

    u32 pending_modules_count() const { return m_pending_modules_count; }

    void set_pending_modules_count(u32 count) { m_pending_modules_count = count; }
    void set_loading(bool is_loading) { m_is_loading = is_loading; }

    GCPtr<PromiseCapability> const& promise_capability() const { return m_capability; }

    GCPtr<FetchState> host_defined() const { return m_host_defined; }

private:
    GCPtr<PromiseCapability> m_capability;  // [[PromiseCapability]]
    bool m_is_loading { false };            // [[IsLoading]]
    u32 m_pending_modules_count { 0 };      // [[PendingModulesCount]]
    Vector<NonnullGCPtr<Module>> m_visited; // [[Visited]]
    GCPtr<FetchState> m_host_defined;       // [[HostDefined]]
};

}
