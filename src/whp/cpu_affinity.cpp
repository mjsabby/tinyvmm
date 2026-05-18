#include "cpu_affinity.h"

#include <Windows.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <map>
#include <mutex>
#include <vector>

namespace tinyvmm::whp {

namespace {

struct CpuSetEntry {
    ULONG  id;
    USHORT group;
    BYTE   logical_processor_index;
    BYTE   core_index;
    BYTE   efficiency_class;
};

struct CpuSetDb {
    std::vector<CpuSetEntry> entries;
    bool hybrid = false;
};

const CpuSetDb& Db() {
    static CpuSetDb db;
    static std::once_flag flag;
    std::call_once(flag, [] {
        ULONG needed = 0;
        ::GetSystemCpuSetInformation(nullptr, 0, &needed,
                                     ::GetCurrentProcess(), 0);
        if (needed == 0) return;

        std::vector<std::uint8_t> buf(needed);
        if (!::GetSystemCpuSetInformation(
                reinterpret_cast<PSYSTEM_CPU_SET_INFORMATION>(buf.data()),
                needed, &needed, ::GetCurrentProcess(), 0)) {
            return;
        }

        auto* p = reinterpret_cast<PSYSTEM_CPU_SET_INFORMATION>(buf.data());
        auto* end = reinterpret_cast<PSYSTEM_CPU_SET_INFORMATION>(
            buf.data() + needed);
        bool first = true;
        BYTE first_eff = 0;
        while (p < end) {
            if (p->Type == CpuSetInformation) {
                CpuSetEntry e{};
                e.id   = p->CpuSet.Id;
                e.group = p->CpuSet.Group;
                e.logical_processor_index = p->CpuSet.LogicalProcessorIndex;
                e.core_index       = p->CpuSet.CoreIndex;
                e.efficiency_class = p->CpuSet.EfficiencyClass;
                db.entries.push_back(e);
                if (first) {
                    first_eff = e.efficiency_class;
                    first     = false;
                } else if (e.efficiency_class != first_eff) {
                    db.hybrid = true;
                }
            }
            p = reinterpret_cast<PSYSTEM_CPU_SET_INFORMATION>(
                reinterpret_cast<std::uint8_t*>(p) + p->Size);
        }
    });
    return db;
}

// Equality-insensitive ASCII compare (no locale issues; CLI tokens only).
bool EqualsCI(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        char ca = a[i];
        char cb = b[i];
        if (ca >= 'A' && ca <= 'Z') ca = static_cast<char>(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z') cb = static_cast<char>(cb - 'A' + 'a');
        if (ca != cb) return false;
    }
    return true;
}

}  // namespace

const HostTopology& GetTopology() {
    static HostTopology top;
    static std::once_flag flag;
    std::call_once(flag, [] {
        const auto& db = Db();
        top.total_logical = static_cast<unsigned>(db.entries.size());
        top.hybrid = db.hybrid;
        // Track unique physical cores by (group, core_index).
        std::map<std::pair<USHORT, BYTE>, bool> p_cores;
        std::map<std::pair<USHORT, BYTE>, bool> e_cores;
        for (const auto& e : db.entries) {
            const bool is_e = (db.hybrid && e.efficiency_class == 0);
            if (is_e) {
                top.e_logical++;
                e_cores[{e.group, e.core_index}] = true;
            } else {
                top.p_logical++;
                p_cores[{e.group, e.core_index}] = true;
            }
        }
        top.p_physical = static_cast<unsigned>(p_cores.size());
    });
    return top;
}

std::vector<ULONG> ResolveCpuSetIds(AffinityMode mode) {
    if (mode == AffinityMode::All) return {};
    const auto& db = Db();
    if (db.entries.empty()) return {};

    std::vector<ULONG> out;
    out.reserve(db.entries.size());

    auto is_p = [&](const CpuSetEntry& e) {
        // On non-hybrid hosts, every core counts as P.
        return !db.hybrid || e.efficiency_class >= 1;
    };

    if (mode == AffinityMode::PCore) {
        for (const auto& e : db.entries) {
            if (is_p(e)) out.push_back(e.id);
        }
    } else if (mode == AffinityMode::ECore) {
        if (!db.hybrid) return {};  // no E-cores on this host
        for (const auto& e : db.entries) {
            if (e.efficiency_class == 0) out.push_back(e.id);
        }
    } else if (mode == AffinityMode::PCorePhysical) {
        // For each physical P-core ((group, core_index)), keep the entry
        // with the smallest LogicalProcessorIndex. This drops SMT siblings.
        std::map<std::pair<USHORT, BYTE>, const CpuSetEntry*> by_core;
        for (const auto& e : db.entries) {
            if (!is_p(e)) continue;
            auto key = std::make_pair(e.group, e.core_index);
            auto it = by_core.find(key);
            if (it == by_core.end() ||
                e.logical_processor_index <
                    it->second->logical_processor_index) {
                by_core[key] = &e;
            }
        }
        for (auto& kv : by_core) out.push_back(kv.second->id);
    }

    std::sort(out.begin(), out.end());
    return out;
}

bool PinCurrentThread(const std::vector<ULONG>& cpu_set_ids) {
    if (cpu_set_ids.empty()) return true;
    BOOL ok = ::SetThreadSelectedCpuSets(
        ::GetCurrentThread(),
        cpu_set_ids.data(),
        static_cast<ULONG>(cpu_set_ids.size()));
    if (!ok) {
        std::fprintf(stderr,
            "[cpu-affinity] SetThreadSelectedCpuSets failed: error=%lu\n",
            ::GetLastError());
        return false;
    }
    return true;
}

bool ParseAffinityMode(std::string_view s, AffinityMode& out) {
    if (EqualsCI(s, "all")) {
        out = AffinityMode::All;
        return true;
    }
    if (EqualsCI(s, "p") || EqualsCI(s, "p-core") || EqualsCI(s, "pcore")) {
        out = AffinityMode::PCore;
        return true;
    }
    if (EqualsCI(s, "e") || EqualsCI(s, "e-core") || EqualsCI(s, "ecore")) {
        out = AffinityMode::ECore;
        return true;
    }
    if (EqualsCI(s, "p-physical") || EqualsCI(s, "p-phys") ||
        EqualsCI(s, "pphysical")) {
        out = AffinityMode::PCorePhysical;
        return true;
    }
    return false;
}

const char* AffinityModeName(AffinityMode m) {
    switch (m) {
        case AffinityMode::All:           return "all";
        case AffinityMode::PCore:         return "p";
        case AffinityMode::PCorePhysical: return "p-physical";
        case AffinityMode::ECore:         return "e";
    }
    return "?";
}

}  // namespace tinyvmm::whp
