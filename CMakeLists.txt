cmake_minimum_required(VERSION 3.20)
project(tinyvmm CXX)

if(NOT WIN32)
    message(FATAL_ERROR "tinyvmm requires Windows + the Windows Hypervisor Platform")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ---------------------------------------------------------------------------
# External dependency locations
#
# XDP for Windows public headers are vendored under
# third_party/xdp-for-windows/published/external pinned to the v1.3.0 tag
# (see that directory's README.md for provenance). The vendored headers
# must match the runtime driver version, because the device name layout
# changed AFTER v1.3.0 -- post-v1.3.0 trees route per-object-type opens
# to \Device\xdpapi\{xsk,program,interface} which the v1.3.0 driver does
# not register. Override XDP_ROOT only if you have a tree pinned to the
# exact same upstream tag as the installed driver.
# ---------------------------------------------------------------------------
set(XDP_ROOT "${CMAKE_SOURCE_DIR}/third_party/xdp-for-windows"
    CACHE PATH "Path to the XDP for Windows source tree")
set(XDP_INCLUDE_DIR "${XDP_ROOT}/published/external")
if(NOT EXISTS "${XDP_INCLUDE_DIR}/xdpapi.h")
    message(WARNING
        "XDP headers not found at ${XDP_INCLUDE_DIR}; XDP-backed devices will "
        "not build. Set -DXDP_ROOT=<path> to override.")
endif()
# Refuse to build against a post-v1.3.0 tree -- those headers route XSK
# opens to a device path the v1.3.0 driver does not register, and
# XskCreate fails at runtime with STATUS_OBJECT_PATH_NOT_FOUND.
if(EXISTS "${XDP_INCLUDE_DIR}/xdp/details/ioctldef.h")
    file(READ "${XDP_INCLUDE_DIR}/xdp/details/ioctldef.h" _xdp_ioctldef)
    if(_xdp_ioctldef MATCHES "XDP_XSK_DEVICE_NAME")
        message(FATAL_ERROR
            "XDP_ROOT=${XDP_ROOT} points at a post-v1.3.0 header tree (it "
            "defines XDP_XSK_DEVICE_NAME, introduced in upstream commit "
            "18e6adc 'Add device objects per XDP object type'). The runtime "
            "v1.3.0 driver only registers \\Device\\xdp; XskCreate would "
            "fail at runtime. Set XDP_ROOT to the vendored "
            "third_party/xdp-for-windows tree, or upgrade your installed "
            "driver and refresh the vendored headers.")
    endif()
endif()

# ---------------------------------------------------------------------------
# tcp-sans-io — Rust user-mode TCP stack (M34)
#
# The crate is built as a `--release` staticlib by the local cargo
# toolchain on every configure/build of tinyvmm. The Rust source tree
# is referenced in-place (no vendoring) via the TINYVMM_TCP_SANS_IO_DIR
# cache var. Each build flavor (Release/Debug/ASan/UBSan) gets its own
# cargo target-dir under ${CMAKE_BINARY_DIR}/cargo/tcp-sans-io to avoid
# cross-config cargo-lock contention.
#
# Library shape: `crate-type = ["cdylib", "staticlib", "rlib"]` in the
# crate's Cargo.toml; we link the staticlib (tcp_sans_io.lib).
# ---------------------------------------------------------------------------
set(TINYVMM_TCP_SANS_IO_DIR "C:/tcp-sans-io" CACHE PATH
    "Path to the tcp-sans-io Rust source tree (Cargo.toml lives here)")

if(NOT EXISTS "${TINYVMM_TCP_SANS_IO_DIR}/Cargo.toml")
    message(FATAL_ERROR
        "TINYVMM_TCP_SANS_IO_DIR='${TINYVMM_TCP_SANS_IO_DIR}' does not "
        "contain Cargo.toml. Override with "
        "-DTINYVMM_TCP_SANS_IO_DIR=<path-to-tcp-sans-io>.")
endif()
if(NOT EXISTS "${TINYVMM_TCP_SANS_IO_DIR}/include/tcp_sans_io.h")
    message(FATAL_ERROR
        "TINYVMM_TCP_SANS_IO_DIR='${TINYVMM_TCP_SANS_IO_DIR}' is missing "
        "include/tcp_sans_io.h. Pointed at the wrong tree?")
endif()

find_program(CARGO_EXECUTABLE cargo REQUIRED)

set(TSI_CARGO_TARGET_DIR "${CMAKE_BINARY_DIR}/cargo/tcp-sans-io")
set(TSI_STATIC_LIB "${TSI_CARGO_TARGET_DIR}/release/tcp_sans_io.lib")
set(TSI_INCLUDE_DIR "${TINYVMM_TCP_SANS_IO_DIR}/include")

# Re-trigger the cargo build whenever any Rust source (or the manifest /
# lockfile) changes. CONFIGURE_DEPENDS re-globs on every reconfigure so
# new files get picked up without needing to re-run CMake by hand.
file(GLOB_RECURSE TSI_SRC_FILES CONFIGURE_DEPENDS
    "${TINYVMM_TCP_SANS_IO_DIR}/src/*.rs"
)

add_custom_command(
    OUTPUT  "${TSI_STATIC_LIB}"
    COMMAND "${CARGO_EXECUTABLE}" build --release --lib
            --manifest-path "${TINYVMM_TCP_SANS_IO_DIR}/Cargo.toml"
            --target-dir    "${TSI_CARGO_TARGET_DIR}"
    DEPENDS "${TINYVMM_TCP_SANS_IO_DIR}/Cargo.toml"
            "${TINYVMM_TCP_SANS_IO_DIR}/Cargo.lock"
            ${TSI_SRC_FILES}
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
    COMMENT "Building tcp_sans_io.lib (release) via cargo"
    VERBATIM
)

add_custom_target(tcp_sans_io_build DEPENDS "${TSI_STATIC_LIB}")

# ---------------------------------------------------------------------------
# Main target
# ---------------------------------------------------------------------------
add_executable(tinyvmm
    src/main.cpp
    src/host/privilege.cpp
    src/whp/partition.cpp
    src/whp/memory.cpp
    src/whp/vcpu.cpp
    src/whp/run_loop.cpp
    src/whp/cpuid.cpp
    src/whp/cpu_affinity.cpp
    src/whp/hv_enlightenment.cpp
    src/whp/snapshot.cpp
    src/whp/snapshot_file.cpp
    src/whp/vcpu_state.cpp
    src/devices/io_bus.cpp
    src/devices/mmio_bus.cpp
    src/devices/serial8250.cpp
    src/devices/pit8254.cpp
    src/devices/legacy_isa.cpp
    src/devices/i8259.cpp
    src/virtio/virtqueue.cpp
    src/virtio/virtio_mmio.cpp
    src/virtio/virtio_net.cpp
    src/virtio/virtio_pci.cpp
    src/virtio/virtio_blk.cpp
    src/virtio/virtio_rng.cpp
    src/virtio/virtio_console.cpp
    src/virtio/virtio_9p.cpp
    src/virtio/net_loopback.cpp
    src/virtio/net_xdp.cpp
    src/virtio/net_wintun.cpp
    src/virtio/net_usernet.cpp
    src/virtio/net_usernet_tsi.cpp
    src/net/tsi_sanity.cpp
    src/net/wintun_loader.cpp
    src/net/wintun_adapter_mgr.cpp
    src/net/wintun_device_path.cpp
    src/net/wintun_svc_client.cpp
    third_party/wintunumapi/cpp/wintun_session.cpp
    src/host/block_file.cpp
    src/host/mapped_file.cpp
    src/host/rng.cpp
    src/host/xdp_probe.cpp
    src/whp/notification_port.cpp
    src/whp/msi.cpp
    src/pci/pci_device.cpp
    src/pci/pci_bus.cpp
    src/pci/msix.cpp
    src/boot/pvh_loader.cpp
    src/boot/acpi_tables.cpp
    src/diag/etw.cpp
    src/debug/gdbstub.cpp
)

target_include_directories(tinyvmm PRIVATE
    src
    "${XDP_INCLUDE_DIR}"
    third_party/wintunumapi/cpp
    third_party/wintun
    "${TSI_INCLUDE_DIR}"
)

target_link_libraries(tinyvmm PRIVATE
    WinHvPlatform.lib
    WinHvEmulation.lib
    # XDP-for-Windows ships its user-mode API as inline headers that hit the
    # XDP driver via NtCreateFile + NtDeviceIoControlFile, so we link ntdll
    # for those Nt* exports. No xdpapi.lib required.
    ntdll.lib
    # IPHLPAPI: CreateUnicastIpAddressEntry / Get|SetIpInterfaceEntry for
    # configuring the WinTun adapter's IPv4 address (M16).
    Iphlpapi.lib
    # Ws2_32: InetPton, basic Winsock helpers used by net_wintun.cpp.
    Ws2_32.lib
    # PathFileExistsW used by net/wintun_loader.cpp for DLL discovery.
    Shlwapi.lib
    # SetupAPI + Cfgmgr32: device-interface enumeration for resolving
    # the wintun device path (\\?\...) by LUID. Used by both the DLL
    # and wintunsvc-driven adapter managers (see src/net/wintun_*.cpp).
    SetupAPI.lib
    Cfgmgr32.lib
    # tcp-sans-io (M34): the Rust crate is built as a staticlib by the
    # `tcp_sans_io_build` custom target above. We link the resulting
    # tcp_sans_io.lib directly. The Rust toolchain may also reference
    # bcrypt (BCryptGenRandom from the `getrandom` crate path) and
    # userenv (from std startup); MSVC auto-links most CRT/Win32
    # imports, but bcrypt is the one Rust staticlibs reliably need
    # explicitly.
    "${TSI_STATIC_LIB}"
    Bcrypt.lib
)
# Ensure the cargo build runs before the linker tries to consume the .lib.
add_dependencies(tinyvmm tcp_sans_io_build)

target_compile_definitions(tinyvmm PRIVATE
    _WIN32_WINNT=0x0A00      # Windows 10
    NOMINMAX
    WIN32_LEAN_AND_MEAN
    UNICODE _UNICODE
)

# The XDP headers redefine STATUS_* macros that winnt.h already declared
# (a handful of overlap entries). They're all identical numeric values
# but /W4 turns C4005 into a warning and /WX promotes it to an error.
# Suppress C4005 only for the XDP-touching translation unit.
set_source_files_properties(src/virtio/net_xdp.cpp src/host/xdp_probe.cpp PROPERTIES
    COMPILE_FLAGS "/wd4005"
)

# The vendored wintun session header `#define`s WIN32_LEAN_AND_MEAN that
# we already defined globally via target_compile_definitions; identical
# value but /W4 still emits C4005. Suppress just for the TUs that pull
# wintun_session.hpp.
set_source_files_properties(
    third_party/wintunumapi/cpp/wintun_session.cpp
    PROPERTIES COMPILE_FLAGS "/wd4005"
)

if(MSVC)
    # Distinguish real MSVC cl.exe from Clang in MSVC-compat mode
    # (clang-cl). `if(MSVC)` is true for both. Some flags are MSVC-only
    # (/analyze, /sdl, /Wall + /external:*, /Qspectre) and clang-cl
    # either warns about them or interprets them very differently.
    set(IS_MSVC_CL ON)
    set(IS_CLANG_CL OFF)
    if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        set(IS_MSVC_CL OFF)
        set(IS_CLANG_CL ON)
    endif()

    target_compile_options(tinyvmm PRIVATE
        /W4 /WX
        /permissive- /Zc:__cplusplus /Zc:preprocessor
        /utf-8
        /EHsc
        # ----- Modern C++ conformance ratchets -----
        # /Zc:throwingNew  - assume operator new throws (it does); enables
        #                    optimizer to skip null-checks after `new T`.
        # /Zc:strictStrings - disallow `char*` (non-const) binding to a
        #                    string literal. Catches a class of OOB-write
        #                    bugs where C-style string code writes through
        #                    a literal-backed pointer.
        # /Zc:rvalueCast   - reject malformed casts that produce a value
        #                    category mismatch the standard forbids.
        # /Zc:referenceBinding - reject binding a non-const lvalue ref to
        #                    a temporary (an old MSVC extension).
        # /Zc:inline       - never emit non-referenced inline functions in
        #                    the obj; trims link work.
        # /Zc:ternary      - C++17-standard ternary operand conversions.
        /Zc:throwingNew /Zc:strictStrings /Zc:rvalueCast
        /Zc:referenceBinding /Zc:inline /Zc:ternary
        # ----- Control Flow Guard -----
        # /guard:cf instruments indirect calls with an OS-checked CFG
        # bitmap so an attacker who corrupts a vtable can't redirect
        # control flow to an arbitrary address.
        /guard:cf
    )

    if(IS_MSVC_CL)
        target_compile_options(tinyvmm PRIVATE
            # ----- SDL (Security Development Lifecycle) checks -----
            # /sdl is a superset of /GS that:
            #  * Promotes a hand-picked set of warnings to errors (C4146,
            #    C4308, C4532, C4533, C4700, C4789, C4995, C4996...) that
            #    cover well-known security pitfalls.
            #  * Forces /guard:cf-friendly codegen.
            #  * Enables strict const propagation through string literals
            #    (overlaps with /Zc:strictStrings).
            /sdl
        )
    endif()

    if(IS_CLANG_CL)
        # clang-cl quietly accepts most MSVC `/wdNNNN` flags but emits
        # `-Wunknown-warning-option` for codes it doesn't have an
        # internal mapping for, plus `-Wunused-command-line-argument`
        # for compile-only flags showing up in link lines. Silence both
        # so the build stays /WX-clean.
        target_compile_options(tinyvmm PRIVATE
            -Wno-unknown-warning-option
            -Wno-unused-command-line-argument
            # clang-cl warns about Microsoft-specific constructs we
            # legitimately use (e.g. casts between function pointers
            # used with GetProcAddress). Already covered by MSVC C4191.
            -Wno-microsoft-cast
            -Wno-language-extension-token
        )
        # The XDP and third-party headers ship with /W4-style
        # warnings under clang-cl (missing-field-initializers,
        # pragma-pack mismatches, enum-int conversions). Mark them
        # as system includes via `/imsvc` so their diagnostics are
        # suppressed wholesale, matching what /external:I does for
        # cl.exe.
        target_compile_options(tinyvmm PRIVATE
            "/imsvc${XDP_INCLUDE_DIR}"
            "/imsvc${CMAKE_SOURCE_DIR}/third_party"
            "/imsvc${CMAKE_SOURCE_DIR}/third_party/wintunumapi/cpp"
            "/imsvc${CMAKE_SOURCE_DIR}/third_party/wintun"
        )
    endif()

    # ----- Opt-in Spectre mitigation -----
    # /Qspectre injects LFENCE around speculative-load patterns where
    # the load is on a bounds-check fail path. Requires the
    # Spectre-mitigated libraries to be installed (VS Installer →
    # Individual components → "MSVC vNNN Spectre-mitigated libs").
    # Off by default because the libs aren't always present.
    option(TINYVMM_QSPECTRE "Enable /Qspectre Spectre v1 mitigation" OFF)
    if(TINYVMM_QSPECTRE AND IS_MSVC_CL)
        target_compile_options(tinyvmm PRIVATE /Qspectre)
    endif()

    # Hardening link options that aren't enabled by default in all
    # CMake-generated link lines.
    target_link_options(tinyvmm PRIVATE
        /GUARD:CF            # CFG (mirror of /guard:cf at link time)
        /CETCOMPAT           # Intel CET shadow stack support
        /DYNAMICBASE         # ASLR opt-in (default ON, but be explicit)
        /NXCOMPAT            # DEP / NX opt-in
        /HIGHENTROPYVA       # 64-bit ASLR
        # M34.2: tcp-sans-io's Tcb is ~2 MiB (two BUF_CAP=1 MiB rings
        # inline). Even with NRVO, the Rust compiler doesn't reliably
        # elide every intermediate (Result<Tcb, _> -> TcpStreamHandle
        # wrap -> ptr::write to caller's heap slot), so `tcp_init` can
        # transiently consume ~2 MiB of caller stack. Windows' default
        # main-thread stack is 1 MiB, which is not enough. Bump to
        # 16 MiB for headroom. Worker threads (M34.3+) must be created
        # with an explicit stack size of at least 8 MiB via
        # _beginthreadex(...) -- std::thread's default 1 MiB is not
        # enough.
        /STACK:16777216
    )

    # ----- MSVC static analysis (Code Analysis, aka PREfast) -----
    # On by default: the default ruleset (NativeRecommendedRules) is the
    # high-signal one (buffer overruns, null derefs, untested error
    # paths, unchecked truncations) and our code passes it clean. Turn
    # off (-DTINYVMM_ANALYZE=OFF) only if you need a faster local
    # rebuild — every Build *must* run /analyze clean.
    option(TINYVMM_ANALYZE "Enable MSVC /analyze static analysis" ON)
    if(TINYVMM_ANALYZE AND IS_MSVC_CL)
        target_compile_options(tinyvmm PRIVATE
            /analyze
            /analyze:external-
        )
    endif()

    # ----- Opt-in AddressSanitizer -----
    # `cmake -DTINYVMM_ASAN=ON` adds /fsanitize=address. Works on x64
    # MSVC since VS 2019 16.9. Catches heap buffer overflow,
    # use-after-free, double-free, stack-buffer-overflow,
    # global-buffer-overflow, container-overflow.
    #
    # Note: ASan is incompatible with /RTC1 (Debug runtime checks) and
    # with /Zi being separated. We disable /RTC1 in Debug below.
    # Also: must NOT mix ASan-instrumented and non-instrumented
    # objects in one binary; we apply it to the whole target.
    option(TINYVMM_ASAN "Enable AddressSanitizer instrumentation" OFF)
    if(TINYVMM_ASAN)
        target_compile_options(tinyvmm PRIVATE
            /fsanitize=address
            /Zi   # PDB required for ASan symbolication
        )
        target_compile_definitions(tinyvmm PRIVATE _DISABLE_VECTOR_ANNOTATION=1)
        # /RTC* and /INCREMENTAL collide with ASan.
        target_compile_options(tinyvmm PRIVATE /RTC- )
        target_link_options(tinyvmm PRIVATE /INCREMENTAL:NO)
    endif()

    # ----- Opt-in UndefinedBehaviorSanitizer (clang-cl only) -----
    # `cmake -DTINYVMM_UBSAN=ON -DCMAKE_CXX_COMPILER=clang-cl
    #  -G Ninja ...` builds with `-fsanitize=undefined`. Catches
    # signed-integer overflow, bad shifts, misaligned loads,
    # out-of-range enum values, null deref, bad vtable pointers,
    # bad function-pointer casts, and a few more — the runtime
    # category complements ASan (spatial bugs) and /analyze
    # (statically-decidable issues).
    #
    # Requires clang-cl 13+. The UBSan runtime libs are bundled with
    # the standalone LLVM install at
    #   C:/Program Files/LLVM/lib/clang/<v>/lib/windows/
    # We auto-detect the path and let the user override it via
    # -DTINYVMM_UBSAN_RT_DIR=...
    option(TINYVMM_UBSAN "Enable UndefinedBehaviorSanitizer (clang-cl only)" OFF)
    if(TINYVMM_UBSAN)
        if(NOT IS_CLANG_CL)
            message(FATAL_ERROR
                "TINYVMM_UBSAN requires clang-cl. Configure with "
                "-DCMAKE_CXX_COMPILER=clang-cl -G Ninja.")
        endif()
        # The XDP-for-Windows inline-function headers use C-style
        # aggregate init that clang-cl rejects in C++20 mode regardless
        # of -W flags (`XSK_BIND_IN Bind = {0}` — int→enum hard error).
        # Build a stub XDP backend instead. UBSan targets the
        # adversarial-guest paths (virtqueue, virtio devices, ELF
        # loader, memory), not the host XDP backend; nothing of value
        # is lost.
        target_compile_definitions(tinyvmm PRIVATE TINYVMM_NO_XDP)
        # Locate the clang_rt.ubsan_standalone-*.lib bundled with the
        # active LLVM toolchain. We walk the clang-cl install dir up to
        # `clang/<version>/lib/windows`.
        get_filename_component(_LLVM_BIN "${CMAKE_CXX_COMPILER}" DIRECTORY)
        get_filename_component(_LLVM_ROOT "${_LLVM_BIN}" DIRECTORY)
        file(GLOB _UBSAN_RT_DIRS "${_LLVM_ROOT}/lib/clang/*/lib/windows")
        list(LENGTH _UBSAN_RT_DIRS _UBSAN_RT_DIRS_LEN)
        if(_UBSAN_RT_DIRS_LEN EQUAL 0)
            message(FATAL_ERROR
                "Could not locate clang_rt.ubsan_*.lib under "
                "${_LLVM_ROOT}/lib/clang/*/lib/windows. Pass "
                "-DTINYVMM_UBSAN_RT_DIR=<dir> with the directory "
                "containing clang_rt.ubsan_standalone-x86_64.lib.")
        endif()
        list(GET _UBSAN_RT_DIRS 0 _UBSAN_RT_DIR)
        set(TINYVMM_UBSAN_RT_DIR "${_UBSAN_RT_DIR}" CACHE PATH
            "Directory containing clang_rt.ubsan_standalone-x86_64.lib")
        message(STATUS "tinyvmm UBSan runtime dir: ${TINYVMM_UBSAN_RT_DIR}")

        target_compile_options(tinyvmm PRIVATE
            -fsanitize=undefined
            # Abort the process on the first UB finding instead of the
            # default "print and continue". A continuing process can
            # corrupt state further and hide the real cause.
            -fno-sanitize-recover=undefined
            # Suppress findings whose root cause is in third-party SDK
            # headers we cannot patch (e.g. TraceLoggingProvider.h's
            # pre-offsetof `&((T*)0)->field` idiom).
            "-fsanitize-ignorelist=${CMAKE_SOURCE_DIR}/tools/ubsan_ignorelist.txt"
            # Stable backtraces — /Oy- is the clang-cl spelling of
            # `-fno-omit-frame-pointer`.
            /Oy-
            /Zi
        )
        # LLVM ships only the static-CRT (`/MT`) variant of the UBSan
        # runtime libs on Windows. Match by forcing the whole target
        # to MultiThreaded (static release CRT) for the UBSan flavor.
        set_property(TARGET tinyvmm PROPERTY
            MSVC_RUNTIME_LIBRARY "MultiThreaded")
        target_link_libraries(tinyvmm PRIVATE
            "${TINYVMM_UBSAN_RT_DIR}/clang_rt.ubsan_standalone-x86_64.lib"
            "${TINYVMM_UBSAN_RT_DIR}/clang_rt.ubsan_standalone_cxx-x86_64.lib"
        )
        # UBSan handlers reference these Win32 helpers via the runtime.
        target_link_libraries(tinyvmm PRIVATE
            dbghelp.lib  # symbol resolution for UBSan reports
        )
        target_link_options(tinyvmm PRIVATE /INCREMENTAL:NO)
    endif()

    # ----- /Wall + system-header exclusion -----
    # Default ON: with the curated `/wdNNNN` silencings below the
    # signal-to-noise ratio is good. Turn off with -DTINYVMM_WALL=OFF
    # for a slightly faster iteration loop, but every Build *must*
    # complete /Wall + /analyze + /WX clean.
    #
    # /Wall + /external:* are MSVC-only. clang-cl's /Wall expands to
    # -Weverything which is unreasonably noisy; skip there.
    option(TINYVMM_WALL "Enable MSVC /Wall (every warning)" ON)
    if(TINYVMM_WALL AND IS_MSVC_CL)
        # Re-declare the third-party + XDP headers as SYSTEM so /Wall
        # doesn't drown us in warnings from them. On MSVC,
        # target_include_directories(... SYSTEM ...) emits /external:I.
        target_include_directories(tinyvmm SYSTEM PRIVATE
            "${XDP_INCLUDE_DIR}"
            "${CMAKE_SOURCE_DIR}/third_party"
        )
        target_compile_options(tinyvmm PRIVATE
            /Wall
            /external:W0 /external:anglebrackets
            # Suppress purely-informational /Wall warnings:
            /wd4820  /wd4710  /wd4711  /wd5045  /wd4514
            /wd4868  /wd5246  /wd4191
            # Implicit copy/move special-member-deletion noise:
            /wd4626  /wd4625  /wd5027  /wd5026
            # /Wall noise we don't want:
            #   C4061: enum case not explicitly handled (we use
            #          `default:` catchall everywhere; the higher-
            #          signal C4062, which fires when no default
            #          exists, is intentionally kept).
            #   C4365: 'int' to <narrower unsigned> sign-conversion.
            #          Fires on benign integer-literal initializers
            #          like `uint8_t x = 0xAB;`. /analyze C26451
            #          ("arithmetic overflow") catches the actual
            #          attacker-data overflow cases.
            /wd4061  /wd4365
        )
    endif()
endif()

# ---------------------------------------------------------------------------
# Output directory: a flat build/<config>/ layout so we can find the .exe easily
# ---------------------------------------------------------------------------
set_target_properties(tinyvmm PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/bin"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/bin"
    RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_BINARY_DIR}/bin"
)
