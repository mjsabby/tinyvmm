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
# ---------------------------------------------------------------------------
set(XDP_ROOT "C:/xdp-for-windows" CACHE PATH "Path to the XDP for Windows source tree")
set(XDP_INCLUDE_DIR "${XDP_ROOT}/published/external")
if(NOT EXISTS "${XDP_INCLUDE_DIR}/xdpapi.h")
    message(WARNING "XDP headers not found at ${XDP_INCLUDE_DIR}; XDP-backed devices will not build")
endif()

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
    src/virtio/net_loopback.cpp
    src/virtio/net_xdp.cpp
    src/virtio/net_wintun.cpp
    src/net/wintun_loader.cpp
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
)

target_include_directories(tinyvmm PRIVATE
    src
    "${XDP_INCLUDE_DIR}"
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
)

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

if(MSVC)
    target_compile_options(tinyvmm PRIVATE
        /W4 /WX
        /permissive- /Zc:__cplusplus /Zc:preprocessor
        /utf-8
        /EHsc
    )
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
