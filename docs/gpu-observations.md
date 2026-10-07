# GPU observations

FICC collects optional GPU readings through its Linux and macOS helpers. NVIDIA
readings use a bounded nvidia-smi query. Generic AMD readings use the documented
amdgpu sysfs and hwmon interfaces. Apple Silicon readings use IORegistry driver
statistics. These collectors do not change device settings or require sudo.

## Generic AMD readings

The helper discovers DRM card entries under /sys/class/drm, resolves each device
and checks its amdgpu driver binding. Duplicate entries for one PCI device produce
one record. Discovery runs for each sample; card and hwmon numbers are not fixed.

| Field | Kernel attribute | Unit |
| --- | --- | --- |
| memory_total_bytes | device/mem_info_vram_total | Bytes |
| memory_used_bytes | device/mem_info_vram_used | Bytes |
| utilization_percent | device/gpu_busy_percent | Percent |
| temperature_c | Device amdgpu hwmon temp1_input | Millidegrees Celsius divided by 1000 |

The kernel documents the [VRAM counters and optional product information](https://docs.kernel.org/gpu/amdgpu/driver-misc.html)
and [utilization and temperature interfaces](https://docs.kernel.org/gpu/amdgpu/thermal.html).
An absent, unreadable or invalid field remains null. Available fields remain
visible when another sensor is missing. A missing reading does not mean zero use.
Samples retain the existing age and stale-state behavior.

AMD memory totals are driver-reported VRAM. On an integrated GPU this can be a
small reserved region. GTT system memory is not added to that total.

The record's uuid field contains AMD-PCI- followed by the PCI address, for
example AMD-PCI-0000:03:00.0. This is a machine-local observation identifier,
not a device serial number. Moving hardware can change it. Product names are
optional; the helper uses a generic AMD GPU label when no valid name is available.

The ordinary helper account needs read access to the attributes. ROCm, sudo and
device control permissions are not required. Attribute availability depends on
the device, driver and kernel. The combined inventory is limited to 64 GPUs.
NVIDIA records precede AMD records when the combined inventory reaches that limit.
The existing capabilities.gpu_source field identifies the returned sources.

AMD records are observation-only. They cannot be selected or admitted for CUDA
reservations. Observation does not add AMD job execution support. CPU jobs and
existing NVIDIA execution retain their current requirements.

Upgrade the controller package and use Overview's **Upgrade helper** action for
existing SSH nodes. Updating the controller alone does not replace remote helpers.
The optional per-GPU fields `source`, `memory_kind` and `reservation_supported`
identify the measurement source, memory semantics and reservation eligibility.
Defaults keep older helper samples valid. Existing CUDA UUID checks also keep
older AMD samples out of reservation controls.

## Apple Silicon readings

The macOS helper runs `/usr/sbin/ioreg -a -r -d 1 -c AGXAccelerator` with a
three-second deadline and a 1 MiB output limit. It parses the plist without an
additional package or privileged daemon. An Intel Mac without an AGX accelerator
reports Apple GPU observation as unsupported.

| Field | IORegistry value | Unit |
| --- | --- | --- |
| name | model | Driver model name |
| utilization_percent | PerformanceStatistics / Device Utilization % | Percent |
| memory_used_bytes | PerformanceStatistics / In use system memory | Bytes |
| memory_total_bytes | Not inferred | Null |
| temperature_c | Not inferred | Null |

Driver statistics vary with the chip and macOS version. Missing or invalid
readings remain null, and a discovered GPU remains visible even when no readings
are available. The UI labels Apple memory as unified memory shared with the
system. System RAM and allocated bytes are not dedicated GPU capacity.

The uuid contains APPLE-REGISTRY- followed by IORegistryEntryID in hexadecimal.
It identifies the device within the current boot and is not a persistent hardware
serial number. Apple devices are observation-only and cannot reserve CUDA job
capacity. Existing native macOS node capabilities are unchanged.

## Qualification

Synthetic fixtures cover discovery, partial readings, malformed values, missing
permissions, mixed NVIDIA/AMD inventories and bounded command execution. Browser
checks cover unified memory, driver-reported VRAM, unavailable readings and the
CUDA reservation boundary at desktop and narrow widths.

Hardware observations were checked on an AMD Raphael integrated GPU alongside an
NVIDIA RTX 4090 on Linux 7.2.3 with the amdgpu driver, and an Apple M5 Pro
running macOS 26.5.2. The AMD driver exposed
512 MiB of VRAM, about 16 MiB used, zero idle utilization and a 37–38 °C
sensor reading. Its separate GTT capacity was excluded. The packaged Apple
helper returned valid observations over SSH with Homebrew Python 3.14.7;
the driver exposed utilization and used unified memory. Apple total memory and
temperature remained null. These are observation checks, not GPU job execution
qualification or a comprehensive load test.

Discrete AMD hardware, RX 590 behavior and wider device/kernel combinations
remain unqualified. An APU hardware check does not close the discrete-hardware
coverage requested in issue #16.

Hardware reports should include the GPU model, kernel and driver versions,
readable attributes, helper-account permissions, idle and bounded-load readings,
and missing-sensor behavior. Exclude private host details and credentials.
