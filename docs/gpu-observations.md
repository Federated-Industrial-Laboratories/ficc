# GPU observations

FICC collects optional GPU readings through its Linux helper. NVIDIA readings
use a bounded nvidia-smi query. Generic AMD readings use the documented amdgpu
sysfs and hwmon interfaces. Neither collector changes device settings.

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
The wire fields are unchanged, so older NVIDIA-only helper samples remain valid.

## Qualification

For 0.2.6r1, the method is checked against the kernel's documented attributes and
units. Synthetic sysfs fixtures check discovery, partial readings, malformed
values, missing permissions and mixed GPU inventories. Integration checks cover
the helper, API, display and CUDA reservation boundary.

Direct AMD hardware testing has not been performed by the project for this
revision. Exact device, kernel and permission combinations remain unqualified.
RX 590 testing, hardware-specific tuning and wider hardware qualification are
planned for 0.2.6r2 with the contributor's hardware results. The documented
mapping and passing software checks do not establish a hardware support matrix.

Hardware reports should include the GPU model, kernel and driver versions,
readable attributes, helper-account permissions, idle and bounded-load readings,
and missing-sensor behavior. Exclude private host details and credentials.
