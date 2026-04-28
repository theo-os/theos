# Plan: Fix Page Fault, Enforce Real Rootfs, and Restore SMP

## Objective
Address the page fault occurring during `ntdll.dll` patching, transition the project to exclusively use the real Windows ISO rootfs (removing the minimal profile), and restore Symmetric Multiprocessing (SMP) functionality using UEFI's Multi-Processor Services.

## Key Files & Context
- `tools/run.rs`: Manages the build and execution environment, including rootfs generation.
- `kernel/user.rs`: Contains the `ntdll.dll` heap global patching logic causing the page fault.
- `kernel/kernel.rs`: The UEFI entry point (`efi_main`) and kernel initialization.
- `kernel/smp.rs`: SMP topology and Application Processor (AP) initialization.

## Implementation Steps

### 1. Enforce Real Rootfs Profile (`tools/run.rs`)
- **Action:** Update the `run.rs` script to default to the `windows-real` (or `windows`, depending on the established naming convention for the actual ISO extraction) profile instead of falling back to `minimal`.
- **Action:** Remove the `minimal` profile handling, including the fallback logic if the ISO is not found. The build should fail explicitly if the required Windows ISO is missing.
- **Action:** Remove the steps that compile and install the custom `native_init` (e.g., `init.exe`, `child.exe`, custom `ntdll.dll`) into the staging directory, as the real Windows binaries will be used.

### 2. Page Fault Safety Check (`kernel/user.rs`)
- **Action:** In the `seed_ntdll_heap_globals` function, add a safety check to ensure `ntdll.size_of_image` is large enough to contain the hardcoded offsets (`0x1d3fc0`, `0x1d3fc8`, `0x1d3fe0`) before attempting to write to them. This prevents writes to unmapped memory.

### 3. Restore SMP via UEFI (`kernel/kernel.rs` & `kernel/smp.rs`)
- **Action:** In `kernel/kernel.rs` (`efi_main`), locate the `uefi::proto::pi::mp::MpServices` protocol.
- **Action:** If `MpServices` is available, retrieve the number of processors.
- **Action:** Define an AP entry procedure that spins on a global atomic flag (e.g., `AP_START_SIGNAL`).
- **Action:** Use `MpServices::startup_all_aps` to start all APs in the background (non-blocking), passing the spin procedure.
- **Action:** In `kernel/smp.rs` (`init`), set the `AP_START_SIGNAL` to release the spinning APs.
- **Action:** The APs, once released, will execute the existing `ap_entry` logic: initializing their local GDT, IDT, APIC, and syscall MSRs, then halting.
- **Action:** Update the topology reporting to reflect the discovered and online CPUs correctly.

## Verification & Testing
- Run `buck2 run :run`.
- Verify the build enforces the real ISO requirement.
- Observe the boot logs to confirm `SMP topology` reports `discovered_cpus > 1` and `online_cpus > 1`.
- Confirm the kernel proceeds past the `ntdll.dll` patching without a page fault and successfully launches the init process from the real rootfs.
