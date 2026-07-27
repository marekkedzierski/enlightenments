#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdint.h>
#include <intrin.h>

typedef unsigned __int64 QWORD;

#define HVL_QUERY_ENLIGHTENMENT_INFO 0x5b

typedef NTSTATUS(WINAPI* PNT_QUERY_SYSTEM_INFORMATION)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);

//
// HvlEnlightenments bit definitions
//
// Source: ntoskrnl.exe (SwapContext, KiPreprocessFlushTb, HvlGetEnlightenmentInfo,
//         KiHvInterruptDispatch, HvlpDetermineEnlightenments, and many others).
//
// HvlEnlightenments is a 32-bit DWORD internally (HvlpDetermineEnlightenments writes
// a DWORD; NtQuerySystemInformation class 0x5b zero-extends it to a QWORD in the output
// struct). The mask 0x7CFFFFF7 is applied unconditionally at init time, so bits 3, 24,
// 25, and 31 are permanently zero and will never appear in any output.
//
// Source of each bit is one of:
//   HVI = HviGetEnlightenmentInformation (enlightenment recommendation word from CPUID)
//   HVI-F = HVI features word (HviGetHypervisorFeatures DWORD at given offset)
//   HV204 = root-partition-only HV register 0x204 (upper 32 bits)
//   EXT = HvlpQueryExtendedCapabilities result byte
//

// -- Bits 0-2: TLB / address-space switch hypercalls --
// Always set together in practice: HVI bit 0 sets {0,1,2,23}; HVI bit 1 sets {1,2,23};
// HVI bit 2 sets {2,23} (or {2} alone if HVI bit 17 set or PRCB[0x8D]==2).

// SwapContext: calls HvlSwitchVirtualAddressSpace instead of MOV CR3.
#define HV_USE_HYPERCALL_FOR_ADDRESS_SPACE_SWITCH   (1ULL << 0)

// KiPreprocessFlushTb: skips per-processor scan, goes directly to HvlFlushRangeListTb.
#define HV_USE_HYPERCALL_FOR_LOCAL_FLUSH            (1ULL << 1)

// KiPreprocessFlushTb: master gate -- enables the TLB flush hypercall path at all
// (replaces inter-processor TLB shootdown IPIs).
#define HV_USE_HYPERCALL_FOR_REMOTE_FLUSH           (1ULL << 2)

// Bit 3: PERMANENTLY ZERO (masked by 0x7CFFFFF7). Never set.

// HvlGetEnlightenmentInfo: installs HvlEndSystemInterrupt and HvlWriteApicCommandRegister
// so the OS uses synthetic MSRs for APIC access instead of MMIO.
// Source: HVI bit 3.
#define HV_USE_APIC_VIA_MSR                         (1ULL << 4)

// Relaxed timing: kernel does not flush TBs on lock acquire.
// Source: HVI bit 5.
#define HV_USE_RELAXED_TIMING                       (1ULL << 5)

// HvlGetEnlightenmentInfo: installs HvlNotifyLongSpinWait function pointer.
// Source: HVI bit 6 (indirectly -- set into slot+20h).
#define HV_USE_HYPERCALL_FOR_NOTIFY_LONG_SPIN_WAIT  (1ULL << 6)

// Unknown capability bit. Set from HVI features DWORD-3 bit 4.
// No direct test site found in this binary.
#define HV_CAPABILITY_BIT7                          (1ULL << 7)

// HvlGetEnlightenmentInfo: installs HvlGetReferenceTimeUsingTscPage for the
// reference-time path. Requires HVI features bits 1 AND 9 to both be present.
#define HV_USE_REFERENCE_TSC_PAGE                   (1ULL << 8)

// Unknown capability bit. Set from HVI features DWORD-3 bit 5.
// No direct test site found in this binary.
#define HV_CAPABILITY_BIT9                          (1ULL << 9)

// HvlpInitializePowerStatistics + PpmIdleUpdateHvStates: enables power-statistics
// hypercall (code 0x9B) and HvlConfigureIdleStates. Root-partition feature.
// Source: HV204 bit 0.
#define HV_POWER_IDLE_HYPERCALL                     (1ULL << 10)

// KiComputeNumaCosts: uses HvlQueryNumaDistance hypercall instead of native NUMA
// distance tables when computing inter-node costs.
// Source: HVI-F DWORD-3 bit 7.
#define HV_NUMA_DISTANCE_HYPERCALL                  (1ULL << 11)

// KiHvInterruptDispatch: calls HalPerformEndOfInterrupt (explicit EOI) after
// dispatching each interrupt. Corresponds to the "Deprecate AutoEOI" recommendation.
// Source: HVI bit 9.
#define HV_SYNIC_APIC_EOI                           (1ULL << 12)

// HvlLogGuestCrashInformation (called by KeBugCheck2): writes BSOD crash parameters
// to synthetic MSRs 0x40000101-0x40000104 for hypervisor capture.
// Note: HvlDisableEnlightenment(1) preserves ONLY this bit during hibernate save.
// Source: HVI-F DWORD-3 bit 10.
#define HV_GUEST_CRASH_MSR_REPORTING                (1ULL << 13)

// HvlGetEnlightenmentInfo: installs HvlSendSyntheticClusterIpi for sending
// IPIs to processor sets via hypercall.
// Source: HVI bit 10.
#define HV_SYNTHETIC_CLUSTER_IPI                    (1ULL << 14)

// HvlGetEnlightenmentInfo: installs HvlHalStartVirtualProcessor and
// HvlHalGetVpIndexFromApicId for virtual-processor start and index management.
// Source: HVI features bit 49 (QWORD).
#define HV_VP_START_ENLIGHTENMENT                   (1ULL << 15)

// HvlGetEnlightenmentInfo: installs HvlSetSystemSleepProperty, HvlEnterSleepState,
// HvlNotifyDebugDeviceAvailable. Also sets HvlHyperVRootPartition = 1.
// Root-partition feature.
// Source: HV204 bit 31 (sign bit of upper dword).
#define HV_SLEEP_POWER_MANAGEMENT                   (1ULL << 16)

// Unknown root-partition capability. Set from HV204 bit 1.
// No direct test site found in this binary.
#define HV_ROOT_CAPABILITY_BIT17                    (1ULL << 17)

// PpmParkSetLpiCap: permits LPI (Low Power Idle) capacity operations on
// multi-processor systems. Also set when HV scheduler type == 4 (Root).
// Source: HV204 bit 2.
#define HV_LPI_CAP_ENLIGHTENMENT                    (1ULL << 18)

// HvlpDetermineEnlightenments: sets this bit when CPUID enlightenment data
// bit 13 is set AND VslGetNestedPageProtectionFlags() returns NPF bit 1.
// Raw code: `bts ebx, 13h` at ntoskrnl line 1843943.
// NOTE: the direct write to SharedUserData+0x308 was NOT found within the
// HvlpDetermineEnlightenments function in the analysed disassembly. The write
// may occur in KiInitializeKernel which reads HvlEnlightenments bit 19 and
// copies it to SharedUserData+0x308, but this path was not confirmed by raw code.
#define HV_SHARED_USER_DATA_HV_FLAG                 (1ULL << 19)

// HvlIsHypercallOverlayLocked: indicates the hypercall overlay page is locked.
// Source: HVI-F DWORD-3 bit 18.
#define HV_HYPERCALL_OVERLAY_LOCKED                 (1ULL << 20)

// HvlNotifyPageHeat first gate. Both bits 21 and 22 must be set to enable
// page heat notifications. Bits 21+22+27 together enable the extended ack variant.
// Source: EXT bit 1.
#define HV_PAGE_HEAT_NOTIFY_GATE1                   (1ULL << 21)

// HvlNotifyPageHeat second gate.
// Source: EXT bit 2.
#define HV_PAGE_HEAT_NOTIFY_GATE2                   (1ULL << 22)

// KiPreprocessFlushTb: when bit 2 is set but bit 1 is clear and the caller
// requests a full/entire TLB invalidation, gates use of HvlFlushRangeListTb
// for the broadcast-flush case (bt eax, 17h = bit 23).
// Always set alongside bits 0/1/2 (same HVI source).
#define HV_BROADCAST_TLB_FLUSH_HYPERCALL            (1ULL << 23)

// Bits 24, 25: PERMANENTLY ZERO (masked by 0x7CFFFFF7). Never set.

// HvlFlushTbAllPartitions: when set AND VSM/VTL is enabled, issues extended
// hypercall 0x213 for cross-partition TLB invalidation instead of VslFlushEntireTb.
// Source: HVI-F DWORD-3 bits 4 AND 28.
#define HV_VSM_CROSS_PARTITION_TLB_FLUSH            (1ULL << 26)

// MiBackgroundZeroLocalPages, MmSetPfnListInfo: enables the extended page heat
// notification variant that expects an acknowledgment (tested as 0x8400000 = bits 22+27).
// Source: EXT bit 7 (sign bit).
#define HV_PAGE_HEAT_ACK_EXTENDED                   (1ULL << 27)

// PpmUpdateIdleStates: installs PpmIdleGuestPreExecute / PpmIdleGuestComplete
// callbacks so the hypervisor manages CPU idle state transitions.
// Source: HV204 bit 3.
#define HV_GUEST_IDLE_MANAGEMENT                    (1ULL << 28)

// HvlGetEnlightenmentInfo: installs HvlRestoreTime (time restoration hypercall).
// Source: HVI bit 20.
#define HV_RESTORE_TIME                             (1ULL << 29)

// HvlGetEnlightenmentInfo: installs HvlWakeVirtualProcessors (wake VP hypercall).
// Source: HVI bit 23.
#define HV_WAKE_VIRTUAL_PROCESSORS                  (1ULL << 30)

// Bit 31: PERMANENTLY ZERO (masked by 0x7CFFFFF7). Never set.

//
// CPUID 0x40000004 EAX -- Enlightenment Recommendations (raw HVI word).
// Bit 12 is the nested-virtualisation flag. Not exposed through HvlEnlightenments
// (it is outside the 0x7CFFFFF7 mask path), so CPUID is the only way to read it.
//
#define HVI_ENLIGHTENMENT_NESTED            (1 << 12)

//
// NtQuerySystemInformation class 0x67 -- code-integrity options.
// The IUM bit is the definitive indicator that securekernel.exe is running in VTL1.
//
// NtQuerySystemInformation(0x67) delegates to ci.dll via SeCiCallbacks[+0x18]
// (CiQueryInformation, VA 0x1800D1EB0 in Server 2025).
//
// Bit 10 (0x400) — HVCI kernel-mode code integrity enforced by hypervisor:
//   Set when g_CiOptions bit 15 (0x8000) is set.
//   g_CiOptions bit 15 is set in CiInitializePolicy when:
//     1. g_HvciSupported != 0  (ntoskrnl passed non-null VslHvciInterface at boot)
//     2. VslHvciInterface[+0x58]() returns a value with bit 1 set
//        (securekernel confirming VTL1 KMCI enforcement is active)
//   Source: ci.dll lines 121782-121790, 300061-300065.
//
// Bit 11 (0x800) — HVCI audit mode, hypervisor NOT enforcing:
//   Set when g_CiDeveloperMode bit 7 (low byte) is set.
//   g_CiDeveloperMode bit 7 is set when:
//     1. Registry HvciAuditMode & 1 is set
//     2. g_CiOptions bit 15 (strict HVCI) is NOT set
//   Source: ci.dll lines 122510-122516, 300082-300086.
//   MUTUALLY EXCLUSIVE with bit 10: guard `bt cs:g_CiOptions, 0Fh; jb skip`
//   at line 122514 prevents bit 11 when bit 10 would be active.
//
// ci.dll has NO direct memory-protection calls. All NPT enforcement is in VTL1.
// Driver image registration with VTL1: ci.dll calls VslHvciInterface[+0x40]
// (transfer relocation data) which triggers securekernel to mark code pages
// non-writable in NPT. VslHvciInterface[+0x58] queries KMCI enforcement state.
//
#define SYSTEM_CODE_INTEGRITY_INFORMATION_CLASS  0x67

#ifndef CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED
// bit 10: g_CiOptions bit 15 set → VslHvciInterface[+0x58]() returned bit 1 set
#  define CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED   0x400
#endif
#ifndef CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED
// bit 11: HVCI audit mode (registry) AND strict HVCI NOT active (mutually excl. with bit 10)
#  define CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED    0x800
#endif
// SYSTEM_CODEINTEGRITY_INFORMATION is defined in winternl.h for SDK 10.0.19041+
// Do not redefine it here.

//
// NtQuerySystemInformation class 0xA9 (169) -- VSM protection info.
// Verified against HvlQueryVsmProtectionInfo at ntoskrnl 0x140A781C8.
//
// THREE PATHS depending on HvlHypervisorConnected AND HvlpFlags bit 1:
//
// PATH A (HvlHypervisorConnected == 0):
//   +0x00  DmaProtectionAvailable = HvlpProcessIommu() result
//            → probes ACPI IVRS (AMD) or DMAR (Intel) via ZwQuerySystemInformation(0x4C)
//   +0x01  DmaProtectionInUse     = 0
//
// PATH B (HvlHypervisorConnected != 0 AND HvlpFlags bit 1 clear):
//   +0x00  DmaProtectionAvailable = 1 if (HvlpFlags bit 6 OR HvlpProcessIommu() != 0); else 0
//   +0x01  DmaProtectionInUse     = (HvlpFlags >> 6) & 1
//   HvlpFlags bit 6 indicates the hypervisor has asserted IOMMU-managed state even though
//   the full VSM VTL call interface (HvlpFlags bit 1) is not active.
//
// PATH C (HvlHypervisorConnected != 0 AND HvlpFlags bit 1 set):
//   Calls HviGetHardwareFeatures → CPUID(40000006h).EAX stored in tmp.
//   +0x00  DmaProtectionAvailable = (tmp.EAX >> 7) & 1   ← CPUID bit 7
//   +0x01  DmaProtectionInUse     = (tmp.EAX >> 7) & 1   ← same CPUID bit 7
//   (Both bytes get the same CPUID(40000006h).EAX bit 7 value in this path.)
//
// All three paths (confirmed raw code):
//   +0x02  HardwareMbecAvailable  = (HvlpFlags >> 17) & 1
//                                   set by HvlSetHardwareMbecAvailable via KiSetFeatureBits:
//                                     Intel: IA32_VMX_EPT_VPID_CAP MSR (48Bh) bit 54
//                                     AMD:   CPUID(8000000Ah).EDX GMET bit
//   +0x03  ApicVirtAvailable      = HvlpFlags bit 24
//                                   `mov al, byte ptr HvlpFlags+3; and al, 1`
//                                   CPUID(40000006h) bit 23 is from hypervisor CPUID emulator
//                                   (hvax64/hvix64) — symbol names user-assigned; code verified.
//   Minimum buffer: 3 bytes. Maximum meaningful: 4 bytes.
//
//
// TPM device info via Tbsi_GetDeviceInfo (tbs.dll) -- loaded dynamically.
// NtQuerySystemInformation(0xA2) (SeQueryTrustedPlatformModuleInformation) would
// be the kernel path but it checks KTHREAD.PreviousMode at offset 0x232 and
// returns STATUS_ACCESS_DENIED unconditionally for user-mode callers.
//
typedef struct _TPM_DEVICE_INFO
{
	UINT32 structVersion;
	UINT32 tpmVersion;        // 1 = TPM 1.2, 2 = TPM 2.0
	UINT32 tpmInterfaceType;  // 0 = TIS, 1 = CRB, 2 = emulated
	UINT32 tpmImpRevision;
} TPM_DEVICE_INFO;

typedef UINT32(WINAPI* PFN_Tbsi_GetDeviceInfo)(UINT32 Size, PVOID Info);

//
// NtQuerySystemInformation class 0xC4 (196) -- KVA Shadow / KPTI (Meltdown mitigation).
// Verified against KeQueryKvaShadowInformation. Minimum: 4 bytes, ReturnLength = 4.
// Single DWORD built from KiKvaShadow, KiFlushPcid, KeQueryImplementedPhysicalBits, KeFeatureBits2.
//
//   bit  0: KvaShadowEnabled          = KiKvaShadow != 0
//   bit  1: KvaShadowUserGlobal       = KiKvaShadowingActive == 2
//   bit  2: KvaShadowPcid             = KiFlushPcid bit 0
//   bit  3: KvaShadowInvpcid          = KiFlushPcid bit 1
//   bit  4: KvaShadowRequired         = SpcQueryKvaLeakagePresent() (CPU vulnerable to Meltdown)
//   bit  5: KvaShadowRequiredAvailable= always 1
//   [11:6]: ImplementedPhysicalBits-1 = (KeQueryImplementedPhysicalBits() - 1) & 0x3F
//   bit 12: KeFeatureBits2 bit 0      (5-level paging / LA57 support indicator)
//   bit 13: always 1
//
#define SYSTEM_KVA_SHADOW_INFORMATION_CLASS  0xC4

//
// NtQuerySystemInformation class 0xC9 (201) -- Speculation Control (Spectre/SSBD/L1TF/MDS).
// Verified against KeQuerySpeculationControlInformation. Minimum: 4 bytes, ReturnLength = 8.
// Two DWORDs (8 bytes total); if caller passes only 4, second DWORD is omitted.
//
// DWORD 0 -- SpeculationControlFlags (Spectre/Retpoline/IBRS/SSBD/TSX):
//   bit  0: BranchPredictorsNeedsFlushing = KiSpecFeatures[36]
//   bit  1: IBRSSupportPresent            = KiSpecFeatures[34]
//   bit  2: IBPBSupportPresent            = KiSpecFeatures[35]
//   bit  3: HardwareBranchFillMitigation  = KiSpecFeatures[4] OR KiSpecFeatures[6]
//   bit  4: KvaShadowRequired             = KiSpecFeatures[2]
//   bit  5: IBRSPresent                   = KiSpecFeatures[4]
//   bit  6: STIBPPresent                  = KiSpecFeatures[6]
//   bit  7: IBPBEnabled                   = KiSpecFeatures[5]
//   bit  8: always 1 (SSBSafeOrNotAffected)
//   bit  9: SSBDPresent                   = KiSpecFeatures[7]
//   bit 10: EnhancedIBRSPresent           = KiSpecFeatures[38]
//   bit 11: EnhancedIBRSEnabled           = KiSpecFeatures[39]
//   bit 12: RDCLNotAffected               = NOT KiSpecFeatures[8]  (inverted: 1 = not vulnerable)
//   bit 13: IBRSAndIBPBApplied            = KiSpecFeatures[36] AND KiSpecFeatures[33]
//   bit 14: MBSPresent                    = KiSpecFeatures[41]
//   bit 15: ImportOptimizationEnabled     = MiIsImportOptimizationEnabled()
//   bit 16: HvBranchPredictionIsolation   = KiSpecFeatures[0]
//   [22:17]: TSX/KeFeatureBits2 composite
//   bit 23: always 1
//   bit 24: KeFeatureBits2[5]
//   bit 25: KiKvaShadow && KeFeatureBits2[3]
//   bit 26: always 1
//   [28:27]: TsxState (00=absent, 01=present, 10=KVA shadow active, 11=disabled by policy)
//   bit 29: always 1
//   bit 30: TsxAbsentAtBoot (TSX not present when system booted)
//
// DWORD 1 -- SpeculationControlFlags2 (L1TF / MDS / TAA / SRBDS):
//   [2:0]:  L1TFMitigationState    = KeFeatureBits2[21:19] (0=not needed, 1=OS, 2=HW)
//   bit  3: FBClearPresent         = KiKvaShadow && SpcIsFbClearSupported()
//   bit  4: always 1
//   [9:8]:  TAA mitigation state   (00=no HW-TSX or not vulnerable, 10=mitigated, 11=unmitigated)
//   bit 10: always 1
//   bit 11: always 1
//   bit 12: KeFeatureBits2[4]
//   bit 13: always 1
//   [15:14]: MDSAndSRBDSState      (same encoding as TAA state)
//   bit 16: always 1
//
#define SYSTEM_SPECULATION_CONTROL_INFORMATION_CLASS  0xC9

typedef struct _SYSTEM_SPECULATION_CONTROL_INFORMATION
{
	ULONG SpeculationControlFlags;   // DWORD 0
	ULONG SpeculationControlFlags2;  // DWORD 1
} SYSTEM_SPECULATION_CONTROL_INFORMATION;

//
// NtQuerySystemInformation class 0xD5 (213) -- VTL1 (securekernel) speculation state.
// NOTE: "VTL2" in older documentation is WRONG. Securekernel IS VTL1.
//
// Handler: KeQuerySecureSpeculationInformation calls VslGetSecureSpeculationControlInformation
// which dispatches as IUM service 258 to SkeQuerySpeculationFeaturesInformation in securekernel.
//
// RAW CODE CONFIRMED (ntoskrnl lines 1922711-1922803): the bit remap is NON-LINEAR with
// 19 distinct bit remappings. VTL1 bits are NOT passed through directly. Examples:
//   VTL1 bit 0  → output bit 0   (bits 0-3: direct)
//   VTL1 bit 8  → output bit 6
//   VTL1 bit 11 → output bit 12
//   VTL1 bit 16 → output bit 5
//   VTL1 bit 17 → output bit 4
//   VTL1 bit 19 → output bit 15
// The labels printed below map to the OUTPUT bit positions after ntoskrnl's remap.
// Minimum: 4 bytes, ReturnLength = 8.
//
#define SYSTEM_SECURE_SPECULATION_CONTROL_CLASS  0xD5

//
// NtQuerySystemInformation class 0x9F (159) -- Hypervisor Detail Information.
// Verified against HvlQueryDetailInfo. Requires EXACTLY 0x70 (112) bytes.
// Seven consecutive 16-byte CPUID leaf dumps in order:
//   [0x00] CPUID 0x40000000 -- max leaf + vendor string
//   [0x10] CPUID 0x40000001 -- interface signature
//   [0x20] CPUID 0x40000002 -- hypervisor version
//   [0x30] CPUID 0x40000003 -- partition privileges / feature identification
//   [0x40] CPUID 0x40000006 -- hardware features
//   [0x50] CPUID 0x40000004 -- enlightenment recommendations
//   [0x60] CPUID 0x40000005 -- implementation limits
//
#define SYSTEM_HYPERVISOR_DETAIL_INFORMATION_CLASS  0x9F

typedef struct _HV_CPUID_LEAF
{
	ULONG Eax, Ebx, Ecx, Edx;
} HV_CPUID_LEAF;

typedef struct _SYSTEM_HYPERVISOR_DETAIL_INFORMATION
{
	HV_CPUID_LEAF Leaf40000000;  // vendor + max leaf
	HV_CPUID_LEAF Leaf40000001;  // interface signature
	HV_CPUID_LEAF Leaf40000002;  // hypervisor version
	HV_CPUID_LEAF Leaf40000003;  // partition privilege flags / feature identification
	HV_CPUID_LEAF Leaf40000006;  // hardware features (note: NOT 0x40000004 here)
	HV_CPUID_LEAF Leaf40000004;  // enlightenment recommendations (0x40000004)
	HV_CPUID_LEAF Leaf40000005;  // implementation limits (max VPs, logical CPUs)
} SYSTEM_HYPERVISOR_DETAIL_INFORMATION;

//
// NtQuerySystemInformation class 0xA6 (166) -- HSTI (Hardware Security Test Interface).
//
// SeQueryHSTIResults (ntoskrnl 0x140ADBE08):
//   *ReturnLength is ALWAYS set to the stored blob size first.
//   blob_size == 0 → STATUS_NOT_FOUND  (0xC0000225): no HSTI firmware provider.
//   SystemInformationLength < blob_size → STATUS_BUFFER_TOO_SMALL (0xC0000004).
//   Sufficient → copies via memmove (or RtlCopyToUser/RtlCopyVolatileMemory when
//   Feature_HstiUMAFix is enabled, checked per-call).
//   NOTE: if AV fires during user-mode copy, the exception handler zeroes the return
//   code → STATUS_SUCCESS is returned even though nothing was copied.
//
// Blob sourced from UEFI firmware via winload BlHSTICallProviders (winload.efi):
//   Enumerates all EFI handles exposing EFI_ADAPTER_INFORMATION_PROTOCOL,
//   queries each for EFI_ADAPTER_INFO_PLATFORM_SECURITY data (GUID
//   {6BE272C7-1320-4CCD-9017-D4612C012B25}), validates size >= 0x20C (524 bytes),
//   builds the compound wrapper blob, saves via BlpPdSaveData.
//   BapdpProcessHSTIResults retrieves from boot persistence (GUID
//   {C0D9DF24-D1DD-4E53-95EB-CBD827B86586}), allocates NonPagedPoolNx (pool tag 'HSTI'),
//   stores pointer permanently in qword_140FF2448 / size in dword_140FF2440.
//
// ci.dll CiInstrumentHstiInfo: reads outer blob[+0] and [+4] for ETW telemetry only;
//   does NOT use HSTI for any code-integrity or security enforcement decisions.
//
// THE RETURNED BLOB IS A COMPOUND WRAPPER, not a bare ADAPTER_INFO_PLATFORM_SECURITY:
//
//   OUTER BLOB (what NtQuerySystemInformation returns):
//   +0x00  DWORD  version        = 1
//   +0x04  DWORD  provider_count = N
//   +0x08  TOC[N] entries (12 bytes each):
//            +0x00 DWORD data_offset  (from blob start)
//            +0x04 DWORD data_size
//            +0x08 DWORD ntstatus     (EFI call result for this provider)
//   +0x08+N*12  provider data blobs, 4-byte aligned between entries
//
//   INNER ADAPTER_INFO_PLATFORM_SECURITY per provider
//   (min size 0x20C = 524 confirmed from winload EfiAdapterInformationGetInformation):
//   +0x000  DWORD    Version
//   +0x004  DWORD    Role              1 = Platform Manufacturer
//   +0x008  CHAR16[256] ImplementorName  (512 bytes)
//   +0x208  DWORD    SecurityFeaturesSize  = S  (bytes per features field)
//   +0x20C  BYTE[S]  SecurityFeaturesRequired
//   +0x20C+S BYTE[S] SecurityFeaturesImplemented
//   +0x20C+2S BYTE[S] SecurityFeaturesVerified
//   +0x20C+3S WCHAR[] ErrorString
//
#define SYSTEM_HSTI_INFORMATION_CLASS  0xA6

// Outer compound blob header
typedef struct _HSTI_OUTER_BLOB {
	ULONG Version;        // +0x00  always 1
	ULONG ProviderCount;  // +0x04  N
} HSTI_OUTER_BLOB;

// Per-provider TOC entry (12 bytes)
typedef struct _HSTI_TOC_ENTRY {
	ULONG DataOffset;   // from blob start
	ULONG DataSize;
	ULONG NtStatus;     // NTSTATUS from EFI call
} HSTI_TOC_ENTRY;

// Inner ADAPTER_INFO_PLATFORM_SECURITY (UEFI HSTI spec, min 0x20C bytes)
typedef struct _HSTI_PROVIDER_BLOB {
	ULONG Version;               // +0x000
	ULONG Role;                  // +0x004
	WCHAR ImplementorName[256];  // +0x008  512 bytes
	ULONG SecurityFeaturesSize;  // +0x208  S bytes per field
	// BYTE SecurityFeaturesRequired[S]    follows at +0x20C
	// BYTE SecurityFeaturesImplemented[S] follows at +0x20C+S
	// BYTE SecurityFeaturesVerified[S]    follows at +0x20C+2S
	// WCHAR ErrorString[]                follows at +0x20C+3S
} HSTI_PROVIDER_BLOB;

//
// NtQuerySystemInformation class 0xA5 (165) -- Device Guard / VBS flags.
// Verified against ExpQuerySystemInformation case 165 at ntoskrnl 0x140ACF920.
//
// Minimum buffer: 0x10 bytes. Kernel copies 16 bytes via movaps xmm0.
//
// Byte +0 -- built from VslIsSecureKernelRunning + VslGetNestedPageProtectionFlags (NPF):
//   bit 0: SecureKernelRunning     = VslIsSecureKernelRunning()
//   bit 1: HvciKernelEnforcement   = NPF bit 1  (HVCI strict kernel-mode CI)
//   bit 2: HvciUserModeEnabled     = NPF bit 5  (user-mode CI / NX via VSM)
//   bit 3: HvciAuditMode           = NPF bit 4  (HVCI enforcement not yet locked)
//   bit 4: FirmwarePageProtection  = ExpFirmwarePageProtectionSupported & 1
//   bit 5: IumEnabled              = VslpEnterIumSecureMode() succeeded (IUM active)
//
// Byte +1 -- VslIsTrustletRunning + further NPF bits:
//   bit 0: TrustletRunning         = VslIsTrustletRunning()
//                                    NOTE: VslIsTrustletRunning makes a LIVE VTL1 call
//                                    via VslpEnterIumSecureMode(mode=2) and reads field
//                                    at output+0x10 -- it is not a global flag read.
//   bit 1: KmciSupplemental        = NPF bit 9
//   bit 2: KernelShadowStacks      = NPF bit 11 (CET-SS for kernel via VSM)
//   bit 3: KernelShadowStacksStrict= NPF bit 12
//   bit 4: ProtectionFlag_13       = NPF bit 13
//   bit 5: ProtectionFlag_16       = NPF bit 16
//   bit 6: ProtectionFlag_18       = NPF bit 18
//
// Byte +2:
//   bit 0: ProtectionFlag_19       = NPF bit 19
//
// Bytes +3..+15: zero (struct is zero-initialised before individual bits are set)
//
#define SYSTEM_DEVICE_GUARD_INFORMATION_CLASS  0xA5

typedef struct _SYSTEM_DEVICE_GUARD_INFORMATION
{
	BYTE  Flags0;     // byte +0 (see bit map above)
	BYTE  Flags1;     // byte +1
	BYTE  Flags2;     // byte +2
	BYTE  Reserved[13];
} SYSTEM_DEVICE_GUARD_INFORMATION;

//
// NtQuerySystemInformation class 0xDD (221) -- CET / Shadow Stack status.
// Verified against ExpQuerySystemInformation case 221 at ntoskrnl 0x140ACF920.
//
// Minimum buffer: 4 bytes. Returns one ULONG built from four KeIs* helpers:
//   bit 0: CetHardwareSupported  = KeIsCetCapable()
//   bit 1: CetUserModeEnabled    = KeIsUserCetAllowed()
//   bit 8: CetKernelModeEnabled  = KeIsKernelCetEnabled()
//   bit 9: CetKernelAuditMode    = KeIsKernelCetAuditModeEnabled()
//
#define SYSTEM_SHADOW_STACK_INFORMATION_CLASS  0xDD

#define SYSTEM_VSM_PROTECTION_INFORMATION_CLASS  0xA9

typedef struct _SYSTEM_VSM_PROTECTION_INFORMATION
{
	BYTE DmaProtectionAvailable;
	BYTE DmaProtectionInUse;
	BYTE HardwareMbecAvailable;
	BYTE ApicVirtAvailable;
} SYSTEM_VSM_PROTECTION_INFORMATION;

typedef struct _HV_FLAG_INFO
{
	QWORD       Flag;
	const char* Name;
	const char* Description;
} HV_FLAG_INFO;

static const HV_FLAG_INFO EnlightenmentFlags[] =
{
	{ HV_USE_HYPERCALL_FOR_ADDRESS_SPACE_SWITCH,  "UseHypercallForAddressSpaceSwitch",  "SwapContext: HvlSwitchVirtualAddressSpace instead of MOV CR3" },
	{ HV_USE_HYPERCALL_FOR_LOCAL_FLUSH,           "UseHypercallForLocalFlush",          "KiPreprocessFlushTb: skip per-processor scan, use HvlFlushRangeListTb directly" },
	{ HV_USE_HYPERCALL_FOR_REMOTE_FLUSH,          "UseHypercallForRemoteFlush",         "KiPreprocessFlushTb: master gate enabling TLB flush hypercall (replaces IPI shootdown)" },
	{ HV_USE_APIC_VIA_MSR,                        "UseApicViaMsr",                      "HvlGetEnlightenmentInfo: HvlEndSystemInterrupt + HvlWriteApicCommandRegister (SynIC APIC)" },
	{ HV_USE_RELAXED_TIMING,                      "UseRelaxedTiming",                   "No TLB flush on lock acquire (HVI recommendation bit 5)" },
	{ HV_USE_HYPERCALL_FOR_NOTIFY_LONG_SPIN_WAIT, "UseHypercallForNotifyLongSpinWait",  "HvlGetEnlightenmentInfo: enables HvlNotifyLongSpinWait" },
	{ HV_CAPABILITY_BIT7,                         "CapabilityBit7",                     "Set from HVI features DWORD-3 bit 4; no direct call site identified" },
	{ HV_USE_REFERENCE_TSC_PAGE,                  "UseReferenceTscPage",                "HvlGetEnlightenmentInfo: enables HvlGetReferenceTimeUsingTscPage (HVI features bits 1+9)" },
	{ HV_CAPABILITY_BIT9,                         "CapabilityBit9",                     "Set from HVI features DWORD-3 bit 5; no direct call site identified" },
	{ HV_POWER_IDLE_HYPERCALL,                    "PowerIdleHypercall",                 "HvlpInitializePowerStatistics + HvlConfigureIdleStates (root partition; HV reg 0x204 bit 0)" },
	{ HV_NUMA_DISTANCE_HYPERCALL,                 "NumaDistanceHypercall",              "KiComputeNumaCosts: HvlQueryNumaDistance instead of native NUMA tables" },
	{ HV_SYNIC_APIC_EOI,                          "SynicApicEoi",                       "KiHvInterruptDispatch: explicit EOI via HalPerformEndOfInterrupt (HVI bit 9 = DeprecateAutoEOI)" },
	{ HV_GUEST_CRASH_MSR_REPORTING,               "GuestCrashMsrReporting",             "HvlLogGuestCrashInformation: BSOD data to synthetic MSRs 0x40000101-0x40000104" },
	{ HV_SYNTHETIC_CLUSTER_IPI,                   "SyntheticClusterIpi",                "HvlGetEnlightenmentInfo: enables HvlSendSyntheticClusterIpi (HVI bit 10)" },
	{ HV_VP_START_ENLIGHTENMENT,                  "VpStartEnlightenment",               "HvlGetEnlightenmentInfo: HvlHalStartVirtualProcessor + HvlHalGetVpIndexFromApicId (HVI features bit 49)" },
	{ HV_SLEEP_POWER_MANAGEMENT,                  "SleepPowerManagement",               "HvlGetEnlightenmentInfo: HvlSetSystemSleepProperty + HvlEnterSleepState + HvlNotifyDebugDeviceAvailable; sets HvlHyperVRootPartition" },
	{ HV_ROOT_CAPABILITY_BIT17,                   "RootCapabilityBit17",                "Root partition capability (HV reg 0x204 upper-dword bit 1); no direct call site found" },
	{ HV_LPI_CAP_ENLIGHTENMENT,                   "LpiCapEnlightenment",                "PpmParkSetLpiCap: allows LPI capacity operations on multi-processor systems" },
	{ HV_SHARED_USER_DATA_HV_FLAG,                "SharedUserDataHvFlag",               "KiInitializeKernel (BSP): writes 1 to SharedUserData+0x308 (user-mode Hyper-V active flag)" },
	{ HV_HYPERCALL_OVERLAY_LOCKED,                "HypercallOverlayLocked",             "HvlIsHypercallOverlayLocked: hypercall page overlay is locked" },
	{ HV_PAGE_HEAT_NOTIFY_GATE1,                  "PageHeatNotifyGate1",                "HvlNotifyPageHeat: first gate (EXT bit 1)" },
	{ HV_PAGE_HEAT_NOTIFY_GATE2,                  "PageHeatNotifyGate2",                "HvlNotifyPageHeat: second gate (EXT bit 2); used alone or combined with bit 27 for ack variant" },
	{ HV_BROADCAST_TLB_FLUSH_HYPERCALL,           "BroadcastTlbFlushHypercall",         "KiPreprocessFlushTb: entire/broadcast TLB flush via hypercall; always set with bits 0+1+2" },
	{ HV_VSM_CROSS_PARTITION_TLB_FLUSH,           "VsmCrossPartitionTlbFlush",          "HvlFlushTbAllPartitions: extended hypercall 0x213 for cross-partition TLB flush when VSM active" },
	{ HV_PAGE_HEAT_ACK_EXTENDED,                  "PageHeatAckExtended",                "MiBackgroundZeroLocalPages/MmSetPfnListInfo: extended page heat with ack (tested as bits 22+27 = 0x8400000)" },
	{ HV_GUEST_IDLE_MANAGEMENT,                   "GuestIdleManagement",                "PpmUpdateIdleStates: installs PpmIdleGuestPreExecute/PpmIdleGuestComplete (HV reg 0x204 bit 3)" },
	{ HV_RESTORE_TIME,                            "RestoreTime",                        "HvlGetEnlightenmentInfo: enables HvlRestoreTime (HVI bit 20)" },
	{ HV_WAKE_VIRTUAL_PROCESSORS,                 "WakeVirtualProcessors",              "HvlGetEnlightenmentInfo: enables HvlWakeVirtualProcessors (HVI bit 23)" },
};

void PrintEnlightenments(QWORD HvlEnlightenments)
{
	printf("\nWindows guest enlightenments:\n");
	printf("Raw HvlEnlightenments: 0x%016llX\n", HvlEnlightenments);
	printf("(bits 3, 24, 25, 31 are permanently masked to 0 by ntoskrnl)\n");
	printf("------------------------------------------------------------\n");
	printf("%-40s | %s\n", "Name", "Description");
	printf("------------------------------------------------------------\n");

	int found = 0;
	int numFlags = (int)(sizeof(EnlightenmentFlags) / sizeof(EnlightenmentFlags[0]));

	for (int i = 0; i < numFlags; i++)
	{
		if (HvlEnlightenments & EnlightenmentFlags[i].Flag)
		{
			printf("%-40s | %s\n", EnlightenmentFlags[i].Name, EnlightenmentFlags[i].Description);
			found = 1;
		}
	}

	if (!found)
		printf("No enlightenments active.\n");
}

const char* GetSchedulerTypeString(BYTE type)
{
	switch (type)
	{
	case 1: return "Classic (SMT disabled)";
	case 2: return "Classic";
	case 3: return "Core";
	case 4: return "Root";
	}
	return "Unknown";
}

void PrintStimerCapabilities()
{
	int cpuInfo[4] = { 0 };
	__cpuid(cpuInfo, 0x40000003);

	// CPUID 0x40000003 EAX: Hyper-V feature identification (VP features)
	bool hasSynIc = (cpuInfo[0] & (1 << 1)) != 0;  // AccessSynicRegs
	bool hasStimer = (cpuInfo[0] & (1 << 2)) != 0;  // AccessSyntheticTimerRegs
	bool hasDirectStimer = (cpuInfo[0] & (1 << 12)) != 0;  // AccessDirectSyntheticTimers

	printf("\nHypervisor Feature Identification (CPUID 0x40000003 EAX):\n");
	printf("------------------------------------------------------------\n");
	printf("%-35s | %s\n", "Feature", "Status");
	printf("------------------------------------------------------------\n");
	printf("%-35s | %s\n", "SynIC (AccessSynicRegs)", hasSynIc ? "[YES]" : "[NO]");
	printf("%-35s | %s\n", "Synthetic Timers (STIMER)", hasStimer ? "[YES]" : "[NO]");
	printf("%-35s | %s\n", "Direct Mode STIMER", hasDirectStimer ? "[YES]" : "[NO]");
}

void DumpHypervisorFeatures()
{
	int cpuInfo[4] = { 0 };
	__cpuid(cpuInfo, 0x40000003);

	// EAX: VP runtime features; EBX: partition privilege flags
	printf("\nHyper-V Feature Identification (CPUID 0x40000003):\n");
	printf("EAX (VP features)    : 0x%08X\n", cpuInfo[0]);
	printf("EBX (Partition priv) : 0x%08X\n", cpuInfo[1]);
	printf("------------------------------------------------------------\n");
	printf("%-35s | %s\n", "Feature", "Status");
	printf("------------------------------------------------------------\n");
	printf("%-35s | %s\n", "AccessVpRunTimeReg", (cpuInfo[0] & (1 << 0)) ? "[YES]" : "[NO]");
	printf("%-35s | %s\n", "AccessSynicRegs", (cpuInfo[0] & (1 << 1)) ? "[YES]" : "[NO]");
	printf("%-35s | %s\n", "AccessSyntheticTimerRegs", (cpuInfo[0] & (1 << 2)) ? "[YES]" : "[NO]");
	printf("%-35s | %s\n", "CreatePartitions", (cpuInfo[1] & (1 << 0)) ? "[YES]" : "[NO]");
	printf("%-35s | %s\n", "AccessPartitionId", (cpuInfo[1] & (1 << 1)) ? "[YES]" : "[NO]");
}

//
// _NK_FLAGS: appears to correspond to HVI_HYPERVISOR_FEATURES (HviGetHypervisorFeatures
// output), not to HvlEnlightenments. Kept for reference; not used in the query path.
//
union _NK_FLAGS
{
	unsigned __int64 all;
	struct
	{
		unsigned __int64 Nested : 1;
		unsigned __int64 SynicAccessible : 1;
		unsigned __int64 VpIndexAccessible : 1;
		unsigned __int64 VpAssistPage : 1;
		unsigned __int64 SintPollingModeAvailable : 1;
		unsigned __int64 FastHypercallOutputAvailable : 1;
		unsigned __int64 XmmRegistersForFastHypercallAvail : 1;
		unsigned __int64 LowerHypervisorLevel : 4;
		unsigned __int64 ApicEnlightened : 1;
		unsigned __int64 ReferenceTimeEnlightened : 1;
		unsigned __int64 IpiEnlightened : 1;
		unsigned __int64 VmcsEnlightenmentsPresent : 1;
		unsigned __int64 FlushGpaHypercallAvailable : 1;
		unsigned __int64 NestedFlushVirtualHypercallAvail : 1;
		unsigned __int64 TscEmulationAvailable : 1;
		unsigned __int64 TscEmulationConfigured : 1;
		unsigned __int64 MsrBitmap : 1;
		unsigned __int64 GuestCrashRegsAvailable : 1;
		unsigned __int64 FrequencyRegsAvailable : 1;
		unsigned __int64 DirectSyntheticTimers : 1;
		unsigned __int64 VirtualizationExceptionEnlightened : 1;
		unsigned __int64 SyntheticTimeUnhaltedTimerAvail : 1;
		unsigned __int64 NoNonArchitecturalCoreSharing : 1;
		unsigned __int64 GuestIdleAvailable : 1;
		unsigned __int64 DebugCtlSupported : 1;
		unsigned __int64 LbrAvailable : 1;
		unsigned __int64 PerfGlobalCtrlSupported : 1;
		unsigned __int64 IdleSpecCtrlAvailable : 1;
		unsigned __int64 TscInvariantAvailable : 1;
		unsigned __int64 UseHypercallForRemoteFlush : 1;
		unsigned __int64 UseHypercallForLocalFlushEntire : 1;
		unsigned __int64 Reserved0 : 5;
		unsigned __int64 PmuAvailable : 1;
		unsigned __int64 Reserved1 : 24;
	} Bits;
};

void PrintTpmAndCredentialGuardInfo()
{
	//
	// TPM -- Tbsi_GetDeviceInfo (tbs.dll).
	// Returns version, interface type, and implementation revision.
	// Works from user mode without elevation.
	//
	printf("\nTPM:\n");
	printf("------------------------------------------------------------\n");

	HMODULE hTbs = LoadLibraryW(L"tbs.dll");
	if (hTbs)
	{
		auto pfnGetDeviceInfo = (PFN_Tbsi_GetDeviceInfo)
			GetProcAddress(hTbs, "Tbsi_GetDeviceInfo");

		if (pfnGetDeviceInfo)
		{
			TPM_DEVICE_INFO tpm = { sizeof(tpm) };
			UINT32 result = pfnGetDeviceInfo(sizeof(tpm), &tpm);

			if (result == 0)
			{
				const char* verStr = tpm.tpmVersion == 1 ? "TPM 1.2" :
					tpm.tpmVersion == 2 ? "TPM 2.0" : "Unknown";
				const char* ifcStr = tpm.tpmInterfaceType == 0 ? "TIS" :
					tpm.tpmInterfaceType == 1 ? "CRB" :
					tpm.tpmInterfaceType == 2 ? "Emulated" : "Unknown";

				printf("%-48s : %u (%s)\n", "TPM version", tpm.tpmVersion, verStr);
				printf("%-48s : %u (%s)\n", "Interface type", tpm.tpmInterfaceType, ifcStr);
				printf("%-48s : %u\n", "Implementation revision", tpm.tpmImpRevision);
			}
			else
			{
				printf("%-48s : Tbsi_GetDeviceInfo failed (0x%X)\n", "TPM", result);
			}
		}
		else
		{
			printf("%-48s : Tbsi_GetDeviceInfo not found in tbs.dll\n", "TPM");
		}

		FreeLibrary(hTbs);
	}
	else
	{
		printf("%-48s : tbs.dll not available (no TPM or service stopped)\n", "TPM");
	}

	//
	// Credential Guard.
	//
	// Two independent indicators:
	//   1. DeviceGuard scenario registry key -- "Enabled" and "Running" values
	//      written by the OS (Running=1 confirmed at boot if CG is active).
	//   2. LSA config flags -- what is *configured* in policy regardless of
	//      whether the VM actually started.
	//
	printf("\nCredential Guard:\n");
	printf("------------------------------------------------------------\n");

	HKEY  hKey;
	DWORD value, size;

	// DeviceGuard scenario key -- most reliable running-state indicator
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
		L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\CredentialGuard",
		0, KEY_READ, &hKey) == ERROR_SUCCESS)
	{
		value = 0; size = sizeof(value);
		if (RegQueryValueExW(hKey, L"Enabled", NULL, NULL, (LPBYTE)&value, &size) == ERROR_SUCCESS)
			printf("%-48s : %s\n", "Configured (Scenarios\\CredentialGuard\\Enabled)",
				value ? "YES" : "NO");

		value = 0; size = sizeof(value);
		if (RegQueryValueExW(hKey, L"Running", NULL, NULL, (LPBYTE)&value, &size) == ERROR_SUCCESS)
			printf("%-48s : %s\n", "Running   (Scenarios\\CredentialGuard\\Running)",
				value ? "YES" : "NO");

		RegCloseKey(hKey);
	}
	else
	{
		printf("%-48s : key absent\n",
			"Scenarios\\CredentialGuard");
	}

	// LsaCfgFlags -- LSA policy configuration
	// 0 = disabled, 1 = enabled with UEFI lock, 2 = enabled without UEFI lock
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
		L"SYSTEM\\CurrentControlSet\\Control\\Lsa",
		0, KEY_READ, &hKey) == ERROR_SUCCESS)
	{
		value = 0; size = sizeof(value);
		if (RegQueryValueExW(hKey, L"LsaCfgFlags", NULL, NULL, (LPBYTE)&value, &size) == ERROR_SUCCESS)
		{
			const char* cfgStr = value == 0 ? "disabled" :
				value == 1 ? "enabled + UEFI lock" :
				value == 2 ? "enabled, no UEFI lock" : "unknown";
			printf("%-48s : 0x%X (%s)\n", "LSA policy (Lsa\\LsaCfgFlags)", value, cfgStr);
		}
		RegCloseKey(hKey);
	}

	// VBS enablement policy (parent DeviceGuard key)
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
		L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard",
		0, KEY_READ, &hKey) == ERROR_SUCCESS)
	{
		value = 0; size = sizeof(value);
		if (RegQueryValueExW(hKey, L"EnableVirtualizationBasedSecurity",
			NULL, NULL, (LPBYTE)&value, &size) == ERROR_SUCCESS)
			printf("%-48s : %s\n", "VBS enabled (DeviceGuard\\EnableVBS)", value ? "YES" : "NO");

		value = 0; size = sizeof(value);
		if (RegQueryValueExW(hKey, L"RequirePlatformSecurityFeatures",
			NULL, NULL, (LPBYTE)&value, &size) == ERROR_SUCCESS)
		{
			const char* reqStr = value == 1 ? "Secure Boot" :
				value == 2 ? "DMA protection" :
				value == 3 ? "Secure Boot + DMA protection" : "unknown";
			printf("%-48s : 0x%X (%s)\n",
				"Platform security required (DeviceGuard\\Require*)", value, reqStr);
		}

		RegCloseKey(hKey);
	}

	//
	// Remaining DeviceGuard scenarios: HVCI, SystemGuard, KernelShadowStacks.
	// Each follows the same Enabled/Running pattern as CredentialGuard.
	//
	struct { const wchar_t* subkey; const char* label; } scenarios[] = {
		{ L"HypervisorEnforcedCodeIntegrity", "HVCI / Memory Integrity" },
		{ L"SystemGuard",                     "System Guard / Secure Launch (DRTM)" },
		{ L"KernelShadowStacks",              "Kernel Shadow Stacks (CET-SS)" },
	};

	for (int i = 0; i < 3; i++)
	{
		wchar_t path[256];
		swprintf_s(path, 256,
			L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\%s",
			scenarios[i].subkey);

		if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &hKey) == ERROR_SUCCESS)
		{
			value = 0; size = sizeof(value);
			BOOL gotEnabled = (RegQueryValueExW(hKey, L"Enabled",
				NULL, NULL, (LPBYTE)&value, &size) == ERROR_SUCCESS);
			DWORD enabledVal = value;

			value = 0; size = sizeof(value);
			BOOL gotRunning = (RegQueryValueExW(hKey, L"Running",
				NULL, NULL, (LPBYTE)&value, &size) == ERROR_SUCCESS);
			DWORD runningVal = value;

			printf("\n%s:\n", scenarios[i].label);
			if (gotEnabled) printf("  %-44s : %s\n", "Configured (Enabled)", enabledVal ? "YES" : "NO");
			if (gotRunning) printf("  %-44s : %s\n", "Running", runningVal ? "YES" : "NO");
			RegCloseKey(hKey);
		}
		else
		{
			printf("\n%s:\n  (scenario key absent)\n", scenarios[i].label);
		}
	}
}

static void PrintBit(const char* name, ULONG flags, ULONG bit)
{
	printf("  %-52s : %s\n", name, (flags >> bit) & 1 ? "YES" : "NO");
}

static void PrintTwoBit(const char* name, ULONG flags, ULONG lobit, const char* s00,
	const char* s01, const char* s10, const char* s11)
{
	const char* strs[4] = { s00, s01, s10, s11 };
	printf("  %-52s : %s\n", name, strs[(flags >> lobit) & 3]);
}

void PrintSpeculationControlInfo(PNT_QUERY_SYSTEM_INFORMATION NtQuerySystemInformation)
{
	ULONG returnLength = 0;

	//
	// 0xC4 -- KVA Shadow / KPTI (Meltdown mitigation)
	//
	printf("\nKVA Shadow / KPTI (0xC4 KeQueryKvaShadowInformation):\n");
	printf("------------------------------------------------------------\n");

	ULONG kva = 0;
	NTSTATUS status = NtQuerySystemInformation(
		(SYSTEM_INFORMATION_CLASS)SYSTEM_KVA_SHADOW_INFORMATION_CLASS,
		&kva, sizeof(kva), &returnLength);

	if (!NT_SUCCESS(status))
	{
		printf("  query failed: 0x%X\n", status);
	}
	else
	{
		PrintBit("KvaShadowEnabled       [0]  KPTI active", kva, 0);
		PrintBit("KvaShadowUserGlobal    [1]  user-mode shadow", kva, 1);
		PrintBit("KvaShadowPcid          [2]  PCID flush", kva, 2);
		PrintBit("KvaShadowInvpcid       [3]  INVPCID method", kva, 3);
		PrintBit("KvaShadowRequired      [4]  CPU vulnerable/Meltdown", kva, 4);
		PrintBit("KvaShadowRequiredAvail [5]  always 1", kva, 5);
		printf("  %-52s : %u\n", "ImplementedPhysicalBits [11:6] +1",
			((kva >> 6) & 0x3F) + 1);
		PrintBit("KeFeatureBits2[0]      [12] (LA57/5-level paging)", kva, 12);
		printf("  Raw KVA DWORD: 0x%08X\n", kva);
	}

	//
	// 0xC9 -- Speculation Control (Spectre / SSBD / L1TF / MDS / TSX)
	//
	printf("\nSpeculation Control (0xC9 KeQuerySpeculationControlInformation):\n");
	printf("------------------------------------------------------------\n");

	SYSTEM_SPECULATION_CONTROL_INFORMATION spec = { 0 };
	status = NtQuerySystemInformation(
		(SYSTEM_INFORMATION_CLASS)SYSTEM_SPECULATION_CONTROL_INFORMATION_CLASS,
		&spec, sizeof(spec), &returnLength);

	if (!NT_SUCCESS(status))
	{
		printf("  query failed: 0x%X\n", status);
	}
	else
	{
		ULONG f0 = spec.SpeculationControlFlags;
		ULONG f1 = spec.SpeculationControlFlags2;

		printf(" DWORD 0 -- Spectre/Retpoline/IBRS/SSBD/TSX:\n");
		PrintBit("BranchPredictorsNeedsFlushing [0]", f0, 0);
		PrintBit("IBRSSupportPresent            [1]", f0, 1);
		PrintBit("IBPBSupportPresent            [2]", f0, 2);
		PrintBit("HardwareBranchFillMitigation  [3]", f0, 3);
		PrintBit("KvaShadowRequired             [4]", f0, 4);
		PrintBit("IBRSPresent                   [5]", f0, 5);
		PrintBit("STIBPPresent                  [6]", f0, 6);
		PrintBit("IBPBEnabled                   [7]", f0, 7);
		PrintBit("SSBSafeOrNotAffected          [8] always1", f0, 8);
		PrintBit("SSBDPresent                   [9]", f0, 9);
		PrintBit("EnhancedIBRSPresent           [10]", f0, 10);
		PrintBit("EnhancedIBRSEnabled           [11]", f0, 11);
		PrintBit("RDCLNotAffected               [12] inv", f0, 12);
		PrintBit("IBRSAndIBPBApplied            [13]", f0, 13);
		PrintBit("MBSPresent                    [14]", f0, 14);
		PrintBit("ImportOptimizationEnabled     [15]", f0, 15);
		PrintBit("HvBranchPredictionIsolation   [16]", f0, 16);
		PrintTwoBit("TsxState [28:27]", f0, 27,
			"absent", "present", "KVA shadow active", "disabled by policy");
		PrintBit("TsxAbsentAtBoot               [30]", f0, 30);
		printf("  Raw DWORD 0: 0x%08X\n", f0);

		printf(" DWORD 1 -- L1TF / MDS / TAA / SRBDS:\n");
		printf("  %-52s : %u\n", "L1TFMitigationState [2:0] (0=OK,1=OS,2=HW)", f1 & 7);
		PrintBit("FBClearPresent           [3]  (MDS/TAA fill-buf clear)", f1, 3);
		PrintTwoBit("TAA state             [9:8]  (0=N/A,2=mitigated,3=unmitigated)",
			f1, 8, "N/A or no HW-TSX", "?", "mitigated", "present unmitigated");
		PrintTwoBit("MDS/SRBDS state       [15:14] (same encoding as TAA)",
			f1, 14, "N/A", "?", "mitigated", "present unmitigated");
		printf("  Raw DWORD 1: 0x%08X\n", f1);
	}

	//
	// 0xD5 -- VTL1 (securekernel) speculation control state.
	//
	// NOTE: there is no VTL2 in standard Windows VBS. Securekernel.exe IS VTL1.
	// The label "VTL2" in older documentation is incorrect; the correct term is VTL1.
	//
	// Data source: SkeQuerySpeculationFeaturesInformation (securekernel 0x14008EA18),
	// dispatched as IUM service 0x102 (258) via:
	//   KeQuerySecureSpeculationInformation
	//   → VslGetSecureSpeculationControlInformation (VslpEnterIumSecureMode mode=2)
	//   → HvlSwitchToVsmVtl1 (VMCALL into VTL1)
	//   → SkeQuerySpeculationFeaturesInformation
	// NOTE: SkiUpdateSpeculationControl (different function) writes per-CPU MSRs from
	// scheduler/init paths. It is NOT on the class 0xD5 query path.
	//
	// ntoskrnl applies a NON-LINEAR bit remap (16 remap pairs, 18 total bit operations
	// including 2 complementary clears, confirmed in KeQuerySecureSpeculationInformation).
	// SK bits → output bits (SK source confirmed from securekernel disassembly):
	//   SK bit  0 → output bit  0   (always-1 sentinel: hardcoded in SK)
	//   SK bit  1 → output bit  1   (SkiKvaShadow != 0)
	//   SK bit  2 → output bit  2   (SkiKvaShadowMode == 2; mutually clears output bit 3)
	//   SK bit  3 → output bit  3   (SkiKvaShadowMode == 1; mutually clears output bit 2)
	//   SK bit  4 = SkiKvaShadowMode == 1 AND SkiFlushPcid bit 1 — DROPPED by ntoskrnl (no output bit)
	//   SK bits 5-7: not set by SkeQuerySpeculationFeaturesInformation
	//   SK bit  8 → output bit  6   (!SkiSpeculationFeatures[16] && !SkiSpeculationFeatures[17])
	//   SK bit  9 → output bit  7   (SkiSpeculationFeatures[4])
	//   SK bit 10 → output bit  8   (SkiSpeculationFeatures[0])
	//   SK bit 11 → output bit 12   (per-CPU gs:0xAB0 bit 1)
	//   SK bit 12 → output bit 13   (per-CPU gs:0xAB0 bit 2)
	//   SK bit 13 → output bit  9   (SkiSpeculationFeatures[6])
	//   SK bit 14 → output bit 10   (SkiSpeculationFeatures[7])
	//   SK bit 15 → output bit 11   (NOT SkiSpeculationFeatures[8] — inverted)
	//   SK bit 16 → output bit  5   (always-1 sentinel: `or ecx, 200h` then `shl ecx, 7`)
	//   SK bit 17 → output bit  4   (always-1 sentinel: `or edx, 20000h` in SK)
	//   SK bit 18 → output bit 14   (SkiSpeculationFeatures[9] OR SkiSpeculationFeatures[13])
	//   SK bit 19 → output bit 15   (SkiSpeculationFeatures[12])
	// per-CPU gs:0xAB0 flags feed boundary-enforcement bits (written by SkiUpdateSpeculationControl,
	// read by SkeQuerySpeculationFeaturesInformation during VTL1 query).
	//
	printf("\nSecure Speculation Control (0xD5 -- VTL1 securekernel state):\n");
	printf("------------------------------------------------------------\n");

	ULONG secspec = 0;
	status = NtQuerySystemInformation(
		(SYSTEM_INFORMATION_CLASS)SYSTEM_SECURE_SPECULATION_CONTROL_CLASS,
		&secspec, sizeof(secspec), &returnLength);

	if (!NT_SUCCESS(status))
	{
		printf("  query failed: 0x%X\n", status);
	}
	else
	{
		// Output bit positions are AFTER ntoskrnl KeQuerySecureSpeculationInformation remap.
		// SK source bits confirmed from code; output bits confirmed from ntoskrnl remap.
		// Parenthetical SK-bit tag shows the verified SK source for each output bit.
		printf("  Raw VTL1 (securekernel) speculation DWORD: 0x%08X\n", secspec);
		PrintBit("VTL1 sentinel always-1           [0] SK0:  hardcoded", secspec, 0);
		PrintBit("VTL1 KPTI active                 [1] SK1:  SkiKvaShadow != 0", secspec, 1);
		PrintBit("VTL1 KPTI no-PCID               [2] SK2:  SkiKvaShadowMode == 2", secspec, 2);
		PrintBit("VTL1 KPTI + PCID                [3] SK3:  SkiKvaShadowMode == 1", secspec, 3);
		PrintBit("VTL1 sentinel always-1           [4] SK17: or edx,20000h", secspec, 4);
		PrintBit("VTL1 sentinel always-1           [5] SK16: or ecx,200h + shl 7", secspec, 5);
		PrintBit("VTL1 !SF[16]&&!SF[17]            [6] SK8:  SkiSpeculationFeatures", secspec, 6);
		PrintBit("VTL1 SF[4]                       [7] SK9:  SkiSpeculationFeatures", secspec, 7);
		PrintBit("VTL1 SF[0]                       [8] SK10: SkiSpeculationFeatures", secspec, 8);
		PrintBit("VTL1 SF[6]                       [9] SK13: SkiSpeculationFeatures", secspec, 9);
		PrintBit("VTL1 SF[7]                      [10] SK14: SkiSpeculationFeatures", secspec, 10);
		PrintBit("VTL1 NOT SF[8]                  [11] SK15: !SkiSpeculationFeatures[8]", secspec, 11);
		PrintBit("VTL1 per-CPU gs:0xAB0[1]        [12] SK11: boundary enforcement", secspec, 12);
		PrintBit("VTL1 per-CPU gs:0xAB0[2]        [13] SK12: boundary enforcement", secspec, 13);
		PrintBit("VTL1 SF[9]||SF[13]              [14] SK18: SkiSpeculationFeatures", secspec, 14);
		PrintBit("VTL1 SF[12]                     [15] SK19: SkiSpeculationFeatures", secspec, 15);
	}
}

void PrintHvDetailInfo(PNT_QUERY_SYSTEM_INFORMATION NtQuerySystemInformation)
{
	printf("\nHypervisor Detail / CPUID leaves (0x9F HvlQueryDetailInfo):\n");
	printf("------------------------------------------------------------\n");

	SYSTEM_HYPERVISOR_DETAIL_INFORMATION hd = { 0 };
	ULONG returnLength = 0;
	NTSTATUS status = NtQuerySystemInformation(
		(SYSTEM_INFORMATION_CLASS)SYSTEM_HYPERVISOR_DETAIL_INFORMATION_CLASS,
		&hd, sizeof(hd), &returnLength);

	if (!NT_SUCCESS(status))
	{
		printf("  query failed: 0x%X (requires hypervisor connected)\n", status);
		return;
	}

	// CPUID 0x40000000 -- vendor + max leaf
	char vendor[13] = { 0 };
	memcpy(vendor + 0, &hd.Leaf40000000.Ebx, 4);
	memcpy(vendor + 4, &hd.Leaf40000000.Ecx, 4);
	memcpy(vendor + 8, &hd.Leaf40000000.Edx, 4);
	printf("  Vendor string       : %.12s\n", vendor);
	printf("  Max hypervisor leaf : 0x%08X\n", hd.Leaf40000000.Eax);

	// CPUID 0x40000001 -- interface signature ("Hv#1")
	char ifc[5] = { 0 };
	memcpy(ifc, &hd.Leaf40000001.Eax, 4);
	printf("  Interface signature : %.4s\n", ifc);

	// CPUID 0x40000002 -- version
	ULONG ver = hd.Leaf40000002.Eax;
	printf("  Version             : %u.%u.%u (build %u, SP %u)\n",
		(ver >> 0) & 0xFF,   // major
		(ver >> 8) & 0xFF,   // minor
		(ver >> 16) & 0xFFFF, // build
		hd.Leaf40000002.Ebx, // service pack
		hd.Leaf40000002.Edx  // service number
	);

	// CPUID 0x40000003 -- partition privilege flags (EAX)
	ULONG pp = hd.Leaf40000003.Eax;
	printf("\n CPUID 0x40000003 EAX -- Partition Privilege Flags: 0x%08X\n", pp);
	PrintBit("CreatePartitions             [0]", pp, 0);
	PrintBit("AccessPartitionId            [1]", pp, 1);
	PrintBit("AccessMemoryPool             [2]", pp, 2);
	PrintBit("AdjustMessageBuffers         [3]", pp, 3);
	PrintBit("PostMessages                 [4]", pp, 4);
	PrintBit("SignalEvents                 [5]", pp, 5);
	PrintBit("CreatePort                   [6]", pp, 6);
	PrintBit("CreateSwitchPort             [7]", pp, 7);
	PrintBit("AccessStats                  [8]", pp, 8);
	PrintBit("Debugging                    [9]", pp, 9);
	PrintBit("CpuManagement                [10]", pp, 10);
	PrintBit("ConfigureProfiler            [11]", pp, 11);
	PrintBit("EnableExpandedStackWalk      [12]", pp, 12);
	PrintBit("AccessVsm                    [13]", pp, 13);
	PrintBit("AccessVpRegisters            [14]", pp, 14);
	PrintBit("EnableExtendedHypercalls     [15]", pp, 15);
	PrintBit("StartVirtualProcessor        [16]", pp, 16);
	PrintBit("IsolateSecureVmReservations  [17]", pp, 17);
	printf("  EBX=0x%08X  ECX=0x%08X\n",
		hd.Leaf40000003.Ebx, hd.Leaf40000003.Ecx);

	// CPUID 0x40000003 EDX -- HAL IOMMU domain capability flags.
	// Extracted by HalpIommuInitDiscard during HAL phase-1 initialisation:
	//   bit 24: HalpHvIommuDeviceDomain    -- HV provides device-level DMA isolation
	//   bit 25: HalpHvParaVirtIommuDomain  -- HV provides paravirt IOMMU domain
	ULONG edx3 = hd.Leaf40000003.Edx;
	printf("\n CPUID 0x40000003 EDX -- HAL IOMMU domain flags: 0x%08X\n", edx3);
	PrintBit("HalpHvIommuDeviceDomain    [24] HV device-level DMA isolation", edx3, 24);
	PrintBit("HalpHvParaVirtIommuDomain  [25] HV paravirt IOMMU domain",      edx3, 25);
	printf("  (remaining EDX bits undocumented / reserved)\n");

	// CPUID 0x40000004 -- enlightenment recommendations (EAX)
	ULONG er = hd.Leaf40000004.Eax;
	printf("\n CPUID 0x40000004 EAX -- Enlightenment Recommendations: 0x%08X\n", er);
	printf("  (This is the raw HVI word that HvlEnlightenments is derived from)\n");
	PrintBit("UseHypercallForAddressSpaceSwitch [0]", er, 0);
	PrintBit("UseHypercallForLocalFlush         [1]", er, 1);
	PrintBit("UseHypercallForRemoteFlush        [2]", er, 2);
	PrintBit("UseApicMsrs                       [3]", er, 3);
	PrintBit("UseHvMonitorPage                  [4]", er, 4);
	PrintBit("UseRelaxedTiming                  [5]", er, 5);
	PrintBit("UseHypercallForDmaRemapping       [6]", er, 6);
	PrintBit("UseHypercallForInterruptRemapping [7]", er, 7);
	PrintBit("UseX2ApicMsrs                     [8]", er, 8);
	PrintBit("DeprecateAutoEOI                  [9]", er, 9);
	PrintBit("UseSyntheticClusterIpi            [10]", er, 10);
	PrintBit("UseExProcessorMasks               [11]", er, 11);
	PrintBit("Nested                            [12]", er, 12);
	PrintBit("UseIntForMbecSystemCalls          [13]", er, 13);
	PrintBit("UseVmcsEnlightenments             [14]", er, 14);
	PrintBit("UseSyncedTimeline                 [15]", er, 15);
	PrintBit("UseDirectLocalFlushEntire         [16]", er, 16);
	PrintBit("NoNonArchitecturalCoreSharing     [17]", er, 17);
	PrintBit("UseHypercallForPgeFlush           [18]", er, 18);
	PrintBit("UseHypercallForRestoreTime        [20]", er, 20);
	PrintBit("UseHypercallForWakeVps            [23]", er, 23);
	printf("  EBX (spinlock retries)=0x%08X  ECX=0x%08X  EDX=0x%08X\n",
		hd.Leaf40000004.Ebx, hd.Leaf40000004.Ecx, hd.Leaf40000004.Edx);

	// CPUID 0x40000005 -- implementation limits
	printf("\n CPUID 0x40000005 -- Implementation Limits:\n");
	printf("  MaxVirtualProcessors  (EAX): %u\n", hd.Leaf40000005.Eax);
	printf("  MaxLogicalProcessors  (EBX): %u\n", hd.Leaf40000005.Ebx);
	printf("  MaxInterruptMappings  (ECX): %u\n", hd.Leaf40000005.Ecx);

	// CPUID 0x40000006 -- hardware features (EAX)
	ULONG hw = hd.Leaf40000006.Eax;
	printf("\n CPUID 0x40000006 EAX -- Hardware Features: 0x%08X\n", hw);
	PrintBit("ApicOverlayAssist                [0]", hw, 0);
	PrintBit("MsrBitmaps                       [1]", hw, 1);
	PrintBit("ArchitecturalPerfCounters        [2]", hw, 2);
	PrintBit("SecondLevelAddressTranslation    [3]", hw, 3);
	PrintBit("DmaRemapping                     [4]", hw, 4);
	PrintBit("InterruptRemapping               [5]", hw, 5);
	PrintBit("MemoryPatrolScrubber             [6]", hw, 6);
	PrintBit("DmaProtection                    [7]", hw, 7);
	PrintBit("HpetRequested                    [8]", hw, 8);
	PrintBit("SyntheticTimersVolatile          [9]", hw, 9);
	PrintBit("HypervisorLevelMachineCheck      [10]", hw, 10);
	PrintBit("GuestCrashMsrsAvailable          [11]", hw, 11);
	PrintBit("DebugRegistersAvailable          [12]", hw, 12);
	PrintBit("NpiepAvailable                   [13]", hw, 13);
	PrintBit("DisableHypervisorAvailable       [14]", hw, 14);
	PrintBit("ExtendedGvaRangesForFlush        [15]", hw, 15);
	PrintBit("XsaveXrstorAvailable             [16]", hw, 16);
	PrintBit("SupervisorShadowStackAvailable   [17]", hw, 17);
	// When bit 17 is set, securekernel (ShvlInitSystem) sets ShvlpFlags bit 3,
	// enabling VTL1 supervisor-mode shadow stacks via HV synthetic VP registers
	// 0x80008 (SSP), 0x80009 (SSCE entry hook), 0x8000A (SSCE MSR).
	PrintBit("MbecAvailable                    [18]", hw, 18);
	PrintBit("GpaSpaceReclaim                  [19]", hw, 19);
	printf("  EBX=0x%08X  ECX=0x%08X  EDX=0x%08X\n",
		hd.Leaf40000006.Ebx, hd.Leaf40000006.Ecx, hd.Leaf40000006.Edx);
}

void PrintHstiInfo(PNT_QUERY_SYSTEM_INFORMATION NtQuerySystemInformation)
{
	printf("\nHSTI -- Hardware Security Test Interface (0xA6 SeQueryHSTIResults):\n");
	printf("------------------------------------------------------------\n");

	// SeQueryHSTIResults always writes blob size to *ReturnLength before any check.
	// blob absent (size==0) → STATUS_NOT_FOUND.
	// blob present but buf too small → STATUS_BUFFER_TOO_SMALL + ReturnLength = needed.
	ULONG blobSize = 0;
	NTSTATUS st = NtQuerySystemInformation(
		(SYSTEM_INFORMATION_CLASS)SYSTEM_HSTI_INFORMATION_CLASS,
		nullptr, 0, &blobSize);

	if (blobSize == 0)
	{
		// STATUS_NOT_FOUND: no UEFI HSTI provider registered results at boot.
		printf("  No HSTI data (firmware did not publish ADAPTER_INFO_PLATFORM_SECURITY).\n");
		return;
	}
	if (st != (NTSTATUS)0xC0000004u)
	{
		printf("  Unexpected probe result: 0x%X  ReturnLength=%u\n", (UINT)st, blobSize);
		return;
	}

	BYTE* blob = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, blobSize);
	if (!blob)
	{
		printf("  HeapAlloc failed for %u bytes.\n", blobSize);
		return;
	}

	ULONG retLen = 0;
	st = NtQuerySystemInformation(
		(SYSTEM_INFORMATION_CLASS)SYSTEM_HSTI_INFORMATION_CLASS,
		blob, blobSize, &retLen);

	if (!NT_SUCCESS(st))
	{
		printf("  Second query failed: 0x%X\n", (UINT)st);
		HeapFree(GetProcessHeap(), 0, blob);
		return;
	}

	printf("  Compound blob : %u bytes  (pool tag 'HSTI', NonPagedPoolNx)\n", retLen);

	// -----------------------------------------------------------------------
	// Parse outer compound wrapper
	// -----------------------------------------------------------------------
	if (retLen < sizeof(HSTI_OUTER_BLOB))
	{
		printf("  Blob too small to parse outer header.\n");
		HeapFree(GetProcessHeap(), 0, blob);
		return;
	}

	HSTI_OUTER_BLOB* outer = (HSTI_OUTER_BLOB*)blob;
	printf("  Outer version    : %u\n", outer->Version);
	printf("  Provider count   : %u\n", outer->ProviderCount);

	const ULONG tocOff  = sizeof(HSTI_OUTER_BLOB);
	const ULONG tocSize = outer->ProviderCount * (ULONG)sizeof(HSTI_TOC_ENTRY);

	if (retLen < tocOff + tocSize)
	{
		printf("  Blob too small to contain %u-entry TOC.\n", outer->ProviderCount);
		HeapFree(GetProcessHeap(), 0, blob);
		return;
	}

	HSTI_TOC_ENTRY* toc = (HSTI_TOC_ENTRY*)(blob + tocOff);

	// -----------------------------------------------------------------------
	// Walk each provider
	// -----------------------------------------------------------------------
	for (ULONG i = 0; i < outer->ProviderCount; i++)
	{
		printf("\n  Provider[%u]:\n", i);
		printf("    data_offset : 0x%X\n", toc[i].DataOffset);
		printf("    data_size   : %u bytes\n", toc[i].DataSize);
		printf("    ntstatus    : 0x%X%s\n", toc[i].NtStatus,
			NT_SUCCESS((NTSTATUS)toc[i].NtStatus) ? "  (OK)" : "  (EFI call failed)");

		if (!NT_SUCCESS((NTSTATUS)toc[i].NtStatus))
			continue;

		// Bounds check: inner blob must fit within outer blob
		const ULONG innerMin = (ULONG)offsetof(HSTI_PROVIDER_BLOB, SecurityFeaturesSize)
		                     + (ULONG)sizeof(ULONG);
		if (toc[i].DataOffset + toc[i].DataSize > retLen
			|| toc[i].DataSize < innerMin)
		{
			printf("    (provider blob out of bounds or smaller than min %u bytes)\n",
				innerMin);
			continue;
		}

		HSTI_PROVIDER_BLOB* p = (HSTI_PROVIDER_BLOB*)(blob + toc[i].DataOffset);

		// ImplementorName: 256 UTF-16LE chars
		char name[257] = {};
		for (int j = 0; j < 256 && p->ImplementorName[j]; j++)
			name[j] = (p->ImplementorName[j] < 0x80) ? (char)p->ImplementorName[j] : '?';

		printf("    Version         : %u\n", p->Version);
		printf("    Role            : %u (%s)\n", p->Role,
			p->Role == 1 ? "Platform Manufacturer" : "unknown");
		printf("    ImplementorName : %s\n", name);
		printf("    FeaturesSize    : %u bytes per field\n", p->SecurityFeaturesSize);

		const ULONG S       = p->SecurityFeaturesSize;
		const ULONG featOff = (ULONG)offsetof(HSTI_PROVIDER_BLOB, SecurityFeaturesSize)
		                    + (ULONG)sizeof(ULONG);

		if (S == 0 || toc[i].DataSize < featOff + S * 3)
		{
			printf("    (feature fields missing or truncated)\n");
			continue;
		}

		BYTE* req   = (BYTE*)p + featOff;
		BYTE* impl  = req  + S;
		BYTE* verif = impl + S;

		auto printField = [&](const char* label, BYTE* field)
		{
			printf("    %-26s: ", label);
			for (ULONG b = 0; b < S; b += 4)
			{
				ULONG dw = 0;
				ULONG chunk = (S - b < 4) ? (S - b) : 4;
				memcpy(&dw, field + b, chunk);
				printf("0x%08X ", dw);
			}
			printf("\n");
		};

		printField("FeaturesRequired",     req);
		printField("FeaturesImplemented",  impl);
		printField("FeaturesVerified",     verif);

		// Check for gaps
		bool anyGap = false;
		for (ULONG b = 0; b < S; b++)
		{
			if ((req[b] & ~impl[b]) || (impl[b] & ~verif[b]))
			{
				anyGap = true;
				break;
			}
		}
		if (anyGap)
			printf("    ** Gap: some required features not implemented or not verified.\n");
		else
			printf("    All required features implemented and verified.\n");
	}

	HeapFree(GetProcessHeap(), 0, blob);
}

void PrintDeviceGuardInfo(PNT_QUERY_SYSTEM_INFORMATION NtQuerySystemInformation)
{
	ULONG returnLength = 0;

	//
	// SystemDeviceGuardInformation (0xA5) -- core VBS protection state.
	//
	printf("\nDevice Guard / VBS protection flags (0xA5):\n");
	printf("------------------------------------------------------------\n");

	SYSTEM_DEVICE_GUARD_INFORMATION dg = { 0 };
	NTSTATUS status = NtQuerySystemInformation(
		(SYSTEM_INFORMATION_CLASS)SYSTEM_DEVICE_GUARD_INFORMATION_CLASS,
		&dg, sizeof(dg), &returnLength);

	if (!NT_SUCCESS(status))
	{
		printf("  query failed: 0x%X\n", status);
	}
	else
	{
		// Byte +0
		printf("%-48s : %s\n", "Secure kernel running     [0].0 VslIsSecureKernelRunning",
			(dg.Flags0 & 0x01) ? "YES" : "NO");
		printf("%-48s : %s\n", "HVCI kernel enforcement   [0].1 NPF bit 1",
			(dg.Flags0 & 0x02) ? "YES" : "NO");
		printf("%-48s : %s\n", "HVCI user mode            [0].2 NPF bit 5",
			(dg.Flags0 & 0x04) ? "YES" : "NO");
		printf("%-48s : %s\n", "HVCI audit mode           [0].3 NPF bit 4",
			(dg.Flags0 & 0x08) ? "YES" : "NO");
		printf("%-48s : %s\n", "Firmware page protection  [0].4 ExpFirmwarePP",
			(dg.Flags0 & 0x10) ? "YES" : "NO");
		printf("%-48s : %s\n", "IUM active                [0].5 VslpEnterIumSecureMode",
			(dg.Flags0 & 0x20) ? "YES" : "NO");

		// Byte +1
		printf("%-48s : %s\n", "Trustlet running          [1].0 VslIsTrustletRunning",
			(dg.Flags1 & 0x01) ? "YES" : "NO");
		printf("%-48s : %s\n", "KMCI supplemental         [1].1 NPF bit 9",
			(dg.Flags1 & 0x02) ? "YES" : "NO");
		printf("%-48s : %s\n", "Kernel shadow stacks      [1].2 NPF bit 11",
			(dg.Flags1 & 0x04) ? "YES" : "NO");
		printf("%-48s : %s\n", "Kernel shadow stacks strict[1].3 NPF bit 12",
			(dg.Flags1 & 0x08) ? "YES" : "NO");
		printf("%-48s : %s\n", "Protection flag           [1].4 NPF bit 13",
			(dg.Flags1 & 0x10) ? "YES" : "NO");
		printf("%-48s : %s\n", "Protection flag           [1].5 NPF bit 16",
			(dg.Flags1 & 0x20) ? "YES" : "NO");
		printf("%-48s : %s\n", "Protection flag           [1].6 NPF bit 18",
			(dg.Flags1 & 0x40) ? "YES" : "NO");

		// Byte +2
		printf("%-48s : %s\n", "Protection flag           [2].0 NPF bit 19",
			(dg.Flags2 & 0x01) ? "YES" : "NO");

		printf("%-48s : 0x%02X  0x%02X  0x%02X\n", "Raw [0] [1] [2]",
			dg.Flags0, dg.Flags1, dg.Flags2);
	}

	//
	// UEFI Secure Boot -- registry (set by bootloader; readable without elevation).
	//
	printf("\nSecure Boot:\n");
	printf("------------------------------------------------------------\n");
	HKEY hKey;
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
		L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
		0, KEY_READ, &hKey) == ERROR_SUCCESS)
	{
		DWORD value = 0, size = sizeof(value);
		if (RegQueryValueExW(hKey, L"UEFISecureBootEnabled",
			NULL, NULL, (LPBYTE)&value, &size) == ERROR_SUCCESS)
			printf("%-48s : %s\n", "UEFI Secure Boot enabled", value ? "YES" : "NO");
		RegCloseKey(hKey);
	}
	else
	{
		printf("%-48s : key absent (not UEFI or not set)\n", "UEFI Secure Boot enabled");
	}

	//
	// SystemControlFlowTransitionInformation (0xDD) -- CET / Shadow Stack.
	// bit 0 = KeIsCetCapable, bit 1 = KeIsUserCetAllowed,
	// bit 8 = KeIsKernelCetEnabled, bit 9 = KeIsKernelCetAuditModeEnabled
	//
	printf("\nCET / Shadow Stack (0xDD):\n");
	printf("------------------------------------------------------------\n");
	ULONG cetFlags = 0;
	status = NtQuerySystemInformation(
		(SYSTEM_INFORMATION_CLASS)SYSTEM_SHADOW_STACK_INFORMATION_CLASS,
		&cetFlags, sizeof(cetFlags), &returnLength);

	if (!NT_SUCCESS(status))
	{
		printf("  query failed: 0x%X\n", status);
	}
	else
	{
		printf("%-48s : %s\n", "CET hardware support  (KeIsCetCapable)",
			(cetFlags & 0x001) ? "YES" : "NO");
		printf("%-48s : %s\n", "CET user mode enabled (KeIsUserCetAllowed)",
			(cetFlags & 0x002) ? "YES" : "NO");
		printf("%-48s : %s\n", "CET kernel enabled    (KeIsKernelCetEnabled)",
			(cetFlags & 0x100) ? "YES" : "NO");
		printf("%-48s : %s\n", "CET kernel audit mode (KeIsKernelCetAuditModeEnabled)",
			(cetFlags & 0x200) ? "YES" : "NO");
		printf("%-48s : 0x%08X\n", "Raw CET flags", cetFlags);
	}
}

void PrintVsmAndNestingInfo(PNT_QUERY_SYSTEM_INFORMATION NtQuerySystemInformation)
{
	printf("\nVSM / Nesting:\n");
	printf("------------------------------------------------------------\n");

	//
	// Nesting: CPUID 0x40000004 EAX bit 12.
	// The outer hypervisor sets this to advertise nested-virt support.
	// Not available via NtQuerySystemInformation(0x5B) -- must use CPUID.
	//
	int cpuInfo[4] = { 0 };
	__cpuid(cpuInfo, 0x40000004);
	bool nestingAvailable = (cpuInfo[0] & HVI_ENLIGHTENMENT_NESTED) != 0;
	printf("%-40s : %s\n", "Nested virt available (CPUID 40000004h[12])",
		nestingAvailable ? "YES" : "NO");

	//
	// VSM / secure kernel: NtQuerySystemInformation(0x67).
	// HVCI_IUM_ENABLED is the direct indicator that securekernel.exe
	// is active in VTL1. HVCI_KMCI_ENABLED means kernel code integrity
	// is enforced via VBS but does not guarantee the secure kernel itself.
	//
	SYSTEM_CODEINTEGRITY_INFORMATION ci = { sizeof(ci), 0 };
	ULONG returnLength = 0;
	NTSTATUS status = NtQuerySystemInformation(
		(SYSTEM_INFORMATION_CLASS)SYSTEM_CODE_INTEGRITY_INFORMATION_CLASS,
		&ci, sizeof(ci), &returnLength);

	if (!NT_SUCCESS(status))
	{
		printf("%-40s : query failed (0x%X)\n", "VSM / secure kernel", status);
		return;
	}

	bool hvci = (ci.CodeIntegrityOptions & CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED) != 0;
	bool ium = (ci.CodeIntegrityOptions & CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED) != 0;

	printf("%-40s : %s\n", "HVCI / kernel VBS (CodeIntegrity[10])", hvci ? "YES" : "NO");
	printf("%-40s : %s\n", "Secure kernel / VTL1 IUM (CodeIntegrity[11])", ium ? "YES" : "NO");
	printf("%-40s : 0x%08X\n", "Raw CodeIntegrityOptions", ci.CodeIntegrityOptions);

	//
	// MBEC: NtQuerySystemInformation(0xA9) byte +2 = HvlpFlags bit 17.
	// Set by KiSetFeatureBits from IA32_VMX_EPT_VPID_CAP bit 54 (Intel) or
	// CPUID(8000000Ah).EDX GMET bit (AMD). Only non-zero when the CPU
	// exposes VMX/SVM to the kernel (bare metal, or nested-virt guest).
	//
	SYSTEM_VSM_PROTECTION_INFORMATION vsm = { 0 };
	status = NtQuerySystemInformation(
		(SYSTEM_INFORMATION_CLASS)SYSTEM_VSM_PROTECTION_INFORMATION_CLASS,
		&vsm, sizeof(vsm), &returnLength);

	if (!NT_SUCCESS(status))
	{
		printf("%-40s : query failed (0x%X)\n", "MBEC hardware available", status);
		return;
	}

	printf("%-40s : %s\n", "DMA protection available (0xA9[0])",
		vsm.DmaProtectionAvailable ? "YES" : "NO");
	// THREE PATHS: (C) HvlHypervisorConnected AND HvlpFlags bit 1 set → both [0]+[1]
	// = CPUID(40000006h).EAX bit 7. (B) HV connected but bit 1 clear → [0] = 1 if
	// (HvlpFlags bit 6 OR HvlpProcessIommu()), [1] = HvlpFlags bit 6. (A) No HV →
	// [0] = HvlpProcessIommu(), [1] = 0.
	printf("%-40s : %s\n", "DMA protection in use   (0xA9[1])",
		vsm.DmaProtectionInUse ? "YES" : "NO");
	printf("%-40s : %s\n", "MBEC hardware available (0xA9[2])",
		vsm.HardwareMbecAvailable ? "YES" : "NO");
	printf("%-40s : %s\n", "APIC virt available     (0xA9[3])",
		vsm.ApicVirtAvailable ? "YES" : "NO");
	// APIC virt (0xA9[3]) = HvlpFlags bit 24 (confirmed by raw code: `mov al, byte ptr HvlpFlags+3; and al, 1`).
	// In hvax64/hvix64, CPUID 0x40000006 EAX bit 23 = a platform capability check (RE-assigned
	// name "HcpCheckPlatformXsaveCapability" unreliable). Actual code checks a VSM-related
	// global AND excludes based on partition flags (bit 15 on both; bit 2 additionally on AMD).
	// The TLFS spec says bit 23 = ApicVirtualizationAvailable.
	// Treat the bit 23 / APIC mapping as from-spec; HV code shows VSM-conditional sourcing.
	// Separate from the software choice made in securekernel:
	//   SkiUseX2Apic  : set from IA32_APIC_BASE MSR bit 10 (x2APIC hardware mode active)
	//   SkiUseApicMsrs: set from CPUID 0x40000004 EAX bit 8 (UseX2ApicMsrs enlightenment)
	// CPUID 0x40000004[8] (UseX2ApicMsrs) is already printed in the HvDetailInfo section.
}

// -----------------------------------------------------------------------------
// PrintSystemInfo -- basic system information dump
//
// Sources:
//   OS version  : RtlGetVersion (ntdll) -- ignores application manifest,
//                 always returns the real build number.
//   Full build  : HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\UBR
//                 gives the update revision (e.g. 26100.4061 where 4061 = UBR).
//   CPU brand   : CPUID leaves 0x80000002-0x80000004 (Intel/AMD brand string).
//   Firmware    : GetFirmwareType -- BIOS vs UEFI.
//   RAM         : GlobalMemoryStatusEx.
//   Uptime      : GetTickCount64.
//   Edition     : HKLM\...\CurrentVersion\ProductName + DisplayVersion.
// -----------------------------------------------------------------------------

typedef NTSTATUS (WINAPI* PFN_RtlGetVersion)(PRTL_OSVERSIONINFOW);

static void RegQueryDword(HKEY hKey, const wchar_t* value, DWORD* out)
{
	DWORD size = sizeof(DWORD);
	RegQueryValueExW(hKey, value, nullptr, nullptr, (LPBYTE)out, &size);
}

static void RegQueryStr(HKEY hKey, const wchar_t* value, char* buf, DWORD bufBytes)
{
	wchar_t tmp[256] = {};
	DWORD size = sizeof(tmp);
	if (RegQueryValueExW(hKey, value, nullptr, nullptr, (LPBYTE)tmp, &size) == ERROR_SUCCESS)
		WideCharToMultiByte(CP_UTF8, 0, tmp, -1, buf, (int)bufBytes, nullptr, nullptr);
}

void PrintSystemInfo()
{
	printf("System Information\n");
	printf("============================================================\n");

	// -- OS version via RtlGetVersion -----------------------------------------
	RTL_OSVERSIONINFOW osvi = { sizeof(osvi) };
	auto pRtlGetVersion = (PFN_RtlGetVersion)
		GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion");
	if (pRtlGetVersion)
		pRtlGetVersion(&osvi);

	// -- Registry: CurrentVersion ----------------------------------------------
	HKEY hCv = nullptr;
	char productName[128]  = "Unknown";
	char displayVersion[32] = {};   // e.g. "24H2"
	char currentBuild[16]  = {};
	DWORD ubr = 0;

	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
			L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
			0, KEY_READ, &hCv) == ERROR_SUCCESS)
	{
		RegQueryStr  (hCv, L"ProductName",    productName,    sizeof(productName));
		RegQueryStr  (hCv, L"DisplayVersion", displayVersion, sizeof(displayVersion));
		RegQueryStr  (hCv, L"CurrentBuild",   currentBuild,   sizeof(currentBuild));
		RegQueryDword(hCv, L"UBR",            &ubr);
		RegCloseKey(hCv);
	}

	// Determine Windows generation from build number
	const char* winGen = osvi.dwBuildNumber >= 22000 ? "Windows 11" :
	                     osvi.dwBuildNumber >= 10240 ? "Windows 10" :
	                                                   "Windows (older)";

	printf("%-30s : %s %s (%s)\n", "OS",
	       winGen, displayVersion[0] ? displayVersion : "", productName);
	printf("%-30s : %lu.%lu.%lu.%lu\n", "Version (major.minor.build.UBR)",
	       osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber, ubr);

	// -- Computer name ---------------------------------------------------------
	wchar_t compName[MAX_COMPUTERNAME_LENGTH + 1] = {};
	DWORD   compLen = MAX_COMPUTERNAME_LENGTH + 1;
	GetComputerNameW(compName, &compLen);
	printf("%-30s : %ls\n", "Computer name", compName);

	// -- Current user ----------------------------------------------------------
	wchar_t userName[256] = {};
	DWORD   userLen = 256;
	GetUserNameW(userName, &userLen);
	printf("%-30s : %ls\n", "Current user", userName);

	// -- Firmware type ---------------------------------------------------------
	FIRMWARE_TYPE ft = FirmwareTypeUnknown;
	GetFirmwareType(&ft);
	const char* ftStr = ft == FirmwareTypeUefi ? "UEFI" :
	                    ft == FirmwareTypeBios  ? "Legacy BIOS" : "Unknown";
	printf("%-30s : %s\n", "Firmware type", ftStr);

	// -- CPU brand string (CPUID 0x80000002-0x80000004) -----------------------
	char brand[49] = {};
	int  cpuInfo[4];
	__cpuid(cpuInfo, 0x80000000);
	if ((unsigned)cpuInfo[0] >= 0x80000004)
	{
		__cpuid(cpuInfo, 0x80000002); memcpy(brand,    cpuInfo, 16);
		__cpuid(cpuInfo, 0x80000003); memcpy(brand+16, cpuInfo, 16);
		__cpuid(cpuInfo, 0x80000004); memcpy(brand+32, cpuInfo, 16);
		const char* trimmed = brand;
		while (*trimmed == ' ') trimmed++;
		printf("%-30s : %s\n", "CPU", trimmed);
	}

	// -- CPU architecture and logical processor count --------------------------
	SYSTEM_INFO si = {};
	GetNativeSystemInfo(&si);
	const char* archStr =
		si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ? "x86-64" :
		si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64 ? "ARM64"  :
		si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL ? "x86-32" : "Unknown";
	printf("%-30s : %s  (%lu logical processors)\n", "CPU architecture",
	       archStr, si.dwNumberOfProcessors);

	// -- RAM -------------------------------------------------------------------
	MEMORYSTATUSEX ms = { sizeof(ms) };
	GlobalMemoryStatusEx(&ms);
	printf("%-30s : %.1f GB total  (%.1f GB available)\n", "Physical RAM",
	       (double)ms.ullTotalPhys / (1024.0*1024.0*1024.0),
	       (double)ms.ullAvailPhys / (1024.0*1024.0*1024.0));

	// -- System uptime ---------------------------------------------------------
	ULONGLONG ms64 = GetTickCount64();
	DWORD days     = (DWORD)(ms64 / 86400000ULL);
	DWORD hours    = (DWORD)((ms64 % 86400000ULL) / 3600000ULL);
	DWORD minutes  = (DWORD)((ms64 % 3600000ULL)  / 60000ULL);
	printf("%-30s : %u days  %u hours  %u minutes\n", "Uptime", days, hours, minutes);

	// -- Process privilege -----------------------------------------------------
	BOOL elevated = FALSE;
	HANDLE hTok;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hTok))
	{
		TOKEN_ELEVATION elev; DWORD sz;
		if (GetTokenInformation(hTok, TokenElevation, &elev, sizeof(elev), &sz))
			elevated = elev.TokenIsElevated;
		CloseHandle(hTok);
	}
	printf("%-30s : %s\n", "Process privilege",
	       elevated ? "Elevated (Administrator)" : "Standard user");

	printf("============================================================\n\n");
}

// -----------------------------------------------------------------------------
// ProbeAcpiTable -- check whether a given ACPI table exists.
//
// Mimics HvlpProcessIommu: passes a 20-byte SYSTEM_FIRMWARE_TABLE_INFORMATION
// with BufferLength=0 (probe-only). If the table exists the kernel returns
// STATUS_BUFFER_TOO_SMALL (0xC0000023) and writes the required size into
// *ReturnLength; if the table is absent it returns STATUS_NOT_FOUND or similar.
//
// TableID convention: the 4-char ACPI signature stored as a little-endian DWORD,
// i.e. the first ASCII character is the least-significant byte.
//   'SDEV' bytes S,D,E,V -> LE DWORD 0x56454453
//   'IVRS' bytes I,V,R,S -> LE DWORD 0x53525649
//   'DMAR' bytes D,M,A,R -> LE DWORD 0x52414D44
//   'MCFG' bytes M,C,F,G -> LE DWORD 0x4746434D
// -----------------------------------------------------------------------------

static BOOL ProbeAcpiTable(PNT_QUERY_SYSTEM_INFORMATION NtQuerySystemInformation,
                            DWORD tableId)
{
#pragma pack(push, 1)
	struct
	{
		ULONG ProviderSignature;  // 'ACPI' = 0x41435049
		ULONG Action;             // 1 = Get
		ULONG TableID;
		ULONG BufferLength;       // 0 = probe for size only
		ULONG Padding;            // pad to 20 bytes (matches HvlpProcessIommu call)
	} sfi = { 0x41435049u, 1u, tableId, 0u, 0u };
#pragma pack(pop)

	ULONG returnLength = 0;
	NTSTATUS status = NtQuerySystemInformation(
		(SYSTEM_INFORMATION_CLASS)0x4C,
		&sfi, sizeof(sfi), &returnLength);

	// Table present: STATUS_BUFFER_TOO_SMALL with ReturnLength > struct size.
	return (status == (NTSTATUS)0xC0000023u && returnLength > sizeof(sfi));
}

// -----------------------------------------------------------------------------
// PrintDmaProtectionDetail -- securekernel-derived DMA protection analysis.
//
// Sources verified against securekernel.exe disassembly:
//   ShvlpHardwareFeatures  = CPUID 0x40000006 EAX (HviGetHardwareFeatures)
//   SkpnppSdevInitialize   = BugChecks (0xA5/'SDEV') if bit 7 = 0 and SDEV present
//   SkhalInitSystem        = initialises per-device IOMMU domain model at VTL1 boot
//   HalpIommuInitDiscard   = reads CPUID 0x40000003 EDX bits 24-25 into
//                            HalpHvIommuDeviceDomain / HalpHvParaVirtIommuDomain
//   ShvlAttachDeviceDomain = hypercall 0xB2: assigns device to IOMMU domain
//   ShvlMapDeviceGpaPages  = hypercall 0xB3: maps specific GPAs into device domain
//   SkmiProtectPageRange   = sets SLAT/NPT permissions; BugCheck 0x1A/0x90A on failure
// -----------------------------------------------------------------------------

void PrintDmaProtectionDetail(PNT_QUERY_SYSTEM_INFORMATION NtQuerySystemInformation)
{
	printf("\nKernel DMA Protection -- securekernel enforcement detail:\n");
	printf("------------------------------------------------------------\n");

	//
	// Determine hypervisor presence and verify max CPUID leaf >= 0x40000006.
	//
	int cpuInfo[4] = { 0 };
	__cpuid(cpuInfo, 1);
	bool hvPresent = ((cpuInfo[2] >> 31) & 1) != 0;
	if (hvPresent)
	{
		__cpuid(cpuInfo, 0x40000000);
		hvPresent = ((ULONG)cpuInfo[0] >= 0x40000006u);
	}

	//
	// CPUID 0x40000006 EAX bits 5 and 7 -- annotated with securekernel context.
	//
	// bit 5: when set, HalpIommuInitDiscard replaces the entire HAL IOMMU
	//        dispatch table with HV-managed wrappers (IommuHvSetAddressSpace,
	//        IommuHvFlushTb, IommuHvDevicePowerChange, ...) and sets
	//        HalpHvIommu = 1.  All IOMMU operations then go via hypercalls
	//        instead of direct MMIO to AMD-Vi / Intel VT-d hardware.
	//
	// bit 7: the single hardware-capability gate in securekernel.exe.
	//        HviGetHardwareFeatures stores this in ShvlpHardwareFeatures.
	//        IumGetDmaEnabler returns STATUS_NOT_SUPPORTED if bit 7 = 0.
	//        SkpnppSdevInitialize calls SkeBugCheckEx(0xA5, 'SDEV', ...)
	//        if bit 7 = 0 and the ACPI SDEV table is present -- the system
	//        cannot boot into VBS without an IOMMU when secure devices exist.
	//        This same bit feeds NtQuerySystemInformation(0xA9) byte[1]
	//        (DmaProtectionInUse) when the hypervisor and VSM are active.
	//
	ULONG hw6 = 0;
	if (hvPresent)
	{
		__cpuid(cpuInfo, 0x40000006);
		hw6 = (ULONG)cpuInfo[0];
	}

	printf("CPUID 0x40000006 EAX -- securekernel DMA gate bits:\n");
	if (hvPresent)
	{
		printf("  bit 5  HV-managed IOMMU (HalpHvIommu=1)           : %s\n",
			(hw6 >> 5) & 1
			? "YES -- HAL IOMMU dispatch replaced with IommuHv* wrappers"
			: "NO  -- HAL programs AMD-Vi/VT-d directly");
		printf("  bit 7  DMA remapping present (SK SDEV gate)        : %s\n",
			(hw6 >> 7) & 1
			? "YES -- securekernel IOMMU domain model operational"
			: "NO  -- IumGetDmaEnabler returns NOT_SUPPORTED; SDEV would BugCheck");
	}
	else
	{
		printf("  N/A (no hypervisor connected -- CPUID 0x40000006 not meaningful)\n");
	}

	//
	// ACPI table presence via NtQuerySystemInformation(0x4C).
	//
	// SDEV (Secure Devices):
	//   securekernel reads this in SkpnppSdevInitialize / SkhalInitSystem
	//   to discover which devices need per-device IOMMU domain protection.
	//   SkpnpSdevDeviceTypesAvailable bit 0 = ACPI-namespace type present,
	//   bit 1 = PCIe type present.  Both drive SkhalpPciInitialize and
	//   SkhalpAcProcessSdevEntry.  If SDEV present and bit 7 of
	//   CPUID 0x40000006 is 0, securekernel BugChecks immediately at boot.
	//
	// IVRS (AMD) / DMAR (Intel):
	//   probed by HvlpProcessIommu to determine DmaProtectionAvailable
	//   (NtQuerySystemInformation 0xA9 byte[0]).  Presence confirms the
	//   BIOS described an IOMMU in firmware.  Does NOT verify it is enabled
	//   or translating -- only the hypervisor's bit 7 assertion does that.
	//
	// MCFG:
	//   used by SkhalpPciMcfgInit in securekernel to map PCIe config space
	//   so the secure kernel can enumerate and attach PCI DMA devices.
	//
	struct { DWORD sig; const char* name; const char* note; } tables[] = {
		{ 0x56454453u, "SDEV",
		  "Secure Devices -- SK per-device DMA policy (BugCheck if IOMMU absent)" },
		{ 0x53525649u, "IVRS",
		  "AMD I/O Virtualization Reporting Structure (AMD-Vi descriptor)" },
		{ 0x52414D44u, "DMAR",
		  "Intel DMA Remapping / VT-d descriptor" },
		{ 0x4746434Du, "MCFG",
		  "PCIe MMCFG -- SkhalpPciMcfgInit in securekernel" },
	};

	printf("\nACPI table presence (NtQuerySystemInformation 0x4C):\n");
	BOOL present[4] = {};
	for (int i = 0; i < 4; i++)
	{
		present[i] = ProbeAcpiTable(NtQuerySystemInformation, tables[i].sig);
		printf("  %-5s : %-10s %s\n",
			tables[i].name,
			present[i] ? "PRESENT" : "absent",
			present[i] ? tables[i].note : "");
	}

	//
	// Read Device Guard state and synthesise the active enforcement model.
	//
	// securekernel enforcement is dual-layered:
	//   1. IOMMU domain isolation  (ShvlAttachDeviceDomain, hypercall 0xB2)
	//      All devices start in VTL1-owned domains with zero pages mapped.
	//      DMA is only allowed to pages explicitly granted by the secure
	//      kernel via ShvlMapDeviceGpaPages (hypercall 0xB3).
	//      ShvlUnmapDeviceGpaPages (0xB4) revokes access when done.
	//   2. SLAT / nested page table enforcement  (SkmiProtectPageRange)
	//      Even if an IOMMU domain mapping were wrong, SLAT prevents DMA
	//      to pages not marked as device-accessible at the hypervisor level.
	//      Any failure to set SLAT permissions is fatal:
	//      SkeBugCheckEx(0x1A, 'VSM', 0x90A, ...) -- SECURE_KERNEL_ERROR.
	//
	SYSTEM_DEVICE_GUARD_INFORMATION dg = { 0 };
	ULONG returnLength2 = 0;
	NtQuerySystemInformation(
		(SYSTEM_INFORMATION_CLASS)0xA5, &dg, sizeof(dg), &returnLength2);

	bool skRunning   = (dg.Flags0 & 0x01) != 0;  // VslIsSecureKernelRunning
	bool iommuGate   = hvPresent && ((hw6 >> 7) & 1);
	bool hvIommu     = hvPresent && ((hw6 >> 5) & 1);
	bool hasSdev     = present[0] != 0;

	printf("\nVTL1 DMA enforcement model:\n");
	printf("  SecureKernel running    [0xA5 byte0 bit0]  : %s\n",
		skRunning ? "YES" : "NO");
	printf("  IOMMU gate              [0x40000006 bit7]  : %s\n",
		iommuGate ? "YES" : "NO");
	printf("  HV-managed IOMMU        [0x40000006 bit5]  : %s\n",
		hvIommu ? "YES" : "NO");
	printf("  ACPI SDEV table present                    : %s\n",
		hasSdev ? "YES" : "NO");

	printf("\n  Active model: ");
	if (skRunning && iommuGate)
	{
		printf("VTL1 per-device IOMMU domain enforcement ACTIVE.\n");
		printf("    All DMA devices placed in VTL1-owned domains at boot (0 pages mapped).\n");
		printf("    Pages granted only via ShvlMapDeviceGpaPages (HV hypercall 0xB3).\n");
		printf("    Backed by SLAT; SLAT failure is fatal (SK BugCheck 0x1A / 0x90A).\n");
		if (hasSdev)
			printf("    SDEV table present -- securekernel has populated device policy.\n");
	}
	else if (hasSdev && !iommuGate)
	{
		printf("CONFLICT.\n");
		printf("    SDEV table present but IOMMU gate (0x40000006[7]) is clear.\n");
		printf("    securekernel would BugCheck (0xA5/'SDEV') if VBS were enabled.\n");
	}
	else if (!skRunning && iommuGate)
	{
		printf("HAL-level DMA guard only.\n");
		printf("    VTL1 not running; securekernel domain model not active.\n");
		printf("    PnP DMA guard (PiDmaGuardProcessPreStart) is the only enforcement.\n");
	}
	else
	{
		printf("No IOMMU-backed enforcement active.\n");
	}
}

// ---------------------------------------------------------------------------
// PrintMorAndMorLock -- TCG Memory Overwrite Request (MOR) and MORlock state
//
// MOR -- MemoryOverwriteRequestControl:
//   Name : "MemoryOverwriteRequestControl"
//   GUID : {E20939BE-32D4-41BE-A150-897F85D49829}  (TCG Platform Reset spec; EfiMorBitVariable)
//   Size : 1 byte
//   bit 0 (MOR bit): 1 = firmware must overwrite memory at next boot (cold-boot defence)
//   bit 4 : cleared by ntoskrnl alongside bit 0 on clean shutdown / hibernate start
//
//   winload BlTcgFwSetMemoryOverwriteRequestBit (winload.efi 0x1801A4C7F):
//     Reads current value (EfiGetVariable, size=1).  Then:
//       bl=0 → sets byte to 0x01  (bit 0 only)
//       bl≠0 → sets byte to 0x11  (bits 0 and 4)
//     Called from winload to arm MOR before kernel launch.
//
//   ntoskrnl PopSetMemoryOverwriteRequestAction (ntoskrnl 0x140B529D4):
//     Reads via HalGetEnvironmentVariableEx, then `and byte, 0xEEh` (clears bits 0 and 4),
//     writes back via HalSetEnvironmentVariableEx.
//     Skipped entirely if PopErrataSkipMemoryOverwriteRequestControlLockAction != 0
//     (set by PopReadErrataSkipMemoryOverwriteRequestControlLockAction via EmClientRuleEvaluate
//     for firmware known to have MORlock bugs).
//     Called from PopShutdownSystem and PopSaveHiberContext.
//
// MORlock -- MemoryOverwriteRequestControlLock:
//   Name : "MemoryOverwriteRequestControlLock"
//   GUID : {BB983CCF-151D-40E1-A07B-4A17BE168292}  (TCG spec v1.10; EfiMorLockVariable)
//   Size : 1 byte (v1) or 8 bytes (v2 with key)
//     0 = unlocked   -- software may change MOR
//     1 = locked, no key -- MOR is read-only until next boot (cannot be changed)
//     2 = locked with key -- unlockable only with 8-byte key (MORlock v2)
//
//   winload BlTcgFwSetAndLockMemoryOverwriteRequestControl (winload.efi 0x1801A4D60):
//     Reads MORlock (size=1 expected).  STATUS_NOT_FOUND (0xC0000023) → variable absent.
//     If value==0: locks by writing 0x01 (no-key) or 8-byte key (v2 with key).
//     If value==1 or 2: already locked → returns ACCESS_DENIED (0xC0000022).
//     After locking, reads back to confirm value==2 (success) before recording config event.
//     Called after BlTcgFwSetMemoryOverwriteRequestBit so MOR is armed before locking.
//
// Requires SeSystemEnvironmentPrivilege (administrator elevation).
// ---------------------------------------------------------------------------

void PrintMorAndMorLock()
{
	printf("\nMOR / MORlock -- TCG Platform Reset Attack Mitigation:\n");
	printf("------------------------------------------------------------\n");

	// Enable SeSystemEnvironmentPrivilege (required for GetFirmwareEnvironmentVariable*).
	BOOL privileged = FALSE;
	{
		HANDLE hTok;
		if (OpenProcessToken(GetCurrentProcess(),
			TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hTok))
		{
			LUID luid = {};
			if (LookupPrivilegeValueW(nullptr, SE_SYSTEM_ENVIRONMENT_NAME, &luid))
			{
				TOKEN_PRIVILEGES tp = { 1, { luid, SE_PRIVILEGE_ENABLED } };
				if (AdjustTokenPrivileges(hTok, FALSE, &tp, sizeof(tp), nullptr, nullptr)
					&& GetLastError() == ERROR_SUCCESS)
					privileged = TRUE;
			}
			CloseHandle(hTok);
		}
	}

	if (!privileged)
	{
		printf("  SeSystemEnvironmentPrivilege unavailable -- run as administrator.\n");
		return;
	}

	// -----------------------------------------------------------------------
	// MOR -- MemoryOverwriteRequestControl
	// GUID {E20939BE-32D4-41BE-A150-897F85D49829}  (EfiMorBitVariable)
	// -----------------------------------------------------------------------
	printf("\n  MemoryOverwriteRequestControl (MOR):\n");
	printf("    GUID : {E20939BE-32D4-41BE-A150-897F85D49829}\n");

	BYTE   morValue  = 0;
	DWORD  morAttrib = 0;
	DWORD  morSize   = GetFirmwareEnvironmentVariableExW(
		L"MemoryOverwriteRequestControl",
		L"{E20939BE-32D4-41BE-A150-897F85D49829}",
		&morValue, sizeof(morValue), &morAttrib);

	if (morSize == 0)
	{
		DWORD err = GetLastError();
		if (err == ERROR_ENVVAR_NOT_FOUND)
			printf("    Value : (absent -- firmware does not support MOR)\n");
		else
			printf("    Query failed: 0x%X\n", err);
	}
	else
	{
		printf("    Raw byte  : 0x%02X\n", morValue);
		printf("    bit 0 MOR : %u  -- %s\n", morValue & 1,
			(morValue & 1)
				? "ACTIVE -- firmware must overwrite RAM at next boot"
				: "clear (no overwrite requested)");
		printf("    bit 4     : %u  (cleared by ntoskrnl alongside bit 0 on shutdown)\n",
			(morValue >> 4) & 1);
		printf("    Attributes: 0x%X  (%s%s%s)\n", morAttrib,
			(morAttrib & 1) ? "NonVolatile " : "",
			(morAttrib & 2) ? "BootSvc " : "",
			(morAttrib & 4) ? "RuntimeSvc" : "");
	}

	// -----------------------------------------------------------------------
	// MORlock -- MemoryOverwriteRequestControlLock
	// GUID {BB983CCF-151D-40E1-A07B-4A17BE168292}  (EfiMorLockVariable)
	// -----------------------------------------------------------------------
	printf("\n  MemoryOverwriteRequestControlLock (MORlock):\n");
	printf("    GUID : {BB983CCF-151D-40E1-A07B-4A17BE168292}\n");

	BYTE  lockBuf[8] = {};
	DWORD lockAttrib = 0;
	DWORD lockSize   = GetFirmwareEnvironmentVariableExW(
		L"MemoryOverwriteRequestControlLock",
		L"{BB983CCF-151D-40E1-A07B-4A17BE168292}",
		lockBuf, sizeof(lockBuf), &lockAttrib);

	if (lockSize == 0)
	{
		DWORD err = GetLastError();
		if (err == ERROR_ENVVAR_NOT_FOUND)
			printf("    Value : (absent -- firmware does not implement MORlock)\n");
		else
			printf("    Query failed: 0x%X\n", err);
	}
	else if (lockSize == 1)
	{
		printf("    Size  : 1 byte  (MORlock v1)\n");
		printf("    Raw   : 0x%02X\n", lockBuf[0]);
		printf("    State : %s\n",
			lockBuf[0] == 0 ? "UNLOCKED -- software may change MOR" :
			lockBuf[0] == 1 ? "LOCKED (no key) -- MOR read-only until reboot" :
			lockBuf[0] == 2 ? "LOCKED WITH KEY -- 8-byte key required (MORlock v2)" :
			                  "unknown value");
		printf("    Attributes: 0x%X\n", lockAttrib);
	}
	else if (lockSize == 8)
	{
		printf("    Size  : 8 bytes  (MORlock v2 -- key present)\n");
		printf("    Key   : ");
		for (DWORD i = 0; i < 8; i++) printf("%02X ", lockBuf[i]);
		printf("\n    State : LOCKED WITH KEY\n");
		printf("    Attributes: 0x%X\n", lockAttrib);
	}
	else
	{
		printf("    Size  : %u bytes (unexpected)\n", lockSize);
		for (DWORD i = 0; i < lockSize && i < 16; i++) printf("%02X ", lockBuf[i]);
		printf("\n");
	}

	// -----------------------------------------------------------------------
	// Errata skip note (kernel global, not readable from user mode)
	// -----------------------------------------------------------------------
	printf("\n  Note: PopErrataSkipMemoryOverwriteRequestControlLockAction (ntoskrnl global)\n");
	printf("    Set at PoInitSystem via PopReadErrataSkipMemoryOverwriteRequestControlLockAction\n");
	printf("    when EmClientRuleEvaluate matches rule {1D7F2399-058C-4FF1-B3B2-81AFED9E838F}.\n");
	printf("    Reason: specific OEM UEFI firmware has bugs in MORlock handling -- firmware\n");
	printf("    hangs, errors, or corrupts the variable store on HalSetEnvironmentVariableEx\n");
	printf("    for MemoryOverwriteRequestControlLock. Identified by BIOS manufacturing date\n");
	printf("    (EmMatchDate reads BIOS ROM at F000:FFF5 into EmpCachedBiosDate; the INF\n");
	printf("    database of affected date ranges is embedded in ntoskrnl / passed via loader).\n");
	printf("    When set, PopSetMemoryOverwriteRequestAction skips the entire MOR clear path.\n");
	printf("    Not readable from user mode; check via kernel debugger: `db nt!PopErrata*`\n");
}

// ---------------------------------------------------------------------------
// PrintSystemBasicInfo -- NtQuerySystemInformation class 0 (SystemBasicInformation)
//
// Sources verified against ntoskrnl ExpGetSystemBasicInformation (0x14044DA5C)
// and securekernel IumpSanitizeSystemBasicInfo (called after NkQuerySystemInformation).
//
// Structure layout (0x40 = 64 bytes; confirmed from ntoskrnl write offsets):
//   +0x00  ULONG   Reserved                  = 0 (always)
//   +0x04  ULONG   TimerResolution            = KeMaximumIncrement (100ns units)
//   +0x08  ULONG   PageSize                   = 0x1000 (hardcoded)
//   +0x0C  ULONG   NumberOfPhysicalPages      = MmGetNumberOfPhysicalPages (capped 0xFFFFFFFF)
//   +0x10  ULONG   LowestPhysicalPageNumber   = MiNode->LowestPfn (capped 0xFFFFFFFF)
//   +0x14  ULONG   HighestPhysicalPageNumber  = MiNode->HighestPfn (capped 0xFFFFFFFF)
//   +0x18  ULONG   AllocationGranularity      = 0x10000 (hardcoded)
//   +0x1C  ULONG   _Pad                       (implicit: QWORD alignment for +0x20)
//   +0x20  QWORD   MinimumUserModeAddress     = 0x10000 (hardcoded)
//   +0x28  QWORD   MaximumUserModeAddress     = 0x7FFFFFFEFFFFh (hardcoded)
//   +0x30  QWORD   ActiveProcessorsAffinityMask = KeActiveProcessors (NUMA node 0)
//   +0x38  CHAR    NumberOfProcessors         = popcount(AffinityMask)
//   +0x39  CHAR[7] _Pad2
//
// Securekernel IumpSanitizeSystemBasicInfo enforcement (called after VTL0 result arrives):
//   [+08] PageSize               <- 0x1000  (defensive; same value ntoskrnl hardcodes)
//   [+18] AllocationGranularity  <- 0x10000 (defensive; same value ntoskrnl hardcodes)
//   [+20] MinimumUserModeAddress <- 0x10000 (defensive; same value ntoskrnl hardcodes)
//   [+28] MaximumUserModeAddress <- 0x7FFFFFFEFFFFh (defensive; same as ntoskrnl)
//   [+38] NumberOfProcessors     clamped to <= 0x40 (VTL1 supports max 64 logical processors)
//
// ClassID 0x3E remapping: securekernel remaps class 0x3E to class 0 internally:
//   `cmp ebx, 3Eh; cmovnz edi, ebx` -- if class==0x3E, edi stays 0; else edi=class.
// ---------------------------------------------------------------------------

void PrintSystemBasicInfo(PNT_QUERY_SYSTEM_INFORMATION NtQuerySystemInformation)
{
	printf("\nSystem Basic Information (0x00 ExpGetSystemBasicInformation):\n");
	printf("------------------------------------------------------------\n");

	typedef struct _SYSTEM_BASIC_INFORMATION_LOCAL {
		ULONG    Reserved;
		ULONG    TimerResolution;
		ULONG    PageSize;
		ULONG    NumberOfPhysicalPages;
		ULONG    LowestPhysicalPageNumber;
		ULONG    HighestPhysicalPageNumber;
		ULONG    AllocationGranularity;
		ULONG    _Pad;                       // implicit 4-byte pad before QWORD
		ULONG64  MinimumUserModeAddress;
		ULONG64  MaximumUserModeAddress;
		ULONG64  ActiveProcessorsAffinityMask;
		CHAR     NumberOfProcessors;
		CHAR     _Pad2[7];
	} SYSTEM_BASIC_INFORMATION_LOCAL;

	static_assert(offsetof(SYSTEM_BASIC_INFORMATION_LOCAL, MinimumUserModeAddress) == 0x20, "layout");
	static_assert(offsetof(SYSTEM_BASIC_INFORMATION_LOCAL, MaximumUserModeAddress) == 0x28, "layout");
	static_assert(offsetof(SYSTEM_BASIC_INFORMATION_LOCAL, NumberOfProcessors)     == 0x38, "layout");
	static_assert(sizeof(SYSTEM_BASIC_INFORMATION_LOCAL) == 0x40, "size");

	SYSTEM_BASIC_INFORMATION_LOCAL bi = {};
	ULONG returnLength = 0;
	NTSTATUS status = NtQuerySystemInformation(
		(SYSTEM_INFORMATION_CLASS)0,
		&bi, sizeof(bi), &returnLength);

	if (!NT_SUCCESS(status))
	{
		printf("  query failed: 0x%X\n", status);
		return;
	}

	printf("  [+00] Reserved                        : 0x%08X\n", bi.Reserved);
	printf("  [+04] TimerResolution  (100ns units)  : %u  (%.3f ms)\n",
		bi.TimerResolution, (double)bi.TimerResolution / 10000.0);
	printf("  [+08] PageSize                        : 0x%X  %s\n",
		bi.PageSize,
		bi.PageSize == 0x1000 ? "(hardcoded by ntoskrnl + SK)" : "(!= expected 0x1000)");
	printf("  [+0C] NumberOfPhysicalPages           : %u  (%.1f GB)\n",
		bi.NumberOfPhysicalPages,
		(double)bi.NumberOfPhysicalPages * bi.PageSize / (1024.0 * 1024.0 * 1024.0));
	printf("  [+10] LowestPhysicalPageNumber        : 0x%X\n", bi.LowestPhysicalPageNumber);
	printf("  [+14] HighestPhysicalPageNumber       : 0x%X\n", bi.HighestPhysicalPageNumber);
	printf("  [+18] AllocationGranularity           : 0x%X  %s\n",
		bi.AllocationGranularity,
		bi.AllocationGranularity == 0x10000 ? "(hardcoded)" : "(!= expected 0x10000)");
	printf("  [+1C] _Pad                            : (4 bytes implicit alignment)\n");
	printf("  [+20] MinimumUserModeAddress          : 0x%016llX  %s\n",
		(unsigned long long)bi.MinimumUserModeAddress,
		bi.MinimumUserModeAddress == 0x10000ULL ? "(hardcoded)" : "(!= expected 0x10000)");
	printf("  [+28] MaximumUserModeAddress          : 0x%016llX  %s\n",
		(unsigned long long)bi.MaximumUserModeAddress,
		bi.MaximumUserModeAddress == 0x7FFFFFFEFFFFull ? "(hardcoded ~127TB limit)" : "(!= expected 0x7FFFFFFEFFFFh)");
	printf("  [+30] ActiveProcessorsAffinityMask    : 0x%016llX\n",
		(unsigned long long)bi.ActiveProcessorsAffinityMask);
	printf("  [+38] NumberOfProcessors              : %u  %s\n",
		(unsigned char)bi.NumberOfProcessors,
		(unsigned char)bi.NumberOfProcessors > 64
			? "(SK would clamp to 64 for VTL1 trustlets)" : "(SK limit ≤ 64 OK)");

	printf("\n  SecureKernel IumpSanitizeSystemBasicInfo -- VTL1 enforcement:\n");
	printf("    [+08] PageSize               <- 0x1000         (defensive; matches ntoskrnl)\n");
	printf("    [+18] AllocationGranularity  <- 0x10000        (defensive; matches ntoskrnl)\n");
	printf("    [+20] MinimumUserModeAddress <- 0x10000        (defensive; matches ntoskrnl)\n");
	printf("    [+28] MaximumUserModeAddress <- 0x7FFFFFFEFFFFh(defensive; matches ntoskrnl)\n");
	printf("    [+38] NumberOfProcessors     clamped to <= 64  (VTL1 max 64 LPs)\n");
	printf("  Class 0x3E is remapped to class 0 in securekernel (cmp 0x3E; cmovnz guard).\n");
}

int main()
{
	PrintSystemInfo();

	HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
	if (!hNtdll) return -1;

	auto NtQuerySystemInformation = (PNT_QUERY_SYSTEM_INFORMATION)
		GetProcAddress(hNtdll, "NtQuerySystemInformation");
	if (!NtQuerySystemInformation) return -1;

	//
	// Layout verified against HvlQueryEnlightenmentInfo at ntoskrnl 0x1407068E8:
	//
	//   +0x00  BYTE   HvlHypervisorConnected  = HvlHypervisorConnected != 0
	//   +0x01  BYTE   IsRootPartition         = (HvlpRootFlags >> 3) & 1
	//                                           *** NOT the full HvlpRootFlags DWORD ***
	//   +0x02  BYTE   IsAnyHypervisorPresent   = (HvlpFlags >> 12) & 1
	//                                           *** NOT the full HvlpFlags DWORD ***
	//                                           *** Misleadingly named IsVmBusPresent in earlier docs ***
	//                                           *** Set in HvlPhase0Initialize from HviIsAnyHypervisorPresent() ***
	//                                           *** which checks only CPUID.1:ECX[31] (HYPERVISOR_BIT) ***
	//                                           *** Has NO connection to VMBus -- true under any hypervisor ***
	//   +0x03  BYTE   SchedulerType           = HvlpSchedulerType low byte
	//   +0x04  DWORD  Reserved                = 0 (always)
	//   +0x08  QWORD  HvlEnlightenments       = HvlEnlightenments (32-bit, zero-extended)
	//   Total: 0x10 bytes
	//
#pragma pack(push, 1)
	typedef struct _ENLIGHTENMENTS_INFO
	{
		BYTE  HvlHypervisorConnected;
		BYTE  IsRootPartition;   // (HvlpRootFlags >> 3) & 1
		BYTE  IsAnyHypervisorPresent; // (HvlpFlags >> 12) & 1 -- set when CPUID.1:ECX[31] is set
		BYTE  SchedulerType;
		DWORD Reserved;
		QWORD HvlEnlightenments;
	} ENLIGHTENMENTS_INFO;
#pragma pack(pop)

	ENLIGHTENMENTS_INFO info = { 0 };
	ULONG               returnLength = 0;

	NTSTATUS status = NtQuerySystemInformation(
		(SYSTEM_INFORMATION_CLASS)HVL_QUERY_ENLIGHTENMENT_INFO,
		&info,
		sizeof(info),
		&returnLength
	);

	if (!NT_SUCCESS(status))
	{
		fprintf(stderr, "NtQuerySystemInformation failed: 0x%X\n", status);
		return -1;
	}

	printf("HvlHypervisorConnected : %s\n", info.HvlHypervisorConnected ? "YES" : "NO");
	printf("IsRootPartition        : %s  [(HvlpRootFlags >> 3) & 1]\n", info.IsRootPartition ? "YES" : "NO");
	printf("IsAnyHypervisorPresent : %s  [(HvlpFlags >> 12) & 1  CPUID.1:ECX[31]]\n",
		info.IsAnyHypervisorPresent ? "YES" : "NO");
	printf("  (Named 'IsVmBusPresent' in older docs but has no VMBus connection;\n");
	printf("   set by HvlPhase0Initialize from HviIsAnyHypervisorPresent() which\n");
	printf("   checks only CPUID.1:ECX[31]. Always YES under any hypervisor incl. KVM.)\n");
	printf("SchedulerType          : %u  (%s)\n", info.SchedulerType, GetSchedulerTypeString(info.SchedulerType));
	if (info.SchedulerType == 0)
		printf("  (0 = HvlpSchedulerType not set: HvlpQueryHypervisorSchedulerType\n"
		       "   calls hypercall 0x7B property 0x0F; returns 0 if not implemented.)\n");

	PrintEnlightenments(info.HvlEnlightenments);
	PrintStimerCapabilities();
	PrintVsmAndNestingInfo(NtQuerySystemInformation);
	PrintMorAndMorLock();
	PrintSystemBasicInfo(NtQuerySystemInformation);
	PrintDeviceGuardInfo(NtQuerySystemInformation);
	PrintDmaProtectionDetail(NtQuerySystemInformation);
	PrintTpmAndCredentialGuardInfo();
	PrintSpeculationControlInfo(NtQuerySystemInformation);
	PrintHvDetailInfo(NtQuerySystemInformation);
	PrintHstiInfo(NtQuerySystemInformation);

	// DumpHypervisorFeatures();

	return 0;
}
