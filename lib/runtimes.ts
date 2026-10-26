export type RuntimeRelease = {
  architecture: "x64" | "arm64";
  label: string;
  version: string;
  bootFile: string;
  repository: string;
  release: string;
  artifact: string;
  artifactUrl: string;
  bytes: number;
  sha256: string;
  maturity: string;
  validatedEnvironment: string;
  requirements: string[];
  limitations: string[];
};

export const runtimes: Record<RuntimeRelease["architecture"], RuntimeRelease> = {
  x64: {
    architecture: "x64",
    label: "x64 / AMD64",
    version: "0.1.0-ovmf-preview.1",
    bootFile: "EFI/BOOT/BOOTX64.EFI",
    repository: "https://github.com/araujota/openconsole",
    release: "https://github.com/araujota/openconsole/releases/tag/v0.1.0-ovmf-preview.1",
    artifact: "openconsole-0.1.0-ovmf-preview.1.fat",
    artifactUrl: "https://github.com/araujota/openconsole/releases/download/v0.1.0-ovmf-preview.1/openconsole-0.1.0-ovmf-preview.1.fat",
    bytes: 67108864,
    sha256: "f4fcfbb97c32524808006725094dc10feca8b2db4c302e7461d68bab62631cf9",
    maturity: "Disposable OVMF development preview",
    validatedEnvironment: "QEMU x86_64 + OVMF",
    requirements: ["64-bit x86 UEFI", "Removable-media boot enabled"],
    limitations: ["Broad physical hardware and Secure Boot enrollment are not claimed."],
  },
  arm64: {
    architecture: "arm64",
    label: "ARM64 / AArch64",
    version: "0.1.0-aavmf-preview.1",
    bootFile: "EFI/BOOT/BOOTAA64.EFI",
    repository: "https://github.com/araujota/openconsole-arm64",
    release: "https://github.com/araujota/openconsole-arm64/releases/tag/v0.1.0-aavmf-preview.1",
    artifact: "openconsole-arm64-0.1.0-aavmf-preview.1.fat",
    artifactUrl: "https://github.com/araujota/openconsole-arm64/releases/download/v0.1.0-aavmf-preview.1/openconsole-arm64-0.1.0-aavmf-preview.1.fat",
    bytes: 67108864,
    sha256: "6f7a2db1adb3d2a5f5275b714d08767488166f84878d17d5f33fa7c63e51896b",
    maturity: "AAVMF-validated development preview",
    validatedEnvironment: "QEMU virt + AAVMF 2024.02",
    requirements: ["64-bit ARM UEFI", "Removable-media boot enabled"],
    limitations: ["Physical hardware, networking, audio, Secure Boot, and GPU acceleration are unverified."],
  },
};

export const runtimeCatalog = {
  schema: "openconsole.runtime-releases.v2",
  defaultArchitecture: "x64",
  runtimes,
  legacyX64: {
    runtimeVersion: runtimes.x64.version,
    runtimeRepository: runtimes.x64.repository,
    runtimeRelease: runtimes.x64.release,
    developmentImage: runtimes.x64.artifact,
  },
};
