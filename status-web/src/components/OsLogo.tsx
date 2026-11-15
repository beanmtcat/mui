import { memo, useState, type CSSProperties } from "react";
import alibabaLogo from "../os-logos/alibabacloud-color.svg";
import linuxLogo from "../os-logos/linux.svg";
import openCloudOsLogo from "../os-logos/os-OpenCloudOS.png";
import almaLogo from "../os-logos/os-alma.svg";
import alpineLogo from "../os-logos/os-alpine.webp";
import archLogo from "../os-logos/os-arch.svg";
import armbianLogo from "../os-logos/os-armbian.svg";
import astraLogo from "../os-logos/os-astar.png";
import centosLogo from "../os-logos/os-centos.svg";
import debianLogo from "../os-logos/os-debian.svg";
import fedoraLogo from "../os-logos/os-fedora.svg";
import fnosLogo from "../os-logos/os-fnos.ico";
import freebsdLogo from "../os-logos/os-freebsd.svg";
import gentooLogo from "../os-logos/os-gentoo.svg";
import huaweiLogo from "../os-logos/os-huawei.svg";
import istoreLogo from "../os-logos/os-istore.png";
import kaliLogo from "../os-logos/os-kail.svg";
import macosLogo from "../os-logos/os-macos.svg";
import manjaroLogo from "../os-logos/os-manjaro-.svg";
import mintLogo from "../os-logos/os-mint.svg";
import nixLogo from "../os-logos/os-nix.svg";
import opensuseLogo from "../os-logos/os-openSUSE.svg";
import openwrtLogo from "../os-logos/os-openwrt.svg";
import orangePiLogo from "../os-logos/os-orange-pi.svg";
import proxmoxLogo from "../os-logos/os-proxmox.ico";
import qnapLogo from "../os-logos/os-qnap.svg";
import redhatLogo from "../os-logos/os-redhat.svg";
import rockyLogo from "../os-logos/os-rocky.svg";
import synologyLogo from "../os-logos/os-synology.ico";
import ubuntuLogo from "../os-logos/os-ubuntu.svg";
import unraidLogo from "../os-logos/os-unraid.svg";
import windowsLogo from "../os-logos/os-windows.svg";

interface OsConfig {
  name: string;
  image: string;
  keywords: string[];
}

const OS_NAME_SPLIT_REGEX = /[\s/]+/;

const OS_CONFIGS: OsConfig[] = [
  { name: "AlmaLinux", image: almaLogo, keywords: ["alma", "almalinux"] },
  { name: "Alpine Linux", image: alpineLogo, keywords: ["alpine", "alpine linux"] },
  { name: "Armbian", image: armbianLogo, keywords: ["armbian"] },
  { name: "CentOS", image: centosLogo, keywords: ["centos", "cent os"] },
  { name: "Debian", image: debianLogo, keywords: ["debian", "deb"] },
  { name: "FreeBSD", image: freebsdLogo, keywords: ["freebsd", "bsd"] },
  { name: "Ubuntu", image: ubuntuLogo, keywords: ["ubuntu", "elementary"] },
  { name: "Windows", image: windowsLogo, keywords: ["windows", "win", "microsoft", "ms"] },
  { name: "Arch Linux", image: archLogo, keywords: ["arch", "archlinux", "arch linux"] },
  { name: "Kali Linux", image: kaliLogo, keywords: ["kail", "kali", "kali linux"] },
  { name: "iStoreOS", image: istoreLogo, keywords: ["istore", "istoreos", "istore os"] },
  { name: "OpenWrt", image: openwrtLogo, keywords: ["openwrt", "open wrt", "open-wrt", "qwrt"] },
  { name: "ImmortalWrt", image: openwrtLogo, keywords: ["immortalwrt", "immortal", "emmortal"] },
  { name: "NixOS", image: nixLogo, keywords: ["nixos", "nix os", "nix"] },
  { name: "Rocky Linux", image: rockyLogo, keywords: ["rocky", "rocky linux"] },
  { name: "Fedora", image: fedoraLogo, keywords: ["fedora"] },
  { name: "openSUSE", image: opensuseLogo, keywords: ["opensuse", "suse"] },
  { name: "Gentoo", image: gentooLogo, keywords: ["gentoo"] },
  { name: "Red Hat", image: redhatLogo, keywords: ["redhat", "rhel", "red hat"] },
  { name: "Linux Mint", image: mintLogo, keywords: ["mint", "linux mint"] },
  { name: "Manjaro", image: manjaroLogo, keywords: ["manjaro"] },
  { name: "Synology DSM", image: synologyLogo, keywords: ["synology", "dsm", "synology dsm"] },
  { name: "fnOS", image: fnosLogo, keywords: ["fnos", "fnnas"] },
  { name: "Proxmox VE", image: proxmoxLogo, keywords: ["proxmox", "proxmox ve"] },
  { name: "macOS", image: macosLogo, keywords: ["macos", "mac os", "mac os x", "osx", "darwin"] },
  { name: "QTS", image: qnapLogo, keywords: ["qts", "quts hero", "qes", "qutscloud"] },
  { name: "Astra Linux", image: astraLogo, keywords: ["astra", "astra linux"] },
  { name: "Orange Pi", image: orangePiLogo, keywords: ["orange pi", "orangepi"] },
  { name: "Huawei", image: huaweiLogo, keywords: ["huawei", "euleros", "euler os"] },
  { name: "Aliyun", image: alibabaLogo, keywords: ["aliyun", "alibaba"] },
  { name: "OpenCloudOS", image: openCloudOsLogo, keywords: ["opencloud"] },
  { name: "Unraid", image: unraidLogo, keywords: ["unraid"] },
];

const DEFAULT_OS_CONFIG: OsConfig = {
  name: "Linux",
  image: linuxLogo,
  keywords: ["unknown"],
};

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

const OS_MATCHERS = OS_CONFIGS.map((config) => ({
  config,
  matcher: new RegExp(`\\b(?:${config.keywords.map(escapeRegExp).join("|")})\\b`),
}));

export function resolveOsInfo(value?: string | null): OsConfig {
  if (value) {
    const normalizedInput = value.toLowerCase().trim();
    for (const { config, matcher } of OS_MATCHERS) {
      if (matcher.test(normalizedInput)) {
        return config;
      }
    }
  }
  const name = value?.trim().split(OS_NAME_SPLIT_REGEX)[0] || DEFAULT_OS_CONFIG.name;
  return {
    ...DEFAULT_OS_CONFIG,
    name,
  };
}

export const OsLogo = memo(function OsLogo({
  value,
  size = 18,
}: {
  value?: string | null;
  size?: number;
}) {
  const os = resolveOsInfo(value);
  const [failedImage, setFailedImage] = useState<string | null>(null);
  const src = failedImage === os.image ? DEFAULT_OS_CONFIG.image : os.image;

  return (
    <img
      className="os-logo"
      src={src}
      alt={os.name}
      title={os.name}
      width={size}
      height={size}
      loading="lazy"
      draggable={false}
      onError={() => {
        if (src !== DEFAULT_OS_CONFIG.image) setFailedImage(os.image);
      }}
      style={{ "--os-logo-size": `${size}px` } as CSSProperties}
    />
  );
});
