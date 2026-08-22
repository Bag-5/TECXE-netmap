from dataclasses import dataclass, field


@dataclass(frozen=True)
class ScanProfile:
    name: str
    description: str
    flags: list[str] = field(default_factory=list)
    requires_admin: bool = False


PROFILES: dict[str, ScanProfile] = {
    "quick": ScanProfile(
        name="quick",
        description="Fast discovery — top 1000 ports + version detection.",
        flags=["-T4", "-F", "--open", "-sV"],
    ),
    "full": ScanProfile(
        name="full",
        description="Deep audit — all ports, OS detect, vuln scripts. Slow.",
        flags=["-T3", "-p-", "-sV", "-O", "--script", "vuln", "--version-all"],
        requires_admin=True,
    ),
    "stealth": ScanProfile(
        name="stealth",
        description="Quiet SYN scan on common admin ports.",
        flags=["-T2", "-sS", "-p", "22,80,443,445,3389,5985", "-O"],
        requires_admin=True,
    ),
    "vuln": ScanProfile(
        name="vuln",
        description="Vulnerability-focused with auth enumeration scripts.",
        flags=["-T3", "--script", "vuln,auth", "-sV"],
    ),
}


def get_profile(name: str) -> ScanProfile:
    profile = PROFILES.get(name)
    if profile is None:
        raise ValueError(
            f"Unknown scan profile '{name}'. Available: {', '.join(PROFILES)}"
        )
    return profile
