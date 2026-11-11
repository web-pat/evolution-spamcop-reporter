"""Validated TOML settings and private XDG storage."""

import ipaddress
import os
import re
import stat
import tomllib
from dataclasses import dataclass, field
from pathlib import Path


def config_path() -> Path:
    return xdg_path("XDG_CONFIG_HOME", Path.home() / ".config") / ("spamreporter/config.toml")


def data_path() -> Path:
    return xdg_path("XDG_DATA_HOME", Path.home() / ".local/share") / "spamreporter"


def xdg_path(name: str, fallback: Path) -> Path:
    value = Path(os.environ.get(name) or fallback).expanduser()
    # XDG specifies that relative environment values must be ignored.
    return value if value.is_absolute() else fallback


def configured_path(value: str, base: Path) -> Path:
    expanded = Path(value).expanduser()
    return Path(os.path.abspath(expanded if expanded.is_absolute() else base / expanded))


def private_dir(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink() or path.stat().st_uid != os.getuid():
        raise ValueError("Storage directory must be owned by you and not a symlink")
    if stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ValueError("Storage directory must have mode 0700")


def private_write(path: Path, data: bytes) -> None:
    """Exclusive creation; never follow symlinks or overwrite user files."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def address(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+", value):
        raise ValueError("Expected a bare ASCII email address")
    return value


@dataclass
class Source:
    name: str
    kind: str = "stdin"
    path: str = ""
    enabled: bool = True
    auto_submit: bool = False
    retention_days: int = 30
    domain: str = ""
    identity: str = "default"
    trusted_hosts: dict[str, list[str]] = field(default_factory=dict)


@dataclass
class Config:
    data_dir: Path = field(default_factory=data_path)
    recipient: str = ""
    identities: dict[str, str] = field(default_factory=dict)
    sources: dict[str, Source] = field(default_factory=dict)
    backend: str = "eml"
    allow_send: bool = False
    allow_automatic: bool = False
    sendmail: list[str] = field(default_factory=lambda: ["/usr/sbin/sendmail", "-i"])
    max_input_bytes: int = 10_000_000
    daily_limit: int = 20
    asn_csv: str = ""
    retain_statistics: bool = False

    def source(self, name: str) -> Source:
        if name not in self.sources or not self.sources[name].enabled:
            raise ValueError("Unknown or disabled source")
        return self.sources[name]

    def submission_addresses(self, source: str) -> tuple[str, str]:
        if not re.fullmatch(r"submit\.[A-Za-z0-9]+@spamcop\.net", self.recipient):
            raise ValueError("Configure your regular submit address (Quick is unsupported)")
        sender = self.identities.get(self.source(source).identity, "")
        return address(sender), self.recipient


def load(path: Path) -> Config:
    base = path.absolute().parent
    if path.is_symlink() or path.stat().st_uid != os.getuid():
        raise ValueError("Configuration must be owned by you and not a symlink")
    if path.stat().st_mode & 0o077:
        raise ValueError("Configuration contains private settings; chmod 600 it")
    with path.open("rb") as stream:
        values = tomllib.load(stream)
    sources = {}
    for entry in values.pop("sources", []):
        source = Source(**entry)
        if any(type(getattr(source, key)) is not bool for key in ("enabled", "auto_submit")):
            raise ValueError("Source permission settings must be TOML booleans, not quoted text")
        if type(source.retention_days) is not int:
            raise ValueError("Retention must be an integer")
        if any(
            not isinstance(getattr(source, key), str)
            for key in ("name", "kind", "path", "domain", "identity")
        ):
            raise ValueError("Source labels, paths and identity must be strings")
        if not isinstance(source.trusted_hosts, dict):
            raise ValueError("trusted_hosts must be a TOML table")
        if not re.fullmatch(r"[A-Za-z0-9_-]+", source.name) or source.name in sources:
            raise ValueError("Source names must be unique simple labels, not email addresses")
        if source.kind not in {"stdin", "eml", "maildir", "mbox"}:
            raise ValueError("Unsupported source kind")
        if not 1 <= source.retention_days <= 36500:
            raise ValueError("Retention must be between 1 and 36500 days")
        if source.path:
            source.path = str(configured_path(source.path, base))
        for host, networks in source.trusted_hosts.items():
            if not re.fullmatch(r"[A-Za-z0-9.-]+", host) or not isinstance(networks, list):
                raise ValueError(
                    "Trust entries require exact host names and arrays of CIDR networks"
                )
            for network in networks:
                ipaddress.ip_network(network)
        sources[source.name] = source
    if "data_dir" in values:
        values["data_dir"] = configured_path(values["data_dir"], base)
    cfg = Config(sources=sources, **values)
    if any(
        type(getattr(cfg, key)) is not bool
        for key in ("allow_send", "allow_automatic", "retain_statistics")
    ):
        raise ValueError("Transport permissions must be TOML booleans, not quoted text")
    if any(type(getattr(cfg, key)) is not int for key in ("daily_limit", "max_input_bytes")):
        raise ValueError("Resource limits must be integers")
    if any(not isinstance(getattr(cfg, key), str) for key in ("backend", "recipient", "asn_csv")):
        raise ValueError("Backend, recipient and ASN path must be strings")
    if not isinstance(cfg.identities, dict) or any(
        not isinstance(value, str) for value in cfg.identities.values()
    ):
        raise ValueError("identities must map names to email address strings")
    if cfg.backend not in {"eml", "evolution", "sendmail"}:
        raise ValueError("Unsupported backend")
    if not 1 <= cfg.daily_limit <= 1000 or not 1 <= cfg.max_input_bytes <= 100_000_000:
        raise ValueError("Invalid resource limits")
    if not isinstance(cfg.sendmail, list) or not cfg.sendmail:
        raise ValueError("sendmail must be a nonempty argument array")
    if any(not isinstance(arg, str) or "\x00" in arg for arg in cfg.sendmail):
        raise ValueError("Invalid sendmail arguments")
    # -t would introduce recipients from mutable headers; only our envelope is allowed.
    if "-t" in cfg.sendmail:
        raise ValueError("Do not use sendmail -t; the envelope recipient is supplied explicitly")
    if cfg.asn_csv:
        cfg.asn_csv = str(configured_path(cfg.asn_csv, base))
    if "/" in cfg.sendmail[0] and not Path(cfg.sendmail[0]).is_absolute():
        cfg.sendmail[0] = str(configured_path(cfg.sendmail[0], base))
    return cfg
