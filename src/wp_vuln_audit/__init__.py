"""Check WordPress core, plugin and theme versions against the Wordfence Intelligence feed."""

from ._version import __version__
from .audit import AuditOptions, AuditResult, Finding, audit, check_component
from .baseline import Baseline, BaselineComparison, BaselineError, compare
from .cache import FeedError, FeedSource
from .feed import Cvss, Feed, FeedFormatError, Software, Vulnerability
from .ignore import IgnoreList, IgnoreRule
from .inventory import Component, Inventory
from .ranges import VersionRange, parse_affected_versions, parse_range_label
from .remote import RemoteOptions, RemoteScanner
from .report import render
from .upgrade import Upgrade, plan_upgrades
from .versions import compare_versions, normalize_version
from .wp_local import scan_local
from .wpcli import parse_combined, parse_list

__all__ = [
    "AuditOptions",
    "AuditResult",
    "Baseline",
    "BaselineComparison",
    "BaselineError",
    "Component",
    "Cvss",
    "Feed",
    "FeedError",
    "FeedFormatError",
    "FeedSource",
    "Finding",
    "IgnoreList",
    "IgnoreRule",
    "Inventory",
    "RemoteOptions",
    "RemoteScanner",
    "Software",
    "Upgrade",
    "VersionRange",
    "Vulnerability",
    "__version__",
    "audit",
    "check_component",
    "compare",
    "compare_versions",
    "normalize_version",
    "parse_affected_versions",
    "parse_combined",
    "parse_list",
    "parse_range_label",
    "plan_upgrades",
    "render",
    "scan_local",
]
