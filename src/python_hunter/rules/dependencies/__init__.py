"""Dependency & Supply-Chain Rules Package."""

from python_hunter.rules.dependencies.pyh_dep_001_unpinned import PYHDep001Unpinned
from python_hunter.rules.dependencies.pyh_dep_002_broad_range import PYHDep002BroadRange
from python_hunter.rules.dependencies.pyh_dep_003_conflicting import PYHDep003Conflicting
from python_hunter.rules.dependencies.pyh_dep_004_lockfile_sync import PYHDep004LockfileSync
from python_hunter.rules.dependencies.pyh_supply_001_mutable_vcs import PYHSupply001MutableVCS
from python_hunter.rules.dependencies.pyh_supply_002_direct_url import PYHSupply002DirectURL
from python_hunter.rules.dependencies.pyh_supply_003_missing_hash import PYHSupply003MissingHash
from python_hunter.rules.dependencies.pyh_supply_004_package_shadowing import PYHSupply004PackageShadowing
from python_hunter.rules.dependencies.pyh_supply_005_yanked_release import PYHSupply005YankedRelease


def get_all_dependency_rules() -> list[object]:
    """Return instances of all 9 dependency and supply-chain analysis rules."""
    return [
        PYHDep001Unpinned(),
        PYHDep002BroadRange(),
        PYHDep003Conflicting(),
        PYHDep004LockfileSync(),
        PYHSupply001MutableVCS(),
        PYHSupply002DirectURL(),
        PYHSupply003MissingHash(),
        PYHSupply004PackageShadowing(),
        PYHSupply005YankedRelease(),
    ]


__all__ = [
    "PYHDep001Unpinned",
    "PYHDep002BroadRange",
    "PYHDep003Conflicting",
    "PYHDep004LockfileSync",
    "PYHSupply001MutableVCS",
    "PYHSupply002DirectURL",
    "PYHSupply003MissingHash",
    "PYHSupply004PackageShadowing",
    "PYHSupply005YankedRelease",
    "get_all_dependency_rules",
]
