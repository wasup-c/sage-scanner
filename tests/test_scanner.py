import pytest

from sagesec.scanner import TargetNotAllowedError, build_command, validate_target

FAKE_NMAP = "/usr/bin/nmap"


def test_in_scope_ip_is_allowed():
    assert str(validate_target("10.10.10.10")) == "10.10.10.10"


@pytest.mark.parametrize("target", ["192.168.0.1", "8.8.8.8", "10.10.11.1"])
def test_out_of_scope_ip_is_rejected(target):
    with pytest.raises(TargetNotAllowedError):
        validate_target(target)


@pytest.mark.parametrize(
    "target",
    [
        "10.10.10.10; rm -rf /",         # shell injection
        "$(whoami)",                      # command substitution
        "-iL /etc/passwd",                # argument injection: read targets from a file
        "--script=http-shellshock",       # argument injection: run an NSE script
        "10.10.10.0/24",                  # ranges not allowed yet
        "dc01.lab.internal",              # hostnames not allowed yet (DNS rebinding)
        "",
    ],
)
def test_malicious_or_unsupported_targets_are_rejected(target):
    with pytest.raises(TargetNotAllowedError):
        validate_target(target)


def test_scope_is_configurable(monkeypatch):
    monkeypatch.setenv("SAGE_ALLOWED_NETWORKS", "10.20.0.0/24")
    assert str(validate_target("10.20.0.5")) == "10.20.0.5"
    with pytest.raises(TargetNotAllowedError):
        validate_target("10.10.10.10")


def test_build_command_structure():
    argv = build_command("service", "10.10.10.10", nmap_path=FAKE_NMAP)
    assert argv[0] == FAKE_NMAP
    assert argv[-1] == "10.10.10.10"
    assert ["-oX", "-"] == argv[-3:-1]
    assert "-sV" in argv


def test_target_is_reserialized_not_passed_through():
    # Whitespace in the user's input never reaches nmap.
    argv = build_command("quick", "  10.10.10.10  ", nmap_path=FAKE_NMAP)
    assert argv[-1] == "10.10.10.10"


def test_unknown_profile_rejected():
    with pytest.raises(ValueError):
        build_command("everything", "10.10.10.10", nmap_path=FAKE_NMAP)
