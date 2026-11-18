"""Debug transcripts are advertised as safe to share: they must not carry identifiers."""

import json
import logging
import os

from icp import diag

APPLE_ID = "jane.doe@example.com"
DSID = "10111809477"


def test_scrub_masks_emails_and_long_numbers_in_free_text():
    text = f"signed in as {APPLE_ID} (dsid {DSID}) via https://p44.icloud.com/x?u={APPLE_ID}"
    out = diag.scrub(text)
    assert APPLE_ID not in out and DSID not in out
    assert "<email>" in out and "<number>" in out and "p44.icloud.com" in out


def test_scrub_leaves_ordinary_text_alone():
    for t in ("HTTP POST gsa.apple.com/grandslam/GsService2 -> 200 (1452 bytes, 0.35s)",
              "version 3.4.0", "ec=-80045", "port 6969", "1794505425"[:8]):
        assert diag.scrub(t) == t


def test_redact_handles_identifiers_in_values_and_keys():
    dumped = json.dumps(diag.redact({
        "primaryEmail": APPLE_ID, "note": f"mail {APPLE_ID} id {DSID}", "DsPrsId": int(DSID),
        "aliases": [f"x{APPLE_ID}"], "ok": "plain"}))
    assert APPLE_ID not in dumped and DSID not in dumped and "plain" in dumped


def test_the_log_file_never_contains_identifiers(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    path = diag.start()
    try:
        log = logging.getLogger("icp.test")
        log.debug("Signed in as %s", APPLE_ID)
        log.info("account %s", DSID)
        diag.dump(log, "response", {"acname": APPLE_ID, "free": f"see {APPLE_ID}"})
    finally:
        for h in list(logging.getLogger("icp").handlers):
            if isinstance(h, logging.FileHandler):
                logging.getLogger("icp").removeHandler(h)
                h.close()
    text = path.read_text()
    assert APPLE_ID not in text and DSID not in text and "response (redacted)" in text
    assert oct(os.stat(path).st_mode & 0o777) == "0o600"


def test_old_transcripts_are_pruned(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    d = tmp_path / "icp"
    d.mkdir()
    for i in range(6):
        f = d / f"debug-{i}.log"
        f.write_text("old")
        os.utime(f, (1000 + i, 1000 + i))
    path = diag.start()
    for h in list(logging.getLogger("icp").handlers):
        if isinstance(h, logging.FileHandler):
            logging.getLogger("icp").removeHandler(h)
            h.close()
    left = sorted(f.name for f in d.glob("debug-*.log"))
    assert len(left) == diag.KEEP_LOGS and path.name in left
    assert "debug-0.log" not in left and "debug-5.log" in left
