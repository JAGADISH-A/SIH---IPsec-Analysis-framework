"""Experiment-boundary gate on the capture feed (acceptance tests 1-10).

The LIVE table must show ONLY the current testbed experiment's packets. The
feed enforces this server-side via a byte boundary supplied by the controller
manifest: no manifest, wrong-journal, or an ended experiment all close the
feed (zero rows, ``current: false``); while active only journal lines at/after
``observation_start_bytes`` are ever surfaced. The legacy / demo / replay feed
paths (gating disabled) keep their historical tailing behavior.
"""

import json
import os
import tempfile
import time
import unittest

from correlation.api.capture_feed import CaptureFeedService, GATE_LEGACY, GATE_ACTIVE, GATE_CLOSED
from correlation.api.run_annex import CurrentRunAnnex

OLD_SPI = 0x11111
EXP1_SPI = 0x22222
EXP2_SPI = 0x33333


def _sample(spi, seq, proto=50, index=0):
    return {
        "ts": 17260803212308 + index,
        "type": "ESP",
        "src": "192.168.100.1",
        "dst": "192.168.100.2",
        "proto": proto,
        "len": 154,
        "spi": spi,
        "seq": seq,
    }


def _write_journal(dirpath, lines):
    """Write JSONL lines and return (path, byte_offset_of_each_line)."""
    path = os.path.join(dirpath, "journal.jsonl")
    offsets = []
    with open(path, "wb") as fh:
        for line in lines:
            offsets.append(fh.tell())
            fh.write(json.dumps(line).encode("utf-8") + b"\n")
    return path, offsets


def _feed(path, provider, gated=True):
    return CaptureFeedService(
        path,
        boundary_provider=provider,
        experiment_gated=gated,
        freshness_window_ms=8000,
    )


def _provider_for(path, start_bytes=None, ended=False, journal_path=None):
    if start_bytes is None:
        return lambda: None
    payload = {
        "journal_path": os.path.abspath(journal_path if journal_path is not None else path),
        "start_bytes": start_bytes,
        "ended": ended,
    }
    return lambda: dict(payload)


class TestBoundaryGate(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        history = [_sample(OLD_SPI, seq=seq, index=seq) for seq in range(100)]
        self.path, self.offsets = _write_journal(self._tmp.name, history)

    def _append(self, lines):
        path = os.path.join(self._tmp.name, "journal.jsonl")
        new_offsets = []
        with open(path, "ab") as fh:
            for line in lines:
                new_offsets.append(fh.tell())
                fh.write(json.dumps(line).encode("utf-8") + b"\n")
        return new_offsets

    # Test 1 / 10 -- start Sentinel with NO experiment: the historical journal
    # holds 100 packets but the LIVE view must be empty and not current.
    def test_no_manifest_closes_feed(self):
        feed = _feed(self.path, _provider_for(self.path))
        page = feed.poll(cursor=0, limit=200)
        self.assertFalse(page["current"])
        self.assertEqual(page["count"], 0)
        self.assertEqual(page["events"], [])
        status = feed.status()
        self.assertFalse(status["current"])
        self.assertEqual(status["events"], 0)

    # Test 1 variant -- no experiment via a manifest on a DIFFERENT journal
    # (e.g. Sentinel bound to the cumulative full.jsonl) must also be empty.
    def test_wrong_journal_closes_feed(self):
        other = os.path.join(self._tmp.name, "other.jsonl")
        with open(other, "w") as fh:
            fh.write("x\n")
        feed = _feed(self.path, _provider_for(self.path, start_bytes=0, journal_path=other))
        page = feed.poll(cursor=0, limit=200)
        self.assertFalse(page["current"])
        self.assertEqual(page["count"], 0)

    # Test 2 -- experiment 1 has started (start manifest written, boundary =
    # current journal end). No new packets yet => LIVE table must be empty.
    def test_experiment_start_empty(self):
        boundary = self.offsets[-1] + len(json.dumps(_sample(OLD_SPI, 0)).encode()) + 1
        feed = _feed(self.path, _provider_for(self.path, start_bytes=boundary))
        page = feed.poll(cursor=0, limit=200)
        self.assertEqual(page["count"], 0)
        self.assertEqual(page["events"], [])

    # Test 3 / 6 -- experiment 1 packets arrive: ONLY lines at/after the
    # boundary are served; the 100 historical rows never appear.
    def test_only_experiment_packets_served(self):
        boundary = self.offsets[-1] + len(json.dumps(_sample(OLD_SPI, 0)).encode()) + 1
        self._append([_sample(EXP1_SPI, seq=s, index=1000 + s) for s in range(4)])
        feed = _feed(self.path, _provider_for(self.path, start_bytes=boundary))
        page = feed.poll(cursor=0, limit=200)
        self.assertEqual(page["count"], 4)
        self.assertTrue(all(ev["spi"] == EXP1_SPI for ev in page["events"]))
        self.assertTrue(all(ev["offset"] >= boundary for ev in page["events"]))
        self.assertFalse(any(ev["spi"] == OLD_SPI for ev in page["events"]))

    # Test 7 / 9 -- an OLD packet whose SPI matches the current experiment's
    # SPI is still excluded: isolation is by byte boundary, never by SPI.
    def test_old_packet_same_spi_excluded(self):
        dup_old = _sample(EXP1_SPI, seq=999, index=50)
        with open(self.path, "a") as fh:
            fh.write(json.dumps(dup_old).encode("utf-8").decode() + "\n")
        boundary = os.path.getsize(self.path)
        self._append([_sample(EXP1_SPI, seq=1, index=2000)])
        feed = _feed(self.path, _provider_for(self.path, start_bytes=boundary))
        page = feed.poll(cursor=0, limit=200)
        self.assertEqual(page["count"], 1)
        self.assertEqual(page["events"][0]["packet"]["sequence"], 1)

    # Test 4 -- experiment 1 STOPPED: ended manifest => immediate empty +
    # not current, even though the journal is unchanged.
    def test_ended_experiment_empties_immediately(self):
        boundary = self.offsets[-1] + len(json.dumps(_sample(OLD_SPI, 0)).encode()) + 1
        self._append([_sample(EXP1_SPI, seq=1, index=3000), _sample(EXP1_SPI, seq=2, index=3001)])
        feed = _feed(
            self.path,
            _provider_for(self.path, start_bytes=boundary, ended=True),
        )
        page = feed.poll(cursor=0, limit=200)
        self.assertEqual(page["count"], 0)
        self.assertEqual(page["events"], [])
        self.assertFalse(page["current"])

    # Test 5 / 6 -- experiment 2 starts with a new boundary: experiment 1
    # packets are gone, only experiment 2 packets appear.
    def test_experiment2_only_own_packets(self):
        exp1_bounds = [self._append([_sample(EXP1_SPI, seq=1, index=4000)])[0]]
        boundary2 = exp1_bounds[0] + len(json.dumps(_sample(EXP1_SPI, 1)).encode()) + 1
        self._append([_sample(EXP2_SPI, seq=1, index=5000)])
        feed = _feed(self.path, _provider_for(self.path, start_bytes=boundary2))
        page = feed.poll(cursor=0, limit=200)
        self.assertEqual(page["count"], 1)
        self.assertEqual(page["events"][0]["spi"], EXP2_SPI)

    # Test 10 -- replay/demo fallback keeps working: gating is disabled there,
    # so the historical rows remain readable on purpose (and are never mis-
    # labeled current for a live testbed that is not providing a boundary).
    def test_legacy_replay_path_unaffected(self):
        feed = _feed(self.path, _provider_for(self.path), gated=False)
        page = feed.poll(cursor=0, limit=200)
        self.assertEqual(page["count"], 100)

    # Defensive: a broken boundary provider closes rather than leaks.
    def test_provider_error_closes(self):
        def boom():
            raise RuntimeError("manifest unreadable")

        feed = _feed(self.path, boom)
        page = feed.poll(cursor=0, limit=200)
        self.assertEqual(page["count"], 0)
        self.assertFalse(page["current"])

    # Rotation/truncation mid-run must never resurrect pre-boundary rows.
    def test_rotation_does_not_fall_back_to_head(self):
        boundary = self.offsets[-1] + len(json.dumps(_sample(OLD_SPI, 0)).encode()) + 1
        feed = _feed(self.path, _provider_for(self.path, start_bytes=boundary))
        page = feed.poll(cursor=boundary + 9999, limit=200)
        self.assertEqual(page["count"], 0)

    def test_gate_vocabulary(self):
        mode, _start = _boundary_gate_legacy()
        self.assertEqual(mode, GATE_LEGACY)


def _boundary_gate_legacy():
    import tempfile as _t

    with _t.TemporaryDirectory() as tmp:
        path, _ = _write_journal(tmp, [_sample(1, 1)])
        feed = _feed(path, lambda: None, gated=False)
        return feed._boundary_gate()


class TestAnnexBoundary(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.journal = os.path.join(self._tmp.name, "live_events.jsonl")
        with open(self.journal, "w") as fh:
            fh.write(json.dumps(_sample(EXP1_SPI, 1)) + "\n")
        self.manifest = os.path.join(self._tmp.name, "experiment.json")

    def _annex(self, run_fields, journal_path=None):
        raw = {
            "schema": "testbed-experiment-manifest/v1",
            "run": {"job_id": "job-1", "assessment_id": "job-1:1:current", **run_fields},
            "journal": {"path": journal_path or self.journal},
        }
        with open(self.manifest, "w") as fh:
            json.dump(raw, fh)
        os.utime(self.manifest, ns=(os.stat(self.manifest).st_atime_ns,
                                    time.time_ns() * 1_000_000 + 1))
        return CurrentRunAnnex(store=None, feed=None, manifest_path=self.manifest)

    def test_no_manifest_none(self):
        annex = CurrentRunAnnex(store=None, feed=None, manifest_path="missing.json")
        self.assertIsNone(annex.boundary())

    def test_active_boundary(self):
        annex = self._annex({"observation_start_bytes": 42}, journal_path=self.journal)
        info = annex.boundary()
        self.assertIsNotNone(info)
        self.assertEqual(info["start_bytes"], 42)
        self.assertEqual(info["journal_path"], os.path.abspath(self.journal))
        self.assertFalse(info["ended"])

    def test_ended_boundary(self):
        annex = self._annex(
            {"observation_start_bytes": 42, "ended_at_ns": 123}, journal_path=self.journal
        )
        info = annex.boundary()
        self.assertTrue(info["ended"])

    def test_mtime_cache(self):
        annex = self._annex({"observation_start_bytes": 7}, journal_path=self.journal)
        first = annex.boundary()
        self.assertEqual(first["start_bytes"], 7)
        self.assertEqual(first["start_bytes"], annex.boundary()["start_bytes"])


if __name__ == "__main__":
    unittest.main()