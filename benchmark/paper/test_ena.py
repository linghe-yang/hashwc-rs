import asyncio
import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock

from measurements import ena_rows, export

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "remote_coin"))
from remote import ena_snapshot


class EnaMeasurements(unittest.TestCase):
    def test_export_roundtrip(self):
        host = AsyncMock()
        host.shell.side_effect = [
            "interface ens5\n bw_in_allowance_exceeded: 7\n bw_out_allowance_exceeded: 2\n pps_allowance_exceeded: 3",
            "interface ens5\n bw_in_allowance_exceeded: 10\n bw_out_allowance_exceeded: 2\n pps_allowance_exceeded: 1",
        ]
        before = asyncio.run(ena_snapshot(host))
        after = asyncio.run(ena_snapshot(host))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            (path/'control.json').write_text(json.dumps(dict(ena_before_start=[before], ena_after_stop=[after])))
            (path/'party-0.jsonl').touch()
            case = dict(n=1, job_id='offline', family='test', protocol='whcc', repeat=1)
            export(path, path/'derived', case)
            with (path/'derived/ena.csv').open() as f:
                rows = {row['counter']:row for row in csv.DictReader(f)}
            self.assertEqual(rows['bw_in_allowance_exceeded']['delta'], '3')
            self.assertEqual(rows['bw_out_allowance_exceeded']['delta'], '0')
            self.assertEqual(rows['pps_allowance_exceeded']['status'], 'counter reset')
            self.assertEqual(rows['pps_allowance_exceeded']['delta'], '')

    def test_unavailable(self):
        host = AsyncMock()
        host.shell.return_value = ''
        missing = asyncio.run(ena_snapshot(host))
        self.assertIn('error', missing)
        partial = {'interfaces': {'ens5': {'bw_in_allowance_exceeded': 3}}}
        for a, b in ((missing, partial), (partial, missing), (missing, missing)):
            rows = ena_rows(dict(ena_before_start=[a], ena_after_stop=[b]), {'n':1})
            self.assertTrue(all(r['delta'] is None and r['status'] != 'ok' for r in rows))
        self.assertEqual(ena_rows({}, {'n':1}), [])
