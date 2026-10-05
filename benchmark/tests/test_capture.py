import tempfile
import unittest
from unittest.mock import Mock, patch
from benchmark.capture import NativeCapture


class CaptureTests(unittest.TestCase):
    def test_final_statistics_override_intermediate_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            capture = NativeCapture({20000: {}}, tmp)
            capture.log.write_text('tcpdump: 4 packets captured, 8 packets received by filter, 0 packets dropped by kernel\n'
                                   '10 packets captured\n20 packets received by filter\n0 packets dropped by kernel\n')
            capture.process = Mock()
            capture.process.wait.return_value = 0
            capture.handle = Mock()
            with patch('benchmark.capture.time.sleep'):
                self.assertEqual(capture.finish(), dict(captured=10, received=20, dropped=0))
