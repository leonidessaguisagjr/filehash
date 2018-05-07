import os.path
import unittest

from filehash import FileHash
from filehash.filehash import CRC32


class TestFileHash(unittest.TestCase):

    def setUp(self):
        self.test_filenames = ['lorem_ipsum.txt', 'lorem_ipsum.zip']
        self.algorithms = ['crc32', 'md5', 'sha1', 'sha256', 'sha512']
        self.expected_results = {
            'lorem_ipsum.txt': {
                'crc32': 'A8504B9F',
                'md5': '72f5d9e3a5fa2f2e591487ae02489388',
                'sha1': 'f7ef3b7afaf1518032da1b832436ef3bbfd4e6f0',
                'sha256': '52ee30e57cc262b84ff73377223818825583b8120394ef54e9b4cd7dbec57d18',
                'sha512': 'dfc4e13af6e57b4982bdac595e83804dcb2d126204baa290f19015982d13e822a07efa1f0e63a8078e10f219c69d26caf4f21a50e3dd5bdf09bea73dfe224e43'
            },
            'lorem_ipsum.zip': {
                'crc32': '7425D3BE',
                'md5': '860f55178330e675fb0d55ac1f2c27b2',
                'sha1': '03da86258449317e8834a54cf8c4d5b41e7c7128',
                'sha256': '8acac0dc358b981aef0dcecc6e6d8f4f1fb98968d61e613b430b2389d9d385e5',
                'sha512': 'edd841dd0ed5bb09fd21054de3aebbbd44d779beaa0289d63bfb64f0eaaa85c73993d5cbc0d0d1dfcc263d7bd8d43bdafe2bcc398cc8453823e50f0d90a3b0ff'
            }
        }
        self.current_dir = os.getcwd()
        os.chdir(os.path.join(os.path.abspath(os.path.dirname(__file__)), "testdata"))

    def tearDown(self):
        os.chdir(self.current_dir)

    def test_hash_file(self):
        for algo in self.algorithms:
            for filename in self.test_filenames:
                hasher = FileHash(algo)
                self.assertEqual(self.expected_results[filename][algo], hasher.hash_file(filename))

    def test_hash_dir(self):
        os.chdir("..")
        for algo in self.algorithms:
            for filename in self.test_filenames:
                hasher = FileHash(algo)
                basename, ext = os.path.splitext(filename)
                results = hasher.hash_dir("./testdata", "*" + ext)
                for result in results:
                    self.assertEqual(self.expected_results[filename][algo], result.hash)

    def test_verify_checksums(self):
        for algo in self.algorithms:
            hasher = FileHash(algo)
            results = [result.hashes_match for result in hasher.verify_checksums("hashes." + algo)]
            self.assertTrue(all(results))

    def test_verify_sfv(self):
        hasher = FileHash('crc32')
        results = [result.hashes_match for result in hasher.verify_sfv("lorem_ipsum.sfv")]
        self.assertTrue(all(results))

    def test_verify_sfv_neg(self):
        hasher = FileHash('sha1')
        self.assertRaises(TypeError, hasher.verify_sfv, "lorem_ipsum.sfv")


class TestCRC32(unittest.TestCase):

    def test_name(self):
        hash = CRC32()
        self.assertEqual(hash.__class__.__name__.lower(), CRC32.name)

    def test_hexdigest(self):
        hash = CRC32()
        hash.update(b'The quick brown fox jumps over the lazy dog')
        self.assertEqual(hex(hash.digest()).upper()[2:], hash.hexdigest())

    def test_update(self):
        hash1 = CRC32()
        hash1.update(b'The quick brown fox ')
        hash1.update(b'jumps over the lazy dog')
        hash2 = CRC32()
        hash2.update(b'The quick brown fox jumps over the lazy dog')
        self.assertEqual(hash1.digest(), hash2.digest())
        self.assertEqual(hash1.hexdigest(), hash2.hexdigest())

    def test_copy(self):
        hash1 = CRC32()
        hash1.update(b'The quick brown fox ')
        hash2 = hash1.copy()
        self.assertEqual(hash1.digest(), hash2.digest())
        hash2.update(b'jumps over the lazy dog')
        self.assertNotEqual(hash1.digest(), hash2.digest())


if __name__ == "__main__":
    unittest.main()
