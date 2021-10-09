import inspect
import os.path
import unittest

import filehash.filehash
from filehash import FileHash, SUPPORTED_ALGORITHMS

from filehash.filehash_cli import create_parser


class TestFileHash(unittest.TestCase):
    """Test the FileHash class."""

    def setUp(self):
        # Expected results from https://www.fileformat.info/tool/hash.htm
        self.expected_results = {
            'lorem_ipsum.txt': {
                'adler32': 'E5ED731F',
                'crc32': 'A8504B9F',
                'md5': '72f5d9e3a5fa2f2e591487ae02489388',
                'sha1': 'f7ef3b7afaf1518032da1b832436ef3bbfd4e6f0',
                'sha224': '9b80ecc279231d72c94385bd27c897cf90d1fd3dd41a88a3d36ba6f3',
                'sha256': '52ee30e57cc262b84ff73377223818825583b8120394ef54e9b4cd7dbec57d18',
                'sha384': '1b5b458dacc254a1236cb713b75acfd86dcdde92c6b7a3619cfc65225f2d0dbb47b4c1cf0fd8d58c3c75f2e3127cbb0a',
                'sha512': 'dfc4e13af6e57b4982bdac595e83804dcb2d126204baa290f19015982d13e822a07efa1f0e63a8078e10f219c69d26caf4f21a50e3dd5bdf09bea73dfe224e43'
            },
            'lorem_ipsum.zip': {
                'adler32': '5195A9D6',
                'crc32': '7425D3BE',
                'md5': '860f55178330e675fb0d55ac1f2c27b2',
                'sha1': '03da86258449317e8834a54cf8c4d5b41e7c7128',
                'sha224': 'ac8991d5bcebdecbc93286ba4010221127e423c5ce903d8e98d71289',
                'sha256': '8acac0dc358b981aef0dcecc6e6d8f4f1fb98968d61e613b430b2389d9d385e5',
                'sha384': '84606ebac41d2d2aaa189a8b1359f966cb8d9e049a517e31768724b6f8543261a0ef64154802fecd10c6d3838a555a37',
                'sha512': 'edd841dd0ed5bb09fd21054de3aebbbd44d779beaa0289d63bfb64f0eaaa85c73993d5cbc0d0d1dfcc263d7bd8d43bdafe2bcc398cc8453823e50f0d90a3b0ff'
            },
            'lorem_ipsum_txt+zip.cat': {
                'adler32': '8BA81D03',
                'crc32': 'C2D8AD7F',
                'md5': '96a7ef7737b1469621832ef6f5b0bc25',
                'sha1': '1ac64d235601ba35d44c56953f338cba294bff9f',
                'sha224': 'f32ea20ea008f9b6590b444ef82c383af4f666ca3de1278cd49359f2',
                'sha256': '49809760aa14e469d3b0bed8a4ba02d46fc5f61f5002499fe10e18d8c531925c',
                'sha384': 'e786fb788469320ef001da2540ad4aabcc971a7cd2c2eb3d5c562cc763964daf674a362ef7024b27e494bf670ed1e69d',
                'sha512': '986783f5f27cbed97b2b1646239ea34d25812c3cb69a80116137e544285a8032df940963ae42576931a35195c433ab0239ea012469b21fcb3df23fce21a9dfba'
            },
            'lorem_ipsum_zip+txt.cat': {
                'adler32': 'F0A31D03',
                'crc32': '6EA6DE9B',
                'md5': '5ff44b587e9630bff7134b7e00726b44',
                'sha1': 'f1741c227c170061863370cc89af4932fad5fcb7',
                'sha224': '0155e4883599dbea532312d92db61f9610e7b38511ee5bf87972f08c',
                'sha256': '64bd25fbb84590cafd716d373796df3a2510e6a14104c30c7d83574cadd6277f',
                'sha384': 'e49c5329024cb8a7da51886647800eba49f3db3e2b21279474db85b078cccc411d86529ae5c50d81a3370aaf1f918fb2',
                'sha512': '775c5b1f2015f777485868ee6de013a29391c4e79c990adeb20d68412d8b650a18d6e3806ded4e0e2ffe197e2a51a52e651d09efe4895a3979f96c34d8cd4ce6'
            }
        }
        self.current_dir = os.getcwd()
        os.chdir(os.path.join(os.path.abspath(os.path.dirname(__file__)), "testdata"))

    def tearDown(self):
        os.chdir(self.current_dir)

    def test_hash_file(self):
        """Test the hash_file() method."""
        for algo in SUPPORTED_ALGORITHMS:
            for filename in self.expected_results.keys():
                hasher = FileHash(algo)
                self.assertEqual(
                    self.expected_results[filename][algo],
                    hasher.hash_file(filename)
                    )

    def test_hash_files(self):
        """Test the hash_files() method."""
        for algo in SUPPORTED_ALGORITHMS:
            hasher = FileHash(algo)
            # test on singleton lists of filenames
            for filename in self.expected_results.keys():
                results = hasher.hash_files([filename])
                self.assertEqual(len(results), 1)
                for result in results:
                    self.assertEqual(
                        self.expected_results[filename][algo],
                        result.hash
                        )
                    self.assertEqual(filename, result.filename)

            # test on all filenames at once
            results = hasher.hash_files(self.expected_results.keys())
            self.assertEqual(len(results), len(self.expected_results))
            for result in results:
                self.assertEqual(
                    self.expected_results[result.filename][algo],
                    result.hash
                    )

    def test_hash_dir(self):
        """"Test the hash_dir() method."""
        os.chdir("..")
        for algo in SUPPORTED_ALGORITHMS:
            for filename in self.expected_results.keys():
                hasher = FileHash(algo)
                basename, ext = os.path.splitext(filename)
                results = hasher.hash_dir("./testdata", "*" + ext)
                for result in results:
                    self.assertEqual(
                        self.expected_results[result.filename][algo],
                        result.hash
                        )
                    if len(results) == 1:
                        self.assertEqual(filename,result.filename)

    def test_cathash_files(self):
        """Test the cathash_files() method."""
        for algo in SUPPORTED_ALGORITHMS:
            for filename in self.expected_results.keys():
                hasher = FileHash(algo)
                self.assertEqual(
                    self.expected_results[filename][algo],
                    hasher.cathash_files([filename])
                )

            hasher = FileHash(algo)
            # shouldn't matter how you order filenames
            self.assertEqual(
                hasher.cathash_files(['lorem_ipsum.txt', 'lorem_ipsum.zip']),
                hasher.cathash_files(['lorem_ipsum.zip', 'lorem_ipsum.txt']),
                )
            # filenames thmeselves shouldn't matter
            self.assertEqual(
                hasher.cathash_files(['./lorem_ipsum.txt', 'lorem_ipsum.zip']),
                hasher.cathash_files(['lorem_ipsum.txt', 'lorem_ipsum.zip']),
                )
            self.assertEqual(
                hasher.cathash_files(['lorem_ipsum.txt', './lorem_ipsum.zip']),
                hasher.cathash_files(['lorem_ipsum.txt', 'lorem_ipsum.zip']),
                )
            # hash of multiple files should be same as
            # hash of files catted together
            self.assertEqual(
                hasher.cathash_files(['lorem_ipsum.txt', 'lorem_ipsum.zip']),
                self.expected_results[
                    'lorem_ipsum_zip+txt.cat' if
                        (self.expected_results['lorem_ipsum.txt'][algo] >
                            self.expected_results['lorem_ipsum.zip'][algo])
                        else 'lorem_ipsum_txt+zip.cat'
                    ][algo]
                )

    def test_cathash_dir(self):
        """"Test the cathash_dir() method."""
        os.chdir("..")
        for algo in SUPPORTED_ALGORITHMS:
            hasher = FileHash(algo)
            self.assertEqual(
                hasher.cathash_dir("./testdata", "*.txt"),
                self.expected_results['lorem_ipsum.txt'][algo]
                )
            self.assertEqual(
                hasher.cathash_dir("./testdata", "*.zip"),
                self.expected_results['lorem_ipsum.zip'][algo]
                )
            self.assertEqual(
                hasher.cathash_dir("./testdata", "*.[ziptxt]*"),
                self.expected_results[
                    'lorem_ipsum_zip+txt.cat' if
                        (self.expected_results['lorem_ipsum.txt'][algo] >
                            self.expected_results['lorem_ipsum.zip'][algo])
                        else 'lorem_ipsum_txt+zip.cat'
                    ][algo]
                    )

    def test_verify_checksums(self):
        """Test the verify_checksums() method."""
        for algo in SUPPORTED_ALGORITHMS:
            hasher = FileHash(algo)
            results = [result.hashes_match for result in hasher.verify_checksums("hashes." + algo)]
            self.assertTrue(all(results))

    def test_verify_sfv(self):
        """Test the verify_sfv() method."""
        hasher = FileHash('crc32')
        results = [result.hashes_match for result in hasher.verify_sfv("lorem_ipsum.sfv")]
        self.assertTrue(all(results))

    def test_verify_sfv_neg(self):
        """Test that verify_sfv() raises an exception if it is not using crc32."""
        hasher = FileHash('sha1')
        self.assertRaises(TypeError, hasher.verify_sfv, "lorem_ipsum.sfv")


class TestZlibHasherSubclasses(unittest.TestCase):
    """Test the subclasses of ZlibHasherBase i.e. Adler32, CRC32."""

    def setUp(self):
        """Dynamically get the list of subclasses for ZlibHasherBase."""
        def is_zlibhasherbase_subclass(o):
            return inspect.isclass(o) and issubclass(o, filehash.filehash.ZlibHasherBase)
        self.zlib_hashers = inspect.getmembers(filehash.filehash,
                                               predicate=is_zlibhasherbase_subclass)
        # inspect.getmembers() returns tuples of names and classes.  issubclass()
        # considers a class to be a subclass of itself.  So we need to remove
        # ZlibHasherBase from the list of subclasses, and convert it into a flat
        # list of just the classes (no names).
        self.zlib_hashers = [hasher[1] for hasher in self.zlib_hashers
                             if hasher[0] != filehash.filehash.ZlibHasherBase.__name__]

    def test_name(self):
        """
        Test that the Class.name attribute is the same as the class name in lowercase.
        """
        for hasher in self.zlib_hashers:
            hash = hasher()
            self.assertEqual(hash.__class__.__name__.lower(), hasher.name)

    def test_hexdigest(self):
        """Test the format of hexdigest();"""
        for hasher in self.zlib_hashers:
            hash = hasher()
            hash.update(b'The quick brown fox jumps over the lazy dog')
            self.assertEqual(hex(hash.digest()).upper()[2:], hash.hexdigest())

    def test_update(self):
        """
        Test the behavior of the update() method.

        m.update(a); m.update(b) is equivalent to m.update(a+b)
        """
        for hasher in self.zlib_hashers:
            hash1 = hasher()
            hash1.update(b'The quick brown fox ')
            hash1.update(b'jumps over the lazy dog')
            hash2 = hasher()
            hash2.update(b'The quick brown fox jumps over the lazy dog')
            self.assertEqual(hash1.digest(), hash2.digest())
            self.assertEqual(hash1.hexdigest(), hash2.hexdigest())

    def test_copy(self):
        """
        Test the behavior of the copy() method.  The call to copy() should
        create a new instance with the same initial digest value as the original
        object.
        """
        for hasher in self.zlib_hashers:
            hash1 = hasher()
            hash1.update(b'The quick brown fox ')
            hash2 = hash1.copy()
            self.assertEqual(hash1.digest(), hash2.digest())
            hash2.update(b'jumps over the lazy dog')
            self.assertNotEqual(hash1.digest(), hash2.digest())


class TestCLI(unittest.TestCase):
    """Test the CLI."""

    def setUp(self):
        self.parser = create_parser()

    def test_with_empty_args(self):
        """
        User passes no args, should fail with SystemExit
        """
        with self.assertRaises(SystemExit):
            self.parser.parse_args([])

    def test_filenames(self):
        """
        Test parsing filenames
        """

        args = self.parser.parse_args(['lorem_impsum.txt'])
        self.assertEqual(args.filenames, ['lorem_impsum.txt'])

        args = self.parser.parse_args(['lorem_impsum.txt', 'lorem_impsum.zip'])
        self.assertEqual(
            args.filenames,
            ['lorem_impsum.txt', 'lorem_impsum.zip']
        )

        args = self.parser.parse_args(['-a', 'sha1', 'lorem_impsum.txt'])
        self.assertEqual(args.filenames, ['lorem_impsum.txt'])

    def test_checksums(self):
        """
        Test parsing checksums
        """

        args = self.parser.parse_args(['-c', 'CHECKSUM'])
        self.assertEqual(args.checksums, 'CHECKSUM')

        args = self.parser.parse_args(['-a', 'sha1', '-c', 'CHECKSUM'])
        self.assertEqual(args.checksums, 'CHECKSUM')

    def test_directories(self):
        """
        Test parsing directories
        """

        args = self.parser.parse_args(['-d', 'DIRECTORY'])
        self.assertEqual(args.directory, 'DIRECTORY')

        args = self.parser.parse_args(['-a', 'sha1', '-d', 'DIRECTORY'])
        self.assertEqual(args.directory, 'DIRECTORY')

    def test_cathash(self):
        """
        Test parsing cathash
        """

        args = self.parser.parse_args(['-t', 'lorem_impsum.txt'])
        self.assertEqual(args.cathash, ['lorem_impsum.txt'])

        args = self.parser.parse_args(['-t', 'lorem_impsum.txt', 'lorem_impsum.zip'])
        self.assertEqual(
            args.cathash,
            ['lorem_impsum.txt', 'lorem_impsum.zip']
        )

        args = self.parser.parse_args(['-a', 'sha1', '-t', 'lorem_impsum.txt'])
        self.assertEqual(args.cathash, ['lorem_impsum.txt'])

    def test_algorithm(self):
        """
        Test parsing algorithm
        """

        args = self.parser.parse_args(['lorem_ipsum.txt'])
        self.assertEqual(args.algorithm, 'sha256')

        args = self.parser.parse_args(['-a', 'sha1', 'lorem_ipsum.txt'])
        self.assertEqual(args.algorithm, 'sha1')

if __name__ == "__main__":
    unittest.main()
