import abc
import collections
import glob
import hashlib
import os
import os.path
import zlib


FileHashResult = collections.namedtuple("FileHashResult", ["filename", "hash"])
VerifyHashResult = collections.namedtuple("VerifyHashResult",
                                          ["filename", "hashes_match"])


class ZlibHasherBase():
    """
    Wrapper around zlib checksum functions to calculate a checksum with a similar
    interface as the algorithms in hashlib.
    """

    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def __init__(self, arg=None):
        """
        Initialize the class.

        :param arg: String to calculate the digest for.
        """
        pass

    @abc.abstractmethod
    def update(self, arg):
        """
        Update the hash object with the string arg.  Repeated calls are
        equivalent to a single call with the concatenation of all the arguments:
        m.update(a); m.update(b) is equivalent to m.update(a+b).

        :param arg: String to update the digest with.
        """
        pass

    def digest(self):
        """
        Return the digest of the strings passed to the update() method so far.
        This is a string of digest_size bytes which may contain non-ASCII
        characters, including null bytes.
        """
        return self._digest

    def hexdigest(self):
        """
        Like digest() except the digest is returned as a string of double length,
        containing only hexadecimal digists.  This may be used to exchange the
        value safely in email or other non-binary environments.
        """
        return hex(self._digest).upper()[2:]

    @abc.abstractmethod
    def copy(self):
        """
        Return a copy ("clone") of the hash object.  This can be used to
        efficiently compute the digests of strings that share a common initial
        substring.
        """
        pass


class Adler32(ZlibHasherBase):
    """
    Wrapper around zlib.adler32 to calculate the adler32 checksum with a similar
    interface as the algorithms in hashlib.
    """
    name = 'adler32'
    digest_size = 4
    block_size = 1

    def __init__(self, arg=None):
        """
        Initialize the class.

        :param arg: String to calculate the digest for.
        """
        self._digest = 1
        if arg is not None:
            self.update(arg)

    def update(self, arg):
        """
        Update the adler32 object with the string arg.  Repeated calls are
        equivalent to a single call with the concatenation of all the arguments:
        m.update(a); m.update(b) is equivalent to m.update(a+b).
        :param arg: String to update the digest with.
        """
        self._digest = zlib.adler32(arg, self._digest) & 0xFFFFFFFF

    def copy(self):
        """
        Return a copy ("clone") of the hash object.  This can be used to
        efficiently compute the digests of strings that share a common initial
        substring.
        """
        copy = Adler32()
        copy._digest = self._digest
        return copy


class CRC32(ZlibHasherBase):
    """
    Wrapper around zlib.crc32 to calculate the crc32 checksum with a similar
    interface as the algorithms in hashlib.
    """
    name = 'crc32'
    digest_size = 4
    block_size = 1

    def __init__(self, arg=None):
        """
        Initialize the class.

        :param arg: String to calculate the digest for.
        """
        self._digest = 0
        if arg is not None:
            self.update(arg)

    def update(self, arg):
        """
        Update the crc32 object with the string arg.  Repeated calls are
        equivalent to a single call with the concatenation of all the arguments:
        m.update(a); m.update(b) is equivalent to m.update(a+b).
        :param arg: String to update the digest with.
        """
        self._digest = zlib.crc32(arg, self._digest) & 0xFFFFFFFF

    def copy(self):
        """
        Return a copy ("clone") of the hash object.  This can be used to
        efficiently compute the digests of strings that share a common initial
        substring.
        """
        copy = CRC32()
        copy._digest = self._digest
        return copy


class FileHash:
    """
    Class wrapping the hashlib module to facilitate calculating file hashes.
    """

    def __init__(self, hash_algorithm='sha256', chunk_size=4096):
        """
        Initialize the FileHash class.

        :param hash_algorithm: String representing the hash algorithm to use.
                               See SUPPORTED_ALGORITHMS to see a list
                               of valid values.  Defaults to 'sha256'.
        :param chunk_size: Integer value specifying the chunk size (in bytes)
                           when reading files.  Files will be read in chunks
                           instead of reading the entire file into memory all at
                           once.  Defaults to 4096 bytes.
        """
        if hash_algorithm not in SUPPORTED_ALGORITHMS:
            raise ValueError("Error, unsupported hash/checksum algorithm: {0}".format(hash_algorithm))
        self.chunk_size = chunk_size
        self.hash_algorithm = hash_algorithm

    def hash_file(self, filename):
        """
        Method for calculating the hash of a file.

        :param filename: Name of the file to calculate the hash for.
        :returns: Digest of the file, in hex.
        """
        with open(filename, mode="rb", buffering=0) as fp:
            hash_func = _ALGORITHM_MAP[self.hash_algorithm]()
            buffer = fp.read(self.chunk_size)
            while len(buffer) > 0:
                hash_func.update(buffer)
                buffer = fp.read(self.chunk_size)
        return hash_func.hexdigest()

    def hash_dir(self, path, pattern='*'):
        """
        Method for calculating the hash of files in a directory.

        :param path: Directory of files to hash.
        :param pattern: Pattern to determine which files to calculate hashes.
                        Defaults to '*' i.e. all files in the directory.
        :returns: List of tuples where each tuple contains a filename and the
                  calculated hash for each file.
        """
        result = []
        saved_dir = os.getcwd()
        os.chdir(os.path.abspath(path))  # pushd
        filenames = [filename for filename in glob.glob(pattern) if os.path.isfile(filename)]
        for filename in filenames:
            hash = self.hash_file(filename)
            result.append(FileHashResult(filename, hash))
        os.chdir(saved_dir)  # popd
        return result

    def verify_checksums(self, checksum_filename):
        """
        Method for verifying the checksums of a file or set of files.  The
        checksum file is a text file where each line has the hash and filename
        in the following format:

        hash[SPACE][ASTERISK]filename

        This format is typical of the outputs of the sha1sum family of tools.

        :param checksum_filename: Name of the file that contains the filenames
                                  and corresponding checksums of the files to be
                                  verified.
        :returns: A list of tuples where each tuple contains a filename and a
                  Boolean value indicating if the checksum matched (True) or if
                  there was a checksum mismatch (False).
        """
        result = []
        with open(checksum_filename, mode="r") as checksum_list:
            for line in checksum_list:
                expected_hash, filename = line.strip().split(" ", 1)
                if filename.startswith("*"):
                    filename = filename[1:]
                actual_hash = self.hash_file(filename)
                result.append(VerifyHashResult(filename, expected_hash == actual_hash))
        return result

    def verify_sfv(self, sfv_filename):
        """
        Method for verifying the checksums of a file or set of files.  The
        sfv (Simple File Verification) file is a text file where each line has
        the filename and CRC32 in the following format:

        filename[SPACE]crc32

        Lines that start with a ';' are comments.  For example:

        ;       10062  12:22.AM 2018-05-06 lorem_ipsum.txt
        ;       3498  12:23.AM 2018-05-06 lorem_ipsum.zip
        lorem_ipsum.txt A8504B9F
        lorem_ipsum.zip 7425D3BE

        :param sfv_filename: Name of the file that contains the filenames and
                                  corresponding crc32 hashes of the files to be
                                  verified.
        :returns: A list of tuples where each tuple contains a filename and a
                  Boolean value indicating if the crc32 matched (True) or if
                  there was a crc32 mismatch (False).
        """
        if self.hash_algorithm.lower() != 'crc32':
            raise TypeError("SFV verification only supported with the 'crc32' algorithm.")
        result = []
        with open(sfv_filename, mode="r") as checksum_list:
            for line in checksum_list:
                if line.startswith(";"):
                    continue
                filename, expected_crc32 = line.strip().split(" ", 1)
                actual_crc32 = self.hash_file(filename)
                result.append(VerifyHashResult(filename, expected_crc32 == actual_crc32))
        return result


_ALGORITHM_MAP = {
    'adler32': Adler32,
    'crc32': CRC32,
    'md5' : hashlib.md5,
    'sha1' : hashlib.sha1,
    'sha256' : hashlib.sha256,
    'sha512' : hashlib.sha512,
}

SUPPORTED_ALGORITHMS = set(_ALGORITHM_MAP.keys())
