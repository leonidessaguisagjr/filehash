import collections
import glob
import hashlib
import os
import os.path


FileHashResult = collections.namedtuple("FileHashResult", ["filename", "hash"])
VerifyHashResult = collections.namedtuple("VerifyHashResult",
                                          ["filename", "hashes_match"])


class FileHash:
    """
    Class wrapping the hashlib module to facilitate calculating file hashes.
    """

    def __init__(self, hash_algorithm='sha256', chunk_size=4096):
        """
        Initialize the FileHash class.

        :param hash_algorithm: String representing the hash algorithm to use.
                               See hashlib.algorithms_available to see a list
                               of valid values.  Defaults to 'sha256'.
        :param chunk_size: Integer value specifying the chunk size (in bytes)
                           when reading files.  Files will be read in chunks
                           instead of reading the entire file into memory all at
                           once.  Defaults to 4096 bytes.
        """
        self.chunk_size = chunk_size
        self.hash_algorithm = hash_algorithm

    def hash_file(self, filename):
        """
        Method for calculating the hash of a file.

        :param filename: Name of the file to calculate the hash for.
        :returns: Digest of the file, in hex.
        """
        with open(filename, mode="rb", buffering=0) as fp:
            hash_func = hashlib.new(self.hash_algorithm)
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
