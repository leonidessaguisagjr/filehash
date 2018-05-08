import argparse
import os.path
import sys

from filehash import FileHash, SUPPORTED_ALGORITHMS


default_hash_algorithm = 'sha256'


def parse_command_line():
    parser = argparse.ArgumentParser(
        description="Tool for calculating the checksum / hash of a file or directory."
    )
    parser.add_argument(
        u"-a",
        u"--algorithm",
        help=u"Checksum/hash algorithm to use.  Valid values are: {0}.  Defaults to \"{1}\"".format(
            ", ".join(['"' + a + '"' for a in SUPPORTED_ALGORITHMS]),
            default_hash_algorithm
        ),
        default=default_hash_algorithm)
    parser_group = parser.add_mutually_exclusive_group(required=True)
    parser_group.add_argument(u"-c", u"--checksums",
                              help=u"Read the file and verify the checksums/hashes match.")
    parser_group.add_argument(u"-d", u"--directory",
                              help=u"Calculate the checksums/hashes for a directory.")
    parser_group.add_argument(u"filename", nargs="?", help=u"file to calculate the checksum/hash")
    return parser.parse_args()


def process_dir(directory, hasher):
    if not os.path.isdir(directory):
        print("ERROR: Unable to read directory: {0}".format(directory))
        sys.exit(1)
    results = hasher.hash_dir(directory)
    for result in results:
        print("{0} *{1}".format(result.hash, result.filename))


def process_file(filename, hasher):
    if not os.path.isfile(filename):
        print("ERROR: Unable to read file: {0}".format(filename))
        sys.exit(1)
    result = hasher.hash_file(filename)
    print("{0} *{1}".format(result, filename))


def process_checksum_file(checksum_filename, hasher):
    if not os.path.isfile(checksum_filename):
        print("ERROR: Unable to read checksum file: {0}".format(checksum_filename))
        sys.exit(1)
    basename, ext = os.path.splitext(checksum_filename)
    if ext.lower() == ".sfv":
        results = hasher.verify_sfv(checksum_filename)
    else:
        results = hasher.verify_checksums(checksum_filename)
    for result in results:
        print("{0}: {1}".format(
            result.filename,
            "OK" if result.hashes_match else "ERROR"
        ))


def main():
    args = parse_command_line()

    if not args.algorithm.lower() in SUPPORTED_ALGORITHMS:
        print("ERROR: Unknown checksum/hash algorithm: {0}".format(args.algorithm))
        parser.print_help()
        sys.exit(1)

    hasher = FileHash(args.algorithm.lower())
    if args.checksums:
        process_checksum_file(args.checksums, hasher)
    elif args.directory:
        process_dir(args.directory, hasher)
    else:
        process_file(args.filename, hasher)


if __name__ == "__main__":
    main()
