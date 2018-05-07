try:
    from filehash import FileHash, SUPPORTED_ALGORITHMS
except ImportError:
    from .filehash import FileHash, SUPPORTED_ALGORITHMS

__all__ = ["FileHash", "SUPPORTED_ALGORITHMS"]
