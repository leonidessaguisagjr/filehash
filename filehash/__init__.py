try:
    from filehash import FileHash
except ImportError:
    from .filehash import FileHash

__all__ = ["FileHash"]
