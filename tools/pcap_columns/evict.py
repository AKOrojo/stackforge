"""Drop a file's pages from the page cache (no root needed for clean pages): python -I evict.py <file>..."""
import os
import sys

for p in sys.argv[1:]:
    fd = os.open(p, os.O_RDONLY)
    try:
        os.fsync(fd)
        os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
    finally:
        os.close(fd)
