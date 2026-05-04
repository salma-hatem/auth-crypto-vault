"""AES-128-CTR V2 (LUT-optimized) — backend selector.

Tries the native C extension first; falls back to the pure-Python
T-tables implementation if the shared library can't be loaded.
"""

try:
    from .native_wrapper import ctr_encrypt, ctr_decrypt
    BACKEND = "c"
except (OSError, ImportError):
    from .python_tables import ctr_encrypt, ctr_decrypt
    BACKEND = "python"

__all__ = ["ctr_encrypt", "ctr_decrypt", "BACKEND"]
