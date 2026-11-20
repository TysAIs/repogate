"""Tiny helper: loads the bundled payload module."""
import importlib.util
spec = importlib.util.spec_from_file_location('payload', 'payload.pyc')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
