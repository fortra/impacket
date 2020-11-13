"""
Compatibility module
"""
import array
if hasattr(array.array, 'frombytes'):
    def frombytes(a, b):
        return a.frombytes(b)
else:
    def frombytes(a, b):
         return a.fromstring(b)

if hasattr(array.array, 'tobytes'):
    def tobytes(a):
        return a.tobytes()
else:
    def tobytes(a):
         return a.tostring()
