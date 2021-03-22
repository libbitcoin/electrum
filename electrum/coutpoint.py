#!/usr/bin/env python
# Taken from Peter Todd's pybitcoinlib
import struct
import binascii
import hashlib
from io import BytesIO as _BytesIO


MAX_SIZE = 0x02000000


class SerializationError(Exception):
    """Base class for serialization errors"""


class SerializationTruncationError(SerializationError):
    """Serialized data was truncated

    Thrown by deserialize() and stream_deserialize()
    """

class DeserializationExtraDataError(SerializationError):
    """Deserialized data had extra data at the end

    Thrown by deserialize() when not all data is consumed during
    deserialization. The deserialized object and extra padding not consumed are
    saved.
    """
    def __init__(self, msg, obj, padding):
        super(DeserializationExtraDataError, self).__init__(msg)
        self.obj = obj
        self.padding = padding


def b2lx(b):
    """Convert bytes to a little-endian hex string

    Lets you show uint256's and uint160's the way the Satoshi codebase shows
    them.
    """
    return binascii.hexlify(b[::-1]).decode('utf8')


def Hash(msg):
    """SHA256^2)(msg) -> bytes"""
    return hashlib.sha256(hashlib.sha256(msg).digest()).digest()


def ser_read(f, n):
    """Read from a stream safely

    Raises SerializationError and SerializationTruncationError appropriately.
    Use this instead of f.read() in your classes stream_(de)serialization()
    functions.
    """
    if n > MAX_SIZE:
        raise SerializationError('Asked to read 0x%x bytes; MAX_SIZE exceeded' % n)
    r = f.read(n)
    if len(r) < n:
        raise SerializationTruncationError('Asked to read %i bytes, but only got %i' % (n, len(r)))
    return r


class Serializable(object):
    """Base class for serializable objects"""

    __slots__ = []

    def stream_serialize(self, f, **kwargs):
        """Serialize to a stream"""
        raise NotImplementedError

    @classmethod
    def stream_deserialize(cls, f, **kwargs):
        """Deserialize from a stream"""
        raise NotImplementedError

    def serialize(self, params={}):
        """Serialize, returning bytes"""
        f = _BytesIO()
        self.stream_serialize(f, **params)
        return f.getvalue()

    @classmethod
    def deserialize(cls, buf, allow_padding=False, params={}):
        """Deserialize bytes, returning an instance

        allow_padding - Allow buf to include extra padding. (default False)

        If allow_padding is False and not all bytes are consumed during
        deserialization DeserializationExtraDataError will be raised.
        """
        fd = _BytesIO(buf)
        r = cls.stream_deserialize(fd, **params)
        if not allow_padding:
            padding = fd.read()
            if len(padding) != 0:
                raise DeserializationExtraDataError('Not all bytes consumed during deserialization',
                                                    r, padding)
        return r

    def GetHash(self):
        """Return the hash of the serialized object"""
        return Hash(self.serialize())

    def __eq__(self, other):
        if (not isinstance(other, self.__class__) and
            not isinstance(self, other.__class__)):
            return NotImplemented
        return self.serialize() == other.serialize()

    def __ne__(self, other):
        return not (self == other)

    def __hash__(self):
        return hash(self.serialize())


class ImmutableSerializable(Serializable):
    """Immutable serializable object"""

    __slots__ = ['_cached_GetHash', '_cached__hash__']

    def __setattr__(self, name, value):
        raise AttributeError('Object is immutable')

    def __delattr__(self, name):
        raise AttributeError('Object is immutable')

    def GetHash(self):
        """Return the hash of the serialized object"""
        try:
            return self._cached_GetHash
        except AttributeError:
            _cached_GetHash = super(ImmutableSerializable, self).GetHash()
            object.__setattr__(self, '_cached_GetHash', _cached_GetHash)
            return _cached_GetHash

    def __hash__(self):
        try:
            return self._cached__hash__
        except AttributeError:
            _cached__hash__ = hash(self.serialize())
            object.__setattr__(self, '_cached__hash__', _cached__hash__)
            return _cached__hash__


class COutPoint(ImmutableSerializable):
    """The combination of a transaction hash and an index n into its vout"""
    __slots__ = ['hash', 'n']

    def __init__(self, hash=b'\x00'*32, n=0xffffffff):
        if not len(hash) == 32:
            raise ValueError('COutPoint: hash must be exactly 32 bytes: got %d bytes' % len(hash))
        object.__setattr__(self, 'hash', hash)
        if not (0 <= n <= 0xffffffff):
            raise ValueError('COutPoint: n must be in range 0x0 to 0xffffffff; got %x' % n)
        object.__setattr__(self, 'n', n)

    @classmethod
    def stream_deserialize(cls, f):
        hash = ser_read(f, 32)
        n = struct.unpack(b"<I", ser_read(f, 4))[0]
        return cls(hash, n)

    def stream_serialize(self, f):
        assert len(self.hash) == 32
        f.write(self.hash)
        f.write(struct.pack(b"<I", self.n))

    def is_null(self):
        return ((self.hash == b'\x00'*32) and (self.n == 0xffffffff))

    def __repr__(self):
        if self.is_null():
            return 'COutPoint()'
        return 'COutPoint(lx(%r), %i)' % (b2lx(self.hash), self.n)

    def __str__(self):
        return '%s:%i' % (b2lx(self.hash), self.n)

    @classmethod
    def from_outpoint(cls, outpoint):
        """Create an immutable copy of an existing OutPoint

        If outpoint is already immutable (outpoint.__class__ is COutPoint) it is
        returned directly.
        """
        if outpoint.__class__ is COutPoint:
            return outpoint

        return cls(outpoint.hash, outpoint.n)
