#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2011 thomasv@gitorious
# Copyright (C) 2021 Ivan J. <parazyd@dyne.org>
# Copyright (C) 2018 Harm Aarts <harmaarts@gmail.com>
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import asyncio
import logging
import functools
import hashlib
import struct
from random import randint
from binascii import hexlify, unhexlify

import zmq
import zmq.asyncio

from .logging import Logger
from .libbitcoin_errors import make_error_code, ErrorCode
from .util import bh2u
from .coutpoint import COutPoint


from datetime import datetime
def __(msg):
    print("***********************")
    print("*** DEBUG %s ***: %s" % (datetime.now().strftime("%H:%M:%S"), msg))


def create_random_id():
    """Generate a random request ID"""
    max_uint32 = 4294967295
    return randint(0, max_uint32)


def checksum(hash_, index):
    """This method takes a transaction hash and an index and returns
    a checksum.
    This checksum is based on 49 bits starting from the 12th byte of the
    reversed hash. Combined with the last 15 bits of the 4 byte index.
    """
    mask = 0xffffffffffff8000
    magic_start_position = 12

    hash_bytes = bytes.fromhex(hash_)[::-1]
    last_20_bytes = hash_bytes[magic_start_position:]

    assert len(hash_bytes) == 32
    assert index < 2**32

    hash_upper_49_bits = to_int(last_20_bytes) & mask
    index_lower_15_bits = index & ~mask

    return hash_upper_49_bits | index_lower_15_bits


def to_int(some_bytes):
    return int.from_bytes(some_bytes, byteorder='little')


def pack_block_index(index):
    if isinstance(index, str):
        index = unhexlify(index)
        assert len(index) == 32
        return index
    elif isinstance(index, int):
        return struct.pack('<I', index)
    else:
        raise ValueError(f"Unknown index type {type(index)} v:{index}, should be int or bytearray")


def unpack_table(row_fmt, data):
    # get the number of rows
    row_size = struct.calcsize(row_fmt)
    nrows = len(data) // row_size

    # unpack
    rows = []
    for idx in range(nrows):
        offset = idx * row_size
        row = struct.unpack_from(row_fmt, data, offset)
        rows.append(row)
    return rows


class ClientSettings:
    """Class implementing client settings"""
    def __init__(self, timeout=10, context=None, loop=None):
        __("Zeromq ClientSettings: __init__")
        self._timeout = timeout
        self._context = context
        self._loop = loop

    @property
    def context(self):
        """zmq context property"""
        if not self._context:
            ctx = zmq.asyncio.Context()
            ctx.linger = 500  # in milliseconds
            self._context = ctx
        return self._context

    @context.setter
    def context(self, context):
        self._context = context

    @property
    def timeout(self):
        """Set to None for no timeout"""
        return self._timeout

    @timeout.setter
    def timeout(self, timeout):
        self._timeout = timeout


class Request:
    """Class implementing a _send_ request.
    This is either a simple request/response affair or a subscription.
    """
    def __init__(self, socket, command, data):
        __("Zeromq Request: __init__")
        self.id_ = create_random_id()
        self.socket = socket
        self.command = command
        self.data = data
        self.future = asyncio.Future()
        self.queue = None

    async def send(self):
        """Send the zmq request"""
        __(f"Zeromq Request: send: {self.command}, {self.data}")
        request = [self.command, struct.pack('<I', self.id_), self.data]
        await self.socket.send_multipart(request)

    def is_subscription(self):
        """If the request is a subscription, then the response to this
        request is a notification.
        """
        return self.queue is not None

    def __str__(self):
        return 'Request(command, ID) {}, {:d}'.format(self.command,
                                                      self.id_)


class InvalidServerResponseException(Exception): pass


class Response:
    """Class implementing a request response"""
    def __init__(self, frame):
        __("Zeromq Response: __init__")
        if len(frame) != 3:
            raise InvalidServerResponseException(
                'Length of the frame was not 3: %d' % len(frame))

        self.command = frame[0]
        self.request_id = struct.unpack('<I', frame[1])[0]
        error_code = struct.unpack('<I', frame[2][:4])[0]
        self.error_code = make_error_code(error_code)
        self.data = frame[2][4:]

    def is_bound_for_queue(self):
        return len(self.data) > 0

    def __str__(self):
        return 'Response(command, request ID, error code, data):' \
            + ' %s, %d, %s, %s' \
            % (self.command, self.request_id, self.error_code, self.data)


class RequestCollection:
    """RequestCollection carries a list of Requests and matches incoming
    responses to them.
    """
    def __init__(self, socket, loop):
        __("Zeromq RequestCollection: __init__")
        self._socket = socket
        self._requests = {}
        self._task = asyncio.ensure_future(self._run(), loop=loop)

    async def _run(self):
        while True:
            __("Zeromq RequestCollection: _run loop iteration")
            await self._receive()

    async def stop(self):
        """Stops listening for incoming responses (or subscription) messages).
        Returns the number of _responses_ expected but which are now dropped
        on the floor.
        """
        __("Zeromq RequestCollection: stop")
        self._task.cancel()
        try:
            await self._task
        except asyncio.CancelledError:
            return len(self._requests)

    async def _receive(self):
        __("Zeromq RequestCollection: receive")
        frame = await self._socket.recv_multipart()
        response = Response(frame)

        if response.request_id in self._requests:
            self._handle_response(response)
        else:
            __("Zeromq RequestCollection: receive: unhandled response %s:%s" % (response.command, response.request_id))

    def _handle_response(self, response):
        __("Zeromq RequestCollection: _handle_response")
        request = self._requests[response.request_id]

        if request.is_subscription():
            if response.is_bound_for_queue():
                # TODO: decode the data into something usable
                request.queue.put_nowait(response.data)
            else:
                request.future.set_result(response)
        else:
            self.delete_request(request)
            request.future.set_result(response)

    def add_request(self, request):
        __("Zeromq RequestCollection: add_request")
        # TODO: we should maybe check if the request.id_ is unique
        self._requests[request.id_] = request

    def delete_request(self, request):
        __("Zeromq RequestCollection: delete_request")
        del self._requests[request.id_]


class Client:
    """This class represents a connection to a libbitcoin server.
    hostname -- the server DNS name to connect to.
    ports -- a dictionary containing four keys; query/heartbeat/block/tx
    """
    # def __init__(self, hostname, ports, settings=ClientSettings()):
    def __init__(self, hostname, ports, loop):
        __("Zeromq Client: __init__")
        self._hostname = hostname
        self._ports = ports
        # self._settings = settings
        self._settings = ClientSettings(loop=loop)
        self._query_socket = self._create_query_socket()
        self._block_socket = self._create_block_socket()
        self._request_collection = RequestCollection(
            self._query_socket, self._settings._loop)

    async def stop(self):
        __("Zeromq Client: stop")
        self._query_socket.close()
        self._block_socket.close()
        return await self._request_collection.stop()

    def _create_block_socket(self):
        __("Zeromq Client: _create_block_socket")
        socket = self._settings.context.socket(
            zmq.SUB, io_loop=self._settings._loop)  # pylint: disable=E1101
        socket.connect(self.__server_url(self._hostname,
                                         self._ports['block']))
        socket.setsockopt_string(zmq.SUBSCRIBE, '')  # pylint: disable=E1101
        return socket

    def _create_query_socket(self):
        __("Zeromq Client: _create_query_socket")
        socket = self._settings.context.socket(
            zmq.DEALER, io_loop=self._settings._loop)  # pylint: disable=E1101
        socket.connect(self.__server_url(self._hostname,
                                         self._ports['query']))
        return socket

    async def _subscription_request(self, command, data):
        __("Zeromq Client: _subscription_request")
        request = await self._request(command, data)
        request.queue = asyncio.Queue(loop=self._settings._loop)
        error_code, _ = await self._wait_for_response(request)
        return error_code, request.queue

    async def _simple_request(self, command, data):
        __("Zeromq Client: _simple_request")
        return await self._wait_for_response(
            await self._request(command, data))

    async def _request(self, command, data):
        """Make a generic request. Both options are byte objects
        specified like b'blockchain.fetch_block_header' as an example.
        """
        __("Zeromq Client: _request")
        request = Request(self._query_socket, command, data)
        await request.send()
        self._request_collection.add_request(request)
        return request

    async def _wait_for_response(self, request):
        __("Zeromq Client: _wait_for_response")
        try:
            response = await asyncio.wait_for(request.future,
                                              self._settings.timeout)
        except asyncio.TimeoutError:
            self._request_collection.delete_request(request)
            return ErrorCode.channel_timeout, None

        assert response.command == request.command
        assert response.request_id == request.id_
        return response.error_code, response.data

    @staticmethod
    def __server_url(hostname, port):
        return 'tcp://' + hostname + ':' + str(port)

    async def last_height(self):
        __("Zeromq Client: last_height")
        command = b'blockchain.fetch_last_height'
        error_code, data = await self._simple_request(command, b'')
        if error_code:
            return error_code, None
        height = struct.unpack('<I', data)[0]
        return error_code, height

    async def subscribe_to_blocks(self, queue):
        __("Zeromq Client: subscribe_to_blocks")
        asyncio.ensure_future(self._listen_for_blocks(queue))
        return queue

    async def _listen_for_blocks(self, queue):
        __("Zeromq Client: _listen_for_blocks")
        _ec, tip = await self.last_height()
        _, header = await self.block_header(tip)
        queue.put_nowait((0, tip, header))
        while True:
            __("Zeromq Client: _listen_for_blocks loop iteration")
            frame = await self._block_socket.recv_multipart()
            seq = struct.unpack('<H', frame[0])[0]
            height = struct.unpack('<I', frame[1])[0]
            block_data = frame[2]
            block_header = block_data[:80]
            # block_header = raw[:80]
            # version = block_header[:4]
            # prev_merkle_root = block_header[4:36]
            # merkle_root = block_header[36:68]
            # timestamp = block_header[68:72]
            # bits = block_header[72:76]
            # nonce = blockheader[76:80]
            queue.put_nowait((seq, height, block_header))

    async def _subscribe_to_scripthash(self, sh, queue):
        __("Zeromq Client: _subscribe_to_scripthash (stub)")
        # TODO: libbitcoin here get history and make status (also review this entire func)
        # https://electrumx-spesmilo.readthedocs.io/en/latest/protocol-methods.html#blockchain-scripthash-subscribe
        # https://electrumx-spesmilo.readthedocs.io/en/latest/protocol-basics.html#status
        # https://parazyd.org/git/electrum-obelisk/file/electrumobelisk/protocol.py.html#l57
        # queue.put_nowait((something,))
        # while True:
        #     recv and put in queue


    async def block_header(self, index):
        """Fetches the block header by height or integer index"""
        __("Zeromq Client: block_header")
        command = b'blockchain.fetch_block_header'
        data = pack_block_index(index)
        error_code, data = await self._simple_request(command, data)
        if error_code:
            return error_code, None
        return error_code, data

    async def block_transaction_hashes(self, index):
        __("Zeromq Client: block_transaction_hashes")
        command = b'blockchain.fetch_block_transaction_hashes'
        data = pack_block_index(index)
        error_code, data = await self._simple_request(command, data)
        if error_code:
            return error_code, None
        data = unpack_table('32s', data)
        return error_code, data

    async def transaction(self, hash_):
        __("Zeromq Client: transaction")
        command = b'blockchain.fetch_transaction2'
        error_code, data = await self._simple_request(
            command, bytes.fromhex(hash_)[::-1])
        if error_code:
            return error_code, None
        return None, data

    async def mempool_transaction(self, hash_):
        __("Zeromq Client: mempool_transaction")
        command = b'transaction_pool.fetch_transaction2'
        error_code, data = await self._simple_request(
            command, bytes.fromhex(hash_)[::-1])
        if error_code:
            return error_code, None
        return None, bh2u(data)

    async def broadcast_transaction(self, rawtx):
        __("Zeromq Client: broadcast_transaction")
        __(rawtx)
        command = b'transaction_pool.broadcast'
        return await self._simple_request(command, unhexlify(rawtx))

    async def history4(self, scripthash, height=0):
        __("Zeromq Client: history4")
        command = b'blockchain.fetch_history4'
        # libbitcoin expects this in reverse?, hence [::-1].
        decoded_address = unhexlify(scripthash)[::-1]
        error_code, raw_points = await self._simple_request(
            command, decoded_address + struct.pack('<I', height))
        if error_code:
            return error_code, None

        def make_tuple(row):
            kind, tx_hash, index, height, value = row
            return (
                kind,
                COutPoint(tx_hash, index),
                height,
                value,
                checksum(tx_hash[::-1].hex(), index),
            )

        rows = unpack_table('<B32sIIQ', raw_points)
        points = [make_tuple(row) for row in rows]
        correlated_points = Client.__correlate(points)
        return None, correlated_points

    async def balance(self, scripthash):
        __("Zeromq Client: balance")
        error, hist = await self.history4(scripthash)
        if error:
            return error, None
        utxo = Client.__receives_without_spends(hist)
        return None, functools.reduce(
            lambda accumulator, point: accumulator + point['value'], utxo, 0)

    async def unspent(self, scripthash):
        __("Zeromq Client: unspent")
        error, hist = await self.history4(scripthash)
        if error:
            return error, None
        return None, Client.__receives_without_spends(hist)

    @staticmethod
    def __receives_without_spends(hist):
        return (point for point in hist if 'spent' not in point)

    @staticmethod
    def __correlate(points):
        transfers, checksum_to_index = Client.__find_receives(points)
        transfers = Client.__correlate_spends_to_receives(
            points, transfers, checksum_to_index)
        return transfers

    @staticmethod
    def __correlate_spends_to_receives(points, transfers, checksum_to_index):
        for point in points:
            if point[0] == 0: # receive
                continue

            spent = {
                'hash': point[1].hash,
                'height': point[2],
                'index': point[1].n,
            }
            if point[3] not in checksum_to_index:
                transfers.append({'spent': spent})
            else:
                transfers[checksum_to_index[point[3]]]['spent'] = spent

        return transfers

    @staticmethod
    def __find_receives(points):
        transfers = []
        checksum_to_index = {}

        for point in points:
            if point[0] == 1:  # spent
                continue

            transfers.append({
                'received': {
                    'hash': point[1].hash,
                    'height': point[2],
                    'index': point[1].n,
                },
                'value': point[3],
            })

            checksum_to_index[point[4]] = len(transfers) - 1

        return transfers, checksum_to_index
