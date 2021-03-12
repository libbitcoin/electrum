#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2011 thomasv@gitorious
# Copyright (C) 2021 Ivan J. <parazyd@dyne.org>
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
import os
import sys
import asyncio
from typing import (Tuple, Union, List, TYPE_CHECKING, Optional, Set,
                    NamedTuple, Any, Sequence)
from collections import defaultdict
from ipaddress import (IPv4Network, IPv6Network, ip_address, IPv6Address,
                       IPv4Address)
from binascii import hexlify, unhexlify
import logging

from aiorpcx import NetAddress
import certifi

from .util import (ignore_exceptions, log_exceptions, bfh, SilentTaskGroup,
                   MySocksProxy, is_integer, is_non_negative_integer,
                   is_hash256_str, is_hex_str, is_int_or_float,
                   is_non_negative_int_or_float)
from . import util
from . import version
from . import blockchain
from .blockchain import Blockchain, HEADER_SIZE
from . import bitcoin
from . import constants
from . import zeromq
from .i18n import _
from .logging import Logger
from .transaction import Transaction
from .merkle import merkle_branch

if TYPE_CHECKING:
    from .network import Network
    from .simple_config import SimpleConfig


ca_path = certifi.where()

BUCKET_NAME_OF_ONION_SERVERS = 'onion'

MAX_INCOMING_MSG_SIZE = 1_000_000  # in bytes

_KNOWN_NETWORK_PROTOCOLS = {'t', 's'}
PREFERRED_NETWORK_PROTOCOL = 's'
assert PREFERRED_NETWORK_PROTOCOL in _KNOWN_NETWORK_PROTOCOLS


class NetworkTimeout:
    # seconds
    class Generic:
        NORMAL = 30
        RELAXED = 45
        MOST_RELAXED = 600

    class Urgent(Generic):
        NORMAL = 10
        RELAXED = 20
        MOST_RELAXED = 60


def assert_non_negative_integer(val: Any) -> None:
    if not is_non_negative_integer(val):
        raise RequestCorrupted(f'{val!r} should be a non-negative integer')


def assert_integer(val: Any) -> None:
    if not is_integer(val):
        raise RequestCorrupted(f'{val!r} should be an integer')


def assert_int_or_float(val: Any) -> None:
    if not is_int_or_float(val):
        raise RequestCorrupted(f'{val!r} should be int or float')


def assert_non_negative_int_or_float(val: Any) -> None:
    if not is_non_negative_int_or_float(val):
        raise RequestCorrupted(f'{val!r} should be a non-negative int or float')


def assert_hash256_str(val: Any) -> None:
    if not is_hash256_str(val):
        raise RequestCorrupted(f'{val!r} should be a hash256 str')


def assert_hex_str(val: Any) -> None:
    if not is_hex_str(val):
        raise RequestCorrupted(f'{val!r} should be a hex str')


def assert_dict_contains_field(d: Any, *, field_name: str) -> Any:
    if not isinstance(d, dict):
        raise RequestCorrupted(f'{d!r} should be a dict')
    if field_name not in d:
        raise RequestCorrupted(f'required field {field_name!r} missing from dict')
    return d[field_name]

def assert_list_or_tuple(val: Any) -> None:
    if not isinstance(val, (list, tuple)):
        raise RequestCorrupted(f'{val!r} should be a list or tuple')


class NetworkException(Exception): pass


class GracefulDisconnect(NetworkException):
    log_level = logging.INFO

    def __init__(self, *args, log_level=None, **kwargs):
        Exception.__init__(self, *args, **kwargs)
        if log_level is not None:
            self.log_level = log_level


class RequestTimedOut(GracefulDisconnect):
    def __str__(self):
        return _("Network request timed out.")


class RequestCorrupted(Exception): pass

class ErrorParsingSSLCert(Exception): pass
class ErrorGettingSSLCertFromServer(Exception): pass
class ErrorSSLCertFingerprintMismatch(Exception): pass
class InvalidOptionCombination(Exception): pass
class ConnectError(NetworkException): pass


class ServerAddr:

    def __init__(self, host: str, port: Union[int, str], *, protocol: str = None):
        assert isinstance(host, str), repr(host)
        if protocol is None:
            protocol = 's'
        if not host:
            raise ValueError('host must not be empty')
        if host[0] == '[' and host[-1] == ']':  # IPv6
            host = host[1:-1]
        try:
            net_addr = NetAddress(host, port)  # this validates host and port
        except Exception as e:
            raise ValueError(f"cannot construct ServerAddr: invalid host or port (host={host}, port={port})") from e
        if protocol not in _KNOWN_NETWORK_PROTOCOLS:
            raise ValueError(f"invalid network protocol: {protocol}")
        self.host = str(net_addr.host)  # canonical form (if e.g. IPv6 address)
        self.port = int(net_addr.port)
        self.protocol = protocol
        self._net_addr_str = str(net_addr)

    @classmethod
    def from_str(cls, s: str) -> 'ServerAddr':
        # host might be IPv6 address, hence do rsplit:
        host, port, protocol = str(s).rsplit(':', 2)
        return ServerAddr(host=host, port=port, protocol=protocol)


    @classmethod
    def from_str_with_inference(cls, s: str) -> Optional['ServerAddr']:
        """Construct ServerAddr from str, guessing missing details.
        Ongoing compatibility not guaranteed.
        """
        if not s:
            return None
        items = str(s).rsplit(':', 2)
        if len(items) < 2:
            return None  # although maybe we could guess the port too?
        host = items[0]
        port = items[1]
        if len(items) >= 3:
            protocol = items[2]
        else:
            protocol = PREFERRED_NETWORK_PROTOCOL
        return ServerAddr(host=host, port=port, protocol=protocol)

    def to_friendly_name(self) -> str:
        # note: this method is closely linked to from_str_with_inference
        if self.protocol == 's':  # hide trailing ":s"
            return self.net_addr_str()
        return str(self)

    def __str__(self):
        return '{}:{}'.format(self.net_addr_str(), self.protocol)

    def to_json(self) -> str:
        return str(self)

    def __repr__(self):
        return f'<ServerAddr host={self.host} port={self.port} protocol={self.protocol}>'

    def net_addr_str(self) -> str:
        return self._net_addr_str

    def __eq__(self, other):
        if not isinstance(other, ServerAddr):
            return False
        return (self.host == other.host
                and self.port == other.port
                and self.protocol == other.protocol)

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return hash((self.host, self.port, self.protocol))


def _get_cert_path_for_host(*, config: 'SimpleConfig', host: str) -> str:
    filename = host
    try:
        ip = ip_address(host)
    except ValueError:
        pass
    else:
        if isinstance(ip, IPv6Address):
            filename = f"ipv6_{ip.packed.hex()}"
    return os.path.join(config.path, 'certs', filename)


from datetime import datetime
def __(msg):
    print("***********************")
    print("*** DEBUG %s ***: %s" % (datetime.now().strftime("%H:%M:%S"), msg))


class Interface(Logger):

    LOGGING_SHORTCUT = 'i'

    def __init__(self, *, network: 'Network', server: ServerAddr, proxy: Optional[dict]):
        __("Interface: __init__")
        self.ready = asyncio.Future()
        self.got_disconnected = asyncio.Event()
        self.server = server
        Logger.__init__(self)
        assert network.config.path
        self.cert_path = _get_cert_path_for_host(config=network.config, host=self.host)
        self.blockchain = None  # type: Optional[Blockchain]
        self._requested_chunks = set()  # type: Set[int]
        self.network = network
        self.proxy = MySocksProxy.from_proxy_dict(proxy)
        self.session = None  # type: Optional[NotificationSession]
        self._ipaddr_bucket = None

        # TODO: libbitcoin (these are for testnet2.libbitcoin.net)
        # This should be incorporated with ServerAddr somehow.
        self.client = None
        self.bs = 'testnet2.libbitcoin.net'
        self.bsports = {'query': 29091,
                        'heartbeat': 29092,
                        'block': 29093,
                        'tx': 29094}

        # Latest block header and corresponding height, as claimed by the server.
        # Note that these values are updated before they are verified.
        # Especially during initial header sync, verification can take a long time.
        # Failing verification will get the interface closed.
        self.tip_header = None
        self.tip = 0

        self.fee_estimates_eta = {}

        # Dump network messages (only for this interface).  Set at runtime from the console.
        self.debug = False

        self.taskgroup = SilentTaskGroup()

        async def spawn_task():
            __("Interface: spawn_task")
            task = await self.network.taskgroup.spawn(self.run())
            if sys.version_info >= (3, 8):
                task.set_name(f"interface::{str(server)}")
        asyncio.run_coroutine_threadsafe(spawn_task(), self.network.asyncio_loop)

    @property
    def host(self):
        return self.server.host

    @property
    def port(self):
        return self.server.port

    @property
    def protocol(self):
        return self.server.protocol

    def diagnostic_name(self):
        return self.server.net_addr_str()

    def __str__(self):
        return f"<Interface {self.diagnostic_name()}>"

    # @ignore_exceptions  # do not kill network.taskgroup
    @log_exceptions
    # @handle_disconnect
    async def run(self):
        __("Interface: run")
        self.client = zeromq.Client(self.bs, self.bsports,
                                    loop=self.network.asyncio_loop)
        async with self.taskgroup as group:
            await group.spawn(self.ping)
            await group.spawn(self.request_fee_estimates)
            await group.spawn(self.run_fetch_blocks)
            await group.spawn(self.monitor_connection)

    def _mark_ready(self) -> None:
        __("Interface: _mark_ready")
        if self.ready.cancelled():
            raise GracefulDisconnect('conn establishment was too slow; %s' % '*ready* future was cancelled')
        if self.ready.done():
            return

        assert self.tip_header
        chain = blockchain.check_header(self.tip_header)
        if not chain:
            self.blockchain = blockchain.get_best_chain()
        else:
            self.blockchain = chain
        assert self.blockchain is not None

        self.logger.info(f"set blockchain with height {self.blockchain.height()}")

        self.ready.set_result(1)

    async def get_block_header(self, height, assert_mode):
        __(f"Interface: get_block_header: {height}")
        self.logger.info(f'requesting block header {height} in mode {assert_mode}')
        # use lower timeout as we usually have network.bhi_lock here
        timeout = self.network.get_network_timeout_seconds(NetworkTimeout.Urgent)
        # ORIG: res = await self.session.send_request('blockchain.block.header', [height], timeout=timeout)
        _ec, res = await self.client.block_header(height)
        if _ec is not None and _ec != 0:
            raise RequestCorrupted(f'got error {_ec}')
        #return blockchain.deserialize_header(bytes.fromhex(res), height)
        return blockchain.deserialize_header(res, height)

    async def request_chunk(self, height: int, tip=None, *, can_return_early=False):
        __("Interface: request_chunk")
        if not is_non_negative_integer(height):
            raise Exception(f"{repr(height)} is not a block height")
        index = height // 2016
        if can_return_early and index in self._requested_chunks:
            return
        self.logger.info(f"requesting chunk from height {height}")
        size = 2016
        if tip is not None:
            size = min(size, tip - index * 2016 + 1)
            size = max(size, 0)
        try:
            self._requested_chunks.add(index)
            #ORIG: res = await self.session.send_request('blockchain.block.headers', [index * 2016, size])
            concat = bytearray()
            for i in range(size):
                _ec, data = await self.client.block_header(index*2016+i)
                if _ec is not None and _ec != 0:
                    # TODO: Don't imply error means we reached tip
                    break
                concat.extend(data)
        finally:
            self._requested_chunks.discard(index)
        # TODO: max in case of libbitcoin is unnecessary
        res = {
            'hex': str(hexlify(concat), 'utf-8'),
            'count': len(concat)//80,
            'max': 2016,
        }
        # TODO: cleanup
        assert_dict_contains_field(res, field_name='count')
        assert_dict_contains_field(res, field_name='hex')
        assert_dict_contains_field(res, field_name='max')
        assert_non_negative_integer(res['count'])
        assert_non_negative_integer(res['max'])
        assert_hex_str(res['hex'])
        if len(res['hex']) != HEADER_SIZE * 2 * res['count']:
            raise RequestCorrupted('inconsistent chunk hex and count')
        # we never request more than 2016 headers, but we enforce those fit in a single response
        if res['max'] < 2016:
            raise RequestCorrupted(f"server uses too low 'max' count for block.headers: {res['max']} < 2016")
        if res['count'] != size:
            raise RequestCorrupted(f"expected {size} headers but only got {res['count']}")
        conn = self.blockchain.connect_chunk(index, res['hex'])
        if not conn:
            return conn, 0
        return conn, res['count']

    def is_main_server(self) -> bool:
        # __("Interface: is_main_server")
        return (self.network.interface == self or
                self.network.interface is None and self.network.default_server == self.server)

    async def monitor_connection(self):
        __("Interface: monitor_connection")
        while True:
            await asyncio.sleep(1)
            if not self.client:
                # TODO: libbitcoin ^ Implement is_closing() in zeromq.Client and check ^
                raise GracefulDisconnect('session was closed')

    async def ping(self):
        __("Interface: ping")
        while True:
            await asyncio.sleep(300)
            __("Interface: ping loop iteration")
            # TODO: libbitcoin bs heartbeat service here?

    async def request_fee_estimates(self):
        __("Interface: request_fee_estimates")
        from .simple_config import FEE_ETA_TARGETS
        while True:
            async with SilentTaskGroup() as group:
                fee_tasks = []
                for i in FEE_ETA_TARGETS:
                    fee_tasks.append((i, await group.spawn(self.get_estimatefee(i))))
            for nblock_target, task in fee_tasks:
                fee = task.result()
                if fee < 0: continue
                self.fee_estimates_eta[nblock_target] = fee
            self.network.update_fee_estimates()
            await asyncio.sleep(60)

    async def close(self, *, force_after: int = None):
        __("Interface: close")
        # TODO: libbitcoin
        if self.session:
            await self.session.stop()
        if self.client:
            await self.client.stop()

    async def run_fetch_blocks(self):
        __("Interface: run_fetch_blocks")
        header_queue = asyncio.Queue()
        # ORIG: await self.session.subscribe('blockchain.headers.subscribe', [], header_queue)
        await self.client.subscribe_to_blocks(header_queue)
        while True:
            item = await header_queue.get()
            # TODO: block to header
            header = item[2]
            height = item[1]
            header = blockchain.deserialize_header(header, height)
            self.tip_header = header
            self.tip = height
            if self.tip < constants.net.max_checkpoint():
                raise GracefulDisconnect('server tip below max checkpoint')
            self._mark_ready()
            await self._process_header_at_tip()
            # header processing done
            util.trigger_callback('blockchain_updated')
            util.trigger_callback('network_updated')
            await self.network.switch_unwanted_fork_interface()
            await self.network.switch_lagging_interface()

    async def _process_header_at_tip(self):
        __("Interface: _process_header_at_tip")
        height, header = self.tip, self.tip_header
        async with self.network.bhi_lock:
            if self.blockchain.height() >= height and self.blockchain.check_header(header):
                # another interface amended the blockchain
                self.logger.info(f"skipping header {height}")
                return
            _, height = await self.step(height, header)
            # in the simple case, height == self.tip+1
            if height <= self.tip:
                await self.sync_until(height)

    async def sync_until(self, height, next_height=None):
        __("Interface: sync_until")
        if next_height is None:
            next_height = self.tip
        last = None
        while last is None or height <= next_height:
            prev_last, prev_height = last, height
            if next_height > height + 10:
                could_connect, num_headers = await self.request_chunk(height, next_height)
                if not could_connect:
                    if height <= constants.net.max_checkpoint():
                        raise GracefulDisconnect('server chain conflicts with checkpoints or genesis')
                    last, height = await self.step(height)
                    continue
                util.trigger_callback('network_updated')
                height = (height // 2016 * 2016) + num_headers
                assert height <= next_height+1, (height, self.tip)
                last = 'catchup'
            else:
                last, height = await self.step(height)
            assert (prev_last, prev_height) != (last, height), 'had to prevent infinite loop in interface.sync_until'
        return last, height

    async def step(self, height, header=None):
        __("Interface: step")
        assert 0 <= height <= self.tip, (height, self.tip)
        if header is None:
            header = await self.get_block_header(height, 'catchup')

        chain = blockchain.check_header(header) if 'mock' not in header else header['mock']['check'](header)
        if chain:
            self.blockchain = chain if isinstance(chain, Blockchain) else self.blockchain
            # note: there is an edge case here that is not handled.
            # we might know the blockhash (enough for check_header) but
            # not have the header itself. e.g. regtest chain with only genesis.
            # this situation resolves itself on the next block
            return 'catchup', height+1

        can_connect = blockchain.can_connect(header) if 'mock' not in header else header['mock']['connect'](height)
        if not can_connect:
            self.logger.info(f"can't connect {height}")
            height, header, bad, bad_header = await self._search_headers_backwards(height, header)
            chain = blockchain.check_header(header) if 'mock' not in header else header['mock']['check'](header)
            can_connect = blockchain.can_connect(header) if 'mock' not in header else header['mock']['connect'](height)
            assert chain or can_connect
        if can_connect:
            self.logger.info(f"could connect {height}")
            height += 1
            if isinstance(can_connect, Blockchain):  # not when mocking
                self.blockchain = can_connect
                self.blockchain.save_header(header)
            return 'catchup', height

        good, bad, bad_header = await self._search_headers_binary(height, bad, bad_header, chain)
        return await self._resolve_potential_chain_fork_given_forkpoint(good, bad, bad_header)

    async def _search_headers_binary(self, height, bad, bad_header, chain):
        __("Interface: _search_headers_binary")
        assert bad == bad_header['block_height']
        _assert_header_does_not_check_against_any_chain(bad_header)

        self.blockchain = chain if isinstance(chain, Blockchain) else self.blockchain
        good = height
        while True:
            assert good < bad, (good, bad)
            height = (good + bad) // 2
            self.logger.info(f"binary step. good {good}, bad {bad}, height {height}")
            header = await self.get_block_header(height, 'binary')
            chain = blockchain.check_header(header) if 'mock' not in header else header['mock']['check'](header)
            if chain:
                self.blockchain = chain if isinstance(chain, Blockchain) else self.blockchain
                good = height
            else:
                bad = height
                bad_header = header
            if good + 1 == bad:
                break

        mock = 'mock' in bad_header and bad_header['mock']['connect'](height)
        real = not mock and self.blockchain.can_connect(bad_header, check_height=False)
        if not real and not mock:
            raise Exception('unexpected bad header during binary: {}'.format(bad_header))
        _assert_header_does_not_check_against_any_chain(bad_header)

        self.logger.info(f"binary search exited. good {good}, bad {bad}")
        return good, bad, bad_header

    async def _resolve_potential_chain_fork_given_forkpoint(self, good, bad, bad_header):
        __("Interface: _resolve_potential_chain_fork_given_forkpoint")
        assert good + 1 == bad
        assert bad == bad_header['block_height']
        _assert_header_does_not_check_against_any_chain(bad_header)
        # 'good' is the height of a block 'good_header', somewhere in self.blockchain.
        # bad_header connects to good_header; bad_header itself is NOT in self.blockchain.

        bh = self.blockchain.height()
        assert bh >= good, (bh, good)
        if bh == good:
            height = good + 1
            self.logger.info(f"catching up from {height}")
            return 'no_fork', height

        # this is a new fork we don't yet have
        height = bad + 1
        self.logger.info(f"new fork at bad height {bad}")
        forkfun = self.blockchain.fork if 'mock' not in bad_header else bad_header['mock']['fork']
        b = forkfun(bad_header)  # type: Blockchain
        self.blockchain = b
        assert b.forkpoint == bad
        return 'fork', height

    async def _search_headers_backwards(self, height, header):
        __("Interface: _search_headers_backwards")
        async def iterate():
            nonlocal height, header
            checkp = False
            if height <= constants.net.max_checkpoint():
                height = constants.net.max_checkpoint()
                checkp = True
            header = await self.get_block_header(height, 'backward')
            chain = blockchain.check_header(header) if 'mock' not in header else header['mock']['check'](header)
            can_connect = blockchain.can_connect(header) if 'mock' not in header else header['mock']['connect'](height)
            if chain or can_connect:
                return False
            if checkp:
                raise GracefulDisconnect("server chain conflicts with checkpoints")
            return True

        bad, bad_header = height, header
        _assert_header_does_not_check_against_any_chain(bad_header)
        with blockchain.blockchains_lock: chains = list(blockchain.blockchains.values())
        local_max = max([0] + [x.height() for x in chains]) if 'mock' not in header else float('inf')
        height = min(local_max + 1, height - 1)
        while await iterate():
            bad, bad_header = height, header
            delta = self.tip - height
            height = self.tip - 2 * delta

        _assert_header_does_not_check_against_any_chain(bad_header)
        self.logger.info(f"exiting backward mode at {height}")
        return height, header, bad, bad_header

    @classmethod
    def client_name(cls) -> str:
        __("Interface: client_name")
        return f'electrum/{version.ELECTRUM_VERSION}'

    def is_tor(self):
        __("Interface: is_tor")
        return self.host.endswith('.onion')

    def ip_addr(self) -> Optional[str]:
        __("Interface: ip_addr")
        return None
        # TODO: libbitcoin
        # This seems always None upstream since remote_address does not exist?
        # session = self.session
        # if not session: return None
        # peer_addr = session.remote_address()
        # if not peer_addr: return None
        # return str(peer_addr.host)

    def bucket_based_on_ipaddress(self) -> str:
        __("Interface: bucket_based_on_ipaddress")
        def do_bucket():
            if self.is_tor():
                return BUCKET_NAME_OF_ONION_SERVERS
            try:
                ip_addr = ip_address(self.ip_addr())  # type: Union[IPv5Address, IPv6Address]
            except ValueError:
                return ''
            if not ip_addr:
                return ''
            if ip_addr.is_loopback:  # localhost is exempt
                return ''
            if ip_addr.version == 4:
                slash16 = IPv4Network(ip_addr).supernet(prefixlen_diff=32-16)
                return str(slash16)
            elif ip_addr.version == 6:
                slash48 = IPv6Network(ip_addr).supernet(prefixlen_diff=128-48)
                return str(slash48)
            return ''

        if not self._ipaddr_bucket:
            self._ipaddr_bucket = do_bucket()
        return self._ipaddr_bucket

    async def get_merkle_for_transaction(self, tx_hash: str, tx_height: int) -> dict:
        __("Interface: get_merkle_for_transaction")
        if not is_hash256_str(tx_hash):
            raise Exception(f"{repr(tx_hash)} is not a txid")
        if not is_non_negative_integer(tx_height):
            raise Exception(f"{repr(tx_height)} is not a block height")
        # do request
        # ORIG: res = await self.session.send_request('blockchain.transaction.get_merkle', [tx_hash, tx_height])
        # TODO: Rework to use txid rather than height with libbitcoin?
        _ec, hashes = await self.client.block_transaction_hashes(tx_height)
        if _ec is not None and _ec != 0:
            raise RequestCorrupted(f'got error {_ec}')
        tx_pos = hashes.index(unhexlify(tx_hash)[::-1])
        branch = merkle_branch(hashes, tx_pos)
        res = {'block_height': tx_height, 'merkle': branch, 'pos': tx_pos}
        block_height = assert_dict_contains_field(res, field_name='block_height')
        merkle = assert_dict_contains_field(res, field_name='merkle')
        pos = assert_dict_contains_field(res, field_name='pos')
        # note: tx_height was just a hint to the server, don't enforce the response to match it
        assert_non_negative_integer(block_height)
        assert_non_negative_integer(pos)
        assert_list_or_tuple(merkle)
        for item in merkle:
            assert_hash256_str(item)
        return res

    async def get_transaction(self, tx_hash: str, *, timeout=None) -> str:
        __("Interface: get_transaction")
        if not is_hash256_str(tx_hash):
            raise Exception(f"{repr(tx_hash)} is not a txid")
        # ORIG: raw = await self.session.send_request('blockchain.transaction.get', [tx_hash], timeout=timeout)
        #_ec, raw = await self.client.transaction(tx_hash)
        _ec, raw = await self.client.mempool_transaction(tx_hash)
        if _ec is not None and _ec != 0:
            raise RequestCorrupted(f"got error: {_ec!r}")
        # validate response
        if not is_hex_str(raw):
            raise RequestCorrupted(f"received garbage (non-hex) as tx data (txid {tx_hash}): {raw!r}")
        tx = Transaction(raw)
        try:
            tx.deserialize()  # see if raises
        except Exception as e:
            raise RequestCorrupted(f"cannot deserialize received transaction (txid {tx_hash})") from e
        if tx.txid() != tx_hash:
            raise RequestCorrupted(f"received tx does not match expected txid {tx_hash} (got {tx.txid()})")
        return raw


    async def get_history_for_scripthash(self, sh: str) -> List[dict]:
        __(f"Interface: get_history_for_scripthash {sh}")
        if not is_hash256_str(sh):
            raise Exception(f"{repr(sh)} is not a scripthash")
        # do request
        # ORIG: res = await self.session.send_request('blockchain.scripthash.get_history', [sh])
        _ec, history = await self.client.history4(sh)
        if _ec is not None and _ec != 0:
            raise RequestCorrupted('got error %d' % _ec)
        __("Interface: get_history_for_scripthash: got history: %s" % (history))
        res = {}
        # check response
        assert_list_or_tuple(res)
        prev_height = 1
        for tx_item in res:
            height = assert_dict_contains_field(tx_item, field_name='height')
            assert_dict_contains_field(tx_item, field_name='tx_hash')
            assert_integer(height)
            assert_hash256_str(tx_item['tx_hash'])
            if height in (-1, 0):
                assert_dict_contains_field(tx_item, field_name='fee')
                assert_non_negative_integer(tx_item['fee'])
                prev_height = - float("inf")  # this ensures confirmed txs can't follow mempool txs
            else:
                # check monotonicity of heights
                if height < prev_height:
                    raise RequestCorrupted(f'heights of confirmed txs must be in increasing order')
                prev_height = height
        hashes = set(map(lambda item: item['tx_hash'], res))
        if len(hashes) != len(res):
            # Either server is sending garbage... or maybe if server is race-prone
            # a recently mined tx could be included in both last block and mempool?
            # Still, it's simplest to just disregard the response.
            raise RequestCorrupted(f"server history has non-unique txids for sh={sh}")

        return res

    async def listunspent_for_scripthash(self, sh: str) -> List[dict]:
        __(f"Interface: listunspent_for_scripthash {sh}")
        if not is_hash256_str(sh):
            raise Exception(f"{repr(sh)} is not a scripthash")
        # do request
        # ORIG: res = await self.session.send_request('blockchain.scripthash.listunspent', [sh])
        _ec, unspent = await self.client.unspent(sh)
        if _ec is not None and _ec != 0:
            raise RequestCorrupted('got error %d' % _ec)
        __("Interface: listunspent_for_scripthash: got unspent: %s" % unspent)
        res = {}
        # check response
        assert_list_or_tuple(res)
        for utxo_item in res:
            assert_dict_contains_field(utxo_item, field_name='tx_pos')
            assert_dict_contains_field(utxo_item, field_name='value')
            assert_dict_contains_field(utxo_item, field_name='tx_hash')
            assert_dict_contains_field(utxo_item, field_name='height')
            assert_non_negative_integer(utxo_item['tx_pos'])
            assert_non_negative_integer(utxo_item['value'])
            assert_non_negative_integer(utxo_item['height'])
            assert_hash256_str(utxo_item['tx_hash'])
        return res

    async def get_balance_for_scripthash(self, sh: str) -> dict:
        __(f"Interface: get_balance_for_scripthash {sh}")
        if not is_hash256_str(sh):
            raise Exception(f"{repr(sh)} is not a scripthash")
        # do request
        # ORIG: res = await self.sessions.send_request('blockchains.scripthash.get_balance', [sh])
        _ec, balance = await self.client.balance(sh)
        if _ec is not None and _ec != 0:
            raise RequestCorrupted('got error %d' % _ec)
        __("Interface: get_balance_for_scripthash: got balance: %s" % balance)
        # TODO: libbitcoin
        res = {}
        # check response
        assert_dict_contains_field(res, field_name='confirmed')
        assert_dict_contains_field(res, field_name='unconfirmed')
        assert_non_negative_integer(res['confirmed'])
        assert_non_negative_integer(res['unconfirmed'])
        return res

    async def get_txid_from_txpos(self, tx_height: int, tx_pos: int, merkle: bool):
        __("Interface: get_txid_from_txpos")
        if not is_non_negative_integer(tx_height):
            raise Exception(f"{repr(tx_height)} is not a block height")
        if not is_non_negative_integer(tx_pos):
            raise Exception(f"{repr(tx_pos)} should be non-negative integer")
        # do request
        # ORIG: res = await self.session.send_request(
            # 'blockchain.transaction.id_from_pos',
            # [tx_height, tx_pos, merkle],
        # )
        _ec, hashes = await self.client.block_transaction_hashes(tx_height)
        if _ec is not None and _ec != 0:
            raise RequestCorrupted('got error %d' % _ec)
        txid = hexlify(hashes[tx_pos][::-1])
        # check response
        if not merkle:
            assert_hash256_str(txid)
            return txid
        branch = merkle_branch(hashes, tx_pos)
        res = {'tx_hash': txid, 'merkle': branch}
        assert_dict_contains_field(res, field_name='tx_hash')
        assert_dict_contains_field(res, field_name='merkle')
        assert_hash256_str(res['tx_hash'])
        assert_list_or_tuple(res['merkle'])
        for node_hash in res['merkle']:
            assert_hash256_str(node_hash)
        return res

    async def get_fee_histogram(self) -> Sequence[Tuple[Union[float, int], int]]:
        __("Interface: get_fee_histogram")
        # do request
        # ORIG: res = await self.session.send_request('mempool.get_fee_histogram')
        # TODO: libbitcoin
        res = [[0, 0]]
        # check response
        assert_list_or_tuple(res)
        prev_fee = float('inf')
        for fee, s in res:
            assert_non_negative_int_or_float(fee)
            assert_non_negative_integer(s)
            if fee >= prev_fee:  # check monotonicity
                raise RequestCorrupted(f'fees must be in decreasing order')
            prev_fee = fee
        return res

    async def get_server_banner(self) -> str:
        __("Interface: get_server_banner")
        # do request
        # ORIG: res = await self.session.send_request('server.banner')
        # TODO: libbitcoin
        res = 'libbitcoin'
        # check response
        if not isinstance(res, str):
            raise RequestCorrupted(f'{res!r} should be a str')
        return res

    async def get_donation_address(self) -> str:
        __("Interface: get_donation_address")
        # do request
        # ORIG: res = await self.session.send_request('server.donation_address')
        # TODO: libbitcoin
        res = None
        # check response
        if not res:  # ignore empty string
            return ''
        if not bitcoin.is_address(res):
            # note: do not hard-fail -- allow server to use future-type
            #       bitcoin address we do not recognize
            self.logger.info(f"invalid donation address from server: {repr(res)}")
            res = ''
        return res

    async def get_relay_fee(self) -> int:
        """Returns the min relay feerate in sat/kbyte."""
        __("Interface: get_relay_fee")
        # do request
        # ORIG: res = await self.session.send_request('blockchain.relayfee')
        # TODO: libbitcoin
        res = 0.00001
        # check response
        assert_non_negative_int_or_float(res)
        relayfee = int(res * bitcoin.COIN)
        relayfee = max(0, relayfee)
        return relayfee

    async def get_estimatefee(self, num_blocks: int) -> int:
        """Returns a feerate estimtte for getting confirmed within
        num_blocks blocks, in sat/kbyte.
        """
        __("Interface: get_estimatefee")
        if not is_non_negative_integer(num_blocks):
            raise Exception(f"{repr(num_blocks)} is not a num_blocks")
        # do request
        # ORIG: res = await self.session.send_request('blockchain.estimatefee', [num_blocks])
        # TODO: libbitcoin
        res = -1
        # check response
        if res != -1:
            assert_non_negative_int_or_float(res)
            res = int(res * bitcoin.COIN)
        return res

    async def broadcast_transaction(self, tx, timeout=None):
        """Broadcasts given transaction"""
        __("Interface: broadcast_transaction")
        assert_hex_str(tx)
        return await self.client.broadcast_transaction(tx)


def _assert_header_does_not_check_against_any_chain(header: dict) -> None:
    __("Interface: _assert_header_does_not_check_against_any_chain")
    chain_bad = blockchain.check_header(header) if 'mock' not in header else header['mock']['check'](header)
    if chain_bad:
        raise Exception('bad_header must not check!')
