#!/usr/bin/env python
#
# Electrum -lightweight Bitcoin client
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
"""Module for calculating merkle branches"""
from math import ceil, log

from .crypto import sha256d


def branch_length(hash_count):
    """Return the length of a merkle branch given the number of hashes"""
    return ceil(log(hash_count, 2))


def merkle_branch_and_root(hashes, index):
    """Return a (merkle branch, merkle_root) pair given hashes, and the
    index of one of those hashes.
    """
    hashes = list(hashes)
    if not isinstance(index, int):
        raise TypeError('index must be an integer')
    # This also asserts hashes is not empty
    if not 0 <= index < len(hashes):
        raise ValueError('index out of range')
    length = branch_length(len(hashes))

    branch = []
    for _ in range(length):
        if len(hashes) & 1:
            hashes.append(hashes[-1])
        branch.append(hashes[index ^ 1])
        index >>= 1
        hashes = [sha256d(hashes[n] + hashes[n+1])
                  for n in range(0, len(hashes), 2)]
    return branch, hashes[0]

def merkle_branch(tx_hashes, tx_pos):
    """Return a merkle branch given hashes and the tx position"""
    branch, _root = merkle_branch_and_root(tx_hashes, tx_pos)
    branch = [bytes(reversed(h)).hex() for h in branch]
    return branch
