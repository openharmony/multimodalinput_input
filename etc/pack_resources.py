#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (c) 2026 Huawei Device Co., Ltd.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
Pack resource files into a gzip-compressed binary container.

Usage:
    python3 pack_resources.py <src_dir> <output_dat>

Binary format (before gzip):
    [uint32 file_count]
    [per file:]
        [uint16 name_len] [name bytes] [uint32 data_len] [data bytes]

All integers are little-endian.
"""

import gzip
import os
import struct
import sys


def pack_directory(src_dir: str, output_path: str) -> None:
    files = []
    for name in sorted(os.listdir(src_dir)):
        full = os.path.join(src_dir, name)
        if not os.path.isfile(full):
            continue
        with open(full, "rb") as f:
            data = f.read()
        files.append((name, data))

    buf = bytearray()
    buf += struct.pack("<I", len(files))
    for name, data in files:
        name_bytes = name.encode("utf-8")
        buf += struct.pack("<H", len(name_bytes))
        buf += name_bytes
        buf += struct.pack("<I", len(data))
        buf += data

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with gzip.open(output_path, "wb") as f:
        f.write(buf)
    print(f"Packed {len(files)} files -> {output_path} ({len(buf)} raw -> "
          f"{os.path.getsize(output_path)} compressed)")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <src_dir> <output_dat>", file=sys.stderr)
        sys.exit(1)
    pack_directory(sys.argv[1], sys.argv[2])
