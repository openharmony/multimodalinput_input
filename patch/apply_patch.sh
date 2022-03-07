#!/bin/bash
# Copyright (c) 2021-2022 Huawei Device Co., Ltd.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -e

<<COMMENT

# -p NUM  --strip=NUM  Strip NUM leading components from file names.
# -i PATCHFILE  --input=PATCHFILE  Read patch from PATCHFILE instead of stdin.
# -d DIR  --directory=DIR  Change the working directory to DIR first.

bash -x  ./apply_patch.sh  \
  ../../../../third_party/libinput/ \
  ../../../../out/ohos-arm-release/libinput_mmi \
 ./diff_libinput_mmi

COMMENT

curdir=$(pwd)
source_dir=$1
out_dir=$2
path_file_dir=$3

echo "curdir: $curdir"
echo "source_dir: $source_dir"
echo "out_dir: $out_dir"
echo "path_file_dir: $path_file_dir"

if [ "$source_dir" == "" ] || [ "$out_dir" == "" ] || [ "$path_file_dir" == "" ]; then
    echo "param is invalid."
    exit 1
fi

echo "check out_dir: $out_dir"
if [ -d "$out_dir" ]; then
    echo "remove $out_dir begin"
    rm -rf "$out_dir"
fi

echo "mkdir out_dir: $out_dir"
mkdir -p $out_dir

echo "cp $source_dir/* to $out_dir/"
cp -fra $source_dir/* $out_dir

ls -l $path_file_dir/*.diff
if [ $? -ne 0 ]; then
    echo "WARNING: no patch."
    exit 0
fi

PATCH_FILE=$(realpath $(ls -l $path_file_dir/*.diff | tail -n 1 | awk '{print $9}'))

echo "PATCH_FILE: $PATCH_FILE"

cd $out_dir
echo "pwd: $(pwd)"
patch -p1 -i $PATCH_FILE
if [ $? -ne 0 ]; then
    echo "patch fail. path_file_dir=$path_file_dir"
    exit 1
fi

cd $curdir
exit 0
