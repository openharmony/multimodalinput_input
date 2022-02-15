/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef LIB_HDF_H
#define LIB_HDF_H
extern int32_t GetInputInterfaceFromInject(IInputInterface** interface);
#define hdfbit(y_) (1UL << (y_))

enum hdf_device_tags {
    HDF_INPUT       = hdfbit(0),
    HDF_KEYBOARD        = hdfbit(1),
    HDF_MOUSE       = hdfbit(2),
    HDF_TOUCHPAD        = hdfbit(3),
    HDF_TOUCHSCREEN = hdfbit(4),
    HDF_TABLET      = hdfbit(5),
    HDF_JOYSTICK        = hdfbit(6),
    HDF_ACCELEROMETER   = hdfbit(7),
    HDF_TABLET_PAD  = hdfbit(8),
    HDF_POINTINGSTICK   = hdfbit(9),
    HDF_TRACKBALL   = hdfbit(10),
    HDF_SWITCH      = hdfbit(11),
};

enum io_ctl_cmd {
    IO_BITS     = 0x20,
    IO_KEYBITS      = 0x21,
    IO_RELBITS      = 0x22,
    IO_ABSBITS      = 0x23,
    IO_MSCBITS  = 0x24,
    IO_SWBITS       = 0x25,
    IO_LEDBITS      = 0x31,
    IO_SNDBITS  = 0x32,
    IO_FFBITS   = 0x35,
    IO_PROPBITS = 0x9,
    IO_KEYVALUES    = 0x18,
    IO_LEDVALUES    = 0x19,
    IO_SWVALUES     = 0x1b,
    IO_NAMES        = 0x6,
    IO_MTVABS       = 0xa,
    IO_IDS      = 0x2,
    IO_ABSBEGIN     = 0x40,
    IO_ABEND        = 0x80,
};
#endif // LIB_HDF_H