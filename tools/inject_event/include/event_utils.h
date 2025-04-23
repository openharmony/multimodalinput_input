/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef EVENT_UTILS_H
#define EVENT_UTILS_H

#include <string>
#include <unordered_map>

#include <linux/input.h>

#include "common.h"

namespace OHOS {
namespace MMI {

// Event type string mapping
static const std::unordered_map<uint16_t, std::string> EVENT_TYPE_MAP = {
    {EV_SYN, "EV_SYN"},
    {EV_KEY, "EV_KEY"},
    {EV_REL, "EV_REL"},
    {EV_ABS, "EV_ABS"},
    {EV_MSC, "EV_MSC"},
    {EV_SW, "EV_SW"},
    {EV_LED, "EV_LED"},
    {EV_SND, "EV_SND"},
    {EV_REP, "EV_REP"},
    {EV_FF, "EV_FF"},
    {EV_PWR, "EV_PWR"},
    {EV_FF_STATUS, "EV_FF_STATUS"}
};

// SYN event code mapping
static const std::unordered_map<uint16_t, std::string> SYN_CODE_MAP = {
    {SYN_REPORT, "SYN_REPORT"},
    {SYN_CONFIG, "SYN_CONFIG"},
    {SYN_MT_REPORT, "SYN_MT_REPORT"},
    {SYN_DROPPED, "SYN_DROPPED"}
};

// Keyboard and button event code mapping
static const std::unordered_map<uint16_t, std::string> KEY_CODE_MAP = {
    // Regular keyboard keys
    {KEY_ESC, "KEY_ESC"},
    {KEY_1, "KEY_1"},
    {KEY_2, "KEY_2"},
    {KEY_3, "KEY_3"},
    {KEY_4, "KEY_4"},
    {KEY_5, "KEY_5"},
    {KEY_6, "KEY_6"},
    {KEY_7, "KEY_7"},
    {KEY_8, "KEY_8"},
    {KEY_9, "KEY_9"},
    {KEY_0, "KEY_0"},
    {KEY_MINUS, "KEY_MINUS"},
    {KEY_EQUAL, "KEY_EQUAL"},
    {KEY_BACKSPACE, "KEY_BACKSPACE"},
    {KEY_TAB, "KEY_TAB"},
    {KEY_Q, "KEY_Q"},
    {KEY_W, "KEY_W"},
    {KEY_E, "KEY_E"},
    {KEY_R, "KEY_R"},
    {KEY_T, "KEY_T"},
    {KEY_Y, "KEY_Y"},
    {KEY_U, "KEY_U"},
    {KEY_I, "KEY_I"},
    {KEY_O, "KEY_O"},
    {KEY_P, "KEY_P"},
    {KEY_LEFTBRACE, "KEY_LEFTBRACE"},
    {KEY_RIGHTBRACE, "KEY_RIGHTBRACE"},
    {KEY_ENTER, "KEY_ENTER"},
    {KEY_LEFTCTRL, "KEY_LEFTCTRL"},
    {KEY_A, "KEY_A"},
    {KEY_S, "KEY_S"},
    {KEY_D, "KEY_D"},
    {KEY_F, "KEY_F"},
    {KEY_G, "KEY_G"},
    {KEY_H, "KEY_H"},
    {KEY_J, "KEY_J"},
    {KEY_K, "KEY_K"},
    {KEY_L, "KEY_L"},
    {KEY_SEMICOLON, "KEY_SEMICOLON"},
    {KEY_APOSTROPHE, "KEY_APOSTROPHE"},
    {KEY_GRAVE, "KEY_GRAVE"},
    {KEY_LEFTSHIFT, "KEY_LEFTSHIFT"},
    {KEY_BACKSLASH, "KEY_BACKSLASH"},
    {KEY_Z, "KEY_Z"},
    {KEY_X, "KEY_X"},
    {KEY_C, "KEY_C"},
    {KEY_V, "KEY_V"},
    {KEY_B, "KEY_B"},
    {KEY_N, "KEY_N"},
    {KEY_M, "KEY_M"},
    {KEY_COMMA, "KEY_COMMA"},
    {KEY_DOT, "KEY_DOT"},
    {KEY_SLASH, "KEY_SLASH"},
    {KEY_RIGHTSHIFT, "KEY_RIGHTSHIFT"},
    {KEY_KPASTERISK, "KEY_KPASTERISK"},
    {KEY_LEFTALT, "KEY_LEFTALT"},
    {KEY_SPACE, "KEY_SPACE"},
    {KEY_CAPSLOCK, "KEY_CAPSLOCK"},

    // Function keys
    {KEY_F1, "KEY_F1"},
    {KEY_F2, "KEY_F2"},
    {KEY_F3, "KEY_F3"},
    {KEY_F4, "KEY_F4"},
    {KEY_F5, "KEY_F5"},
    {KEY_F6, "KEY_F6"},
    {KEY_F7, "KEY_F7"},
    {KEY_F8, "KEY_F8"},
    {KEY_F9, "KEY_F9"},
    {KEY_F10, "KEY_F10"},
    {KEY_F11, "KEY_F11"},
    {KEY_F12, "KEY_F12"},

    // Navigation keys
    {KEY_HOME, "KEY_HOME"},
    {KEY_UP, "KEY_UP"},
    {KEY_PAGEUP, "KEY_PAGEUP"},
    {KEY_LEFT, "KEY_LEFT"},
    {KEY_RIGHT, "KEY_RIGHT"},
    {KEY_END, "KEY_END"},
    {KEY_DOWN, "KEY_DOWN"},
    {KEY_PAGEDOWN, "KEY_PAGEDOWN"},
    {KEY_INSERT, "KEY_INSERT"},
    {KEY_DELETE, "KEY_DELETE"},

    // Multimedia control keys
    {KEY_MUTE, "KEY_MUTE"},
    {KEY_VOLUMEDOWN, "KEY_VOLUMEDOWN"},
    {KEY_VOLUMEUP, "KEY_VOLUMEUP"},
    {KEY_POWER, "KEY_POWER"},
    {KEY_PAUSE, "KEY_PAUSE"},
    {KEY_PLAYPAUSE, "KEY_PLAYPAUSE"},
    {KEY_NEXTSONG, "KEY_NEXTSONG"},
    {KEY_PREVIOUSSONG, "KEY_PREVIOUSSONG"},

    // Mouse buttons
    {BTN_LEFT, "BTN_LEFT"},
    {BTN_RIGHT, "BTN_RIGHT"},
    {BTN_MIDDLE, "BTN_MIDDLE"},
    {BTN_SIDE, "BTN_SIDE"},
    {BTN_EXTRA, "BTN_EXTRA"},
    {BTN_FORWARD, "BTN_FORWARD"},
    {BTN_BACK, "BTN_BACK"},

    // Gamepad buttons
    {BTN_SOUTH, "BTN_SOUTH"},
    {BTN_EAST, "BTN_EAST"},
    {BTN_NORTH, "BTN_NORTH"},
    {BTN_WEST, "BTN_WEST"},
    {BTN_TL, "BTN_TL"},
    {BTN_TR, "BTN_TR"},
    {BTN_TL2, "BTN_TL2"},
    {BTN_TR2, "BTN_TR2"},
    {BTN_SELECT, "BTN_SELECT"},
    {BTN_START, "BTN_START"},
    {BTN_MODE, "BTN_MODE"},
    {BTN_THUMBL, "BTN_THUMBL"},
    {BTN_THUMBR, "BTN_THUMBR"},

    // D-Pad buttons
    {BTN_DPAD_UP, "BTN_DPAD_UP"},
    {BTN_DPAD_DOWN, "BTN_DPAD_DOWN"},
    {BTN_DPAD_LEFT, "BTN_DPAD_LEFT"},
    {BTN_DPAD_RIGHT, "BTN_DPAD_RIGHT"},

    // Pen/digitizer
    {BTN_TOOL_PEN, "BTN_TOOL_PEN"},
    {BTN_TOOL_RUBBER, "BTN_TOOL_RUBBER"},
    {BTN_TOOL_BRUSH, "BTN_TOOL_BRUSH"},
    {BTN_TOOL_PENCIL, "BTN_TOOL_PENCIL"},
    {BTN_TOOL_FINGER, "BTN_TOOL_FINGER"},
    {BTN_TOUCH, "BTN_TOUCH"},
    {BTN_STYLUS, "BTN_STYLUS"},
    {BTN_STYLUS2, "BTN_STYLUS2"}
};

// Relative coordinate event code mapping
static const std::unordered_map<uint16_t, std::string> REL_CODE_MAP = {
    {REL_X, "REL_X"},
    {REL_Y, "REL_Y"},
    {REL_Z, "REL_Z"},
    {REL_RX, "REL_RX"},
    {REL_RY, "REL_RY"},
    {REL_RZ, "REL_RZ"},
    {REL_HWHEEL, "REL_HWHEEL"},
    {REL_DIAL, "REL_DIAL"},
    {REL_WHEEL, "REL_WHEEL"},
    {REL_MISC, "REL_MISC"},
    {REL_WHEEL_HI_RES, "REL_WHEEL_HI_RES"},
    {REL_HWHEEL_HI_RES, "REL_HWHEEL_HI_RES"}
};

// Absolute coordinate event code mapping
static const std::unordered_map<uint16_t, std::string> ABS_CODE_MAP = {
    {ABS_X, "ABS_X"},
    {ABS_Y, "ABS_Y"},
    {ABS_Z, "ABS_Z"},
    {ABS_RX, "ABS_RX"},
    {ABS_RY, "ABS_RY"},
    {ABS_RZ, "ABS_RZ"},
    {ABS_THROTTLE, "ABS_THROTTLE"},
    {ABS_RUDDER, "ABS_RUDDER"},
    {ABS_WHEEL, "ABS_WHEEL"},
    {ABS_GAS, "ABS_GAS"},
    {ABS_BRAKE, "ABS_BRAKE"},
    {ABS_HAT0X, "ABS_HAT0X"},
    {ABS_HAT0Y, "ABS_HAT0Y"},
    {ABS_HAT1X, "ABS_HAT1X"},
    {ABS_HAT1Y, "ABS_HAT1Y"},
    {ABS_HAT2X, "ABS_HAT2X"},
    {ABS_HAT2Y, "ABS_HAT2Y"},
    {ABS_HAT3X, "ABS_HAT3X"},
    {ABS_HAT3Y, "ABS_HAT3Y"},
    {ABS_PRESSURE, "ABS_PRESSURE"},
    {ABS_DISTANCE, "ABS_DISTANCE"},
    {ABS_TILT_X, "ABS_TILT_X"},
    {ABS_TILT_Y, "ABS_TILT_Y"},
    {ABS_TOOL_WIDTH, "ABS_TOOL_WIDTH"},
    {ABS_VOLUME, "ABS_VOLUME"},
    {ABS_MISC, "ABS_MISC"},

    // Multi-touch
    {ABS_MT_SLOT, "ABS_MT_SLOT"},
    {ABS_MT_TOUCH_MAJOR, "ABS_MT_TOUCH_MAJOR"},
    {ABS_MT_TOUCH_MINOR, "ABS_MT_TOUCH_MINOR"},
    {ABS_MT_WIDTH_MAJOR, "ABS_MT_WIDTH_MAJOR"},
    {ABS_MT_WIDTH_MINOR, "ABS_MT_WIDTH_MINOR"},
    {ABS_MT_ORIENTATION, "ABS_MT_ORIENTATION"},
    {ABS_MT_POSITION_X, "ABS_MT_POSITION_X"},
    {ABS_MT_POSITION_Y, "ABS_MT_POSITION_Y"},
    {ABS_MT_TOOL_TYPE, "ABS_MT_TOOL_TYPE"},
    {ABS_MT_BLOB_ID, "ABS_MT_BLOB_ID"},
    {ABS_MT_TRACKING_ID, "ABS_MT_TRACKING_ID"},
    {ABS_MT_PRESSURE, "ABS_MT_PRESSURE"},
    {ABS_MT_DISTANCE, "ABS_MT_DISTANCE"},
    {ABS_MT_TOOL_X, "ABS_MT_TOOL_X"},
    {ABS_MT_TOOL_Y, "ABS_MT_TOOL_Y"}
};

// Switch event code mapping
static const std::unordered_map<uint16_t, std::string> SW_CODE_MAP = {
    {SW_LID, "SW_LID"},
    {SW_TABLET_MODE, "SW_TABLET_MODE"},
    {SW_HEADPHONE_INSERT, "SW_HEADPHONE_INSERT"},
    {SW_RFKILL_ALL, "SW_RFKILL_ALL"},
    {SW_MICROPHONE_INSERT, "SW_MICROPHONE_INSERT"},
    {SW_DOCK, "SW_DOCK"},
    {SW_LINEOUT_INSERT, "SW_LINEOUT_INSERT"},
    {SW_JACK_PHYSICAL_INSERT, "SW_JACK_PHYSICAL_INSERT"},
    {SW_VIDEOOUT_INSERT, "SW_VIDEOOUT_INSERT"},
    {SW_CAMERA_LENS_COVER, "SW_CAMERA_LENS_COVER"},
    {SW_KEYPAD_SLIDE, "SW_KEYPAD_SLIDE"},
    {SW_FRONT_PROXIMITY, "SW_FRONT_PROXIMITY"},
    {SW_ROTATE_LOCK, "SW_ROTATE_LOCK"},
    {SW_LINEIN_INSERT, "SW_LINEIN_INSERT"},
    {SW_MUTE_DEVICE, "SW_MUTE_DEVICE"},
    {SW_PEN_INSERTED, "SW_PEN_INSERTED"},
    {SW_MACHINE_COVER, "SW_MACHINE_COVER"}
};

// Miscellaneous event code mapping
static const std::unordered_map<uint16_t, std::string> MSC_CODE_MAP = {
    {MSC_SERIAL, "MSC_SERIAL"},
    {MSC_PULSELED, "MSC_PULSELED"},
    {MSC_GESTURE, "MSC_GESTURE"},
    {MSC_RAW, "MSC_RAW"},
    {MSC_SCAN, "MSC_SCAN"},
    {MSC_TIMESTAMP, "MSC_TIMESTAMP"}
};

// LED event code mapping
static const std::unordered_map<uint16_t, std::string> LED_CODE_MAP = {
    {LED_NUML, "LED_NUML"},
    {LED_CAPSL, "LED_CAPSL"},
    {LED_SCROLLL, "LED_SCROLLL"},
    {LED_COMPOSE, "LED_COMPOSE"},
    {LED_KANA, "LED_KANA"},
    {LED_SLEEP, "LED_SLEEP"},
    {LED_SUSPEND, "LED_SUSPEND"},
    {LED_MUTE, "LED_MUTE"},
    {LED_MISC, "LED_MISC"},
    {LED_MAIL, "LED_MAIL"},
    {LED_CHARGING, "LED_CHARGING"}
};

// Auto-repeat event code mapping
static const std::unordered_map<uint16_t, std::string> REP_CODE_MAP = {
    {REP_DELAY, "REP_DELAY"},
    {REP_PERIOD, "REP_PERIOD"}
};

// Sound event code mapping
static const std::unordered_map<uint16_t, std::string> SND_CODE_MAP = {
    {SND_CLICK, "SND_CLICK"},
    {SND_BELL, "SND_BELL"},
    {SND_TONE, "SND_TONE"}
};
} // namespace MMI
} // namespace OHOS
#endif // EVENT_UTILS_H