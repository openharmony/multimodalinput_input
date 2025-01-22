/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef HOS_KEY_EVENT_H
#define HOS_KEY_EVENT_H

#include "define_multimodal.h"

namespace OHOS {
enum HosKeyState {
    /**
     * Indicates that the key is being pressed down.
     *
     * @since 3
     */
    HOS_KEY_PRESSED = 0,

    /**
     * Indicates that the key is being released.
     *
     * @since 3
     */
    HOS_KEY_RELEASED = 1,
};

enum HosKeyEventEnum {
    /**
     * Keycode constant: unknown keycode
     * <p>The keycode is unknown.
     *
     * @since 1
     */
    HOS_UNKNOWN_KEY_BASE = 10000,
    HOS_KEY_UNKNOWN = -1,
    /**
     * Keycode constant: Fn key
     *
     * @since 1
     */
    HOS_KEY_FN = 0,
    /**
     * Keycode constant: Home key
     * <p>This key is processed by the framework and will never be sent to the application.
     *
     * @since 1
     */
    HOS_KEY_HOME = 1,

    /**
     * Keycode constant: Back key
     *
     * @since 1
     */
    HOS_KEY_BACK = 2,

    /**
     * Keycode constant: Call key
     *
     * @since 1
     */
    HOS_KEY_CALL = 3,

    /**
     * Keycode constant: End Call key
     *
     * @since 1
     */
    HOS_KEY_ENDCALL = 4,

    /**
     * Keycode constant: Clear key
     *
     * @since 1
     */
    HOS_KEY_CLEAR = 5,

    /**
     * Keycode constant: Headset Hook key
     * <p>The key is used to end a call and stop media.
     *
     * @since 1
     */
    HOS_KEY_HEADSETHOOK = 6,

    /**
     * Keycode constant: Camera Focus key
     * <p>This key is used to enable focus for the camera.
     *
     * @since 1
     */
    HOS_KEY_FOCUS = 7,

    /**
     * Keycode constant: Notification key
     *
     * @since 1
     */
    HOS_KEY_NOTIFICATION = 8,

    /**
     * Keycode constant: Search key
     *
     * @since 1
     */
    HOS_KEY_SEARCH = 9,

    /**
     * Keycode constant: Play/Pause media key
     *
     * @since 1
     */
    HOS_KEY_MEDIA_PLAY_PAUSE = 10,

    /**
     * Keycode constant: Stop media key
     *
     * @since 1
     */
    HOS_KEY_MEDIA_STOP = 11,

    /**
     * Keycode constant: Play Next media key
     *
     * @since 1
     */
    HOS_KEY_MEDIA_NEXT = 12,

    /**
     * Keycode constant: Play Previous media key
     *
     * @since 1
     */
    HOS_KEY_MEDIA_PREVIOUS = 13,

    /**
     * Keycode constant: Rewind media key
     *
     * @since 1
     */
    HOS_KEY_MEDIA_REWIND = 14,

    /**
     * Keycode constant: Fast Forward media key
     *
     * @since 1
     */
    HOS_KEY_MEDIA_FAST_FORWARD = 15,

    /**
     * Turns up the volume.
     *
     * @since 1
     */
    HOS_KEY_VOLUME_UP = 16,

    /**
     * Turns down the volume.
     *
     * @since 1
     */
    HOS_KEY_VOLUME_DOWN = 17,

    /**
     * Presses the power button.
     *
     * @since 1
     */
    HOS_KEY_POWER = 18,

    /**
     * Presses the camera key.
     * <p>It is used to start the camera or take photos.
     *
     * @since 1
     */
    HOS_KEY_CAMERA = 19,

    /**
     * Voice Assistant key
     * <p>This key is used to wake up the voice assistant.
     *
     * @since 1
     */
    HOS_KEY_VOICE_ASSISTANT = 20,

    /**
     * Custom key 1
     * <p>The actions mapping to the custom keys are user-defined. Key values 521-529 are reserved for custom keys.
     *
     * @since 1
     */
    HOS_KEY_CUSTOM1 = 21,

    HOS_KEY_VOLUME_MUTE = 22,
    HOS_KEY_MUTE = 23,

    /**
     * Brightness UP key
     *
     * @since 1
     */
    HOS_KEY_BRIGHTNESS_UP = 40,

    /**
     * Brightness Down key
     *
     * @since 1
     */
    HOS_KEY_BRIGHTNESS_DOWN = 41,

    /**
     * Indicates general-purpose key 1 on the wearables
     *
     * @since 3
     */
    HOS_KEY_WEAR_1 = 1001,

    /**
     * Keycode constant: '0' key
     *
     * @since 1
     */
    HOS_KEY_0 = 2000,

    /**
     * Keycode constant: '1' key
     *
     * @since 1
     */
    HOS_KEY_1 = 2001,

    /**
     * Keycode constant: '2' key
     *
     * @since 1
     */
    HOS_KEY_2 = 2002,

    /**
     * Keycode constant: '3' key
     *
     * @since 1
     */
    HOS_KEY_3 = 2003,

    /**
     * Keycode constant: '4' key
     *
     * @since 1
     */
    HOS_KEY_4 = 2004,

    /**
     * Keycode constant: '5' key
     *
     * @since 1
     */
    HOS_KEY_5 = 2005,

    /**
     * Keycode constant: '6' key
     *
     * @since 1
     */
    HOS_KEY_6 = 2006,

    /**
     * Keycode constant: '7' key
     *
     * @since 1
     */
    HOS_KEY_7 = 2007,

    /**
     * Keycode constant: '8' key
     *
     * @since 1
     */
    HOS_KEY_8 = 2008,

    /**
     * Keycode constant: '9' key
     *
     * @since 1
     */
    HOS_KEY_9 = 2009,

    /**
     * Keycode constant: '*' key
     *
     * @since 1
     */
    HOS_KEY_STAR = 2010,

    /**
     * Keycode constant: '#' key
     *
     * @since 1
     */
    HOS_KEY_POUND = 2011,

    /**
     * Keycode constant: Directional Pad Up key
     * <p>The key may also be synthesized from trackball motions.
     *
     * @since 1
     */
    HOS_KEY_DPAD_UP = 2012,

    /**
     * Keycode constant: Directional Pad Down key
     * <p>The key may also be synthesized from trackball motions.
     *
     * @since 1
     */
    HOS_KEY_DPAD_DOWN = 2013,

    /**
     * Keycode constant: Directional Pad Left key
     * <p>The key may also be synthesized from trackball motions.
     *
     * @since 1
     */
    HOS_KEY_DPAD_LEFT = 2014,

    /**
     * Keycode constant: Directional Pad Right key
     * <p>The key may also be synthesized from trackball motions.
     *
     * @since 1
     */
    HOS_KEY_DPAD_RIGHT = 2015,

    /**
     * Keycode constant: Directional Pad Center key
     * <p>The key may also be synthesized from trackball motions.
     *
     * @since 1
     */
    HOS_KEY_DPAD_CENTER = 2016,

    /**
     * Keycode constant: 'A' key
     *
     * @since 1
     */
    HOS_KEY_A = 2017,

    /**
     * Keycode constant: 'B' key
     *
     * @since 1
     */
    HOS_KEY_B = 2018,

    /**
     * Keycode constant: 'C' key
     *
     * @since 1
     */
    HOS_KEY_C = 2019,

    /**
     * Keycode constant: 'D' key
     *
     * @since 1
     */
    HOS_KEY_D = 2020,

    /**
     * Keycode constant: 'E' key
     *
     * @since 1
     */
    HOS_KEY_E = 2021,

    /**
     * Keycode constant: 'F' key
     *
     * @since 1
     */
    HOS_KEY_F = 2022,

    /**
     * Keycode constant: 'G' key
     *
     * @since 1
     */
    HOS_KEY_G = 2023,

    /**
     * Keycode constant: 'H' key
     *
     * @since 1
     */
    HOS_KEY_H = 2024,

    /**
     * Keycode constant: 'I' key
     *
     * @since 1
     */
    HOS_KEY_I = 2025,

    /**
     * Keycode constant: 'J' key
     *
     * @since 1
     */
    HOS_KEY_J = 2026,

    /**
     * Keycode constant: 'K' key
     *
     * @since 1
     */
    HOS_KEY_K = 2027,

    /**
     * Keycode constant: 'L' key
     *
     * @since 1
     */
    HOS_KEY_L = 2028,

    /**
     * Keycode constant: 'M' key
     *
     * @since 1
     */
    HOS_KEY_M = 2029,

    /**
     * Keycode constant: 'N' key
     *
     * @since 1
     */
    HOS_KEY_N = 2030,

    /**
     * Keycode constant: 'O' key
     *
     * @since 1
     */
    HOS_KEY_O = 2031,

    /**
     * Keycode constant: 'P' key
     *
     * @since 1
     */
    HOS_KEY_P = 2032,

    /**
     * Keycode constant: 'Q' key
     *
     * @since 1
     */
    HOS_KEY_Q = 2033,

    /**
     * Keycode constant: 'R' key
     *
     * @since 1
     */
    HOS_KEY_R = 2034,

    /**
     * Keycode constant: 'S' key
     *
     * @since 1
     */
    HOS_KEY_S = 2035,

    /**
     * Keycode constant: 'T' key
     *
     * @since 1
     */
    HOS_KEY_T = 2036,

    /**
     * Keycode constant: 'U' key
     *
     * @since 1
     */
    HOS_KEY_U = 2037,

    /**
     * Keycode constant: 'V' key
     *
     * @since 1
     */
    HOS_KEY_V = 2038,

    /**
     * Keycode constant: 'W' key
     *
     * @since 1
     */
    HOS_KEY_W = 2039,

    /**
     * Keycode constant: 'X' key
     *
     * @since 1
     */
    HOS_KEY_X = 2040,

    /**
     * Keycode constant: 'Y' key
     *
     * @since 1
     */
    HOS_KEY_Y = 2041,

    /**
     * Keycode constant: 'Z' key
     *
     * @since 1
     */
    HOS_KEY_Z = 2042,

    /**
     * Keycode constant: ',' key
     *
     * @since 1
     */
    HOS_KEY_COMMA = 2043,

    /**
     * Keycode constant: '.' key
     *
     * @since 1
     */
    HOS_KEY_PERIOD = 2044,

    /**
     * Keycode constant: Left Alt modifier key
     *
     * @since 1
     */
    HOS_KEY_ALT_LEFT = 2045,

    /**
     * Keycode constant: Right Alt modifier key
     *
     * @since 1
     */
    HOS_KEY_ALT_RIGHT = 2046,

    /**
     * Keycode constant: Left Shift modifier key
     *
     * @since 1
     */
    HOS_KEY_SHIFT_LEFT = 2047,

    /**
     * Keycode constant: Right Shift modifier key
     *
     * @since 1
     */
    HOS_KEY_SHIFT_RIGHT = 2048,

    /**
     * Keycode constant: Tab key
     *
     * @since 1
     */
    HOS_KEY_TAB = 2049,

    /**
     * Keycode constant: Space key
     *
     * @since 1
     */
    HOS_KEY_SPACE = 2050,

    /**
     * Keycode constant: Symbol modifier key
     * <p>The key is used to input alternate symbols.
     *
     * @since 1
     */
    HOS_KEY_SYM = 2051,

    /**
     * Keycode constant: Explorer function key
     * <p>This key is used to launch a browser application.
     *
     * @since 1
     */
    HOS_KEY_EXPLORER = 2052,

    /**
     * Keycode constant: Email function key
     * <p>This key is used to launch an email application.
     *
     * @since 1
     */
    HOS_KEY_ENVELOPE = 2053,

    /**
     * Keycode constant: Enter key
     *
     * @since 1
     */
    HOS_KEY_ENTER = 2054,

    /**
     * Keycode constant: Backspace key
     * <p>Unlike {@link #KEY_FORWARD_DEL}, this key is used to delete characters before the
     * insertion point.
     *
     * @since 1
     */
    HOS_KEY_DEL = 2055,

    /**
     * Keycode constant: '`' key (backtick key)
     *
     * @since 1
     */
    HOS_KEY_GRAVE = 2056,

    /**
     * Keycode constant: '-' key
     *
     * @since 1
     */
    HOS_KEY_MINUS = 2057,

    /**
     * Keycode constant: '=' key
     *
     * @since 1
     */
    HOS_KEY_EQUALS = 2058,

    /**
     * Keycode constant: '[' key
     *
     * @since 1
     */
    HOS_KEY_LEFT_BRACKET = 2059,

    /**
     * Keycode constant: ']' key
     *
     * @since 1
     */
    HOS_KEY_RIGHT_BRACKET = 2060,

    /**
     * Keycode constant: '\' key
     *
     * @since 1
     */
    HOS_KEY_BACKSLASH = 2061,

    /**
     * Keycode constant: ',' key
     *
     * @since 1
     */
    HOS_KEY_SEMICOLON = 2062,

    /**
     * Keycode constant: ''' key (apostrophe key)
     *
     * @since 1
     */
    HOS_KEY_APOSTROPHE = 2063,

    /**
     * Keycode constant: '/' key
     *
     * @since 1
     */
    HOS_KEY_SLASH = 2064,

    /**
     * Keycode constant: '{@literal @}' key
     *
     * @since 1
     */
    HOS_KEY_AT = 2065,

    /**
     * Keycode constant: '+' key
     *
     * @since 1
     */
    HOS_KEY_PLUS = 2066,

    /**
     * Keycode constant: Menu key
     *
     * @since 1
     */
    HOS_KEY_MENU = 2067,

    /**
     * Keycode constant: Page Up key
     *
     * @since 1
     */
    HOS_KEY_PAGE_UP = 2068,

    /**
     * Keycode constant: Page Down key
     *
     * @since 1
     */
    HOS_KEY_PAGE_DOWN = 2069,

    /**
     * Keycode constant: Escape key
     *
     * @since 1
     */
    HOS_KEY_ESCAPE = 2070,

    /**
     * Keycode constant: Forward Delete key
     * <p>Unlike {@link #KEY_DEL}, this key is used to delete characters ahead of the insertion
     * point.
     *
     * @since 1
     */
    HOS_KEY_FORWARD_DEL = 2071,

    /**
     * Keycode constant: Left Control modifier key
     *
     * @since 1
     */
    HOS_KEY_CTRL_LEFT = 2072,

    /**
     * Keycode constant: Right Control modifier key
     *
     * @since 1
     */
    HOS_KEY_CTRL_RIGHT = 2073,

    /**
     * Keycode constant: Caps Lock key
     *
     * @since 1
     */
    HOS_KEY_CAPS_LOCK = 2074,

    /**
     * Keycode constant: Scroll Lock key
     *
     * @since 1
     */
    HOS_KEY_SCROLL_LOCK = 2075,

    /**
     * Keycode constant: Left Meta modifier key
     *
     * @since 1
     */
    HOS_KEY_META_LEFT = 2076,

    /**
     * Keycode constant: Right Meta modifier key
     *
     * @since 1
     */
    HOS_KEY_META_RIGHT = 2077,

    /**
     * Keycode constant: Function modifier key
     *
     * @since 1
     */
    HOS_KEY_FUNCTION = 2078,

    /**
     * Keycode constant: System Request/Print Screen key
     *
     * @since 1
     */
    HOS_KEY_SYSRQ = 2079,

    /**
     * Keycode constant: Break/Pause key
     *
     * @since 1
     */
    HOS_KEY_BREAK = 2080,

    /**
     * Keycode constant: Home Movement key
     * <p>This key is used to scroll or move the cursor around to the start of a line or to the
     * top of a list.
     *
     * @since 1
     */
    HOS_KEY_MOVE_HOME = 2081,

    /**
     * Keycode constant: End Movement key
     * <p>This key is used to scroll or move the cursor around to the end of a line or to the
     * bottom of a list.
     *
     * @since 1
     */
    HOS_KEY_MOVE_END = 2082,

    /**
     * Keycode constant: Insert key
     * <p>This key is used to toggle the insert or overwrite edit mode.
     *
     * @since 1
     */
    HOS_KEY_INSERT = 2083,

    /**
     * Keycode constant: Forward key
     * <p>This key is used to navigate forward in the history stack. It is a complement of
     * {@link #KEY_BACK}.
     *
     * @since 1
     */
    HOS_KEY_FORWARD = 2084,

    /**
     * Keycode constant: Play media key
     *
     * @since 1
     */
    HOS_KEY_MEDIA_PLAY = 2085,

    /**
     * Keycode constant: Pause media key
     *
     * @since 1
     */
    HOS_KEY_MEDIA_PAUSE = 2086,

    /**
     * Keycode constant: Close media key
     * <p>This key can be used to close a CD tray, for example.
     *
     * @since 1
     */
    HOS_KEY_MEDIA_CLOSE = 2087,

    /**
     * Keycode constant: Eject media key
     * <p>This key can be used to eject a CD tray, for example.
     *
     * @since 1
     */
    HOS_KEY_MEDIA_EJECT = 2088,

    /**
     * Keycode constant: Record media key
     *
     * @since 1
     */
    HOS_KEY_MEDIA_RECORD = 2089,

    /**
     * Keycode constant: F1 key
     *
     * @since 1
     */
    HOS_KEY_F1 = 2090,

    /**
     * Keycode constant: F2 key
     *
     * @since 1
     */
    HOS_KEY_F2 = 2091,

    /**
     * Keycode constant: F3 key
     *
     * @since 1
     */
    HOS_KEY_F3 = 2092,

    /**
     * Keycode constant: F4 key
     *
     * @since 1
     */
    HOS_KEY_F4 = 2093,

    /**
     * Keycode constant: F5 key
     *
     * @since 1
     */
    HOS_KEY_F5 = 2094,

    /**
     * Keycode constant: F6 key
     *
     * @since 1
     */
    HOS_KEY_F6 = 2095,

    /**
     * Keycode constant: F7 key
     *
     * @since 1
     */
    HOS_KEY_F7 = 2096,

    /**
     * Keycode constant: F8 key
     *
     * @since 1
     */
    HOS_KEY_F8 = 2097,

    /**
     * Keycode constant: F9 key
     *
     * @since 1
     */
    HOS_KEY_F9 = 2098,

    /**
     * Keycode constant: F10 key
     *
     * @since 1
     */
    HOS_KEY_F10 = 2099,

    /**
     * Keycode constant: F11 key
     *
     * @since 1
     */
    HOS_KEY_F11 = 2100,

    /**
     * Keycode constant: F12 key
     *
     * @since 1
     */
    HOS_KEY_F12 = 2101,

    /**
     * Keycode constant: Num Lock key
     * <p>This key is used to alter the behavior of other keys on the numeric keypad.
     *
     * @since 1
     */
    HOS_KEY_NUM_LOCK = 2102,

    /**
     * Keycode constant: '0' key on the numeric keypad
     *
     * @since 1
     */
    HOS_KEY_NUMPAD_0 = 2103,

    /**
     * Keycode constant: '1' key on the numeric keypad
     *
     * @since 1
     */
    HOS_KEY_NUMPAD_1 = 2104,

    /**
     * Keycode constant: '2' key on the numeric keypad
     *
     * @since 1
     */
    HOS_KEY_NUMPAD_2 = 2105,

    /**
     * Keycode constant: '3' key on the numeric keypad
     *
     * @since 1
     */
    HOS_KEY_NUMPAD_3 = 2106,

    /**
     * Keycode constant: '4' key on the numeric keypad
     *
     * @since 1
     */
    HOS_KEY_NUMPAD_4 = 2107,

    /**
     * Keycode constant: '5' key on the numeric keypad
     *
     * @since 1
     */
    HOS_KEY_NUMPAD_5 = 2108,

    /**
     * Keycode constant: '6' key on the numeric keypad
     *
     * @since 1
     */
    HOS_KEY_NUMPAD_6 = 2109,

    /**
     * Keycode constant: '7' key on the numeric keypad
     *
     * @since 1
     */
    HOS_KEY_NUMPAD_7 = 2110,

    /**
     * Keycode constant: '8' key on the numeric keypad
     *
     * @since 1
     */
    HOS_KEY_NUMPAD_8 = 2111,

    /**
     * Keycode constant: '9' key on the numeric keypad
     *
     * @since 1
     */
    HOS_KEY_NUMPAD_9 = 2112,

    /**
     * Keycode constant: '/' key (for division) on the numeric keypad
     *
     * @since 1
     */
    HOS_KEY_NUMPAD_DIVIDE = 2113,

    /**
     * Keycode constant: '*' key (for multiplication) on the numeric keypad
     *
     * @since 1
     */
    HOS_KEY_NUMPAD_MULTIPLY = 2114,

    /**
     * Keycode constant: '-' key (for subtraction) on the numeric keypad
     *
     * @since 1
     */
    HOS_KEY_NUMPAD_SUBTRACT = 2115,

    /**
     * Keycode constant: '+' key (for addition) on the numeric keypad
     *
     * @since 1
     */
    HOS_KEY_NUMPAD_ADD = 2116,

    /**
     * Key code constant: '.' key (for decimals or digit grouping) on the numeric keypad
     *
     * @since 1
     */
    HOS_KEY_NUMPAD_DOT = 2117,

    /**
     * Key code constant: ',' key (for decimals or digit grouping) on the numeric keypad
     *
     * @since 1
     */
    HOS_KEY_NUMPAD_COMMA = 2118,

    /**
     * Keycode constant: Enter key on the numeric keypad
     *
     * @since 1
     */
    HOS_KEY_NUMPAD_ENTER = 2119,

    /**
     * Keycode constant: '=' key on the numeric keypad
     *
     * @since 1
     */
    HOS_KEY_NUMPAD_EQUALS = 2120,

    /**
     * Keycode constant: '(' key on the numeric keypad
     *
     * @since 1
     */
    HOS_KEY_NUMPAD_LEFT_PAREN = 2121,

    /**
     * Keycode constant: ')' key on the numeric keypad
     *
     * @since 1
     */
    HOS_KEY_NUMPAD_RIGHT_PAREN = 2122,

    /**
     * Key code: The virtual multitask key
     *
     * @since 1
     */
    HOS_KEY_VIRTUAL_MULTITASK = 2210,

    HOS_KEY_COMPOSE = 2466,
    HOS_KEY_SLEEP = 2600,
    HOS_KEY_ZENKAKU_HANKAKU = 2601,
    HOS_KEY_102ND = 2602,
    HOS_KEY_RO = 2603,
    HOS_KEY_KATAKANA = 2604,
    HOS_KEY_HIRAGANA = 2605,
    HOS_KEY_HENKAN = 2606,
    HOS_KEY_KATAKANA_HIRAGANA = 2607,
    HOS_KEY_MUHENKAN = 2608,
    HOS_KEY_LINEFEED = 2609,
    HOS_KEY_MACRO = 2610,
    HOS_KEY_NUMPAD_PLUSMINUS = 2611,
    HOS_KEY_SCALE = 2612,
    HOS_KEY_HANGUEL = 2613,
    HOS_KEY_HANJA = 2614,
    HOS_KEY_YEN = 2615,
    HOS_KEY_STOP = 2616,
    HOS_KEY_AGAIN = 2617,
    HOS_KEY_PROPS = 2618,
    HOS_KEY_UNDO = 2619,
    HOS_KEY_COPY = 2620,
    HOS_KEY_OPEN = 2621,
    HOS_KEY_PASTE = 2622,
    HOS_KEY_FIND = 2623,
    HOS_KEY_CUT = 2624,
    HOS_KEY_HELP = 2625,
    HOS_KEY_CALC = 2626,
    HOS_KEY_FILE = 2627,
    HOS_KEY_BOOKMARKS = 2628,
    HOS_KEY_NEXT = 2629,
    HOS_KEY_PLAYPAUSE = 2630,
    HOS_KEY_PREVIOUS = 2631,
    HOS_KEY_STOPCD = 2632,
    HOS_KEY_CONFIG = 2634,
    HOS_KEY_REFRESH = 2635,
    HOS_KEY_EXIT = 2636,
    HOS_KEY_EDIT = 2637,
    HOS_KEY_SCROLLUP = 2638,
    HOS_KEY_SCROLLDOWN = 2639,
    HOS_KEY_NEW = 2640,
    HOS_KEY_REDO = 2641,
    HOS_KEY_CLOSE = 2642,
    HOS_KEY_PLAY = 2643,
    HOS_KEY_BASSBOOST = 2644,
    HOS_KEY_PRINT = 2645,
    HOS_KEY_CHAT = 2646,
    HOS_KEY_FINANCE = 2647,
    HOS_KEY_CANCEL = 2648,
    HOS_KEY_KBDILLUM_TOGGLE = 2649,
    HOS_KEY_KBDILLUM_DOWN = 2650,
    HOS_KEY_KBDILLUM_UP = 2651,
    HOS_KEY_SEND = 2652,
    HOS_KEY_REPLY = 2653,
    HOS_KEY_FORWARDMAIL = 2654,
    HOS_KEY_SAVE = 2655,
    HOS_KEY_DOCUMENTS = 2656,
    HOS_KEY_VIDEO_NEXT = 2657,
    HOS_KEY_VIDEO_PREV = 2658,
    HOS_KEY_BRIGHTNESS_CYCLE = 2659,
    HOS_KEY_BRIGHTNESS_ZERO = 2660,
    HOS_KEY_DISPLAY_OFF = 2661,
    HOS_BTN_MISC = 2662,
    HOS_KEY_GOTO = 2663,
    HOS_KEY_INFO = 2664,
    HOS_KEY_PROGRAM = 2665,
    HOS_KEY_PVR = 2666,
    HOS_KEY_SUBTITLE = 2667,
    HOS_KEY_FULL_SCREEN = 2668,
    HOS_KEY_KEYBOARD = 2669,
    HOS_KEY_ASPECT_RATIO = 2670,
    HOS_KEY_PC = 2671,
    HOS_KEY_TV = 2672,
    HOS_KEY_TV2 = 2673,
    HOS_KEY_VCR = 2674,
    HOS_KEY_VCR2 = 2675,
    HOS_KEY_SAT = 2676,
    HOS_KEY_CD = 2677,
    HOS_KEY_TAPE = 2678,
    HOS_KEY_TUNER = 2679,
    HOS_KEY_PLAYER = 2680,
    HOS_KEY_DVD = 2681,
    HOS_KEY_AUDIO = 2682,
    HOS_KEY_VIDEO = 2683,
    HOS_KEY_MEMO = 2684,
    HOS_KEY_CALENDAR = 2685,
    HOS_KEY_RED = 2686,
    HOS_KEY_GREEN = 2687,
    HOS_KEY_YELLOW = 2688,
    HOS_KEY_BLUE = 2689,
    HOS_KEY_CHANNELUP = 2690,
    HOS_KEY_CHANNELDOWN = 2691,
    HOS_KEY_LAST = 2692,
    HOS_KEY_RESTART = 2693,
    HOS_KEY_SLOW = 2694,
    HOS_KEY_SHUFFLE = 2695,
    HOS_KEY_VIDEOPHONE = 2696,
    HOS_KEY_GAMES = 2697,
    HOS_KEY_ZOOMIN = 2698,
    HOS_KEY_ZOOMOUT = 2699,
    HOS_KEY_ZOOMRESET = 2700,
    HOS_KEY_WORDPROCESSOR = 2701,
    HOS_KEY_EDITOR = 2702,
    HOS_KEY_SPREADSHEET = 2703,
    HOS_KEY_GRAPHICSEDITOR = 2704,
    HOS_KEY_PRESENTATION = 2705,
    HOS_KEY_DATABASE = 2706,
    HOS_KEY_NEWS = 2707,
    HOS_KEY_VOICEMAIL = 2708,
    HOS_KEY_ADDRESSBOOK = 2709,
    HOS_KEY_MESSENGER = 2710,
    HOS_KEY_BRIGHTNESS_TOGGLE = 2711,
    HOS_KEY_SPELLCHECK = 2712,
    HOS_KEY_COFFEE = 2713,
    HOS_KEY_MEDIA_REPEAT = 2714,
    HOS_KEY_IMAGES = 2715,
    HOS_KEY_BUTTONCONFIG = 2716,
    HOS_KEY_TASKMANAGER = 2717,
    HOS_KEY_JOURNAL = 2718,
    HOS_KEY_CONTROLPANEL = 2719,
    HOS_KEY_APPSELECT = 2720,
    HOS_KEY_SCREENSAVER = 2721,
    HOS_KEY_ASSISTANT = 2722,
    HOS_KEY_KBD_LAYOUT_NEXT = 2723,
    HOS_KEY_BRIGHTNESS_MIN = 2724,
    HOS_KEY_BRIGHTNESS_MAX = 2725,
    HOS_KEY_KBDINPUTASSIST_PREV = 2726,
    HOS_KEY_KBDINPUTASSIST_NEXT = 2727,
    HOS_KEY_KBDINPUTASSIST_PREVGROUP = 2728,
    HOS_KEY_KBDINPUTASSIST_NEXTGROUP = 2729,
    HOS_KEY_KBDINPUTASSIST_ACCEPT = 2730,
    HOS_KEY_KBDINPUTASSIST_CANCEL = 2731,

    HOS_KEY_FRONT = 2800,
    HOS_KEY_SETUP = 2801,
    HOS_KEY_WAKEUP = 2802,
    HOS_KEY_SENDFILE = 2803,
    HOS_KEY_DELETEFILE = 2804,
    HOS_KEY_XFER = 2805,
    HOS_KEY_PROG1 = 2806,
    HOS_KEY_PROG2 = 2807,
    HOS_KEY_MSDOS = 2808,
    HOS_KEY_SCREENLOCK = 2809,
    HOS_KEY_DIRECTION_ROTATE_DISPLAY = 2810,
    HOS_KEY_CYCLEWINDOWS = 2811,
    HOS_KEY_COMPUTER = 2812,
    HOS_KEY_EJECTCLOSECD = 2813,
    HOS_KEY_ISO = 2814,
    HOS_KEY_MOVE = 2815,
    HOS_KEY_F13 = 2816,
    HOS_KEY_F14 = 2817,
    HOS_KEY_F15 = 2818,
    HOS_KEY_F16 = 2819,
    HOS_KEY_F17 = 2820,
    HOS_KEY_F18 = 2821,
    HOS_KEY_F19 = 2822,
    HOS_KEY_F20 = 2823,
    HOS_KEY_F21 = 2824,
    HOS_KEY_F22 = 2825,
    HOS_KEY_F23 = 2826,
    HOS_KEY_F24 = 2827,
    HOS_KEY_PROG3 = 2828,
    HOS_KEY_PROG4 = 2829,
    HOS_KEY_DASHBOARD = 2830,
    HOS_KEY_SUSPEND = 2831,
    HOS_KEY_HP = 2832,
    HOS_KEY_SOUND = 2833,
    HOS_KEY_QUESTION = 2834,
    HOS_KEY_CONNECT = 2836,
    HOS_KEY_SPORT = 2837,
    HOS_KEY_SHOP = 2838,
    HOS_KEY_ALTERASE = 2839,
    HOS_KEY_SWITCHVIDEOMODE = 2841,
    HOS_KEY_BATTERY = 2842,
    HOS_KEY_BLUETOOTH = 2843,
    HOS_KEY_WLAN = 2844,
    HOS_KEY_UWB = 2845,
    HOS_KEY_WWAN_WIMAX = 2846,
    HOS_KEY_RFKILL = 2847,
    HOS_KEY_F26 = 2848,
    HOS_KEY_F27 = 2849,

    HOS_KEY_CHANNEL = 3001,
    HOS_KEY_BTN_0 = 3100,
    HOS_KEY_BTN_1 = 3101,
    HOS_KEY_BTN_2 = 3102,
    HOS_KEY_BTN_3 = 3103,
    HOS_KEY_BTN_4 = 3104,
    HOS_KEY_BTN_5 = 3105,
    HOS_KEY_BTN_6 = 3106,
    HOS_KEY_BTN_7 = 3107,
    HOS_KEY_BTN_8 = 3108,
    HOS_KEY_BTN_9 = 3109,

    HOS_KEY_BRL_DOT1 = 3201,
    HOS_KEY_BRL_DOT2 = 3202,
    HOS_KEY_BRL_DOT3 = 3203,
    HOS_KEY_BRL_DOT4 = 3204,
    HOS_KEY_BRL_DOT5 = 3205,
    HOS_KEY_BRL_DOT6 = 3206,
    HOS_KEY_BRL_DOT7 = 3207,
    HOS_KEY_BRL_DOT8 = 3208,
    HOS_KEY_BRL_DOT9 = 3209,
    HOS_KEY_BRL_DOT10 = 3210,
    DAGGER_CLICK = 3211,
    DAGGER_DOUBLE_CLICK = 3212,
    DAGGER_LONG_PRESS = 3213,
    HOS_KEY_PEN_AIR_MOUSE = 3214,
    HOS_KEY_PEN_LIGHT_PINCH = 3215,
    HOS_KEY_PEN_AI = 3216,
    HOS_KEY_PEN_END_CLICK = 3217,
    HOS_KEY_PEN_END_DOUBLE_CLICK = 3218,
    /**
     * Left Knob roll-up
     * <p>In contrast to {@link #KEY_LEFT_KNOB_ROLL_DOWN}, it means rolling the left knob upwards. The knob function
     * is scenario-specific, for example, increasing the volume or air conditioner temperature.
     *
     * @since 1
     */
    HOS_KEY_LEFT_KNOB_ROLL_UP = 10001,

    /**
     * Left Knob roll-down
     * <p>In contrast to {@link #KEY_LEFT_KNOB_ROLL_UP}, it means rolling the left knob downwards. The knob function
     * is scenario-specific, for example, reducing the volume or air conditioner temperature.
     *
     * @since 1
     */
    HOS_KEY_LEFT_KNOB_ROLL_DOWN = 10002,

    /**
     * Left Knob
     * <p>Pressing the knob will activate its adjustment function.
     *
     * @since 1
     */
    HOS_KEY_LEFT_KNOB = 10003,

    /**
     * Right Knob roll-up
     * <p>In contrast to {@link #KEY_RIGHT_KNOB_ROLL_DOWN}, it means rolling the right knob upwards. The knob
     * function is scenario-specific, for example, increasing the volume or air conditioner temperature.
     *
     * @since 1
     */
    HOS_KEY_RIGHT_KNOB_ROLL_UP = 10004,

    /**
     * Right Knob roll-down
     * <p>In contrast to {@link #KEY_RIGHT_KNOB_ROLL_UP}, it means rolling the right knob downwards. The knob
     * function is scenario-specific, for example, reducing the volume or air conditioner temperature.
     *
     * @since 1
     */
    HOS_KEY_RIGHT_KNOB_ROLL_DOWN = 10005,

    /**
     * Right Knob
     * <p>Pressing the knob will activate its adjustment function.
     *
     * @since 1
     */
    HOS_KEY_RIGHT_KNOB = 10006,

    /**
     * Audio Source Switch button
     * <p>Pressing this button will enable the audio source. Depending on the actual scenario, it may also
     * indicate that the Bluetooth call control button is pressed.
     *
     * @since 1
     */
    HOS_KEY_VOICE_SOURCE_SWITCH = 10007,

    /**
     * Menu key
     * <p>Pressing this key will display the launcher page.
     *
     * @since 1
     */
    HOS_KEY_LAUNCHER_MENU = 10008,

    /**
     * Keycode constant: max keycode
     * <p> If a new keycode added to {@code KeyEvent} is greater than the maximum keycode, update
     * the maximum keycode accordingly.
     *
     * @since 1
     */
    HOS_NOW_MAX_KEY = HOS_KEY_LAUNCHER_MENU
};

enum MouseEnum {
    /**
     * Indicates that the left button on the mouse is pressed.
     *
     * @since 1
     */
    HOS_LEFT_BUTTON = 1 << 0,

    /**
     * Indicates that the right button on the mouse is pressed.
     *
     * @since 1
     */
    HOS_RIGHT_BUTTON = 1 << 1,

    /**
     * Indicates that the middle button on the mouse is pressed.
     *
     * @since 1
     */
    HOS_MIDDLE_BUTTON = 1 << 2,

    /**
     * Indicates that the back button on the mouse is pressed.
     *
     * @since 1
     */
    HOS_BACK_BUTTON = 1 << 3,

    /**
     * Indicates that the forward button on the mouse is pressed.
     *
     * @since 1
     */
    HOS_FORWARD_BUTTON = 1 << 4,

    HOS_SIDE_BUTTON = 1 << 5,
    HOS_EXTRA_BUTTON = 1 << 6,
    HOS_TASK_BUTTON = 1 << 7,
};

enum JoystickEnum {
    /**
     * Key code of joystick:
     *
     * @since 1
     */
    HOS_KEY_BUTTON_TRIGGER = 2401,

    /**
     * Key code of joystick:
     *
     * @since 1
     */
    HOS_KEY_BUTTON_THUMB = 2402,

    /**
     * Key code of joystick:
     *
     * @since 1
     */
    HOS_KEY_BUTTON_THUMB2 = 2403,

    /**
     * Key code of joystick:
     *
     * @since 1
     */
    HOS_KEY_BUTTON_TOP = 2404,

    /**
     * Key code of joystick:
     *
     * @since 1
     */
    HOS_KEY_BUTTON_TOP2 = 2405,

    /**
     * Key code of joystick:
     *
     * @since 1
     */
    HOS_KEY_BUTTON_PINKIE = 2406,

    /**
     * Key code of joystick:
     *
     * @since 1
     */
    HOS_KEY_BUTTON_BASE1 = 2407,

    /**
     * Key code of joystick:
     *
     * @since 1
     */
    HOS_KEY_BUTTON_BASE2 = 2408,

    /**
     * Key code of joystick:
     *
     * @since 1
     */
    HOS_KEY_BUTTON_BASE3 = 2409,

    /**
     * Key code of joystick:
     *
     * @since 1
     */
    HOS_KEY_BUTTON_BASE4 = 2410,

    /**
     * Key code of joystick:
     *
     * @since 1
     */
    HOS_KEY_BUTTON_BASE5 = 2411,

    /**
     * Key code of joystick:
     *
     * @since 1
     */
    HOS_KEY_BUTTON_BASE6 = 2412,

    /**
     * Key code of joystick:
     *
     * @since 1
     */
    HOS_KEY_BUTTON_BASE7 = 2413,

    /**
     * Key code of joystick:
     *
     * @since 1
     */
    HOS_KEY_BUTTON_BASE8 = 2414,

    /**
     * Key code of joystick:
     *
     * @since 1
     */
    HOS_KEY_BUTTON_BASE9 = 2415,

    /**
     * Key code of joystick:
     *
     * @since 1
     */
    HOS_KEY_BUTTON_DEAD = 2416,
};

enum HandleEnum {
    /**
     * Key code of handle:
     *
     * @since 1
     */
    HOS_KEY_BUTTON_A = 2301,

    /**
     * Key code of handle:
     *
     * @since 1
     */
    HOS_KEY_BUTTON_B = 2302,

    /**
     * Key code of handle:
     *
     * @since 1
     */
    HOS_KEY_BUTTON_C = 2303,

    /**
     * Key code of handle:
     *
     * @since 1
     */
    HOS_KEY_BUTTON_X = 2304,

    /**
     * Key code of handle:
     *
     * @since 1
     */
    HOS_KEY_BUTTON_Y = 2305,

    /**
     * Key code of handle:
     *
     * @since 1
     */
    HOS_KEY_BUTTON_Z = 2306,

    /**
     * Key code of handle:
     *
     * @since 1
     */
    HOS_KEY_BUTTON_L1 = 2307,

    /**
     * Key code of handle:
     *
     * @since 1
     */
    HOS_KEY_BUTTON_R1 = 2308,

    /**
     * Key code of handle:
     *
     * @since 1
     */
    HOS_KEY_BUTTON_L2 = 2309,

    /**
     * Key code of handle:
     *
     * @since 1
     */
    HOS_KEY_BUTTON_R2 = 2310,

    /**
     * Key code of handle:
     *
     * @since 1
     */
    HOS_KEY_BUTTON_SELECT = 2311,

    /**
     * Key code of handle:
     *
     * @since 1
     */
    HOS_KEY_BUTTON_START = 2312,

    /**
     * Key code of handle:
     *
     * @since 1
     */
    HOS_KEY_BUTTON_MODE = 2313,

    /**
     * Key code of handle:
     *
     * @since 1
     */
    HOS_KEY_BUTTON_THUMBL = 2314,

    /**
     * Key code of handle:
     *
     * @since 1
     */
    HOS_KEY_BUTTON_THUMBR = 2315,
};

enum TouchEnum {
    /**
     * Key code of touch:
     *
     * @since 1
     */
    HOS_BUTTON_TOUCH = 2500,

    HOS_BUTTON_TOOL_PEN = 2501,
    HOS_BUTTON_TOOL_RUBBER = 2502,
    HOS_BUTTON_TOOL_BRUSH = 2503,
    HOS_BUTTON_TOOL_PENCIL = 2504,
    HOS_BUTTON_TOOL_AIRBRUSH = 2505,
    HOS_BUTTON_TOOL_FINGER = 2506,
    HOS_BUTTON_TOOL_MOUSE = 2507,
    HOS_BUTTON_TOOL_LENS = 2508,
    HOS_BUTTON_STYLUS = 2509,
    HOS_BUTTON_STYLUS2 = 2510,
    HOS_BUTTON_STYLUS3 = 2511,
    HOS_BUTTON_TOOL_DOUBLETAP = 2512,
    HOS_BUTTON_TOOL_TRIPLETAP = 2513,
    HOS_BUTTON_TOOL_QUADTAP = 2514,
    HOS_BUTTON_TOOL_QUINTTAP = 2515,
};
} // namespace OHOS
#endif // HOS_KEY_EVENT_H