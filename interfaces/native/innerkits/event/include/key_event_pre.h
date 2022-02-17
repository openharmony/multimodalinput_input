/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#ifndef KEY_EVENT_PRE_H
#define KEY_EVENT_PRE_H
#include <memory>
#include <vector>
#include "multimodal_event.h"

namespace OHOS {
enum KeyState {
    /* *
     * Indicates that the key is being pressed down.
     *
     * @since 3
     */
    KEY_PRESSED = 0,

    /* *
     * Indicates that the key is being released.
     *
     * @since 3
     */
    KEY_RELEASED = 1,
};

enum KeyEventEnum {
    /* *
     * Keycode constant: unknown keycode
     * <p>The keycode is unknown.
     *
     * @since 1
     */
    KEY_UNKNOWN = -1,

    /* *
     * Keycode constant: Home key
     * <p>This key is processed by the framework and will never be sent to the application.
     *
     * @since 1
     */
    KEY_HOME = 1,

    /* *
     * Keycode constant: Back key
     *
     * @since 1
     */
    KEY_BACK = 2,

    /* *
     * Keycode constant: Call key
     *
     * @since 1
     */
    KEY_CALL = 3,

    /* *
     * Keycode constant: End Call key
     *
     * @since 1
     */
    KEY_ENDCALL = 4,

    /* *
     * Keycode constant: Clear key
     *
     * @since 1
     */
    KEY_CLEAR = 5,

    /* *
     * Keycode constant: Headset Hook key
     * <p>The key is used to end a call and stop media.
     *
     * @since 1
     */
    KEY_HEADSETHOOK = 6,

    /* *
     * Keycode constant: Camera Focus key
     * <p>This key is used to enable focus for the camera.
     *
     * @since 1
     */
    KEY_FOCUS = 7,

    /* *
     * Keycode constant: Notification key
     *
     * @since 1
     */
    KEY_NOTIFICATION = 8,

    /* *
     * Keycode constant: Search key
     *
     * @since 1
     */
    KEY_SEARCH = 9,

    /* *
     * Keycode constant: Play/Pause media key
     *
     * @since 1
     */
    KEY_MEDIA_PLAY_PAUSE = 10,

    /* *
     * Keycode constant: Stop media key
     *
     * @since 1
     */
    KEY_MEDIA_STOP = 11,

    /* *
     * Keycode constant: Play Next media key
     *
     * @since 1
     */
    KEY_MEDIA_NEXT = 12,

    /* *
     * Keycode constant: Play Previous media key
     *
     * @since 1
     */
    KEY_MEDIA_PREVIOUS = 13,

    /* *
     * Keycode constant: Rewind media key
     *
     * @since 1
     */
    KEY_MEDIA_REWIND = 14,

    /* *
     * Keycode constant: Fast Forward media key
     *
     * @since 1
     */
    KEY_MEDIA_FAST_FORWARD = 15,

    /* *
     * Turns up the volume.
     *
     * @since 1
     */
    KEY_VOLUME_UP = 16,

    /* *
     * Turns down the volume.
     *
     * @since 1
     */
    KEY_VOLUME_DOWN = 17,

    /* *
     * Presses the power button.
     *
     * @since 1
     */
    KEY_POWER = 18,

    /* *
     * Presses the camera key.
     * <p>It is used to start the camera or take photos.
     *
     * @since 1
     */
    KEY_CAMERA = 19,

    /* *
     * Voice Assistant key
     * <p>This key is used to wake up the voice assistant.
     *
     * @since 1
     */
    KEY_VOICE_ASSISTANT = 20,

    /* *
     * Custom key 1
     * <p>The actions mapping to the custom keys are user-defined. Key values 521-529 are reserved for custom keys.
     *
     * @since 1
     */
    KEY_CUSTOM1 = 21,

    KEY_VOLUME_MUTE = 22,
    KEY_MUTE = 23,

    /* *
     * Brightness UP key
     *
     * @since 1
     */
    KEY_BRIGHTNESS_UP = 40,

    /* *
     * Brightness Down key
     *
     * @since 1
     */
    KEY_BRIGHTNESS_DOWN = 41,

    /* *
     * Indicates general-purpose key 1 on the wearables
     *
     * @since 3
     */
    KEY_WEAR_1 = 1001,

    /* *
     * Keycode constant: '0' key
     *
     * @since 1
     */
    KEY_0 = 2000,

    /* *
     * Keycode constant: '1' key
     *
     * @since 1
     */
    KEY_1 = 2001,

    /* *
     * Keycode constant: '2' key
     *
     * @since 1
     */
    KEY_2 = 2002,

    /* *
     * Keycode constant: '3' key
     *
     * @since 1
     */
    KEY_3 = 2003,

    /* *
     * Keycode constant: '4' key
     *
     * @since 1
     */
    KEY_4 = 2004,

    /* *
     * Keycode constant: '5' key
     *
     * @since 1
     */
    KEY_5 = 2005,

    /* *
     * Keycode constant: '6' key
     *
     * @since 1
     */
    KEY_6 = 2006,

    /* *
     * Keycode constant: '7' key
     *
     * @since 1
     */
    KEY_7 = 2007,

    /* *
     * Keycode constant: '8' key
     *
     * @since 1
     */
    KEY_8 = 2008,

    /* *
     * Keycode constant: '9' key
     *
     * @since 1
     */
    KEY_9 = 2009,

    /* *
     * Keycode constant: '*' key
     *
     * @since 1
     */
    KEY_STAR = 2010,

    /* *
     * Keycode constant: '#' key
     *
     * @since 1
     */
    KEY_POUND = 2011,

    /* *
     * Keycode constant: Directional Pad Up key
     * <p>The key may also be synthesized from trackball motions.
     *
     * @since 1
     */
    KEY_DPAD_UP = 2012,

    /* *
     * Keycode constant: Directional Pad Down key
     * <p>The key may also be synthesized from trackball motions.
     *
     * @since 1
     */
    KEY_DPAD_DOWN = 2013,

    /* *
     * Keycode constant: Directional Pad Left key
     * <p>The key may also be synthesized from trackball motions.
     *
     * @since 1
     */
    KEY_DPAD_LEFT = 2014,

    /* *
     * Keycode constant: Directional Pad Right key
     * <p>The key may also be synthesized from trackball motions.
     *
     * @since 1
     */
    KEY_DPAD_RIGHT = 2015,

    /* *
     * Keycode constant: Directional Pad Center key
     * <p>The key may also be synthesized from trackball motions.
     *
     * @since 1
     */
    KEY_DPAD_CENTER = 2016,

    /* *
     * Keycode constant: 'A' key
     *
     * @since 1
     */
    KEY_A = 2017,

    /* *
     * Keycode constant: 'B' key
     *
     * @since 1
     */
    KEY_B = 2018,

    /* *
     * Keycode constant: 'C' key
     *
     * @since 1
     */
    KEY_C = 2019,

    /* *
     * Keycode constant: 'D' key
     *
     * @since 1
     */
    KEY_D = 2020,

    /* *
     * Keycode constant: 'E' key
     *
     * @since 1
     */
    KEY_E = 2021,

    /* *
     * Keycode constant: 'F' key
     *
     * @since 1
     */
    KEY_F = 2022,

    /* *
     * Keycode constant: 'G' key
     *
     * @since 1
     */
    KEY_G = 2023,

    /* *
     * Keycode constant: 'H' key
     *
     * @since 1
     */
    KEY_H = 2024,

    /* *
     * Keycode constant: 'I' key
     *
     * @since 1
     */
    KEY_I = 2025,

    /* *
     * Keycode constant: 'J' key
     *
     * @since 1
     */
    KEY_J = 2026,

    /* *
     * Keycode constant: 'K' key
     *
     * @since 1
     */
    KEY_K = 2027,

    /* *
     * Keycode constant: 'L' key
     *
     * @since 1
     */
    KEY_L = 2028,

    /* *
     * Keycode constant: 'M' key
     *
     * @since 1
     */
    KEY_M = 2029,

    /* *
     * Keycode constant: 'N' key
     *
     * @since 1
     */
    KEY_N = 2030,

    /* *
     * Keycode constant: 'O' key
     *
     * @since 1
     */
    KEY_O = 2031,

    /* *
     * Keycode constant: 'P' key
     *
     * @since 1
     */
    KEY_P = 2032,

    /* *
     * Keycode constant: 'Q' key
     *
     * @since 1
     */
    KEY_Q = 2033,

    /* *
     * Keycode constant: 'R' key
     *
     * @since 1
     */
    KEY_R = 2034,

    /* *
     * Keycode constant: 'S' key
     *
     * @since 1
     */
    KEY_S = 2035,

    /* *
     * Keycode constant: 'T' key
     *
     * @since 1
     */
    KEY_T = 2036,

    /* *
     * Keycode constant: 'U' key
     *
     * @since 1
     */
    KEY_U = 2037,

    /* *
     * Keycode constant: 'V' key
     *
     * @since 1
     */
    KEY_V = 2038,

    /* *
     * Keycode constant: 'W' key
     *
     * @since 1
     */
    KEY_W = 2039,

    /* *
     * Keycode constant: 'X' key
     *
     * @since 1
     */
    KEY_X = 2040,

    /* *
     * Keycode constant: 'Y' key
     *
     * @since 1
     */
    KEY_Y = 2041,

    /* *
     * Keycode constant: 'Z' key
     *
     * @since 1
     */
    KEY_Z = 2042,

    /* *
     * Keycode constant: ',' key
     *
     * @since 1
     */
    KEY_COMMA = 2043,

    /* *
     * Keycode constant: '.' key
     *
     * @since 1
     */
    KEY_PERIOD = 2044,

    /* *
     * Keycode constant: Left Alt modifier key
     *
     * @since 1
     */
    KEY_ALT_LEFT = 2045,

    /* *
     * Keycode constant: Right Alt modifier key
     *
     * @since 1
     */
    KEY_ALT_RIGHT = 2046,

    /* *
     * Keycode constant: Left Shift modifier key
     *
     * @since 1
     */
    KEY_SHIFT_LEFT = 2047,

    /* *
     * Keycode constant: Right Shift modifier key
     *
     * @since 1
     */
    KEY_SHIFT_RIGHT = 2048,

    /* *
     * Keycode constant: Tab key
     *
     * @since 1
     */
    KEY_TAB = 2049,

    /* *
     * Keycode constant: Space key
     *
     * @since 1
     */
    KEY_SPACE = 2050,

    /* *
     * Keycode constant: Symbol modifier key
     * <p>The key is used to input alternate symbols.
     *
     * @since 1
     */
    KEY_SYM = 2051,

    /* *
     * Keycode constant: Explorer function key
     * <p>This key is used to launch a browser application.
     *
     * @since 1
     */
    KEY_EXPLORER = 2052,

    /* *
     * Keycode constant: Email function key
     * <p>This key is used to launch an email application.
     *
     * @since 1
     */
    KEY_ENVELOPE = 2053,

    /* *
     * Keycode constant: Enter key
     *
     * @since 1
     */
    KEY_ENTER = 2054,

    /* *
     * Keycode constant: Backspace key
     * <p>Unlike {@link #KEY_FORWARD_DEL}, this key is used to delete characters before the
     * insertion point.
     *
     * @since 1
     */
    KEY_DEL = 2055,

    /* *
     * Keycode constant: '`' key (backtick key)
     *
     * @since 1
     */
    KEY_GRAVE = 2056,

    /* *
     * Keycode constant: '-' key
     *
     * @since 1
     */
    KEY_MINUS = 2057,

    /* *
     * Keycode constant: '=' key
     *
     * @since 1
     */
    KEY_EQUALS = 2058,

    /* *
     * Keycode constant: '[' key
     *
     * @since 1
     */
    KEY_LEFT_BRACKET = 2059,

    /* *
     * Keycode constant: ']' key
     *
     * @since 1
     */
    KEY_RIGHT_BRACKET = 2060,

    /* *
     * Keycode constant: '\' key
     *
     * @since 1
     */
    KEY_BACKSLASH = 2061,

    /* *
     * Keycode constant: ',' key
     *
     * @since 1
     */
    KEY_SEMICOLON = 2062,

    /* *
     * Keycode constant: ''' key (apostrophe key)
     *
     * @since 1
     */
    KEY_APOSTROPHE = 2063,

    /* *
     * Keycode constant: '/' key
     *
     * @since 1
     */
    KEY_SLASH = 2064,

    /* *
     * Keycode constant: '{@literal @}' key
     *
     * @since 1
     */
    KEY_AT = 2065,

    /* *
     * Keycode constant: '+' key
     *
     * @since 1
     */
    KEY_PLUS = 2066,

    /* *
     * Keycode constant: Menu key
     *
     * @since 1
     */
    KEY_MENU = 2067,

    /* *
     * Keycode constant: Page Up key
     *
     * @since 1
     */
    KEY_PAGE_UP = 2068,

    /* *
     * Keycode constant: Page Down key
     *
     * @since 1
     */
    KEY_PAGE_DOWN = 2069,

    /* *
     * Keycode constant: Escape key
     *
     * @since 1
     */
    KEY_ESCAPE = 2070,

    /* *
     * Keycode constant: Forward Delete key
     * <p>Unlike {@link #KEY_DEL}, this key is used to delete characters ahead of the insertion
     * point.
     *
     * @since 1
     */
    KEY_FORWARD_DEL = 2071,

    /* *
     * Keycode constant: Left Control modifier key
     *
     * @since 1
     */
    KEY_CTRL_LEFT = 2072,

    /* *
     * Keycode constant: Right Control modifier key
     *
     * @since 1
     */
    KEY_CTRL_RIGHT = 2073,

    /* *
     * Keycode constant: Caps Lock key
     *
     * @since 1
     */
    KEY_CAPS_LOCK = 2074,

    /* *
     * Keycode constant: Scroll Lock key
     *
     * @since 1
     */
    KEY_SCROLL_LOCK = 2075,

    /* *
     * Keycode constant: Left Meta modifier key
     *
     * @since 1
     */
    KEY_META_LEFT = 2076,

    /* *
     * Keycode constant: Right Meta modifier key
     *
     * @since 1
     */
    KEY_META_RIGHT = 2077,

    /* *
     * Keycode constant: Function modifier key
     *
     * @since 1
     */
    KEY_FUNCTION = 2078,

    /* *
     * Keycode constant: System Request/Print Screen key
     *
     * @since 1
     */
    KEY_SYSRQ = 2079,

    /* *
     * Keycode constant: Break/Pause key
     *
     * @since 1
     */
    KEY_BREAK = 2080,

    /* *
     * Keycode constant: Home Movement key
     * <p>This key is used to scroll or move the cursor around to the start of a line or to the
     * top of a list.
     *
     * @since 1
     */
    KEY_MOVE_HOME = 2081,

    /* *
     * Keycode constant: End Movement key
     * <p>This key is used to scroll or move the cursor around to the end of a line or to the
     * bottom of a list.
     *
     * @since 1
     */
    KEY_MOVE_END = 2082,

    /* *
     * Keycode constant: Insert key
     * <p>This key is used to toggle the insert or overwrite edit mode.
     *
     * @since 1
     */
    KEY_INSERT = 2083,

    /* *
     * Keycode constant: Forward key
     * <p>This key is used to navigate forward in the history stack. It is a complement of
     * {@link #KEY_BACK}.
     *
     * @since 1
     */
    KEY_FORWARD = 2084,

    /* *
     * Keycode constant: Play media key
     *
     * @since 1
     */
    KEY_MEDIA_PLAY = 2085,

    /* *
     * Keycode constant: Pause media key
     *
     * @since 1
     */
    KEY_MEDIA_PAUSE = 2086,

    /* *
     * Keycode constant: Close media key
     * <p>This key can be used to close a CD tray, for example.
     *
     * @since 1
     */
    KEY_MEDIA_CLOSE = 2087,

    /* *
     * Keycode constant: Eject media key
     * <p>This key can be used to eject a CD tray, for example.
     *
     * @since 1
     */
    KEY_MEDIA_EJECT = 2088,

    /* *
     * Keycode constant: Record media key
     *
     * @since 1
     */
    KEY_MEDIA_RECORD = 2089,

    /* *
     * Keycode constant: F1 key
     *
     * @since 1
     */
    KEY_F1 = 2090,

    /* *
     * Keycode constant: F2 key
     *
     * @since 1
     */
    KEY_F2 = 2091,

    /* *
     * Keycode constant: F3 key
     *
     * @since 1
     */
    KEY_F3 = 2092,

    /* *
     * Keycode constant: F4 key
     *
     * @since 1
     */
    KEY_F4 = 2093,

    /* *
     * Keycode constant: F5 key
     *
     * @since 1
     */
    KEY_F5 = 2094,

    /* *
     * Keycode constant: F6 key
     *
     * @since 1
     */
    KEY_F6 = 2095,

    /* *
     * Keycode constant: F7 key
     *
     * @since 1
     */
    KEY_F7 = 2096,

    /* *
     * Keycode constant: F8 key
     *
     * @since 1
     */
    KEY_F8 = 2097,

    /* *
     * Keycode constant: F9 key
     *
     * @since 1
     */
    KEY_F9 = 2098,

    /* *
     * Keycode constant: F10 key
     *
     * @since 1
     */
    KEY_F10 = 2099,

    /* *
     * Keycode constant: F11 key
     *
     * @since 1
     */
    KEY_F11 = 2100,

    /* *
     * Keycode constant: F12 key
     *
     * @since 1
     */
    KEY_F12 = 2101,

    /* *
     * Keycode constant: Num Lock key
     * <p>This key is used to alter the behavior of other keys on the numeric keypad.
     *
     * @since 1
     */
    KEY_NUM_LOCK = 2102,

    /* *
     * Keycode constant: '0' key on the numeric keypad
     *
     * @since 1
     */
    KEY_NUMPAD_0 = 2103,

    /* *
     * Keycode constant: '1' key on the numeric keypad
     *
     * @since 1
     */
    KEY_NUMPAD_1 = 2104,

    /* *
     * Keycode constant: '2' key on the numeric keypad
     *
     * @since 1
     */
    KEY_NUMPAD_2 = 2105,

    /* *
     * Keycode constant: '3' key on the numeric keypad
     *
     * @since 1
     */
    KEY_NUMPAD_3 = 2106,

    /* *
     * Keycode constant: '4' key on the numeric keypad
     *
     * @since 1
     */
    KEY_NUMPAD_4 = 2107,

    /* *
     * Keycode constant: '5' key on the numeric keypad
     *
     * @since 1
     */
    KEY_NUMPAD_5 = 2108,

    /* *
     * Keycode constant: '6' key on the numeric keypad
     *
     * @since 1
     */
    KEY_NUMPAD_6 = 2109,

    /* *
     * Keycode constant: '7' key on the numeric keypad
     *
     * @since 1
     */
    KEY_NUMPAD_7 = 2110,

    /* *
     * Keycode constant: '8' key on the numeric keypad
     *
     * @since 1
     */
    KEY_NUMPAD_8 = 2111,

    /* *
     * Keycode constant: '9' key on the numeric keypad
     *
     * @since 1
     */
    KEY_NUMPAD_9 = 2112,

    /* *
     * Keycode constant: '/' key (for division) on the numeric keypad
     *
     * @since 1
     */
    KEY_NUMPAD_DIVIDE = 2113,

    /* *
     * Keycode constant: '*' key (for multiplication) on the numeric keypad
     *
     * @since 1
     */
    KEY_NUMPAD_MULTIPLY = 2114,

    /* *
     * Keycode constant: '-' key (for subtraction) on the numeric keypad
     *
     * @since 1
     */
    KEY_NUMPAD_SUBTRACT = 2115,

    /* *
     * Keycode constant: '+' key (for addition) on the numeric keypad
     *
     * @since 1
     */
    KEY_NUMPAD_ADD = 2116,

    /* *
     * Key code constant: '.' key (for decimals or digit grouping) on the
     * numeric keypad
     *
     * @since 1
     */
    KEY_NUMPAD_DOT = 2117,

    /* *
     * Key code constant: ',' key (for decimals or digit grouping) on the
     * numeric keypad
     *
     * @since 1
     */
    KEY_NUMPAD_COMMA = 2118,

    /* *
     * Keycode constant: Enter key on the numeric keypad
     *
     * @since 1
     */
    KEY_NUMPAD_ENTER = 2119,

    /* *
     * Keycode constant: '=' key on the numeric keypad
     *
     * @since 1
     */
    KEY_NUMPAD_EQUALS = 2120,

    /* *
     * Keycode constant: '(' key on the numeric keypad
     *
     * @since 1
     */
    KEY_NUMPAD_LEFT_PAREN = 2121,

    /* *
     * Keycode constant: ')' key on the numeric keypad
     *
     * @since 1
     */
    KEY_NUMPAD_RIGHT_PAREN = 2122,

    /* *
     * Key code:  The virtual multitask key
     *
     * @since 1
     */
    KEY_VIRTUAL_MULTITASK = 2210,

    /* *
     * Key code:  The handle button key
     *
     * @since 1
     */
    KEY_BUTTON_A = 2301,
    KEY_BUTTON_B = 2302,
    KEY_BUTTON_C = 2303,
    KEY_BUTTON_X = 2304,
    KEY_BUTTON_Y = 2305,
    KEY_BUTTON_Z = 2306,
    KEY_BUTTON_L1 = 2307,
    KEY_BUTTON_R1 = 2308,
    KEY_BUTTON_L2 = 2309,
    KEY_BUTTON_R2 = 2310,
    KEY_BUTTON_SELECT = 2311,
    KEY_BUTTON_START = 2312,
    KEY_BUTTON_MODE = 2313,
    KEY_BUTTON_THUMBL = 2314,
    KEY_BUTTON_THUMBR = 2315,

    /* *
     * Key code:  The joystick button key
     *
     * @since 1
     */
    KEY_BUTTON_TRIGGER = 2401,
    KEY_BUTTON_THUMB = 2402,
    KEY_BUTTON_THUMB2 = 2403,
    KEY_BUTTON_TOP = 2404,
    KEY_BUTTON_TOP2 = 2405,
    KEY_BUTTON_PINKIE = 2406,
    KEY_BUTTON_BASE1 = 2407,
    KEY_BUTTON_BASE2 = 2408,
    KEY_BUTTON_BASE3 = 2409,
    KEY_BUTTON_BASE4 = 2410,
    KEY_BUTTON_BASE5 = 2411,
    KEY_BUTTON_BASE6 = 2412,
    KEY_BUTTON_BASE7 = 2413,
    KEY_BUTTON_BASE8 = 2414,
    KEY_BUTTON_BASE9 = 2415,
    KEY_BUTTON_DEAD = 2416,

    KEY_SLEEP = 2600,
    KEY_ZENKAKU_HANKAKU = 2601,
    KEY_102ND = 2602,
    KEY_RO = 2603,
    KEY_KATAKANA = 2604,
    KEY_HIRAGANA = 2605,
    KEY_HENKAN = 2606,
    KEY_KATAKANA_HIRAGANA = 2607,
    KEY_MUHENKAN = 2608,
    KEY_LINEFEED = 2609,
    KEY_MACRO = 2610,
    KEY_NUMPAD_PLUSMINUS = 2611,
    KEY_SCALE = 2612,
    KEY_HANGUEL = 2613,
    KEY_HANJA = 2614,
    KEY_YEN = 2615,
    KEY_STOP = 2616,
    KEY_AGAIN = 2617,
    KEY_PROPS = 2618,
    KEY_UNDO = 2619,
    KEY_COPY = 2620,
    KEY_OPEN = 2621,
    KEY_PASTE = 2622,
    KEY_FIND = 2623,
    KEY_CUT = 2624,
    KEY_HELP = 2625,
    KEY_CALC = 2626,
    KEY_FILE = 2627,
    KEY_BOOKMARKS = 2628,
    KEY_NEXT = 2629,
    KEY_PLAYPAUSE = 2630,
    KEY_PREVIOUS = 2631,
    KEY_STOPCD = 2632,
    KEY_CONFIG = 2634,
    KEY_REFRESH = 2635,
    KEY_EXIT = 2636,
    KEY_EDIT = 2637,
    KEY_SCROLLUP = 2638,
    KEY_SCROLLDOWN = 2639,
    KEY_NEW = 2640,
    KEY_REDO = 2641,
    KEY_CLOSE = 2642,
    KEY_PLAY = 2643,
    KEY_BASSBOOST = 2644,
    KEY_PRINT = 2645,
    KEY_CHAT = 2646,
    KEY_FINANCE = 2647,
    KEY_CANCEL = 2648,
    KEY_KBDILLUM_TOGGLE = 2649,
    KEY_KBDILLUM_DOWN = 2650,
    KEY_KBDILLUM_UP = 2651,
    KEY_SEND = 2652,
    KEY_REPLY = 2653,
    KEY_FORWARDMAIL = 2654,
    KEY_SAVE = 2655,
    KEY_DOCUMENTS = 2656,
    KEY_VIDEO_NEXT = 2657,
    KEY_VIDEO_PREV = 2658,
    KEY_BRIGHTNESS_CYCLE = 2659,
    KEY_BRIGHTNESS_ZERO = 2660,
    KEY_DISPLAY_OFF = 2661,
    BTN_MISC = 2662,
    KEY_GOTO = 2663,
    KEY_INFO = 2664,
    KEY_PROGRAM = 2665,
    KEY_PVR = 2666,
    KEY_SUBTITLE = 2667,
    KEY_FULL_SCREEN = 2668,
    KEY_KEYBOARD = 2669,
    KEY_ASPECT_RATIO = 2670,
    KEY_PC = 2671,
    KEY_TV = 2672,
    KEY_TV2 = 2673,
    KEY_VCR = 2674,
    KEY_VCR2 = 2675,
    KEY_SAT = 2676,
    KEY_CD = 2677,
    KEY_TAPE = 2678,
    KEY_TUNER = 2679,
    KEY_PLAYER = 2680,
    KEY_DVD = 2681,
    KEY_AUDIO = 2682,
    KEY_VIDEO = 2683,
    KEY_MEMO = 2684,
    KEY_CALENDAR = 2685,
    KEY_RED = 2686,
    KEY_GREEN = 2687,
    KEY_YELLOW = 2688,
    KEY_BLUE = 2689,
    KEY_CHANNELUP = 2690,
    KEY_CHANNELDOWN = 2691,
    KEY_LAST = 2692,
    KEY_RESTART = 2693,
    KEY_SLOW = 2694,
    KEY_SHUFFLE = 2695,
    KEY_VIDEOPHONE = 2696,
    KEY_GAMES = 2697,
    KEY_ZOOMIN = 2698,
    KEY_ZOOMOUT = 2699,
    KEY_ZOOMRESET = 2700,
    KEY_WORDPROCESSOR = 2701,
    KEY_EDITOR = 2702,
    KEY_SPREADSHEET = 2703,
    KEY_GRAPHICSEDITOR = 2704,
    KEY_PRESENTATION = 2705,
    KEY_DATABASE = 2706,
    KEY_NEWS = 2707,
    KEY_VOICEMAIL = 2708,
    KEY_ADDRESSBOOK = 2709,
    KEY_MESSENGER = 2710,
    KEY_BRIGHTNESS_TOGGLE = 2711,
    KEY_SPELLCHECK = 2712,
    KEY_COFFEE = 2713,
    KEY_MEDIA_REPEAT = 2714,
    KEY_IMAGES = 2715,
    KEY_BUTTONCONFIG = 2716,
    KEY_TASKMANAGER = 2717,
    KEY_JOURNAL = 2718,
    KEY_CONTROLPANEL = 2719,
    KEY_APPSELECT = 2720,
    KEY_SCREENSAVER = 2721,
    KEY_ASSISTANT = 2722,
    KEY_KBD_LAYOUT_NEXT = 2723,
    KEY_BRIGHTNESS_MIN = 2724,
    KEY_BRIGHTNESS_MAX = 2725,
    KEY_KBDINPUTASSIST_PREV = 2726,
    KEY_KBDINPUTASSIST_NEXT = 2727,
    KEY_KBDINPUTASSIST_PREVGROUP = 2728,
    KEY_KBDINPUTASSIST_NEXTGROUP = 2729,
    KEY_KBDINPUTASSIST_ACCEPT = 2730,
    KEY_KBDINPUTASSIST_CANCEL = 2731,

    KEY_FRONT = 2800,
    KEY_SETUP = 2801,
    KEY_WAKEUP = 2802,
    KEY_SENDFILE = 2803,
    KEY_DELETEFILE = 2804,
    KEY_XFER = 2805,
    KEY_PROG1 = 2806,
    KEY_PROG2 = 2807,
    KEY_MSDOS = 2808,
    KEY_SCREENLOCK = 2809,
    KEY_DIRECTION_ROTATE_DISPLAY = 2810,
    KEY_CYCLEWINDOWS = 2811,
    KEY_COMPUTER = 2812,
    KEY_EJECTCLOSECD = 2813,
    KEY_ISO = 2814,
    KEY_MOVE = 2815,
    KEY_F13 = 2816,
    KEY_F14 = 2817,
    KEY_F15 = 2818,
    KEY_F16 = 2819,
    KEY_F17 = 2820,
    KEY_F18 = 2821,
    KEY_F19 = 2822,
    KEY_F20 = 2823,
    KEY_F21 = 2824,
    KEY_F22 = 2825,
    KEY_F23 = 2826,
    KEY_F24 = 2827,
    KEY_PROG3 = 2828,
    KEY_PROG4 = 2829,
    KEY_DASHBOARD = 2830,
    KEY_SUSPEND = 2831,
    KEY_HP = 2832,
    KEY_SOUND = 2833,
    KEY_QUESTION = 2834,
    KEY_CONNECT = 2836,
    KEY_SPORT = 2837,
    KEY_SHOP = 2838,
    KEY_ALTERASE = 2839,
    KEY_SWITCHVIDEOMODE = 2841,
    KEY_BATTERY = 2842,
    KEY_BLUETOOTH = 2843,
    KEY_WLAN = 2844,
    KEY_UWB = 2845,
    KEY_WWAN_WIMAX = 2846,
    KEY_RFKILL = 2847,

    KEY_CHANNEL = 3001,
    KEY_BTN_0 = 3100,
    KEY_BTN_1 = 3101,
    KEY_BTN_2 = 3102,
    KEY_BTN_3 = 3103,
    KEY_BTN_4 = 3104,
    KEY_BTN_5 = 3105,
    KEY_BTN_6 = 3106,
    KEY_BTN_7 = 3107,
    KEY_BTN_8 = 3108,
    KEY_BTN_9 = 3109,

    KEY_BRL_DOT1 = 3201,
    KEY_BRL_DOT2 = 3202,
    KEY_BRL_DOT3 = 3203,
    KEY_BRL_DOT4 = 3204,
    KEY_BRL_DOT5 = 3205,
    KEY_BRL_DOT6 = 3206,
    KEY_BRL_DOT7 = 3207,
    KEY_BRL_DOT8 = 3208,
    KEY_BRL_DOT9 = 3209,
    KEY_BRL_DOT10 = 3210,

    /* *
     * Left Knob roll-up
     * <p>In contrast to {@link #KEY_LEFT_KNOB_ROLL_DOWN}, it means rolling
     * the left knob upwards. The knob functionis scenario-specific, for example,
     * increasing the volume or air conditioner temperature.
     *
     * @since 1
     */
    KEY_LEFT_KNOB_ROLL_UP = 10001,

    /* *
     * Left Knob roll-down
     * <p>In contrast to {@link #KEY_LEFT_KNOB_ROLL_UP},
     * it means rolling the left knob downwards. The knob function is
     * scenario-specific, for example, reducing the volume or air
     * conditioner temperature.
     * @since 1
     */
    KEY_LEFT_KNOB_ROLL_DOWN = 10002,

    /* *
     * Left Knob
     * <p>Pressing the knob will activate its adjustment function.
     *
     * @since 1
     */
    KEY_LEFT_KNOB = 10003,

    /* *
     * Right Knob roll-up
     * <p>In contrast to {@link #KEY_RIGHT_KNOB_ROLL_DOWN}, it means rolling
     * the right knob upwards. The knobfunction is scenario-specific, for example,
     * increasing the volume or air conditioner temperature.
     *
     *
     * @since 1
     */
    KEY_RIGHT_KNOB_ROLL_UP = 10004,

    /* *
     * Right Knob roll-down
     * <p>In contrast to {@link #KEY_RIGHT_KNOB_ROLL_UP}, it means rolling
     * the right knob downwards. The knobfunction is scenario-specific,
     * for example, reducing the volume or air conditioner temperature.
     *
     * @since 1
     */
    KEY_RIGHT_KNOB_ROLL_DOWN = 10005,

    /* *
     * Right Knob
     * <p>Pressing the knob will activate its adjustment function.
     *
     * @since 1
     */
    KEY_RIGHT_KNOB = 10006,

    /* *
     * Audio Source Switch button
     * <p>Pressing this button will enable the audio source. Depending on the
     * actual scenario, it may also indicate that the Bluetooth call control
     * button is pressed.
     * @since 1
     */
    KEY_VOICE_SOURCE_SWITCH = 10007,

    /* *
     * Menu key
     * <p>Pressing this key will display the launcher page.
     *
     * @since 1
     */
    KEY_LAUNCHER_MENU = 10008,

    /* *
     * Keycode constant: max keycode
     * <p> If a new keycode added to {@code KeyEvent} is greater than the
     * maximum keycode, update the maximum keycode accordingly.
     *
     *
     * @since 1
     */
    NOW_MAX_KEY = KEY_LAUNCHER_MENU
};

class KeyEvent : public MMI::MultimodalEvent {
public:
    virtual ~KeyEvent();
    /* *
     * initialize the object.
     *
     * @return void
     * @since 1
     */
    void Initialize(int32_t windowId, bool isPressed, int32_t keyCode, int32_t keyDownDuration, int32_t highLevelEvent,
                    const std::string& uuid, int32_t sourceType, uint64_t occurredTime, const std::string& deviceId,
                    int32_t inputDeviceId,  bool isHighLevelEvent, uint16_t deviceUdevTags = 0,
                    int32_t deviceEventType = 0, bool isIntercepted = true);
    /**
    * initialize the object.
    *
    * @return void
    * @since 1
    */
    void Initialize(const KeyEvent& keyEvent);

    /**
    * initialize the object.
    *
    * @return void
    * @since 1
    */
    void DeviceInitialize(MultimodalEvent& deviceEvent);

    /**
    * Obtains the max keycode of the current key event.
    *
    * @return Returns the max keycode of the current key event.
    * @since 1
    */
    virtual int32_t GetMaxKeyCode() const;

    /* *
     * Obtains the press-down state of the current key.
     *
     * @return Returns {@code true} if the current key is pressed down; returns
     * {@code false} otherwise .
     * @since 1
     */
    virtual bool IsKeyDown() const;

    /* *
     * Obtains the keycode of the current key event.
     *
     * @return Returns the keycode of the event; returns {@link #KEY_UNKNOWN}
     * if the keycode cannot be obtained.
     * @see #getMaxKeyCode()
     * @since 1
     */
    virtual int32_t GetKeyCode() const;

    /* *
     * Obtains the duration during which the current key is pressed down
     * before this method is called.
     *
     * @return Returns the duration (in ms) during which the current key
     * is pressed down; returns{@code 0} if the current key has not been pressed down.
     * @since 1
     */
    virtual int32_t GetKeyDownDuration() const;
    virtual int32_t GetOriginEventType() const;

private:
    bool isPressed_ = false;
    int32_t keyCode_ = 0;
    int32_t keyDownDuration_ = 0;
    int32_t deviceEventType_ = 0;
};
} // namespace OHOS
#endif // KEY_EVENT_PRE_H