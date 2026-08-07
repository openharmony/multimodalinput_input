/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

/**
 * @addtogroup input
 * @{
 *
 * @brief Provides the C interface in the multi-modal input domain.
 *
 * @since 12
 */

/**
 * @file oh_key_code.h
 *
 * @brief Defines the key event structure and related enumeration values.
 * @kit InputKit
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @library libohinput.so
 * @since 12
 */

#ifndef OH_KEY_CODE_H
#define OH_KEY_CODE_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Enumerates the key codes.
 *
 * @since 12
 */
typedef enum {
    /**
     * Unknown key
     */
    KEYCODE_UNKNOWN = -1,
    /**
     * Function (Fn) key
     */
    KEYCODE_FN = 0,
    /**
     * Function (Home) key
     * @since 22
     */
    KEYCODE_HOME = 1,
    /**
     * Back button
     * @since 22
     */
    KEYCODE_BACK = 2,
    /**
     * Search key
     * @since 22
     */
    KEYCODE_SEARCH = 9,
    /**
     * Media: Play/Pause key<br>Difference between this key and **KEYCODE_PLAYPAUSE**:<br>**KEYCODE_PLAYPAUSE** is an
     * earlier definition, while **KEYCODE_MEDIA_PLAY_PAUSE** is designed for modern media key devices.
     * @since 22
     */
    KEYCODE_MEDIA_PLAY_PAUSE = 10,
    /**
     * Media: Stop Key
     * @since 22
     */
    KEYCODE_MEDIA_STOP = 11,
    /**
     * Media: Next key
     * @since 22
     */
    KEYCODE_MEDIA_NEXT = 12,
    /**
     * Media: Previous key
     * @since 22
     */
    KEYCODE_MEDIA_PREVIOUS = 13,
    /**
     * Media: Rewind key
     * @since 22
     */
    KEYCODE_MEDIA_REWIND = 14,
    /**
     * Media: Fast Forward key
     * @since 22
     */
    KEYCODE_MEDIA_FAST_FORWARD = 15,
    /**
     * Volume Up key
     */
    KEYCODE_VOLUME_UP = 16,
    /**
     * Volume Down key
     */
    KEYCODE_VOLUME_DOWN = 17,
    /**
     * Power key
     */
    KEYCODE_POWER = 18,
    /**
     * Camera key
     */
    KEYCODE_CAMERA = 19,
    /**
     * Speaker Mute key
     */
    KEYCODE_VOLUME_MUTE = 22,
    /**
     * Mute key
     */
    KEYCODE_MUTE = 23,
    /**
     * Brightness Up key
     */
    KEYCODE_BRIGHTNESS_UP = 40,
    /**
     * Brightness Down key
     */
    KEYCODE_BRIGHTNESS_DOWN = 41,
    /**
     * Key 0
     */
    KEYCODE_0 = 2000,
    /**
     * Key 1
     */
    KEYCODE_1 = 2001,
    /**
     * Key 2
     */
    KEYCODE_2 = 2002,
    /**
     * Key 3
     */
    KEYCODE_3 = 2003,
    /**
     * Key 4
     */
    KEYCODE_4 = 2004,
    /**
     * Key 5
     */
    KEYCODE_5 = 2005,
    /**
     * Key 6
     */
    KEYCODE_6 = 2006,
    /**
     * Key 7
     */
    KEYCODE_7 = 2007,
    /**
     * Key 8
     */
    KEYCODE_8 = 2008,
    /**
     * Key 9
     */
    KEYCODE_9 = 2009,
    /**
     * Key *
     */
    KEYCODE_STAR = 2010,
    /**
     * Key #
     */
    KEYCODE_POUND = 2011,
     /**
     * Up key on D-pad
     */
    KEYCODE_DPAD_UP = 2012,
    /**
     * Down key on D-pad
     */
    KEYCODE_DPAD_DOWN = 2013,
    /**
     * Left key on D-pad
     */
    KEYCODE_DPAD_LEFT = 2014,
    /**
     * Right key on D-pad
     */
    KEYCODE_DPAD_RIGHT = 2015,
    /**
     * Center key on D-pad
     */
    KEYCODE_DPAD_CENTER = 2016,
    /**
     * Key A
     */
    KEYCODE_A = 2017,
    /**
     * Key B
     */
    KEYCODE_B = 2018,
    /**
     * Key C
     */
    KEYCODE_C = 2019,
    /**
     * Key D
     */
    KEYCODE_D = 2020,
    /**
     * Key E
     */
    KEYCODE_E = 2021,
    /**
     * Key F
     */
    KEYCODE_F = 2022,
    /**
     * Key G
     */
    KEYCODE_G = 2023,
    /**
     * Key H
     */
    KEYCODE_H = 2024,
    /**
     * Key I
     */
    KEYCODE_I = 2025,
    /**
     * Key J
     */
    KEYCODE_J = 2026,
    /**
     * Key K
     */
    KEYCODE_K = 2027,
    /**
     * Key L
     */
    KEYCODE_L = 2028,
    /**
     * Key M
     */
    KEYCODE_M = 2029,
    /**
     * Key N
     */
    KEYCODE_N = 2030,
    /**
     * Key O
     */
    KEYCODE_O = 2031,
    /**
     * Key P
     */
    KEYCODE_P = 2032,
    /**
     * Key Q
     */
    KEYCODE_Q = 2033,
    /**
     * Key R
     */
    KEYCODE_R = 2034,
    /**
     * Key S
     */
    KEYCODE_S = 2035,
    /**
     * Key T
     */
    KEYCODE_T = 2036,
    /**
     * Key U
     */
    KEYCODE_U = 2037,
    /**
     * Key V
     */
    KEYCODE_V = 2038,
    /**
     * Key W
     */
    KEYCODE_W = 2039,
    /**
     * Key X
     */
    KEYCODE_X = 2040,
    /**
     * Key Y
     */
    KEYCODE_Y = 2041,
    /**
     * Key Z
     */
    KEYCODE_Z = 2042,
    /**
     * Key ,
     */
    KEYCODE_COMMA = 2043,
    /**
     * Key .
     */
    KEYCODE_PERIOD = 2044,
    /**
     * Left Alt key
     */
    KEYCODE_ALT_LEFT = 2045,
    /**
     * Right Alt key
     */
    KEYCODE_ALT_RIGHT = 2046,
    /**
     * Left Shift key
     */
    KEYCODE_SHIFT_LEFT = 2047,
    /**
     * Right Shift key
     */
    KEYCODE_SHIFT_RIGHT = 2048,
    /**
     * Tab key
     */
    KEYCODE_TAB = 2049,
    /**
     * Space key
     */
    KEYCODE_SPACE = 2050,
    /**
     * Symbol key
     */
    KEYCODE_SYM = 2051,
    /**
     * Browser function key, used to launch the browser application.
     */
    KEYCODE_EXPLORER = 2052,
    /**
     * Email function key, used to launch the email application.
     */
    KEYCODE_ENVELOPE = 2053,
    /**
     * Enter key
     */
    KEYCODE_ENTER = 2054,
    /**
     * Delete key
     */
    KEYCODE_DEL = 2055,
    /**
     * Key *
     */
    KEYCODE_GRAVE = 2056,
    /**
     * Key -
     */
    KEYCODE_MINUS = 2057,
    /**
     * Key =
     */
    KEYCODE_EQUALS = 2058,
    /**
     * Key [
     */
    KEYCODE_LEFT_BRACKET = 2059,
    /**
     * Key ]
     */
    KEYCODE_RIGHT_BRACKET = 2060,
    /**
     * Key \|
     */
    KEYCODE_BACKSLASH = 2061,
    /**
     * Key ;
     */
    KEYCODE_SEMICOLON = 2062,
    /**
     * Key '
     */
    KEYCODE_APOSTROPHE = 2063,
    /**
     * Key /
     */
    KEYCODE_SLASH = 2064,
    /**
     * Key @
     */
    KEYCODE_AT = 2065,
    /**
     * Key +
     */
    KEYCODE_PLUS = 2066,
    /**
     * Menu key
     */
    KEYCODE_MENU = 2067,
    /**
     * Page Up key
     */
    KEYCODE_PAGE_UP = 2068,
    /**
     * Page Down key
     */
    KEYCODE_PAGE_DOWN = 2069,
    /**
     * Esc key
     */
    KEYCODE_ESCAPE = 2070,
    /**
     * Forward Delete key
     */
    KEYCODE_FORWARD_DEL = 2071,
    /**
     * Left Ctrl key
     */
    KEYCODE_CTRL_LEFT = 2072,
    /**
     * Right Ctrl key
     */
    KEYCODE_CTRL_RIGHT = 2073,
    /**
     * Caps Lock key
     */
    KEYCODE_CAPS_LOCK = 2074,
    /**
     * Scroll Lock key
     */
    KEYCODE_SCROLL_LOCK = 2075,
    /**
     * Left Meta key
     */
    KEYCODE_META_LEFT = 2076,
    /**
     * Right Meta key
     */
    KEYCODE_META_RIGHT = 2077,
    /**
     * Function key
     */
    KEYCODE_FUNCTION = 2078,
    /**
     * System Request/Print Screen key
     */
    KEYCODE_SYSRQ = 2079,
    /**
     * Break/Pause key
     */
    KEYCODE_BREAK = 2080,
    /**
     * Move to Home key
     */
    KEYCODE_MOVE_HOME = 2081,
    /**
     * Move to End key
     */
    KEYCODE_MOVE_END = 2082,
    /**
     * Insert key
     */
    KEYCODE_INSERT = 2083,
    /**
     * Forward key
     */
    KEYCODE_FORWARD = 2084,
    /**
     * Media: Play key
     */
    KEYCODE_MEDIA_PLAY = 2085,
    /**
     * Media: Pause key
     */
    KEYCODE_MEDIA_PAUSE = 2086,
    /**
     * Media: Close key
     */
    KEYCODE_MEDIA_CLOSE = 2087,
    /**
     * Media: Reject key
     */
    KEYCODE_MEDIA_EJECT = 2088,
    /**
     * Media: Record key
     */
    KEYCODE_MEDIA_RECORD = 2089,
    /**
     * F1 key
     */
    KEYCODE_F1 = 2090,
    /**
     * F2 key
     */
    KEYCODE_F2 = 2091,
    /**
     * F3 key
     */
    KEYCODE_F3 = 2092,
    /**
     * F4 key
     */
    KEYCODE_F4 = 2093,
    /**
     * F5 key
     */
    KEYCODE_F5 = 2094,
    /**
     * F6 key
     */
    KEYCODE_F6 = 2095,
    /**
     * F7 key
     */
    KEYCODE_F7 = 2096,
    /**
     * F8 key
     */
    KEYCODE_F8 = 2097,
    /**
     * F9 key
     */
    KEYCODE_F9 = 2098,
    /**
     * F10 key
     */
    KEYCODE_F10 = 2099,
    /**
     * F11 key
     */
    KEYCODE_F11 = 2100,
    /**
     * F12 key
     */
    KEYCODE_F12 = 2101,
    /**
     * Number Lock key
     */
    KEYCODE_NUM_LOCK = 2102,
    /**
     * Key 0 on numeric keypad
     */
    KEYCODE_NUMPAD_0 = 2103,
    /**
     * Key 1 on numeric keypad
     */
    KEYCODE_NUMPAD_1 = 2104,
    /**
     * Key 2 on numeric keypad
     */
    KEYCODE_NUMPAD_2 = 2105,
    /**
     * Key 3 on numeric keypad
     */
    KEYCODE_NUMPAD_3 = 2106,
    /**
     * Key 4 on numeric keypad
     */
    KEYCODE_NUMPAD_4 = 2107,
    /**
     * Key 5 on numeric keypad
     */
    KEYCODE_NUMPAD_5 = 2108,
    /**
     * Key 6 on numeric keypad
     */
    KEYCODE_NUMPAD_6 = 2109,
    /**
     * Key 7 on numeric keypad
     */
    KEYCODE_NUMPAD_7 = 2110,
    /**
     * Key 8 on numeric keypad
     */
    KEYCODE_NUMPAD_8 = 2111,
    /**
     * Key 9 on numeric keypad
     */
    KEYCODE_NUMPAD_9 = 2112,
    /**
     * Key / on numeric keypad
     */
    KEYCODE_NUMPAD_DIVIDE = 2113,
    /**
     * Key * on numeric keypad
     */
    KEYCODE_NUMPAD_MULTIPLY = 2114,
    /**
     * Key - on numeric keypad
     */
    KEYCODE_NUMPAD_SUBTRACT = 2115,
    /**
     * Key + on numeric keypad
     */
    KEYCODE_NUMPAD_ADD = 2116,
    /**
     * Key . on numeric keypad
     */
    KEYCODE_NUMPAD_DOT = 2117,
    /**
     * Key , on numeric keypad
     */
    KEYCODE_NUMPAD_COMMA = 2118,
    /**
     * Enter key on numeric keypad
     */
    KEYCODE_NUMPAD_ENTER = 2119,
    /**
     * Key = on numeric keypad
     */
    KEYCODE_NUMPAD_EQUALS = 2120,
    /**
     * Key ( on numeric keypad
     */
    KEYCODE_NUMPAD_LEFT_PAREN = 2121,
    /**
     * Key ) on numeric keypad
     */
    KEYCODE_NUMPAD_RIGHT_PAREN = 2122,
    /**
     * Multi-task key
     * @since 22
     */
    KEYCODE_VIRTUAL_MULTITASK = 2210,
    /**
     * Joystick key A
     * @since 22
     */
    KEYCODE_BUTTON_A = 2301,
    /**
     * Joystick key B
     * @since 22
     */
    KEYCODE_BUTTON_B = 2302,
    /**
     * Joystick key X
     * @since 22
     */
    KEYCODE_BUTTON_X = 2304,
    /**
     * Joystick key Y
     * @since 22
     */
    KEYCODE_BUTTON_Y = 2305,
    /**
     * Joystick key L1
     * @since 22
     */
    KEYCODE_BUTTON_L1 = 2307,
    /**
     * Joystick key R1
     * @since 22
     */
    KEYCODE_BUTTON_R1 = 2308,
    /**
     * Joystick key L2
     * @since 22
     */
    KEYCODE_BUTTON_L2 = 2309,
    /**
     * Joystick key R2
     * @since 22
     */
    KEYCODE_BUTTON_R2 = 2310,
    /**
     * Joystick key Select
     * @since 22
     */
    KEYCODE_BUTTON_SELECT = 2311,
    /**
     * Joystick key Start
     * @since 22
     */
    KEYCODE_BUTTON_START = 2312,
    /**
     * Joystick key Mode
     * @since 22
     */
    KEYCODE_BUTTON_MODE = 2313,
    /**
     * Joystick key THUMBL
     * @since 22
     */
    KEYCODE_BUTTON_THUMBL = 2314,
    /**
     * Joystick key THUMBR
     * @since 22
     */
    KEYCODE_BUTTON_THUMBR = 2315,
    /**
     *Sleep key
     * @since 22
     */
    KEYCODE_SLEEP = 2600,
    /**
     * Zenkaku/Hankaku key
     * @since 22
     */
    KEYCODE_ZENKAKU_HANKAKU = 2601,
    /**
     *International Keyboard Extension key
     * @since 22
     */
    KEYCODE_102ND = 2602,
    /**
     * Ro key
     * @since 22
     */
    KEYCODE_RO = 2603,
    /**
     * Katakana key
     * @since 22
     */
    KEYCODE_KATAKANA = 2604,
    /**
     * Hiragana key
     * @since 22
     */
    KEYCODE_HIRAGANA = 2605,
    /**
     * Henkan key
     * @since 22
     */
    KEYCODE_HENKAN = 2606,
    /**
     * Katakana/Hiragana key
     * @since 22
     */
    KEYCODE_KATAKANA_HIRAGANA = 2607,
    /**
     * Muhenkan key
     * @since 22
     */
    KEYCODE_MUHENKAN = 2608,
    /**
     * Linefeed key
     * @since 22
     */
    KEYCODE_LINEFEED = 2609,
    /**
     * Macro key
     * @since 22
     */
    KEYCODE_MACRO = 2610,
    /**
     * Plus/Minus key on the numeric keypad
     * @since 22
     */
    KEYCODE_NUMPAD_PLUSMINUS = 2611,
    /**
     * Scale key
     * @since 22
     */
    KEYCODE_SCALE = 2612,
    /**
     * Hanguel key
     * @since 22
     */
    KEYCODE_HANGUEL = 2613,
    /**
     * Hanja key
     * @since 22
     */
    KEYCODE_HANJA = 2614,
    /**
     * Yen key
     * @since 22
     */
    KEYCODE_YEN = 2615,
    /**
     * Stop key
     * @since 22
     */
    KEYCODE_STOP = 2616,
    /**
     * Again key
     * @since 22
     */
    KEYCODE_AGAIN = 2617,
    /**
     * Props key
     * @since 22
     */
    KEYCODE_PROPS = 2618,
    /**
     * Undo key
     * @since 22
     */
    KEYCODE_UNDO = 2619,
    /**
     * Copy key
     * @since 22
     */
    KEYCODE_COPY = 2620,
    /**
     * Open key
     * @since 22
     */
    KEYCODE_OPEN = 2621,
    /**
     * Paste key
     * @since 22
     */
    KEYCODE_PASTE = 2622,
    /**
     * Find key
     * @since 22
     */
    KEYCODE_FIND = 2623,
    /**
     * Cut key
     * @since 22
     */
    KEYCODE_CUT = 2624,
    /**
     * Help key
     * @since 22
     */
    KEYCODE_HELP = 2625,
    /**
     * Calculator special function key, used to launch the calculator application.
     * @since 22
     */
    KEYCODE_CALC = 2626,
    /**
     * File key
     * @since 22
     */
    KEYCODE_FILE = 2627,
    /**
     * Bookmarks key
     * @since 22
     */
    KEYCODE_BOOKMARKS = 2628,
    /**
     * Page Down key
     * @since 22
     */
    KEYCODE_NEXT = 2629,
    /**
     * Media: Play/Pause key<br>Difference between this key and **KEYCODE_MEDIA_PLAY_PAUSE**:<br>**KEYCODE_PLAYPAUSE**
     * is an earlier definition, while **KEYCODE_MEDIA_PLAY_PAUSE** is designed for modern media key devices.
     * @since 22
     */
    KEYCODE_PLAYPAUSE = 2630,
    /**
     * Page Up key
     * @since 22
     */
    KEYCODE_PREVIOUS = 2631,
    /**
     * Stop CD key
     * @since 22
     */
    KEYCODE_STOPCD = 2632,
    /**
     * Configuration key
     * @since 22
     */
    KEYCODE_CONFIG = 2634,
    /**
     * Refresh key
     * @since 22
     */
    KEYCODE_REFRESH = 2635,
    /**
     * Exit key
     * @since 22
     */
    KEYCODE_EXIT = 2636,
    /**
     * Edit key
     * @since 22
     */
    KEYCODE_EDIT = 2637,
    /**
     * Scroll Up key
     * @since 22
     */
    KEYCODE_SCROLLUP = 2638,
    /**
     * Scroll Down key
     * @since 22
     */
    KEYCODE_SCROLLDOWN = 2639,
    /**
     * New key
     * @since 22
     */
    KEYCODE_NEW = 2640,
    /**
     * Redo key
     * @since 22
     */
    KEYCODE_REDO = 2641,
    /**
     * Close key
     * @since 22
     */
    KEYCODE_CLOSE = 2642,
    /**
     * Play key
     * @since 22
     */
    KEYCODE_PLAY = 2643,
    /**
     *Bass Boost key
     * @since 22
     */
    KEYCODE_BASSBOOST = 2644,
    /**
     * Print key
     * @since 22
     */
    KEYCODE_PRINT = 2645,
    /**
     * Chat key
     * @since 22
     */
    KEYCODE_CHAT = 2646,
    /**
     * Finance key
     * @since 22
     */
    KEYCODE_FINANCE = 2647,
    /**
     * Cancel key
     * @since 22
     */
    KEYCODE_CANCEL = 2648,
    /**
     * Keyboard Illumination Toggle key
     * @since 22
     */
    KEYCODE_KBDILLUM_TOGGLE = 2649,
    /**
     * Keyboard Illumination Down key
     * @since 22
     */
    KEYCODE_KBDILLUM_DOWN = 2650,
    /**
     * Keyboard Illumination Up key
     * @since 22
     */
    KEYCODE_KBDILLUM_UP = 2651,
    /**
     * Send key
     * @since 22
     */
    KEYCODE_SEND = 2652,
    /**
     * Reply key
     * @since 22
     */
    KEYCODE_REPLY = 2653,
    /**
     * Forward Mail key
     * @since 22
     */
    KEYCODE_FORWARDMAIL = 2654,
    /**
     * Save key
     * @since 22
     */
    KEYCODE_SAVE = 2655,
    /**
     * Documents key
     * @since 22
     */
    KEYCODE_DOCUMENTS = 2656,
    /**
     * Next Video key
     * @since 22
     */
    KEYCODE_VIDEO_NEXT = 2657,
    /**
     * Previous Video key
     * @since 22
     */
    KEYCODE_VIDEO_PREV = 2658,
    /**
     * Brightness Cycle key
     * @since 22
     */
    KEYCODE_BRIGHTNESS_CYCLE = 2659,
    /**
     * Brightness Zero key
     * @since 22
     */
    KEYCODE_BRIGHTNESS_ZERO = 2660,
    /**
     * Display Off Key
     * @since 22
     */
    KEYCODE_DISPLAY_OFF = 2661,
    /**
     * Misc Button key
     * @since 22
     */
    KEYCODE_BTN_MISC = 2662,
    /**
     * Goto key
     * @since 22
     */
    KEYCODE_GOTO = 2663,
    /**
     * Info key
     * @since 22
     */
    KEYCODE_INFO = 2664,
    /**
     * Program key
     * @since 22
     */
    KEYCODE_PROGRAM = 2665,
    /**
     * PVR key
     * @since 22
     */
    KEYCODE_PVR = 2666,
    /**
     * Subtitle key
     * @since 22
     */
    KEYCODE_SUBTITLE = 2667,
    /**
     * Full Screen key
     * @since 22
     */
    KEYCODE_FULL_SCREEN = 2668,
    /**
     * Keyboard
     * @since 22
     */
    KEYCODE_KEYBOARD = 2669,
    /**
     * Aspect Ratio key
     * @since 22
     */
    KEYCODE_ASPECT_RATIO = 2670,
    /**
     * Port Control key
     * @since 22
     */
    KEYCODE_PC = 2671,
    /**
     * TV key
     * @since 22
     */
    KEYCODE_TV = 2672,
    /**
     * TV key 2
     * @since 22
     */
    KEYCODE_TV2 = 2673,
    /**
     * VCR key
     * @since 22
     */
    KEYCODE_VCR = 2674,
    /**
     * VCR key 2
     * @since 22
     */
    KEYCODE_VCR2 = 2675,
    /**
     * SAT key
     * @since 22
     */
    KEYCODE_SAT = 2676,
    /**
     * CD key
     * @since 22
     */
    KEYCODE_CD = 2677,
    /**
     * Tape key
     * @since 22
     */
    KEYCODE_TAPE = 2678,
    /**
     * Tuner key
     * @since 22
     */
    KEYCODE_TUNER = 2679,
    /**
     * Player key
     * @since 22
     */
    KEYCODE_PLAYER = 2680,
    /**
     * DVD key
     * @since 22
     */
    KEYCODE_DVD = 2681,
    /**
     * Audio key
     * @since 22
     */
    KEYCODE_AUDIO = 2682,
    /**
     * Video key
     * @since 22
     */
    KEYCODE_VIDEO = 2683,
    /**
     * Memo key
     * @since 22
     */
    KEYCODE_MEMO = 2684,
    /**
     * Calendar key
     * @since 22
     */
    KEYCODE_CALENDAR = 2685,
    /**
     * Red indicator
     * @since 22
     */
    KEYCODE_RED = 2686,
    /**
     * Green indicator
     * @since 22
     */
    KEYCODE_GREEN = 2687,
    /**
     * Yellow indicator
     * @since 22
     */
    KEYCODE_YELLOW = 2688,
    /**
     * Blue indicator
     * @since 22
     */
    KEYCODE_BLUE = 2689,
    /**
     * Channel Up key
     * @since 22
     */
    KEYCODE_CHANNELUP = 2690,
    /**
     * Channel Down key
     * @since 22
     */
    KEYCODE_CHANNELDOWN = 2691,
    /**
     * Last key
     * @since 22
     */
    KEYCODE_LAST = 2692,
    /**
     * Restart key
     * @since 22
     */
    KEYCODE_RESTART = 2693,
    /**
     * Slow key
     * @since 22
     */
    KEYCODE_SLOW = 2694,
    /**
     * Shuffle key
     * @since 22
     */
    KEYCODE_SHUFFLE = 2695,
    /**
     * Videophone key
     * @since 22
     */
    KEYCODE_VIDEOPHONE = 2696,
    /**
     * Games key
     * @since 22
     */
    KEYCODE_GAMES = 2697,
    /**
     * Zoom In key
     * @since 22
     */
    KEYCODE_ZOOMIN = 2698,
    /**
     * Zoom Out key
     * @since 22
     */
    KEYCODE_ZOOMOUT = 2699,
    /**
     * Zoom Reset key
     * @since 22
     */
    KEYCODE_ZOOMRESET = 2700,
    /**
     * Word Processor key
     * @since 22
     */
    KEYCODE_WORDPROCESSOR = 2701,
    /**
     * Editor key
     * @since 22
     */
    KEYCODE_EDITOR = 2702,
    /**
     * Spreadsheet key
     * @since 22
     */
    KEYCODE_SPREADSHEET = 2703,
    /**
     * Graphics Editor key
     * @since 22
     */
    KEYCODE_GRAPHICSEDITOR = 2704,
    /**
     * Presentation key
     * @since 22
     */
    KEYCODE_PRESENTATION = 2705,
    /**
     * Database key
     * @since 22
     */
    KEYCODE_DATABASE = 2706,
    /**
     * News key
     * @since 22
     */
    KEYCODE_NEWS = 2707,
    /**
     * Voice mailbox
     * @since 22
     */
    KEYCODE_VOICEMAIL = 2708,
    /**
     * Address book key
     * @since 22
     */
    KEYCODE_ADDRESSBOOK = 2709,
    /**
     * Messenger key
     * @since 22
     */
    KEYCODE_MESSENGER = 2710,
    /**
     * Brightness Toggle key
     * @since 22
     */
    KEYCODE_BRIGHTNESS_TOGGLE = 2711,
    /**
     * Spell Check key
     * @since 22
     */
    KEYCODE_SPELLCHECK = 2712,
    /**
     * Coffee key, which is used to launch screen lock or screen saver
     * @since 22
     */
    KEYCODE_COFFEE = 2713,
    /**
     * Media Repeat key
     * @since 22
     */
    KEYCODE_MEDIA_REPEAT = 2714,
    /**
     * Images key
     * @since 22
     */
    KEYCODE_IMAGES = 2715,
    /**
     * Button Configuration key
     * @since 22
     */
    KEYCODE_BUTTONCONFIG = 2716,
    /**
     * Task Manager
     * @since 22
     */
    KEYCODE_TASKMANAGER = 2717,
    /**
     * Log key
     * @since 22
     */
    KEYCODE_JOURNAL = 2718,
    /**
     * Control Panel key
     * @since 22
     */
    KEYCODE_CONTROLPANEL = 2719,
    /**
     * App Select key
     * @since 22
     */
    KEYCODE_APPSELECT = 2720,
    /**
     * Screen Saver key
     * @since 22
     */
    KEYCODE_SCREENSAVER = 2721,
    /**
     * Assistant key
     * @since 22
     */
    KEYCODE_ASSISTANT = 2722,
    /**
     * Next Keyboard Layout key
     * @since 22
     */
    KEYCODE_KBD_LAYOUT_NEXT = 2723,
    /**
     * Min Brightness key
     * @since 22
     */
    KEYCODE_BRIGHTNESS_MIN = 2724,
    /**
     * Max Brightness key
     * @since 22
     */
    KEYCODE_BRIGHTNESS_MAX = 2725,
    /**
     * Keyboard Input Assist_Previous, used to view input method input history.
     * @since 22
     */
    KEYCODE_KBDINPUTASSIST_PREV = 2726,
    /**
     * Keyboard Input Assist_Next, used to view input method input extensions.
     * @since 22
     */
    KEYCODE_KBDINPUTASSIST_NEXT = 2727,
    /**
     * Keyboard Input Assist_Previous, used to switch to the previous input method in the input group.
     * @since 22
     */
    KEYCODE_KBDINPUTASSIST_PREVGROUP = 2728,
    /**
     * Keyboard Input Assist_Next, used to switch to the next input method in the input group.
     * @since 22
     */
    KEYCODE_KBDINPUTASSIST_NEXTGROUP = 2729,
    /**
     * Keyboard Input-assisted Accept key
     * @since 22
     */
    KEYCODE_KBDINPUTASSIST_ACCEPT = 2730,
    /**
     * Keyboard Input-assisted Cancel key
     * @since 22
     */
    KEYCODE_KBDINPUTASSIST_CANCEL = 2731,
    /**
     * Mouse AI Assistant key
     * @since 26.0.0
     */
    KEYCODE_MOUSE_ASSISTANT = 2732,
    /**
     * Mouse Smart Selection key
     * @since 26.0.0
     */
    KEYCODE_MOUSE_INTELLIGENCE_SELECTION = 2733,
    /**
     * Phone touchscreen single-click event, used in Always-On Display state.
     * @since 26.0.0
     */
    KEYCODE_AOD_SINGLE_CLICK = 2740,
    /**
     * Front key, which is used to launch the windshield defogger
     * @since 22
     */
    KEYCODE_FRONT = 2800,
    /**
     * Setup key
     * @since 22
     */
    KEYCODE_SETUP = 2801,
    /**
     * Wakeup key
     * @since 22
     */
    KEYCODE_WAKEUP = 2802,
    /**
     * Send File key
     * @since 22
     */
    KEYCODE_SENDFILE = 2803,
    /**
     * Delete File key
     * @since 22
     */
    KEYCODE_DELETEFILE = 2804,
    /**
     * XFER key, which is used to start file transfer
     * @since 22
     */
    KEYCODE_XFER = 2805,
    /**
     * Program key 1
     * @since 22
     */
    KEYCODE_PROG1 = 2806,
    /**
     * Program key 2
     * @since 22
     */
    KEYCODE_PROG2 = 2807,
    /**
     * DOS key
     * @since 22
     */
    KEYCODE_MSDOS = 2808,
    /**
     * Screen Lock key
     * @since 22
     */
    KEYCODE_SCREENLOCK = 2809,
    /**
     * Directional Rotation Display key
     * @since 22
     */
    KEYCODE_DIRECTION_ROTATE_DISPLAY = 2810,
    /**
     * Window Cycle key
     * @since 22
     */
    KEYCODE_CYCLEWINDOWS = 2811,
    /**
     * Computer key
     * @since 22
     */
    KEYCODE_COMPUTER = 2812,
    /**
     * Eject CD key
     * @since 22
     */
    KEYCODE_EJECTCLOSECD = 2813,
    /**
     * ISO key
     * @since 22
     */
    KEYCODE_ISO = 2814,
    /**
     * Move key
     * @since 22
     */
    KEYCODE_MOVE = 2815,
    /**
     * F13 key
     * @since 22
     */
    KEYCODE_F13 = 2816,
    /**
     * F14 key
     * @since 22
     */
    KEYCODE_F14 = 2817,
    /**
     * F15 key
     * @since 22
     */
    KEYCODE_F15 = 2818,
    /**
     * F16 key
     * @since 22
     */
    KEYCODE_F16 = 2819,
    /**
     * F17 key
     * @since 22
     */
    KEYCODE_F17 = 2820,
    /**
     * F18 key
     * @since 22
     */
    KEYCODE_F18 = 2821,
    /**
     * F19 key
     * @since 22
     */
    KEYCODE_F19 = 2822,
    /**
     * F20 key
     * @since 22
     */
    KEYCODE_F20 = 2823,
    /**
     * F21 key
     * @since 22
     */
    KEYCODE_F21 = 2824,
    /**
     * F22 key
     * @since 22
     */
    KEYCODE_F22 = 2825,
    /**
     * F23 key
     * @since 22
     */
    KEYCODE_F23 = 2826,
    /**
     * F24 key
     * @since 22
     */
    KEYCODE_F24 = 2827,
    /**
     * Program key 3
     * @since 22
     */
    KEYCODE_PROG3 = 2828,
    /**
     * Program key 4
     * @since 22
     */
    KEYCODE_PROG4 = 2829,
    /**
     * Dashboard
     * @since 22
     */
    KEYCODE_DASHBOARD = 2830,
    /**
     * Suspend key
     * @since 22
     */
    KEYCODE_SUSPEND = 2831,
    /**
     * HP key
     * @since 22
     */
    KEYCODE_HP = 2832,
    /**
     * Sound key
     * @since 22
     */
    KEYCODE_SOUND = 2833,
    /**
     * Question key
     * @since 22
     */
    KEYCODE_QUESTION = 2834,
    /**
     * Connect key
     * @since 22
     */
    KEYCODE_CONNECT = 2836,
    /**
     * Sport key
     * @since 22
     */
    KEYCODE_SPORT = 2837,
    /**
     * Shop key
     * @since 22
     */
    KEYCODE_SHOP = 2838,
    /**
     * Alternate key
     * @since 22
     */
    KEYCODE_ALTERASE = 2839,
    /**
     * Cycle output between available videos (monitor/LCD/TV output/more)
     * @since 22
     */
    KEYCODE_SWITCHVIDEOMODE = 2841,
    /**
     * Battery key
     * @since 22
     */
    KEYCODE_BATTERY = 2842,
    /**
     * Bluetooth key
     * @since 22
     */
    KEYCODE_BLUETOOTH = 2843,
    /**
     * WLAN key
     * @since 22
     */
    KEYCODE_WLAN = 2844,
    /**
     * Ultra-wideband key
     * @since 22
     */
    KEYCODE_UWB = 2845,
    /**
     * Mobile Network Control key
     * @since 22
     */
    KEYCODE_WWAN_WIMAX = 2846,
    /**
     * RF Kill key
     * @since 22
     */
    KEYCODE_RFKILL = 2847,
    /**
     * Channel key
     * @since 22
     */
    KEYCODE_CHANNEL = 3001,
    /**
     *Button 0
     * @since 22
     */
    KEYCODE_BTN_0 = 3100,
    /**
     * Button 1
     * @since 22
     */
    KEYCODE_BTN_1 = 3101,
    /**
     * Button 2
     * @since 22
     */
    KEYCODE_BTN_2 = 3102,
    /**
     * Button 3
     * @since 22
     */
    KEYCODE_BTN_3 = 3103,
    /**
     * Button 4
     * @since 22
     */
    KEYCODE_BTN_4 = 3104,
    /**
     * Button 5
     * @since 22
     */
    KEYCODE_BTN_5 = 3105,
    /**
     * Button 6
     * @since 22
     */
    KEYCODE_BTN_6 = 3106,
    /**
     * Button 7
     * @since 22
     */
    KEYCODE_BTN_7 = 3107,
    /**
     * Button 8
     * @since 22
     */
    KEYCODE_BTN_8 = 3108,
    /**
     * Button 9
     * @since 22
     */
    KEYCODE_BTN_9 = 3109,
    /**
     * Single tapping the smart watch's X-TAP sensor
     * @since 22
     */
    KEYCODE_DAGGER_CLICK = 3211,
    /**
     * Double tapping the smart watch's X-TAP sensor
     * @since 22
     */
    KEYCODE_DAGGER_DOUBLE_CLICK = 3212,
    /**
     * Long-pressing the smart watch's X-TAP sensor
     * @since 22
     */
    KEYCODE_DAGGER_LONG_PRESS = 3213,
    /**
     * Left button of the smart watch
     * @since 22
     */
    KEYCODE_DIV = 3220,
    /**
     * Custom Shortcut Keys
     * @since 26.0.0
     */
    KEYCODE_XKEY = 3232,
    /**
     * Smart control Key slide-up
     * @since 26.0.0
     */
    KEYCODE_FINGERPRINT_SLIDE_UP = 3233,
    /**
     * Smart control Key slide-down
     * @since 26.0.0
     */
    KEYCODE_FINGERPRINT_SLIDE_DOWN = 3234,
    /**
     * Wrist Turn key
     * @since 26.0.0
     */
    KEYCODE_WRIST_TURN = 16777216,
    /**
     * Back panel double tap key
     * @since 26.0.0
     */
    KEYCODE_BACK_PANEL_DOUBLE_TAP = 16842752
} Input_KeyCode;

#ifdef __cplusplus
}
#endif
/** @} */

#endif /* OH_KEY_CODE_H */
