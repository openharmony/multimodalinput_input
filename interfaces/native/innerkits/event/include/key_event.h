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
#ifndef KEY_EVENT_H
#define KEY_EVENT_H
#include <memory>
#include <vector>
#include "parcel.h"
#include "input_event.h"

namespace OHOS {
namespace MMI {
class KeyEvent : public InputEvent {
public:
    // KEYCODE
    static constexpr int32_t KEYCODE_FN = 0;
    /* *
     * Keycode constant: unknown keycode
     * <p>The keycode is unknown.
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_UNKNOWN = -1;

    /* *
     * Keycode constant: Home key
     * <p>This key is processed by the framework and will never be sent to the application.
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_HOME = 1;

    /* *
     * Keycode constant: Back key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_BACK = 2;

    /* *
     * Keycode constant: Call key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_CALL = 3;

    /* *
     * Keycode constant: End Call key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_ENDCALL = 4;

    /* *
     * Keycode constant: Clear key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_CLEAR = 5;

    /* *
     * Keycode constant: Headset Hook key
     * <p>The key is used to end a call and stop media.
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_HEADSETHOOK = 6;

    /* *
     * Keycode constant: Camera Focus key
     * <p>This key is used to enable focus for the camera.
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_FOCUS = 7;

    /* *
     * Keycode constant: Notification key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_NOTIFICATION = 8;

    /* *
     * Keycode constant: Search key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_SEARCH = 9;

    /* *
     * Keycode constant: Play/Pause media key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_MEDIA_PLAY_PAUSE = 10;

    /* *
     * Keycode constant: Stop media key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_MEDIA_STOP = 11;

    /* *
     * Keycode constant: Play Next media key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_MEDIA_NEXT = 12;

    /* *
     * Keycode constant: Play Previous media key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_MEDIA_PREVIOUS = 13;

    /* *
     * Keycode constant: Rewind media key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_MEDIA_REWIND = 14;

    /* *
     * Keycode constant: Fast Forward media key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_MEDIA_FAST_FORWARD = 15;

    /* *
     * Turns up the volume.
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_VOLUME_UP = 16;

    /* *
     * Turns down the volume.
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_VOLUME_DOWN = 17;

    /* *
     * Presses the power button.
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_POWER = 18;

    /* *
     * Presses the camera key.
     * <p>It is used to start the camera or take photos.
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_CAMERA = 19;

    /* *
     * Voice Assistant key
     * <p>This key is used to wake up the voice assistant.
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_VOICE_ASSISTANT = 20;

    /* *
     * Custom key 1
     * <p>The actions mapping to the custom keys are user-defined. Key values 521-529 are reserved for custom keys.
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_CUSTOM1 = 21;

    static constexpr int32_t KEYCODE_VOLUME_MUTE = 22;
    static constexpr int32_t KEYCODE_MUTE = 23;

    /* *
     * Brightness UP key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_BRIGHTNESS_UP = 40;

    /* *
     * Brightness Down key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_BRIGHTNESS_DOWN = 41;

    /* *
     * Indicates general-purpose key 1 on the wearables
     *
     * @since 3
     */
    static constexpr int32_t KEYCODE_WEAR_1 = 1001;

    /* *
     * Keycode constant: '0' key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_0 = 2000;

    /* *
     * Keycode constant: '1' key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_1 = 2001;

    /* *
     * Keycode constant: '2' key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_2 = 2002;

    /* *
     * Keycode constant: '3' key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_3 = 2003;

    /* *
     * Keycode constant: '4' key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_4 = 2004;

    /* *
     * Keycode constant: '5' key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_5 = 2005;

    /* *
     * Keycode constant: '6' key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_6 = 2006;

    /* *
     * Keycode constant: '7' key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_7 = 2007;

    /* *
     * Keycode constant: '8' key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_8 = 2008;

    /* *
     * Keycode constant: '9' key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_9 = 2009;

    /* *
     * Keycode constant: '*' key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_STAR = 2010;

    /* *
     * Keycode constant: '#' key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_POUND = 2011;

    /* *
     * Keycode constant: Directional Pad Up key
     * <p>The key may also be synthesized from trackball motions.
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_DPAD_UP = 2012;

    /* *
     * Keycode constant: Directional Pad Down key
     * <p>The key may also be synthesized from trackball motions.
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_DPAD_DOWN = 2013;

    /* *
     * Keycode constant: Directional Pad Left key
     * <p>The key may also be synthesized from trackball motions.
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_DPAD_LEFT = 2014;

    /* *
     * Keycode constant: Directional Pad Right key
     * <p>The key may also be synthesized from trackball motions.
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_DPAD_RIGHT = 2015;

    /* *
     * Keycode constant: Directional Pad Center key
     * <p>The key may also be synthesized from trackball motions.
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_DPAD_CENTER = 2016;

    /* *
     * Keycode constant: 'A' key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_A = 2017;

    /* *
     * Keycode constant: 'B' key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_B = 2018;

    /* *
     * Keycode constant: 'C' key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_C = 2019;

    /* *
     * Keycode constant: 'D' key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_D = 2020;

    /* *
     * Keycode constant: 'E' key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_E = 2021;

    /* *
     * Keycode constant: 'F' key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_F = 2022;

    /* *
     * Keycode constant: 'G' key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_G = 2023;

    /* *
     * Keycode constant: 'H' key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_H = 2024;

    /* *
     * Keycode constant: 'I' key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_I = 2025;

    /* *
     * Keycode constant: 'J' key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_J = 2026;

    /* *
     * Keycode constant: 'K' key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_K = 2027;

    /* *
     * Keycode constant: 'L' key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_L = 2028;

    /* *
     * Keycode constant: 'M' key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_M = 2029;

    /* *
     * Keycode constant: 'N' key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_N = 2030;

    /* *
     * Keycode constant: 'O' key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_O = 2031;

    /* *
     * Keycode constant: 'P' key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_P = 2032;

    /* *
     * Keycode constant: 'Q' key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_Q = 2033;

    /* *
     * Keycode constant: 'R' key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_R = 2034;

    /* *
     * Keycode constant: 'S' key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_S = 2035;

    /* *
     * Keycode constant: 'T' key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_T = 2036;

    /* *
     * Keycode constant: 'U' key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_U = 2037;

    /* *
     * Keycode constant: 'V' key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_V = 2038;

    /* *
     * Keycode constant: 'W' key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_W = 2039;

    /* *
     * Keycode constant: 'X' key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_X = 2040;

    /* *
     * Keycode constant: 'Y' key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_Y = 2041;

    /* *
     * Keycode constant: 'Z' key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_Z = 2042;

    /* *
     * Keycode constant: ';' key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_COMMA = 2043;

    /* *
     * Keycode constant: '.' key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_PERIOD = 2044;

    /* *
     * Keycode constant: Left Alt modifier key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_ALT_LEFT = 2045;

    /* *
     * Keycode constant: Right Alt modifier key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_ALT_RIGHT = 2046;

    /* *
     * Keycode constant: Left Shift modifier key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_SHIFT_LEFT = 2047;

    /* *
     * Keycode constant: Right Shift modifier key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_SHIFT_RIGHT = 2048;

    /* *
     * Keycode constant: Tab key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_TAB = 2049;

    /* *
     * Keycode constant: Space key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_SPACE = 2050;

    /* *
     * Keycode constant: Symbol modifier key
     * <p>The key is used to input alternate symbols.
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_SYM = 2051;

    /* *
     * Keycode constant: Explorer function key
     * <p>This key is used to launch a browser application.
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_EXPLORER = 2052;

    /* *
     * Keycode constant: Email function key
     * <p>This key is used to launch an email application.
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_ENVELOPE = 2053;

    /* *
     * Keycode constant: Enter key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_ENTER = 2054;

    /* *
     * Keycode constant: Backspace key
     * <p>Unlike {@link #static const int32_t KEYCODE_FORWARD_DEL}; this key is used to delete characters before the
     * insertion point.
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_DEL = 2055;

    /* *
     * Keycode constant: '`' key (backtick key)
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_GRAVE = 2056;

    /* *
     * Keycode constant: '-' key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_MINUS = 2057;

    /* *
     * Keycode constant: '=' key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_EQUALS = 2058;

    /* *
     * Keycode constant: '[' key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_LEFT_BRACKET = 2059;

    /* *
     * Keycode constant: ']' key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_RIGHT_BRACKET = 2060;

    /* *
     * Keycode constant: '\' key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_BACKSLASH = 2061;

    /* *
     * Keycode constant: ';' key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_SEMICOLON = 2062;

    /* *
     * Keycode constant: ''' key (apostrophe key)
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_APOSTROPHE = 2063;

    /* *
     * Keycode constant: '/' key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_SLASH = 2064;

    /* *
     * Keycode constant: '{@literal @}' key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_AT = 2065;

    /* *
     * Keycode constant: '+' key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_PLUS = 2066;

    /* *
     * Keycode constant: Menu key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_MENU = 2067;

    /* *
     * Keycode constant: Page Up key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_PAGE_UP = 2068;

    /* *
     * Keycode constant: Page Down key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_PAGE_DOWN = 2069;

    /* *
     * Keycode constant: Escape key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_ESCAPE = 2070;

    /* *
     * Keycode constant: Forward Delete key
     * <p>Unlike {@link #static const int32_t KEYCODE_DEL}; this key is used to delete characters ahead of the insertion
     * point.
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_FORWARD_DEL = 2071;

    /* *
     * Keycode constant: Left Control modifier key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_CTRL_LEFT = 2072;

    /* *
     * Keycode constant: Right Control modifier key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_CTRL_RIGHT = 2073;

    /* *
     * Keycode constant: Caps Lock key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_CAPS_LOCK = 2074;

    /* *
     * Keycode constant: Scroll Lock key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_SCROLL_LOCK = 2075;

    /* *
     * Keycode constant: Left Meta modifier key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_META_LEFT = 2076;

    /* *
     * Keycode constant: Right Meta modifier key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_META_RIGHT = 2077;

    /* *
     * Keycode constant: Function modifier key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_FUNCTION = 2078;

    /* *
     * Keycode constant: System Request/Print Screen key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_SYSRQ = 2079;

    /* *
     * Keycode constant: Break/Pause key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_BREAK = 2080;

    /* *
     * Keycode constant: Home Movement key
     * <p>This key is used to scroll or move the cursor around to the start of a line or to the
     * top of a list.
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_MOVE_HOME = 2081;

    /* *
     * Keycode constant: End Movement key
     * <p>This key is used to scroll or move the cursor around to the end of a line or to the
     * bottom of a list.
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_MOVE_END = 2082;

    /* *
     * Keycode constant: Insert key
     * <p>This key is used to toggle the insert or overwrite edit mode.
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_INSERT = 2083;

    /* *
     * Keycode constant: Forward key
     * <p>This key is used to navigate forward in the history stack. It is a complement of
     * {@link #static const int32_t KEYCODE_BACK}.
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_FORWARD = 2084;

    /* *
     * Keycode constant: Play media key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_MEDIA_PLAY = 2085;

    /* *
     * Keycode constant: Pause media key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_MEDIA_PAUSE = 2086;

    /* *
     * Keycode constant: Close media key
     * <p>This key can be used to close a CD tray; for example.
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_MEDIA_CLOSE = 2087;

    /* *
     * Keycode constant: Eject media key
     * <p>This key can be used to eject a CD tray; for example.
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_MEDIA_EJECT = 2088;

    /* *
     * Keycode constant: Record media key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_MEDIA_RECORD = 2089;

    /* *
     * Keycode constant: F1 key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_F1 = 2090;

    /* *
     * Keycode constant: F2 key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_F2 = 2091;

    /* *
     * Keycode constant: F3 key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_F3 = 2092;

    /* *
     * Keycode constant: F4 key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_F4 = 2093;

    /* *
     * Keycode constant: F5 key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_F5 = 2094;

    /* *
     * Keycode constant: F6 key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_F6 = 2095;

    /* *
     * Keycode constant: F7 key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_F7 = 2096;

    /* *
     * Keycode constant: F8 key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_F8 = 2097;

    /* *
     * Keycode constant: F9 key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_F9 = 2098;

    /* *
     * Keycode constant: F10 key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_F10 = 2099;

    /* *
     * Keycode constant: F11 key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_F11 = 2100;

    /* *
     * Keycode constant: F12 key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_F12 = 2101;

    /* *
     * Keycode constant: Num Lock key
     * <p>This key is used to alter the behavior of other keys on the numeric keypad.
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_NUM_LOCK = 2102;

    /* *
     * Keycode constant: '0' key on the numeric keypad
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_NUMPAD_0 = 2103;

    /* *
     * Keycode constant: '1' key on the numeric keypad
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_NUMPAD_1 = 2104;

    /* *
     * Keycode constant: '2' key on the numeric keypad
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_NUMPAD_2 = 2105;

    /* *
     * Keycode constant: '3' key on the numeric keypad
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_NUMPAD_3 = 2106;

    /* *
     * Keycode constant: '4' key on the numeric keypad
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_NUMPAD_4 = 2107;

    /* *
     * Keycode constant: '5' key on the numeric keypad
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_NUMPAD_5 = 2108;

    /* *
     * Keycode constant: '6' key on the numeric keypad
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_NUMPAD_6 = 2109;

    /* *
     * Keycode constant: '7' key on the numeric keypad
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_NUMPAD_7 = 2110;

    /* *
     * Keycode constant: '8' key on the numeric keypad
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_NUMPAD_8 = 2111;

    /* *
     * Keycode constant: '9' key on the numeric keypad
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_NUMPAD_9 = 2112;

    /* *
     * Keycode constant: '/' key (for division) on the numeric keypad
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_NUMPAD_DIVIDE = 2113;

    /* *
     * Keycode constant: '*' key (for multiplication) on the numeric keypad
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_NUMPAD_MULTIPLY = 2114;

    /* *
     * Keycode constant: '-' key (for subtraction) on the numeric keypad
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_NUMPAD_SUBTRACT = 2115;

    /* *
     * Keycode constant: '+' key (for addition) on the numeric keypad
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_NUMPAD_ADD = 2116;

    /* *
     * Key code constant: '.' key (for decimals or digit grouping) on the
     * numeric keypad
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_NUMPAD_DOT = 2117;

    /* *
     * Key code constant: ';' key (for decimals or digit grouping) on the
     * numeric keypad
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_NUMPAD_COMMA = 2118;

    /* *
     * Keycode constant: Enter key on the numeric keypad
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_NUMPAD_ENTER = 2119;

    /* *
     * Keycode constant: '=' key on the numeric keypad
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_NUMPAD_EQUALS = 2120;

    /* *
     * Keycode constant: '(' key on the numeric keypad
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_NUMPAD_LEFT_PAREN = 2121;

    /* *
     * Keycode constant: ')' key on the numeric keypad
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_NUMPAD_RIGHT_PAREN = 2122;

    /* *
     * Key code:  The virtual multitask key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_VIRTUAL_MULTITASK = 2210;

    /* *
     * Key code:  The handle button key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_BUTTON_A = 2301;
    static constexpr int32_t KEYCODE_BUTTON_B = 2302;
    static constexpr int32_t KEYCODE_BUTTON_C = 2303;
    static constexpr int32_t KEYCODE_BUTTON_X = 2304;
    static constexpr int32_t KEYCODE_BUTTON_Y = 2305;
    static constexpr int32_t KEYCODE_BUTTON_Z = 2306;
    static constexpr int32_t KEYCODE_BUTTON_L1 = 2307;
    static constexpr int32_t KEYCODE_BUTTON_R1 = 2308;
    static constexpr int32_t KEYCODE_BUTTON_L2 = 2309;
    static constexpr int32_t KEYCODE_BUTTON_R2 = 2310;
    static constexpr int32_t KEYCODE_BUTTON_SELECT = 2311;
    static constexpr int32_t KEYCODE_BUTTON_START = 2312;
    static constexpr int32_t KEYCODE_BUTTON_MODE = 2313;
    static constexpr int32_t KEYCODE_BUTTON_THUMBL = 2314;
    static constexpr int32_t KEYCODE_BUTTON_THUMBR = 2315;

    /* *
     * Key code:  The joystick button key
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_BUTTON_TRIGGER = 2401;
    static constexpr int32_t KEYCODE_BUTTON_THUMB = 2402;
    static constexpr int32_t KEYCODE_BUTTON_THUMB2 = 2403;
    static constexpr int32_t KEYCODE_BUTTON_TOP = 2404;
    static constexpr int32_t KEYCODE_BUTTON_TOP2 = 2405;
    static constexpr int32_t KEYCODE_BUTTON_PINKIE = 2406;
    static constexpr int32_t KEYCODE_BUTTON_BASE1 = 2407;
    static constexpr int32_t KEYCODE_BUTTON_BASE2 = 2408;
    static constexpr int32_t KEYCODE_BUTTON_BASE3 = 2409;
    static constexpr int32_t KEYCODE_BUTTON_BASE4 = 2410;
    static constexpr int32_t KEYCODE_BUTTON_BASE5 = 2411;
    static constexpr int32_t KEYCODE_BUTTON_BASE6 = 2412;
    static constexpr int32_t KEYCODE_BUTTON_BASE7 = 2413;
    static constexpr int32_t KEYCODE_BUTTON_BASE8 = 2414;
    static constexpr int32_t KEYCODE_BUTTON_BASE9 = 2415;
    static constexpr int32_t KEYCODE_BUTTON_DEAD = 2416;

    static constexpr int32_t KEYCODE_SLEEP = 2600;
    static constexpr int32_t KEYCODE_ZENKAKU_HANKAKU = 2601;
    static constexpr int32_t KEYCODE_102ND = 2602;
    static constexpr int32_t KEYCODE_RO = 2603;
    static constexpr int32_t KEYCODE_KATAKANA = 2604;
    static constexpr int32_t KEYCODE_HIRAGANA = 2605;
    static constexpr int32_t KEYCODE_HENKAN = 2606;
    static constexpr int32_t KEYCODE_KATAKANA_HIRAGANA = 2607;
    static constexpr int32_t KEYCODE_MUHENKAN = 2608;
    static constexpr int32_t KEYCODE_LINEFEED = 2609;
    static constexpr int32_t KEYCODE_MACRO = 2610;
    static constexpr int32_t KEYCODE_NUMPAD_PLUSMINUS = 2611;
    static constexpr int32_t KEYCODE_SCALE = 2612;
    static constexpr int32_t KEYCODE_HANGUEL = 2613;
    static constexpr int32_t KEYCODE_HANJA = 2614;
    static constexpr int32_t KEYCODE_YEN = 2615;
    static constexpr int32_t KEYCODE_STOP = 2616;
    static constexpr int32_t KEYCODE_AGAIN = 2617;
    static constexpr int32_t KEYCODE_PROPS = 2618;
    static constexpr int32_t KEYCODE_UNDO = 2619;
    static constexpr int32_t KEYCODE_COPY = 2620;
    static constexpr int32_t KEYCODE_OPEN = 2621;
    static constexpr int32_t KEYCODE_PASTE = 2622;
    static constexpr int32_t KEYCODE_FIND = 2623;
    static constexpr int32_t KEYCODE_CUT = 2624;
    static constexpr int32_t KEYCODE_HELP = 2625;
    static constexpr int32_t KEYCODE_CALC = 2626;
    static constexpr int32_t KEYCODE_FILE = 2627;
    static constexpr int32_t KEYCODE_BOOKMARKS = 2628;
    static constexpr int32_t KEYCODE_NEXT = 2629;
    static constexpr int32_t KEYCODE_PLAYPAUSE = 2630;
    static constexpr int32_t KEYCODE_PREVIOUS = 2631;
    static constexpr int32_t KEYCODE_STOPCD = 2632;
    static constexpr int32_t KEYCODE_CONFIG = 2634;
    static constexpr int32_t KEYCODE_REFRESH = 2635;
    static constexpr int32_t KEYCODE_EXIT = 2636;
    static constexpr int32_t KEYCODE_EDIT = 2637;
    static constexpr int32_t KEYCODE_SCROLLUP = 2638;
    static constexpr int32_t KEYCODE_SCROLLDOWN = 2639;
    static constexpr int32_t KEYCODE_NEW = 2640;
    static constexpr int32_t KEYCODE_REDO = 2641;
    static constexpr int32_t KEYCODE_CLOSE = 2642;
    static constexpr int32_t KEYCODE_PLAY = 2643;
    static constexpr int32_t KEYCODE_BASSBOOST = 2644;
    static constexpr int32_t KEYCODE_PRINT = 2645;
    static constexpr int32_t KEYCODE_CHAT = 2646;
    static constexpr int32_t KEYCODE_FINANCE = 2647;
    static constexpr int32_t KEYCODE_CANCEL = 2648;
    static constexpr int32_t KEYCODE_KBDILLUM_TOGGLE = 2649;
    static constexpr int32_t KEYCODE_KBDILLUM_DOWN = 2650;
    static constexpr int32_t KEYCODE_KBDILLUM_UP = 2651;
    static constexpr int32_t KEYCODE_SEND = 2652;
    static constexpr int32_t KEYCODE_REPLY = 2653;
    static constexpr int32_t KEYCODE_FORWARDMAIL = 2654;
    static constexpr int32_t KEYCODE_SAVE = 2655;
    static constexpr int32_t KEYCODE_DOCUMENTS = 2656;
    static constexpr int32_t KEYCODE_VIDEO_NEXT = 2657;
    static constexpr int32_t KEYCODE_VIDEO_PREV = 2658;
    static constexpr int32_t KEYCODE_BRIGHTNESS_CYCLE = 2659;
    static constexpr int32_t KEYCODE_BRIGHTNESS_ZERO = 2660;
    static constexpr int32_t KEYCODE_DISPLAY_OFF = 2661;
    static constexpr int32_t KEYCODE_BTN_MISC = 2662;
    static constexpr int32_t KEYCODE_GOTO = 2663;
    static constexpr int32_t KEYCODE_INFO = 2664;
    static constexpr int32_t KEYCODE_PROGRAM = 2665;
    static constexpr int32_t KEYCODE_PVR = 2666;
    static constexpr int32_t KEYCODE_SUBTITLE = 2667;
    static constexpr int32_t KEYCODE_FULL_SCREEN = 2668;
    static constexpr int32_t KEYCODE_KEYBOARD = 2669;
    static constexpr int32_t KEYCODE_ASPECT_RATIO = 2670;
    static constexpr int32_t KEYCODE_PC = 2671;
    static constexpr int32_t KEYCODE_TV = 2672;
    static constexpr int32_t KEYCODE_TV2 = 2673;
    static constexpr int32_t KEYCODE_VCR = 2674;
    static constexpr int32_t KEYCODE_VCR2 = 2675;
    static constexpr int32_t KEYCODE_SAT = 2676;
    static constexpr int32_t KEYCODE_CD = 2677;
    static constexpr int32_t KEYCODE_TAPE = 2678;
    static constexpr int32_t KEYCODE_TUNER = 2679;
    static constexpr int32_t KEYCODE_PLAYER = 2680;
    static constexpr int32_t KEYCODE_DVD = 2681;
    static constexpr int32_t KEYCODE_AUDIO = 2682;
    static constexpr int32_t KEYCODE_VIDEO = 2683;
    static constexpr int32_t KEYCODE_MEMO = 2684;
    static constexpr int32_t KEYCODE_CALENDAR = 2685;
    static constexpr int32_t KEYCODE_RED = 2686;
    static constexpr int32_t KEYCODE_GREEN = 2687;
    static constexpr int32_t KEYCODE_YELLOW = 2688;
    static constexpr int32_t KEYCODE_BLUE = 2689;
    static constexpr int32_t KEYCODE_CHANNELUP = 2690;
    static constexpr int32_t KEYCODE_CHANNELDOWN = 2691;
    static constexpr int32_t KEYCODE_LAST = 2692;
    static constexpr int32_t KEYCODE_RESTART = 2693;
    static constexpr int32_t KEYCODE_SLOW = 2694;
    static constexpr int32_t KEYCODE_SHUFFLE = 2695;
    static constexpr int32_t KEYCODE_VIDEOPHONE = 2696;
    static constexpr int32_t KEYCODE_GAMES = 2697;
    static constexpr int32_t KEYCODE_ZOOMIN = 2698;
    static constexpr int32_t KEYCODE_ZOOMOUT = 2699;
    static constexpr int32_t KEYCODE_ZOOMRESET = 2700;
    static constexpr int32_t KEYCODE_WORDPROCESSOR = 2701;
    static constexpr int32_t KEYCODE_EDITOR = 2702;
    static constexpr int32_t KEYCODE_SPREADSHEET = 2703;
    static constexpr int32_t KEYCODE_GRAPHICSEDITOR = 2704;
    static constexpr int32_t KEYCODE_PRESENTATION = 2705;
    static constexpr int32_t KEYCODE_DATABASE = 2706;
    static constexpr int32_t KEYCODE_NEWS = 2707;
    static constexpr int32_t KEYCODE_VOICEMAIL = 2708;
    static constexpr int32_t KEYCODE_ADDRESSBOOK = 2709;
    static constexpr int32_t KEYCODE_MESSENGER = 2710;
    static constexpr int32_t KEYCODE_BRIGHTNESS_TOGGLE = 2711;
    static constexpr int32_t KEYCODE_SPELLCHECK = 2712;
    static constexpr int32_t KEYCODE_COFFEE = 2713;
    static constexpr int32_t KEYCODE_MEDIA_REPEAT = 2714;
    static constexpr int32_t KEYCODE_IMAGES = 2715;
    static constexpr int32_t KEYCODE_BUTTONCONFIG = 2716;
    static constexpr int32_t KEYCODE_TASKMANAGER = 2717;
    static constexpr int32_t KEYCODE_JOURNAL = 2718;
    static constexpr int32_t KEYCODE_CONTROLPANEL = 2719;
    static constexpr int32_t KEYCODE_APPSELECT = 2720;
    static constexpr int32_t KEYCODE_SCREENSAVER = 2721;
    static constexpr int32_t KEYCODE_ASSISTANT = 2722;
    static constexpr int32_t KEYCODE_KBD_LAYOUT_NEXT = 2723;
    static constexpr int32_t KEYCODE_BRIGHTNESS_MIN = 2724;
    static constexpr int32_t KEYCODE_BRIGHTNESS_MAX = 2725;
    static constexpr int32_t KEYCODE_KBDINPUTASSIST_PREV = 2726;
    static constexpr int32_t KEYCODE_KBDINPUTASSIST_NEXT = 2727;
    static constexpr int32_t KEYCODE_KBDINPUTASSIST_PREVGROUP = 2728;
    static constexpr int32_t KEYCODE_KBDINPUTASSIST_NEXTGROUP = 2729;
    static constexpr int32_t KEYCODE_KBDINPUTASSIST_ACCEPT = 2730;
    static constexpr int32_t KEYCODE_KBDINPUTASSIST_CANCEL = 2731;

    static constexpr int32_t KEYCODE_FRONT = 2800;
    static constexpr int32_t KEYCODE_SETUP = 2801;
    static constexpr int32_t KEYCODE_WAKEUP = 2802;
    static constexpr int32_t KEYCODE_SENDFILE = 2803;
    static constexpr int32_t KEYCODE_DELETEFILE = 2804;
    static constexpr int32_t KEYCODE_XFER = 2805;
    static constexpr int32_t KEYCODE_PROG1 = 2806;
    static constexpr int32_t KEYCODE_PROG2 = 2807;
    static constexpr int32_t KEYCODE_MSDOS = 2808;
    static constexpr int32_t KEYCODE_SCREENLOCK = 2809;
    static constexpr int32_t KEYCODE_DIRECTION_ROTATE_DISPLAY = 2810;
    static constexpr int32_t KEYCODE_CYCLEWINDOWS = 2811;
    static constexpr int32_t KEYCODE_COMPUTER = 2812;
    static constexpr int32_t KEYCODE_EJECTCLOSECD = 2813;
    static constexpr int32_t KEYCODE_ISO = 2814;
    static constexpr int32_t KEYCODE_MOVE = 2815;
    static constexpr int32_t KEYCODE_F13 = 2816;
    static constexpr int32_t KEYCODE_F14 = 2817;
    static constexpr int32_t KEYCODE_F15 = 2818;
    static constexpr int32_t KEYCODE_F16 = 2819;
    static constexpr int32_t KEYCODE_F17 = 2820;
    static constexpr int32_t KEYCODE_F18 = 2821;
    static constexpr int32_t KEYCODE_F19 = 2822;
    static constexpr int32_t KEYCODE_F20 = 2823;
    static constexpr int32_t KEYCODE_F21 = 2824;
    static constexpr int32_t KEYCODE_F22 = 2825;
    static constexpr int32_t KEYCODE_F23 = 2826;
    static constexpr int32_t KEYCODE_F24 = 2827;
    static constexpr int32_t KEYCODE_PROG3 = 2828;
    static constexpr int32_t KEYCODE_PROG4 = 2829;
    static constexpr int32_t KEYCODE_DASHBOARD = 2830;
    static constexpr int32_t KEYCODE_SUSPEND = 2831;
    static constexpr int32_t KEYCODE_HP = 2832;
    static constexpr int32_t KEYCODE_SOUND = 2833;
    static constexpr int32_t KEYCODE_QUESTION = 2834;
    static constexpr int32_t KEYCODE_CONNECT = 2836;
    static constexpr int32_t KEYCODE_SPORT = 2837;
    static constexpr int32_t KEYCODE_SHOP = 2838;
    static constexpr int32_t KEYCODE_ALTERASE = 2839;
    static constexpr int32_t KEYCODE_SWITCHVIDEOMODE = 2841;
    static constexpr int32_t KEYCODE_BATTERY = 2842;
    static constexpr int32_t KEYCODE_BLUETOOTH = 2843;
    static constexpr int32_t KEYCODE_WLAN = 2844;
    static constexpr int32_t KEYCODE_UWB = 2845;
    static constexpr int32_t KEYCODE_WWAN_WIMAX = 2846;
    static constexpr int32_t KEYCODE_RFKILL = 2847;

    static constexpr int32_t KEYCODE_CHANNEL = 3001;
    static constexpr int32_t KEYCODE_BTN_0 = 3100;
    static constexpr int32_t KEYCODE_BTN_1 = 3101;
    static constexpr int32_t KEYCODE_BTN_2 = 3102;
    static constexpr int32_t KEYCODE_BTN_3 = 3103;
    static constexpr int32_t KEYCODE_BTN_4 = 3104;
    static constexpr int32_t KEYCODE_BTN_5 = 3105;
    static constexpr int32_t KEYCODE_BTN_6 = 3106;
    static constexpr int32_t KEYCODE_BTN_7 = 3107;
    static constexpr int32_t KEYCODE_BTN_8 = 3108;
    static constexpr int32_t KEYCODE_BTN_9 = 3109;

    static constexpr int32_t KEYCODE_BRL_DOT1 = 3201;
    static constexpr int32_t KEYCODE_BRL_DOT2 = 3202;
    static constexpr int32_t KEYCODE_BRL_DOT3 = 3203;
    static constexpr int32_t KEYCODE_BRL_DOT4 = 3204;
    static constexpr int32_t KEYCODE_BRL_DOT5 = 3205;
    static constexpr int32_t KEYCODE_BRL_DOT6 = 3206;
    static constexpr int32_t KEYCODE_BRL_DOT7 = 3207;
    static constexpr int32_t KEYCODE_BRL_DOT8 = 3208;
    static constexpr int32_t KEYCODE_BRL_DOT9 = 3209;
    static constexpr int32_t KEYCODE_BRL_DOT10 = 3210;

    /* *
     * Left Knob roll-up
     * <p>In contrast to {@link #static const int32_t KEYCODE_LEFT_KNOB_ROLL_DOWN}; it means rolling
     * the left knob upwards. The knob functionis scenario-specific; for example;
     * increasing the volume or air conditioner temperature.
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_LEFT_KNOB_ROLL_UP = 10001;
    /* *
     * Left Knob roll-down
     * <p>In contrast to {@link #static const int32_t KEYCODE_LEFT_KNOB_ROLL_UP};
     * it means rolling the left knob downwards. The knob function is
     * scenario-specific; for example; reducing the volume or air
     * conditioner temperature.
     * @since 1
     */
    static constexpr int32_t KEYCODE_LEFT_KNOB_ROLL_DOWN = 10002;

    /* *
     * Left Knob
     * <p>Pressing the knob will activate its adjustment function.
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_LEFT_KNOB = 10003;
    /* *
     * Right Knob roll-up
     * <p>In contrast to {@link #static const int32_t KEYCODE_RIGHT_KNOB_ROLL_DOWN}; it means rolling
     * the right knob upwards. The knobfunction is scenario-specific; for example;
     * increasing the volume or air conditioner temperature.
     *
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_RIGHT_KNOB_ROLL_UP = 10004;
    /* *
     * Right Knob roll-down
     * <p>In contrast to {@link #static const int32_t KEYCODE_RIGHT_KNOB_ROLL_UP}; it means rolling
     * the right knob downwards. The knobfunction is scenario-specific;
     * for example; reducing the volume or air conditioner temperature.
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_RIGHT_KNOB_ROLL_DOWN = 10005;
    /* *
     * Right Knob
     * <p>Pressing the knob will activate its adjustment function.
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_RIGHT_KNOB = 10006;
    /* *
     * Audio Source Switch button
     * <p>Pressing this button will enable the audio source. Depending on the
     * actual scenario; it may also indicate that the Bluetooth call control
     * button is pressed.
     * @since 1
     */
    static constexpr int32_t KEYCODE_VOICE_SOURCE_SWITCH = 10007;
    /* *
     * Menu key
     * <p>Pressing this key will display the launcher page.
     *
     * @since 1
     */
    static constexpr int32_t KEYCODE_LAUNCHER_MENU = 10008;

    // Unknown key action. Usually used to indicate the initial invalid value
    static constexpr int32_t KEY_ACTION_UNKNOWN = 0X00000000;
    // Indicates cancel action.
    // When the button is pressed, and the lifting action cannot be reported normally, report the key event of this
    // action
    static constexpr int32_t KEY_ACTION_CANCEL = 0X00000001;

    // Indicates key press action
    static constexpr int32_t KEY_ACTION_DOWN = 0x00000002;
    // Indicates key release action
    static constexpr int32_t KEY_ACTION_UP = 0X00000003;

public:
    class KeyItem {
    public:
        KeyItem();
        virtual ~KeyItem();

        // Get or set the key code.
        // The key code is the number that identifies the key
        int32_t GetKeyCode() const;
        void SetKeyCode(int32_t keyCode);

        // Get or set the key press time
        int32_t GetDownTime() const;
        void SetDownTime(int32_t downTime);

        // Get or set the unique identifier of the device reporting this button. i
        // The default value is 0, which means that the non-real device reports.
        int32_t GetDeviceId() const;
        void SetDeviceId(int32_t deviceId);

        // Gets or sets whether the key is currently pressed.
        // The default value is true, which means it is in a pressed state.
        bool IsPressed() const;
        void SetPressed(bool pressed);
    public:
        bool WriteToParcel(Parcel &out) const;
        bool ReadFromParcel(Parcel &in);

    private:
        bool pressed_;
        int32_t downTime_;
        int32_t deviceId_;
        int32_t keyCode_;
    };

public:
    // Try to convert the InputEvent object into a KeyEvent object.
    // Returning an empty smart pointer object indicates that the conversion failed
    static std::shared_ptr<KeyEvent> from(std::shared_ptr<InputEvent> inputEvent);

    static const char* ActionToString(int32_t action);
    static const char* KeyCodeToString(int32_t keyCode);
    static std::shared_ptr<KeyEvent> Clone(std::shared_ptr<KeyEvent> keyEvent);

public:
    virtual ~KeyEvent();
    static std::shared_ptr<KeyEvent> Create();
    // Get or change the key code of the device.
    // Only one key will change in an event report
    int32_t GetKeyCode() const;
    void SetKeyCode(int32_t keyCode);

    // Get or set the key action. The default value is the state of the current key code.
    int32_t GetKeyAction() const;
    void SetKeyAction(int32_t keyAction);

    // Get the list of keys currently in the pressed state
    std::vector<int32_t> GetPressedKeys() const;
    void AddKeyItem(const KeyItem& keyItem);
    std::vector<KeyEvent::KeyItem> GetKeyItems();
    void AddPressedKeyItems(const KeyItem& keyItem);
    void RemoveReleasedKeyItems(const KeyItem& keyItem);

    const KeyItem* GetKeyItem() const;
    const KeyItem* GetKeyItem(int32_t keyCode) const;
    bool IsValid() const;
public:
    bool WriteToParcel(Parcel &out) const;
    bool ReadFromParcel(Parcel &in);

protected:
    explicit KeyEvent(int32_t eventType);

private:
    bool IsValidKeyItem() const;

private:
    int32_t keyCode_;
    std::vector<KeyItem> keys_;
    int32_t keyAction_;
};
}
}
#endif // KEY_EVENT_H