/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef KEY_EVENT_H
#define KEY_EVENT_H

#include "multimodal_event.h"
#include "mmi_point.h"

namespace OHOS {
struct KeyProperty {
    bool isPressed;
    int keyCode;
    int keyDownDuration;
};

class KeyEvent : public MultimodalEvent {
public:
    void Initialize(MultimodalProperty &multiProperty, KeyProperty &KeyProperty);

    virtual int GetMaxKeyCode();

    virtual bool IsKeyDown();

    virtual int GetKeyCode();

    virtual int GetKeyDownDuration();

    bool Marshalling(Parcel &parcel) const override;
    static KeyEvent *Unmarshalling(Parcel &parcel);

    static constexpr int KEY_PRESSED = 0;

    static constexpr int KEY_RELEASED = 1;

    static constexpr int CODE_UNKNOWN = -1;

    static constexpr int CODE_HOME = 1;

    static constexpr int CODE_BACK = 2;

    static constexpr int CODE_CALL = 3;

    static constexpr int CODE_ENDCALL = 4;

    static constexpr int CODE_CLEAR = 5;

    static constexpr int CODE_HEADSETHOOK = 6;

    static constexpr int CODE_FOCUS = 7;

    static constexpr int CODE_NOTIFICATION = 8;

    static constexpr int CODE_SEARCH = 9;

    static constexpr int CODE_MEDIA_PLAY_PAUSE = 10;

    static constexpr int CODE_MEDIA_STOP = 11;

    static constexpr int CODE_MEDIA_NEXT = 12;

    static constexpr int CODE_MEDIA_PREVIOUS = 13;

    static constexpr int CODE_MEDIA_REWIND = 14;

    static constexpr int CODE_MEDIA_FAST_FORWARD = 15;

    static constexpr int CODE_VOLUME_UP = 16;

    static constexpr int CODE_VOLUME_DOWN = 17;

    static constexpr int CODE_POWER = 18;

    static constexpr int CODE_CAMERA = 19;

    static constexpr int CODE_VOICE_ASSISTANT = 20;

    static constexpr int CODE_CUSTOM1 = 21;

    static constexpr int CODE_BRIGHTNESS_UP = 40;

    static constexpr int CODE_BRIGHTNESS_DOWN = 41;

    static constexpr int CODE_WEAR_1 = 1001;

    static constexpr int CODE_0 = 2000;

    static constexpr int CODE_1 = 2001;

    static constexpr int CODE_2 = 2002;

    static constexpr int CODE_3 = 2003;

    static constexpr int CODE_4 = 2004;

    static constexpr int CODE_5 = 2005;

    static constexpr int CODE_6 = 2006;

    static constexpr int CODE_7 = 2007;

    static constexpr int CODE_8 = 2008;

    static constexpr int CODE_9 = 2009;

    static constexpr int CODE_STAR = 2010;

    static constexpr int CODE_POUND = 2011;

    static constexpr int CODE_DPAD_UP = 2012;

    static constexpr int CODE_DPAD_DOWN = 2013;

    static constexpr int CODE_DPAD_LEFT = 2014;

    static constexpr int CODE_DPAD_RIGHT = 2015;

    static constexpr int CODE_DPAD_CENTER = 2016;

    static constexpr int CODE_A = 2017;

    static constexpr int CODE_B = 2018;

    static constexpr int CODE_C = 2019;

    static constexpr int CODE_D = 2020;

    static constexpr int CODE_E = 2021;

    static constexpr int CODE_F = 2022;

    static constexpr int CODE_G = 2023;

    static constexpr int CODE_H = 2024;

    static constexpr int CODE_I = 2025;

    static constexpr int CODE_J = 2026;

    static constexpr int CODE_K = 2027;

    static constexpr int CODE_L = 2028;

    static constexpr int CODE_M = 2029;

    static constexpr int CODE_N = 2030;

    static constexpr int CODE_O = 2031;

    static constexpr int CODE_P = 2032;

    static constexpr int CODE_Q = 2033;

    static constexpr int CODE_R = 2034;

    static constexpr int CODE_S = 2035;

    static constexpr int CODE_T = 2036;

    static constexpr int CODE_U = 2037;

    static constexpr int CODE_V = 2038;

    static constexpr int CODE_W = 2039;

    static constexpr int CODE_X = 2040;

    static constexpr int CODE_Y = 2041;

    static constexpr int CODE_Z = 2042;

    static constexpr int CODE_COMMA = 2043;

    static constexpr int CODE_PERIOD = 2044;

    static constexpr int CODE_ALT_LEFT = 2045;

    static constexpr int CODE_ALT_RIGHT = 2046;

    static constexpr int CODE_SHIFT_LEFT = 2047;

    static constexpr int CODE_SHIFT_RIGHT = 2048;

    static constexpr int CODE_TAB = 2049;

    static constexpr int CODE_SPACE = 2050;

    static constexpr int CODE_SYM = 2051;

    static constexpr int CODE_EXPLORER = 2052;

    static constexpr int CODE_ENVELOPE = 2053;

    static constexpr int CODE_ENTER = 2054;

    static constexpr int CODE_DEL = 2055;

    static constexpr int CODE_GRAVE = 2056;

    static constexpr int CODE_MINUS = 2057;

    static constexpr int CODE_EQUALS = 2058;

    static constexpr int CODE_LEFT_BRACKET = 2059;

    static constexpr int CODE_RIGHT_BRACKET = 2060;

    static constexpr int CODE_BACKSLASH = 2061;

    static constexpr int CODE_SEMICOLON = 2062;

    static constexpr int CODE_APOSTROPHE = 2063;

    static constexpr int CODE_SLASH = 2064;

    static constexpr int CODE_AT = 2065;

    static constexpr int CODE_PLUS = 2066;

    static constexpr int CODE_MENU = 2067;

    static constexpr int CODE_PAGE_UP = 2068;

    static constexpr int CODE_PAGE_DOWN = 2069;

    static constexpr int CODE_ESCAPE = 2070;

    static constexpr int CODE_FORWARD_DEL = 2071;

    static constexpr int CODE_CTRL_LEFT = 2072;

    static constexpr int CODE_CTRL_RIGHT = 2073;

    static constexpr int CODE_CAPS_LOCK = 2074;

    static constexpr int CODE_SCROLL_LOCK = 2075;

    static constexpr int CODE_META_LEFT = 2076;

    static constexpr int CODE_META_RIGHT = 2077;

    static constexpr int CODE_FUNCTION = 2078;

    static constexpr int CODE_SYSRQ = 2079;

    static constexpr int CODE_BREAK = 2080;

    static constexpr int CODE_MOVE_HOME = 2081;

    static constexpr int CODE_MOVE_END = 2082;

    static constexpr int CODE_INSERT = 2083;

    static constexpr int CODE_FORWARD = 2084;

    static constexpr int CODE_MEDIA_PLAY = 2085;

    static constexpr int CODE_MEDIA_PAUSE = 2086;

    static constexpr int CODE_MEDIA_CLOSE = 2087;

    static constexpr int CODE_MEDIA_EJECT = 2088;

    static constexpr int CODE_MEDIA_RECORD = 2089;

    static constexpr int CODE_F1 = 2090;

    static constexpr int CODE_F2 = 2091;

    static constexpr int CODE_F3 = 2092;

    static constexpr int CODE_F4 = 2093;

    static constexpr int CODE_F5 = 2094;

    static constexpr int CODE_F6 = 2095;

    static constexpr int CODE_F7 = 2096;

    static constexpr int CODE_F8 = 2097;

    static constexpr int CODE_F9 = 2098;

    static constexpr int CODE_F10 = 2099;

    static constexpr int CODE_F11 = 2100;

    static constexpr int CODE_F12 = 2101;

    static constexpr int CODE_NUM_LOCK = 2102;

    static constexpr int CODE_NUMPAD_0 = 2103;

    static constexpr int CODE_NUMPAD_1 = 2104;

    static constexpr int CODE_NUMPAD_2 = 2105;

    static constexpr int CODE_NUMPAD_3 = 2106;

    static constexpr int CODE_NUMPAD_4 = 2107;

    static constexpr int CODE_NUMPAD_5 = 2108;

    static constexpr int CODE_NUMPAD_6 = 2109;

    static constexpr int CODE_NUMPAD_7 = 2110;

    static constexpr int CODE_NUMPAD_8 = 2111;

    static constexpr int CODE_NUMPAD_9 = 2112;

    static constexpr int CODE_NUMPAD_DIVIDE = 2113;

    static constexpr int CODE_NUMPAD_MULTIPLY = 2114;

    static constexpr int CODE_NUMPAD_SUBTRACT = 2115;

    static constexpr int CODE_NUMPAD_ADD = 2116;

    static constexpr int CODE_NUMPAD_DOT = 2117;

    static constexpr int CODE_NUMPAD_COMMA = 2118;

    static constexpr int CODE_NUMPAD_ENTER = 2119;

    static constexpr int CODE_NUMPAD_EQUALS = 2120;

    static constexpr int CODE_NUMPAD_LEFT_PAREN = 2121;

    static constexpr int CODE_NUMPAD_RIGHT_PAREN = 2122;

    static constexpr int CODE_LEFT_KNOB_ROLL_UP = 10001;

    static constexpr int CODE_LEFT_KNOB_ROLL_DOWN = 10002;

    static constexpr int CODE_LEFT_KNOB = 10003;

    static constexpr int CODE_RIGHT_KNOB_ROLL_UP = 10004;

    static constexpr int CODE_RIGHT_KNOB_ROLL_DOWN = 10005;

    static constexpr int CODE_RIGHT_KNOB = 10006;

    static constexpr int CODE_VOICE_SOURCE_SWITCH = 10007;

    static constexpr int CODE_LAUNCHER_MENU = 10008;

    static constexpr int NOW_MAX_CODE = CODE_LAUNCHER_MENU;
protected:
    KeyProperty keyProperty_;
};
}  // namespace OHOS
#endif  // KEY_EVENT_H
