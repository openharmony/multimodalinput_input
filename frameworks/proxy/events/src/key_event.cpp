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

#include "key_event.h"
#include "hilog/log.h"

using namespace OHOS::HiviewDFX;
namespace OHOS {
namespace MMI {
namespace {
    constexpr HiLogLabel LABEL = { LOG_CORE, 0xD002800, "KeyEvent" };
}
const int32_t KeyEvent::KEYCODE_FN = 0;
const int32_t KeyEvent::KEYCODE_UNKNOWN = -1;
const int32_t KeyEvent::KEYCODE_HOME = 1;
const int32_t KeyEvent::KEYCODE_BACK = 2;
const int32_t KeyEvent::KEYCODE_CALL = 3;
const int32_t KeyEvent::KEYCODE_ENDCALL = 4;
const int32_t KeyEvent::KEYCODE_CLEAR = 5;
const int32_t KeyEvent::KEYCODE_HEADSETHOOK = 6;
const int32_t KeyEvent::KEYCODE_FOCUS = 7;
const int32_t KeyEvent::KEYCODE_NOTIFICATION = 8;
const int32_t KeyEvent::KEYCODE_SEARCH = 9;
const int32_t KeyEvent::KEYCODE_MEDIA_PLAY_PAUSE = 10;
const int32_t KeyEvent::KEYCODE_MEDIA_STOP = 11;
const int32_t KeyEvent::KEYCODE_MEDIA_NEXT = 12;
const int32_t KeyEvent::KEYCODE_MEDIA_PREVIOUS = 13;
const int32_t KeyEvent::KEYCODE_MEDIA_REWIND = 14;
const int32_t KeyEvent::KEYCODE_MEDIA_FAST_FORWARD = 15;
const int32_t KeyEvent::KEYCODE_VOLUME_UP = 16;
const int32_t KeyEvent::KEYCODE_VOLUME_DOWN = 17;
const int32_t KeyEvent::KEYCODE_POWER = 18;
const int32_t KeyEvent::KEYCODE_CAMERA = 19;
const int32_t KeyEvent::KEYCODE_VOICE_ASSISTANT = 20;
const int32_t KeyEvent::KEYCODE_CUSTOM1 = 21;
const int32_t KeyEvent::KEYCODE_VOLUME_MUTE = 22;
const int32_t KeyEvent::KEYCODE_MUTE = 23;
const int32_t KeyEvent::KEYCODE_BRIGHTNESS_UP = 40;
const int32_t KeyEvent::KEYCODE_BRIGHTNESS_DOWN = 41;
const int32_t KeyEvent::KEYCODE_WEAR_1 = 1001;
const int32_t KeyEvent::KEYCODE_0 = 2000;
const int32_t KeyEvent::KEYCODE_1 = 2001;
const int32_t KeyEvent::KEYCODE_2 = 2002;
const int32_t KeyEvent::KEYCODE_3 = 2003;
const int32_t KeyEvent::KEYCODE_4 = 2004;
const int32_t KeyEvent::KEYCODE_5 = 2005;
const int32_t KeyEvent::KEYCODE_6 = 2006;
const int32_t KeyEvent::KEYCODE_7 = 2007;
const int32_t KeyEvent::KEYCODE_8 = 2008;
const int32_t KeyEvent::KEYCODE_9 = 2009;
const int32_t KeyEvent::KEYCODE_STAR = 2010;
const int32_t KeyEvent::KEYCODE_POUND = 2011;
const int32_t KeyEvent::KEYCODE_DPAD_UP = 2012;
const int32_t KeyEvent::KEYCODE_DPAD_DOWN = 2013;
const int32_t KeyEvent::KEYCODE_DPAD_LEFT = 2014;
const int32_t KeyEvent::KEYCODE_DPAD_RIGHT = 2015;
const int32_t KeyEvent::KEYCODE_DPAD_CENTER = 2016;
const int32_t KeyEvent::KEYCODE_A = 2017;
const int32_t KeyEvent::KEYCODE_B = 2018;
const int32_t KeyEvent::KEYCODE_C = 2019;
const int32_t KeyEvent::KEYCODE_D = 2020;
const int32_t KeyEvent::KEYCODE_E = 2021;
const int32_t KeyEvent::KEYCODE_F = 2022;
const int32_t KeyEvent::KEYCODE_G = 2023;
const int32_t KeyEvent::KEYCODE_H = 2024;
const int32_t KeyEvent::KEYCODE_I = 2025;
const int32_t KeyEvent::KEYCODE_J = 2026;
const int32_t KeyEvent::KEYCODE_K = 2027;
const int32_t KeyEvent::KEYCODE_L = 2028;
const int32_t KeyEvent::KEYCODE_M = 2029;
const int32_t KeyEvent::KEYCODE_N = 2030;
const int32_t KeyEvent::KEYCODE_O = 2031;
const int32_t KeyEvent::KEYCODE_P = 2032;
const int32_t KeyEvent::KEYCODE_Q = 2033;
const int32_t KeyEvent::KEYCODE_R = 2034;
const int32_t KeyEvent::KEYCODE_S = 2035;
const int32_t KeyEvent::KEYCODE_T = 2036;
const int32_t KeyEvent::KEYCODE_U = 2037;
const int32_t KeyEvent::KEYCODE_V = 2038;
const int32_t KeyEvent::KEYCODE_W = 2039;
const int32_t KeyEvent::KEYCODE_X = 2040;
const int32_t KeyEvent::KEYCODE_Y = 2041;
const int32_t KeyEvent::KEYCODE_Z = 2042;
const int32_t KeyEvent::KEYCODE_COMMA = 2043;
const int32_t KeyEvent::KEYCODE_PERIOD = 2044;
const int32_t KeyEvent::KEYCODE_ALT_LEFT = 2045;
const int32_t KeyEvent::KEYCODE_ALT_RIGHT = 2046;
const int32_t KeyEvent::KEYCODE_SHIFT_LEFT = 2047;
const int32_t KeyEvent::KEYCODE_SHIFT_RIGHT = 2048;
const int32_t KeyEvent::KEYCODE_TAB = 2049;
const int32_t KeyEvent::KEYCODE_SPACE = 2050;
const int32_t KeyEvent::KEYCODE_SYM = 2051;
const int32_t KeyEvent::KEYCODE_EXPLORER = 2052;
const int32_t KeyEvent::KEYCODE_ENVELOPE = 2053;
const int32_t KeyEvent::KEYCODE_ENTER = 2054;
const int32_t KeyEvent::KEYCODE_DEL = 2055;
const int32_t KeyEvent::KEYCODE_GRAVE = 2056;
const int32_t KeyEvent::KEYCODE_MINUS = 2057;
const int32_t KeyEvent::KEYCODE_EQUALS = 2058;
const int32_t KeyEvent::KEYCODE_LEFT_BRACKET = 2059;
const int32_t KeyEvent::KEYCODE_RIGHT_BRACKET = 2060;
const int32_t KeyEvent::KEYCODE_BACKSLASH = 2061;
const int32_t KeyEvent::KEYCODE_SEMICOLON = 2062;
const int32_t KeyEvent::KEYCODE_APOSTROPHE = 2063;
const int32_t KeyEvent::KEYCODE_SLASH = 2064;
const int32_t KeyEvent::KEYCODE_AT = 2065;
const int32_t KeyEvent::KEYCODE_PLUS = 2066;
const int32_t KeyEvent::KEYCODE_MENU = 2067;
const int32_t KeyEvent::KEYCODE_PAGE_UP = 2068;
const int32_t KeyEvent::KEYCODE_PAGE_DOWN = 2069;
const int32_t KeyEvent::KEYCODE_ESCAPE = 2070;
const int32_t KeyEvent::KEYCODE_FORWARD_DEL = 2071;
const int32_t KeyEvent::KEYCODE_CTRL_LEFT = 2072;
const int32_t KeyEvent::KEYCODE_CTRL_RIGHT = 2073;
const int32_t KeyEvent::KEYCODE_CAPS_LOCK = 2074;
const int32_t KeyEvent::KEYCODE_SCROLL_LOCK = 2075;
const int32_t KeyEvent::KEYCODE_META_LEFT = 2076;
const int32_t KeyEvent::KEYCODE_META_RIGHT = 2077;
const int32_t KeyEvent::KEYCODE_FUNCTION = 2078;
const int32_t KeyEvent::KEYCODE_SYSRQ = 2079;
const int32_t KeyEvent::KEYCODE_BREAK = 2080;
const int32_t KeyEvent::KEYCODE_MOVE_HOME = 2081;
const int32_t KeyEvent::KEYCODE_MOVE_END = 2082;
const int32_t KeyEvent::KEYCODE_INSERT = 2083;
const int32_t KeyEvent::KEYCODE_FORWARD = 2084;
const int32_t KeyEvent::KEYCODE_MEDIA_PLAY = 2085;
const int32_t KeyEvent::KEYCODE_MEDIA_PAUSE = 2086;
const int32_t KeyEvent::KEYCODE_MEDIA_CLOSE = 2087;
const int32_t KeyEvent::KEYCODE_MEDIA_EJECT = 2088;
const int32_t KeyEvent::KEYCODE_MEDIA_RECORD = 2089;
const int32_t KeyEvent::KEYCODE_F1 = 2090;
const int32_t KeyEvent::KEYCODE_F2 = 2091;
const int32_t KeyEvent::KEYCODE_F3 = 2092;
const int32_t KeyEvent::KEYCODE_F4 = 2093;
const int32_t KeyEvent::KEYCODE_F5 = 2094;
const int32_t KeyEvent::KEYCODE_F6 = 2095;
const int32_t KeyEvent::KEYCODE_F7 = 2096;
const int32_t KeyEvent::KEYCODE_F8 = 2097;
const int32_t KeyEvent::KEYCODE_F9 = 2098;
const int32_t KeyEvent::KEYCODE_F10 = 2099;
const int32_t KeyEvent::KEYCODE_F11 = 2100;
const int32_t KeyEvent::KEYCODE_F12 = 2101;
const int32_t KeyEvent::KEYCODE_NUM_LOCK = 2102;
const int32_t KeyEvent::KEYCODE_NUMPAD_0 = 2103;
const int32_t KeyEvent::KEYCODE_NUMPAD_1 = 2104;
const int32_t KeyEvent::KEYCODE_NUMPAD_2 = 2105;
const int32_t KeyEvent::KEYCODE_NUMPAD_3 = 2106;
const int32_t KeyEvent::KEYCODE_NUMPAD_4 = 2107;
const int32_t KeyEvent::KEYCODE_NUMPAD_5 = 2108;
const int32_t KeyEvent::KEYCODE_NUMPAD_6 = 2109;
const int32_t KeyEvent::KEYCODE_NUMPAD_7 = 2110;
const int32_t KeyEvent::KEYCODE_NUMPAD_8 = 2111;
const int32_t KeyEvent::KEYCODE_NUMPAD_9 = 2112;
const int32_t KeyEvent::KEYCODE_NUMPAD_DIVIDE = 2113;
const int32_t KeyEvent::KEYCODE_NUMPAD_MULTIPLY = 2114;
const int32_t KeyEvent::KEYCODE_NUMPAD_SUBTRACT = 2115;
const int32_t KeyEvent::KEYCODE_NUMPAD_ADD = 2116;
const int32_t KeyEvent::KEYCODE_NUMPAD_DOT = 2117;
const int32_t KeyEvent::KEYCODE_NUMPAD_COMMA = 2118;
const int32_t KeyEvent::KEYCODE_NUMPAD_ENTER = 2119;
const int32_t KeyEvent::KEYCODE_NUMPAD_EQUALS = 2120;
const int32_t KeyEvent::KEYCODE_NUMPAD_LEFT_PAREN = 2121;
const int32_t KeyEvent::KEYCODE_NUMPAD_RIGHT_PAREN = 2122;
const int32_t KeyEvent::KEYCODE_VIRTUAL_MULTITASK = 2210;
const int32_t KeyEvent::KEYCODE_BUTTON_A = 2301;
const int32_t KeyEvent::KEYCODE_BUTTON_B = 2302;
const int32_t KeyEvent::KEYCODE_BUTTON_C = 2303;
const int32_t KeyEvent::KEYCODE_BUTTON_X = 2304;
const int32_t KeyEvent::KEYCODE_BUTTON_Y = 2305;
const int32_t KeyEvent::KEYCODE_BUTTON_Z = 2306;
const int32_t KeyEvent::KEYCODE_BUTTON_L1 = 2307;
const int32_t KeyEvent::KEYCODE_BUTTON_R1 = 2308;
const int32_t KeyEvent::KEYCODE_BUTTON_L2 = 2309;
const int32_t KeyEvent::KEYCODE_BUTTON_R2 = 2310;
const int32_t KeyEvent::KEYCODE_BUTTON_SELECT = 2311;
const int32_t KeyEvent::KEYCODE_BUTTON_START = 2312;
const int32_t KeyEvent::KEYCODE_BUTTON_MODE = 2313;
const int32_t KeyEvent::KEYCODE_BUTTON_THUMBL = 2314;
const int32_t KeyEvent::KEYCODE_BUTTON_THUMBR = 2315;
const int32_t KeyEvent::KEYCODE_BUTTON_TRIGGER = 2401;
const int32_t KeyEvent::KEYCODE_BUTTON_THUMB = 2402;
const int32_t KeyEvent::KEYCODE_BUTTON_THUMB2 = 2403;
const int32_t KeyEvent::KEYCODE_BUTTON_TOP = 2404;
const int32_t KeyEvent::KEYCODE_BUTTON_TOP2 = 2405;
const int32_t KeyEvent::KEYCODE_BUTTON_PINKIE = 2406;
const int32_t KeyEvent::KEYCODE_BUTTON_BASE1 = 2407;
const int32_t KeyEvent::KEYCODE_BUTTON_BASE2 = 2408;
const int32_t KeyEvent::KEYCODE_BUTTON_BASE3 = 2409;
const int32_t KeyEvent::KEYCODE_BUTTON_BASE4 = 2410;
const int32_t KeyEvent::KEYCODE_BUTTON_BASE5 = 2411;
const int32_t KeyEvent::KEYCODE_BUTTON_BASE6 = 2412;
const int32_t KeyEvent::KEYCODE_BUTTON_BASE7 = 2413;
const int32_t KeyEvent::KEYCODE_BUTTON_BASE8 = 2414;
const int32_t KeyEvent::KEYCODE_BUTTON_BASE9 = 2415;
const int32_t KeyEvent::KEYCODE_BUTTON_DEAD = 2416;
const int32_t KeyEvent::KEYCODE_SLEEP = 2600;
const int32_t KeyEvent::KEYCODE_ZENKAKU_HANKAKU = 2601;
const int32_t KeyEvent::KEYCODE_102ND = 2602;
const int32_t KeyEvent::KEYCODE_RO = 2603;
const int32_t KeyEvent::KEYCODE_KATAKANA = 2604;
const int32_t KeyEvent::KEYCODE_HIRAGANA = 2605;
const int32_t KeyEvent::KEYCODE_HENKAN = 2606;
const int32_t KeyEvent::KEYCODE_KATAKANA_HIRAGANA = 2607;
const int32_t KeyEvent::KEYCODE_MUHENKAN = 2608;
const int32_t KeyEvent::KEYCODE_LINEFEED = 2609;
const int32_t KeyEvent::KEYCODE_MACRO = 2610;
const int32_t KeyEvent::KEYCODE_NUMPAD_PLUSMINUS = 2611;
const int32_t KeyEvent::KEYCODE_SCALE = 2612;
const int32_t KeyEvent::KEYCODE_HANGUEL = 2613;
const int32_t KeyEvent::KEYCODE_HANJA = 2614;
const int32_t KeyEvent::KEYCODE_YEN = 2615;
const int32_t KeyEvent::KEYCODE_STOP = 2616;
const int32_t KeyEvent::KEYCODE_AGAIN = 2617;
const int32_t KeyEvent::KEYCODE_PROPS = 2618;
const int32_t KeyEvent::KEYCODE_UNDO = 2619;
const int32_t KeyEvent::KEYCODE_COPY = 2620;
const int32_t KeyEvent::KEYCODE_OPEN = 2621;
const int32_t KeyEvent::KEYCODE_PASTE = 2622;
const int32_t KeyEvent::KEYCODE_FIND = 2623;
const int32_t KeyEvent::KEYCODE_CUT = 2624;
const int32_t KeyEvent::KEYCODE_HELP = 2625;
const int32_t KeyEvent::KEYCODE_CALC = 2626;
const int32_t KeyEvent::KEYCODE_FILE = 2627;
const int32_t KeyEvent::KEYCODE_BOOKMARKS = 2628;
const int32_t KeyEvent::KEYCODE_NEXT = 2629;
const int32_t KeyEvent::KEYCODE_PLAYPAUSE = 2630;
const int32_t KeyEvent::KEYCODE_PREVIOUS = 2631;
const int32_t KeyEvent::KEYCODE_STOPCD = 2632;
const int32_t KeyEvent::KEYCODE_CONFIG = 2634;
const int32_t KeyEvent::KEYCODE_REFRESH = 2635;
const int32_t KeyEvent::KEYCODE_EXIT = 2636;
const int32_t KeyEvent::KEYCODE_EDIT = 2637;
const int32_t KeyEvent::KEYCODE_SCROLLUP = 2638;
const int32_t KeyEvent::KEYCODE_SCROLLDOWN = 2639;
const int32_t KeyEvent::KEYCODE_NEW = 2640;
const int32_t KeyEvent::KEYCODE_REDO = 2641;
const int32_t KeyEvent::KEYCODE_CLOSE = 2642;
const int32_t KeyEvent::KEYCODE_PLAY = 2643;
const int32_t KeyEvent::KEYCODE_BASSBOOST = 2644;
const int32_t KeyEvent::KEYCODE_PRINT = 2645;
const int32_t KeyEvent::KEYCODE_CHAT = 2646;
const int32_t KeyEvent::KEYCODE_FINANCE = 2647;
const int32_t KeyEvent::KEYCODE_CANCEL = 2648;
const int32_t KeyEvent::KEYCODE_KBDILLUM_TOGGLE = 2649;
const int32_t KeyEvent::KEYCODE_KBDILLUM_DOWN = 2650;
const int32_t KeyEvent::KEYCODE_KBDILLUM_UP = 2651;
const int32_t KeyEvent::KEYCODE_SEND = 2652;
const int32_t KeyEvent::KEYCODE_REPLY = 2653;
const int32_t KeyEvent::KEYCODE_FORWARDMAIL = 2654;
const int32_t KeyEvent::KEYCODE_SAVE = 2655;
const int32_t KeyEvent::KEYCODE_DOCUMENTS = 2656;
const int32_t KeyEvent::KEYCODE_VIDEO_NEXT = 2657;
const int32_t KeyEvent::KEYCODE_VIDEO_PREV = 2658;
const int32_t KeyEvent::KEYCODE_BRIGHTNESS_CYCLE = 2659;
const int32_t KeyEvent::KEYCODE_BRIGHTNESS_ZERO = 2660;
const int32_t KeyEvent::KEYCODE_DISPLAY_OFF = 2661;
const int32_t KeyEvent::KEYCODE_BTN_MISC = 2662;
const int32_t KeyEvent::KEYCODE_GOTO = 2663;
const int32_t KeyEvent::KEYCODE_INFO = 2664;
const int32_t KeyEvent::KEYCODE_PROGRAM = 2665;
const int32_t KeyEvent::KEYCODE_PVR = 2666;
const int32_t KeyEvent::KEYCODE_SUBTITLE = 2667;
const int32_t KeyEvent::KEYCODE_FULL_SCREEN = 2668;
const int32_t KeyEvent::KEYCODE_KEYBOARD = 2669;
const int32_t KeyEvent::KEYCODE_ASPECT_RATIO = 2670;
const int32_t KeyEvent::KEYCODE_PC = 2671;
const int32_t KeyEvent::KEYCODE_TV = 2672;
const int32_t KeyEvent::KEYCODE_TV2 = 2673;
const int32_t KeyEvent::KEYCODE_VCR = 2674;
const int32_t KeyEvent::KEYCODE_VCR2 = 2675;
const int32_t KeyEvent::KEYCODE_SAT = 2676;
const int32_t KeyEvent::KEYCODE_CD = 2677;
const int32_t KeyEvent::KEYCODE_TAPE = 2678;
const int32_t KeyEvent::KEYCODE_TUNER = 2679;
const int32_t KeyEvent::KEYCODE_PLAYER = 2680;
const int32_t KeyEvent::KEYCODE_DVD = 2681;
const int32_t KeyEvent::KEYCODE_AUDIO = 2682;
const int32_t KeyEvent::KEYCODE_VIDEO = 2683;
const int32_t KeyEvent::KEYCODE_MEMO = 2684;
const int32_t KeyEvent::KEYCODE_CALENDAR = 2685;
const int32_t KeyEvent::KEYCODE_RED = 2686;
const int32_t KeyEvent::KEYCODE_GREEN = 2687;
const int32_t KeyEvent::KEYCODE_YELLOW = 2688;
const int32_t KeyEvent::KEYCODE_BLUE = 2689;
const int32_t KeyEvent::KEYCODE_CHANNELUP = 2690;
const int32_t KeyEvent::KEYCODE_CHANNELDOWN = 2691;
const int32_t KeyEvent::KEYCODE_LAST = 2692;
const int32_t KeyEvent::KEYCODE_RESTART = 2693;
const int32_t KeyEvent::KEYCODE_SLOW = 2694;
const int32_t KeyEvent::KEYCODE_SHUFFLE = 2695;
const int32_t KeyEvent::KEYCODE_VIDEOPHONE = 2696;
const int32_t KeyEvent::KEYCODE_GAMES = 2697;
const int32_t KeyEvent::KEYCODE_ZOOMIN = 2698;
const int32_t KeyEvent::KEYCODE_ZOOMOUT = 2699;
const int32_t KeyEvent::KEYCODE_ZOOMRESET = 2700;
const int32_t KeyEvent::KEYCODE_WORDPROCESSOR = 2701;
const int32_t KeyEvent::KEYCODE_EDITOR = 2702;
const int32_t KeyEvent::KEYCODE_SPREADSHEET = 2703;
const int32_t KeyEvent::KEYCODE_GRAPHICSEDITOR = 2704;
const int32_t KeyEvent::KEYCODE_PRESENTATION = 2705;
const int32_t KeyEvent::KEYCODE_DATABASE = 2706;
const int32_t KeyEvent::KEYCODE_NEWS = 2707;
const int32_t KeyEvent::KEYCODE_VOICEMAIL = 2708;
const int32_t KeyEvent::KEYCODE_ADDRESSBOOK = 2709;
const int32_t KeyEvent::KEYCODE_MESSENGER = 2710;
const int32_t KeyEvent::KEYCODE_BRIGHTNESS_TOGGLE = 2711;
const int32_t KeyEvent::KEYCODE_SPELLCHECK = 2712;
const int32_t KeyEvent::KEYCODE_COFFEE = 2713;
const int32_t KeyEvent::KEYCODE_MEDIA_REPEAT = 2714;
const int32_t KeyEvent::KEYCODE_IMAGES = 2715;
const int32_t KeyEvent::KEYCODE_BUTTONCONFIG = 2716;
const int32_t KeyEvent::KEYCODE_TASKMANAGER = 2717;
const int32_t KeyEvent::KEYCODE_JOURNAL = 2718;
const int32_t KeyEvent::KEYCODE_CONTROLPANEL = 2719;
const int32_t KeyEvent::KEYCODE_APPSELECT = 2720;
const int32_t KeyEvent::KEYCODE_SCREENSAVER = 2721;
const int32_t KeyEvent::KEYCODE_ASSISTANT = 2722;
const int32_t KeyEvent::KEYCODE_KBD_LAYOUT_NEXT = 2723;
const int32_t KeyEvent::KEYCODE_BRIGHTNESS_MIN = 2724;
const int32_t KeyEvent::KEYCODE_BRIGHTNESS_MAX = 2725;
const int32_t KeyEvent::KEYCODE_KBDINPUTASSIST_PREV = 2726;
const int32_t KeyEvent::KEYCODE_KBDINPUTASSIST_NEXT = 2727;
const int32_t KeyEvent::KEYCODE_KBDINPUTASSIST_PREVGROUP = 2728;
const int32_t KeyEvent::KEYCODE_KBDINPUTASSIST_NEXTGROUP = 2729;
const int32_t KeyEvent::KEYCODE_KBDINPUTASSIST_ACCEPT = 2730;
const int32_t KeyEvent::KEYCODE_KBDINPUTASSIST_CANCEL = 2731;
const int32_t KeyEvent::KEYCODE_FRONT = 2800;
const int32_t KeyEvent::KEYCODE_SETUP = 2801;
const int32_t KeyEvent::KEYCODE_WAKEUP = 2802;
const int32_t KeyEvent::KEYCODE_SENDFILE = 2803;
const int32_t KeyEvent::KEYCODE_DELETEFILE = 2804;
const int32_t KeyEvent::KEYCODE_XFER = 2805;
const int32_t KeyEvent::KEYCODE_PROG1 = 2806;
const int32_t KeyEvent::KEYCODE_PROG2 = 2807;
const int32_t KeyEvent::KEYCODE_MSDOS = 2808;
const int32_t KeyEvent::KEYCODE_SCREENLOCK = 2809;
const int32_t KeyEvent::KEYCODE_DIRECTION_ROTATE_DISPLAY = 2810;
const int32_t KeyEvent::KEYCODE_CYCLEWINDOWS = 2811;
const int32_t KeyEvent::KEYCODE_COMPUTER = 2812;
const int32_t KeyEvent::KEYCODE_EJECTCLOSECD = 2813;
const int32_t KeyEvent::KEYCODE_ISO = 2814;
const int32_t KeyEvent::KEYCODE_MOVE = 2815;
const int32_t KeyEvent::KEYCODE_F13 = 2816;
const int32_t KeyEvent::KEYCODE_F14 = 2817;
const int32_t KeyEvent::KEYCODE_F15 = 2818;
const int32_t KeyEvent::KEYCODE_F16 = 2819;
const int32_t KeyEvent::KEYCODE_F17 = 2820;
const int32_t KeyEvent::KEYCODE_F18 = 2821;
const int32_t KeyEvent::KEYCODE_F19 = 2822;
const int32_t KeyEvent::KEYCODE_F20 = 2823;
const int32_t KeyEvent::KEYCODE_F21 = 2824;
const int32_t KeyEvent::KEYCODE_F22 = 2825;
const int32_t KeyEvent::KEYCODE_F23 = 2826;
const int32_t KeyEvent::KEYCODE_F24 = 2827;
const int32_t KeyEvent::KEYCODE_PROG3 = 2828;
const int32_t KeyEvent::KEYCODE_PROG4 = 2829;
const int32_t KeyEvent::KEYCODE_DASHBOARD = 2830;
const int32_t KeyEvent::KEYCODE_SUSPEND = 2831;
const int32_t KeyEvent::KEYCODE_HP = 2832;
const int32_t KeyEvent::KEYCODE_SOUND = 2833;
const int32_t KeyEvent::KEYCODE_QUESTION = 2834;
const int32_t KeyEvent::KEYCODE_CONNECT = 2836;
const int32_t KeyEvent::KEYCODE_SPORT = 2837;
const int32_t KeyEvent::KEYCODE_SHOP = 2838;
const int32_t KeyEvent::KEYCODE_ALTERASE = 2839;
const int32_t KeyEvent::KEYCODE_SWITCHVIDEOMODE = 2841;
const int32_t KeyEvent::KEYCODE_BATTERY = 2842;
const int32_t KeyEvent::KEYCODE_BLUETOOTH = 2843;
const int32_t KeyEvent::KEYCODE_WLAN = 2844;
const int32_t KeyEvent::KEYCODE_UWB = 2845;
const int32_t KeyEvent::KEYCODE_WWAN_WIMAX = 2846;
const int32_t KeyEvent::KEYCODE_RFKILL = 2847;
const int32_t KeyEvent::KEYCODE_CHANNEL = 3001;
const int32_t KeyEvent::KEYCODE_BTN_0 = 3100;
const int32_t KeyEvent::KEYCODE_BTN_1 = 3101;
const int32_t KeyEvent::KEYCODE_BTN_2 = 3102;
const int32_t KeyEvent::KEYCODE_BTN_3 = 3103;
const int32_t KeyEvent::KEYCODE_BTN_4 = 3104;
const int32_t KeyEvent::KEYCODE_BTN_5 = 3105;
const int32_t KeyEvent::KEYCODE_BTN_6 = 3106;
const int32_t KeyEvent::KEYCODE_BTN_7 = 3107;
const int32_t KeyEvent::KEYCODE_BTN_8 = 3108;
const int32_t KeyEvent::KEYCODE_BTN_9 = 3109;
const int32_t KeyEvent::KEYCODE_BRL_DOT1 = 3201;
const int32_t KeyEvent::KEYCODE_BRL_DOT2 = 3202;
const int32_t KeyEvent::KEYCODE_BRL_DOT3 = 3203;
const int32_t KeyEvent::KEYCODE_BRL_DOT4 = 3204;
const int32_t KeyEvent::KEYCODE_BRL_DOT5 = 3205;
const int32_t KeyEvent::KEYCODE_BRL_DOT6 = 3206;
const int32_t KeyEvent::KEYCODE_BRL_DOT7 = 3207;
const int32_t KeyEvent::KEYCODE_BRL_DOT8 = 3208;
const int32_t KeyEvent::KEYCODE_BRL_DOT9 = 3209;
const int32_t KeyEvent::KEYCODE_BRL_DOT10 = 3210;
const int32_t KeyEvent::KEYCODE_LEFT_KNOB_ROLL_UP = 10001;
const int32_t KeyEvent::KEYCODE_LEFT_KNOB_ROLL_DOWN = 10002;
const int32_t KeyEvent::KEYCODE_LEFT_KNOB = 10003;
const int32_t KeyEvent::KEYCODE_RIGHT_KNOB_ROLL_UP = 10004;
const int32_t KeyEvent::KEYCODE_RIGHT_KNOB_ROLL_DOWN = 10005;
const int32_t KeyEvent::KEYCODE_RIGHT_KNOB = 10006;
const int32_t KeyEvent::KEYCODE_VOICE_SOURCE_SWITCH = 10007;
const int32_t KeyEvent::KEYCODE_LAUNCHER_MENU = 10008;

const int32_t KeyEvent::KEY_ACTION_UNKNOWN = 0X00000000;
const int32_t KeyEvent::KEY_ACTION_CANCEL = 0X00000001;

const int32_t KeyEvent::KEY_ACTION_DOWN = 0x00000002;
const int32_t KeyEvent::KEY_ACTION_UP = 0X00000003;

KeyEvent::KeyItem::KeyItem() {}

KeyEvent::KeyItem::~KeyItem() {}

int32_t KeyEvent::KeyItem::GetKeyCode() const
{
    return keyCode_;
}

void KeyEvent::KeyItem::SetKeyCode(int32_t keyCode)
{
    keyCode_ = keyCode;
}

int32_t KeyEvent::KeyItem::GetDownTime() const
{
    return downTime_;
}

void KeyEvent::KeyItem::SetDownTime(int32_t downTime)
{
    downTime_ = downTime;
}

int32_t KeyEvent::KeyItem::GetDeviceId() const
{
    return deviceId_;
}

void KeyEvent::KeyItem::SetDeviceId(int32_t deviceId)
{
    deviceId_ = deviceId;
}

bool KeyEvent::KeyItem::IsPressed() const
{
    return pressed_;
}

void KeyEvent::KeyItem::SetPressed(bool pressed)
{
    pressed_ = pressed;
}


bool KeyEvent::KeyItem::WriteToParcel(Parcel &out) const
{
    if (!out.WriteBool(pressed_)) {
        return false;
    }
    if (!out.WriteInt32(downTime_)) {
        return false;
    }
    if (!out.WriteInt32(deviceId_)) {
        return false;
    }
    if (!out.WriteInt32(keyCode_)) {
        return false;
    }

    return true;
}

bool KeyEvent::KeyItem::ReadFromParcel(Parcel &in)
{
    if (!in.ReadBool(pressed_)) {
        return false;
    }
    if (!in.ReadInt32(downTime_)) {
        return false;
    }
    if (!in.ReadInt32(deviceId_)) {
        return false;
    }
    if (!in.ReadInt32(keyCode_)) {
        return false;
    }

    return true;
}

std::shared_ptr<KeyEvent> KeyEvent::from(std::shared_ptr<InputEvent> inputEvent)
{
    return nullptr;
}

KeyEvent::KeyEvent(int32_t eventType) : InputEvent(eventType) {}

KeyEvent::~KeyEvent() {}

std::shared_ptr<KeyEvent> KeyEvent::Create()
{
    return std::shared_ptr<KeyEvent>(new KeyEvent(InputEvent::EVENT_TYPE_KEY));
}

int32_t KeyEvent::GetKeyCode() const
{
    return keyCode_;
}

void KeyEvent::SetKeyCode(int32_t keyCode)
{
    keyCode_ = keyCode;
}

int32_t KeyEvent::GetKeyAction() const
{
    return keyAction_;
}

void KeyEvent::SetKeyAction(int32_t keyAction)
{
    keyAction_ = keyAction;
}

void KeyEvent::AddKeyItem(const KeyItem& keyItem)
{
    keys_.push_back(keyItem);
}

std::vector<KeyEvent::KeyItem> KeyEvent::GetKeyItems()
{
    return keys_;
}

std::vector<int32_t> KeyEvent::GetPressedKeys() const
{
    std::vector<int32_t> result;
    for (const auto &item : keys_) {
        if (item.IsPressed()) {
            result.push_back(item.GetKeyCode());
        }
    }
    return result;
}

void KeyEvent::AddPressedKeyItems(const KeyItem& keyItem)
{
    std::vector<int32_t> pressedkeys = GetPressedKeys();
    std::vector<int32_t>::iterator result = std::find(pressedkeys.begin(),
        pressedkeys.end(), keyItem.GetKeyCode());
    if (result == pressedkeys.end()) {
        keys_.push_back(keyItem);
    }
}

void KeyEvent::RemoveReleasedKeyItems(const KeyItem& keyItem)
{
    std::vector<KeyItem> tempKeyItems = keys_;
    keys_.clear();
    for (const auto &item : tempKeyItems) {
        if (item.GetKeyCode() != keyItem.GetKeyCode()) {
            keys_.push_back(item);
        }
    }
}

const KeyEvent::KeyItem* KeyEvent::GetKeyItem() const
{
    return GetKeyItem(keyCode_);
}

const KeyEvent::KeyItem* KeyEvent::GetKeyItem(int32_t keyCode) const
{
    for (const auto &item : keys_) {
        if (item.GetKeyCode() == keyCode) {
            return &item;
        }
    }
    return nullptr;
}

const char* KeyEvent::ActionToString(int32_t action)
{
    switch (action) {
        case KEY_ACTION_UNKNOWN:
            return "KEY_ACTION_UNKNOWN";
        case KEY_ACTION_CANCEL:
            return "KEY_ACTION_CANCEL";
        case KEY_ACTION_DOWN:
            return "KEY_ACTION_DOWN";
        case KEY_ACTION_UP:
            return "KEY_ACTION_UP";
        default:
            return "KEY_ACTION_INVALID";
    }
}

const char* KeyEvent::KeyCodeToString(int32_t keyCode)
{
    switch (keyCode) {
        case KEYCODE_FN:
            return "KEYCODE_FN";
        case KEYCODE_UNKNOWN:
            return "KEYCODE_UNKNOWN";
        case KEYCODE_HOME:
            return "KEYCODE_HOME";
        case KEYCODE_BACK:
            return "KEYCODE_BACK";
        case KEYCODE_CALL:
            return "KEYCODE_CALL";
        case KEYCODE_ENDCALL:
            return "KEYCODE_ENDCALL";
        case KEYCODE_CLEAR:
            return "KEYCODE_CLEAR";
        case KEYCODE_HEADSETHOOK:
            return "KEYCODE_HEADSETHOOK";
        case KEYCODE_FOCUS:
            return "KEYCODE_FOCUS";
        case KEYCODE_NOTIFICATION:
            return "KEYCODE_NOTIFICATION";
        case KEYCODE_SEARCH:
            return "KEYCODE_SEARCH";
        case KEYCODE_MEDIA_PLAY_PAUSE:
            return "KEYCODE_MEDIA_PLAY_PAUSE";
        case KEYCODE_MEDIA_STOP:
            return "KEYCODE_MEDIA_STOP";
        case KEYCODE_MEDIA_NEXT:
            return "KEYCODE_MEDIA_NEXT";
        case KEYCODE_MEDIA_PREVIOUS:
            return "KEYCODE_MEDIA_PREVIOUS";
        case KEYCODE_MEDIA_REWIND:
            return "KEYCODE_MEDIA_REWIND";
        case KEYCODE_MEDIA_FAST_FORWARD:
            return "KEYCODE_MEDIA_FAST_FORWARD";
        case KEYCODE_VOLUME_UP:
            return "KEYCODE_VOLUME_UP";
        case KEYCODE_VOLUME_DOWN:
            return "KEYCODE_VOLUME_DOWN";
        case KEYCODE_POWER:
            return "KEYCODE_POWER";
        case KEYCODE_CAMERA:
            return "KEYCODE_CAMERA";
        case KEYCODE_VOICE_ASSISTANT:
            return "KEYCODE_VOICE_ASSISTANT";
        case KEYCODE_CUSTOM1:
            return "KEYCODE_CUSTOM1";
        case KEYCODE_VOLUME_MUTE:
            return "KEYCODE_VOLUME_MUTE";
        case KEYCODE_MUTE:
            return "KEYCODE_MUTE";
        case KEYCODE_BRIGHTNESS_UP:
            return "KEYCODE_BRIGHTNESS_UP";
        case KEYCODE_BRIGHTNESS_DOWN:
            return "KEYCODE_BRIGHTNESS_DOWN";
        case KEYCODE_WEAR_1:
            return "KEYCODE_WEAR_1";
        case KEYCODE_0:
            return "KEYCODE_0";
        case KEYCODE_1:
            return "KEYCODE_1";
        case KEYCODE_2:
            return "KEYCODE_2";
        case KEYCODE_3:
            return "KEYCODE_3";
        case KEYCODE_4:
            return "KEYCODE_4";
        case KEYCODE_5:
            return "KEYCODE_5";
        case KEYCODE_6:
            return "KEYCODE_6";
        case KEYCODE_7:
            return "KEYCODE_7";
        case KEYCODE_8:
            return "KEYCODE_8";
        case KEYCODE_9:
            return "KEYCODE_9";
        case KEYCODE_STAR:
            return "KEYCODE_STAR";
        case KEYCODE_POUND:
            return "KEYCODE_POUND";
        case KEYCODE_DPAD_UP:
            return "KEYCODE_DPAD_UP";
        case KEYCODE_DPAD_DOWN:
            return "KEYCODE_DPAD_DOWN";
        case KEYCODE_DPAD_LEFT:
            return "KEYCODE_DPAD_LEFT";
        case KEYCODE_DPAD_RIGHT:
            return "KEYCODE_DPAD_RIGHT";
        case KEYCODE_DPAD_CENTER:
            return "KEYCODE_DPAD_CENTER";
        case KEYCODE_A:
            return "KEYCODE_A";
        case KEYCODE_B:
            return "KEYCODE_B";
        case KEYCODE_C:
            return "KEYCODE_C";
        case KEYCODE_D:
            return "KEYCODE_D";
        case KEYCODE_E:
            return "KEYCODE_E";
        case KEYCODE_F:
            return "KEYCODE_F";
        case KEYCODE_G:
            return "KEYCODE_G";
        case KEYCODE_H:
            return "KEYCODE_H";
        case KEYCODE_I:
            return "KEYCODE_I";
        case KEYCODE_J:
            return "KEYCODE_J";
        case KEYCODE_K:
            return "KEYCODE_K";
        case KEYCODE_L:
            return "KEYCODE_L";
        case KEYCODE_M:
            return "KEYCODE_M";
        case KEYCODE_N:
            return "KEYCODE_N";
        case KEYCODE_O:
            return "KEYCODE_O";
        case KEYCODE_P:
            return "KEYCODE_P";
        case KEYCODE_Q:
            return "KEYCODE_Q";
        case KEYCODE_R:
            return "KEYCODE_R";
        case KEYCODE_S:
            return "KEYCODE_S";
        case KEYCODE_T:
            return "KEYCODE_T";
        case KEYCODE_U:
            return "KEYCODE_U";
        case KEYCODE_V:
            return "KEYCODE_V";
        case KEYCODE_W:
            return "KEYCODE_W";
        case KEYCODE_X:
            return "KEYCODE_X";
        case KEYCODE_Y:
            return "KEYCODE_Y";
        case KEYCODE_Z:
            return "KEYCODE_Z";
        case KEYCODE_COMMA:
            return "KEYCODE_COMMA";
        case KEYCODE_PERIOD:
            return "KEYCODE_PERIOD";
        case KEYCODE_ALT_LEFT:
            return "KEYCODE_ALT_LEFT";
        case KEYCODE_ALT_RIGHT:
            return "KEYCODE_ALT_RIGHT";
        case KEYCODE_SHIFT_LEFT:
            return "KEYCODE_SHIFT_LEFT";
        case KEYCODE_SHIFT_RIGHT:
            return "KEYCODE_SHIFT_RIGHT";
        case KEYCODE_TAB:
            return "KEYCODE_TAB";
        case KEYCODE_SPACE:
            return "KEYCODE_SPACE";
        case KEYCODE_SYM:
            return "KEYCODE_SYM";
        case KEYCODE_EXPLORER:
            return "KEYCODE_EXPLORER";
        case KEYCODE_ENVELOPE:
            return "KEYCODE_ENVELOPE";
        case KEYCODE_ENTER:
            return "KEYCODE_ENTER";
        case KEYCODE_DEL:
            return "KEYCODE_DEL";
        case KEYCODE_GRAVE:
            return "KEYCODE_GRAVE";
        case KEYCODE_MINUS:
            return "KEYCODE_MINUS";
        case KEYCODE_EQUALS:
            return "KEYCODE_EQUALS";
        case KEYCODE_LEFT_BRACKET:
            return "KEYCODE_LEFT_BRACKET";
        case KEYCODE_RIGHT_BRACKET:
            return "KEYCODE_RIGHT_BRACKET";
        case KEYCODE_BACKSLASH:
            return "KEYCODE_BACKSLASH";
        case KEYCODE_SEMICOLON:
            return "KEYCODE_SEMICOLON";
        case KEYCODE_APOSTROPHE:
            return "KEYCODE_APOSTROPHE";
        case KEYCODE_SLASH:
            return "KEYCODE_SLASH";
        case KEYCODE_AT:
            return "KEYCODE_AT";
        case KEYCODE_PLUS:
            return "KEYCODE_PLUS";
        case KEYCODE_MENU:
            return "KEYCODE_MENU";
        case KEYCODE_PAGE_UP:
            return "KEYCODE_PAGE_UP";
        case KEYCODE_PAGE_DOWN:
            return "KEYCODE_PAGE_DOWN";
        case KEYCODE_ESCAPE:
            return "KEYCODE_ESCAPE";
        case KEYCODE_FORWARD_DEL:
            return "KEYCODE_FORWARD_DEL";
        case KEYCODE_CTRL_LEFT:
            return "KEYCODE_CTRL_LEFT";
        case KEYCODE_CTRL_RIGHT:
            return "KEYCODE_CTRL_RIGHT";
        case KEYCODE_CAPS_LOCK:
            return "KEYCODE_CAPS_LOCK";
        case KEYCODE_SCROLL_LOCK:
            return "KEYCODE_SCROLL_LOCK";
        case KEYCODE_META_LEFT:
            return "KEYCODE_META_LEFT";
        case KEYCODE_META_RIGHT:
            return "KEYCODE_META_RIGHT";
        case KEYCODE_FUNCTION:
            return "KEYCODE_FUNCTION";
        case KEYCODE_SYSRQ:
            return "KEYCODE_SYSRQ";
        case KEYCODE_BREAK:
            return "KEYCODE_BREAK";
        case KEYCODE_MOVE_HOME:
            return "KEYCODE_MOVE_HOME";
        case KEYCODE_MOVE_END:
            return "KEYCODE_MOVE_END";
        case KEYCODE_INSERT:
            return "KEYCODE_INSERT";
        case KEYCODE_FORWARD:
            return "KEYCODE_FORWARD";
        case KEYCODE_MEDIA_PLAY:
            return "KEYCODE_MEDIA_PLAY";
        case KEYCODE_MEDIA_PAUSE:
            return "KEYCODE_MEDIA_PAUSE";
        case KEYCODE_MEDIA_CLOSE:
            return "KEYCODE_MEDIA_CLOSE";
        case KEYCODE_MEDIA_EJECT:
            return "KEYCODE_MEDIA_EJECT";
        case KEYCODE_MEDIA_RECORD:
            return "KEYCODE_MEDIA_RECORD";
        case KEYCODE_F1:
            return "KEYCODE_F1";
        case KEYCODE_F2:
            return "KEYCODE_F2";
        case KEYCODE_F3:
            return "KEYCODE_F3";
        case KEYCODE_F4:
            return "KEYCODE_F4";
        case KEYCODE_F5:
            return "KEYCODE_F5";
        case KEYCODE_F6:
            return "KEYCODE_F6";
        case KEYCODE_F7:
            return "KEYCODE_F7";
        case KEYCODE_F8:
            return "KEYCODE_F8";
        case KEYCODE_F9:
            return "KEYCODE_F9";
        case KEYCODE_F10:
            return "KEYCODE_F10";
        case KEYCODE_F11:
            return "KEYCODE_F11";
        case KEYCODE_F12:
            return "KEYCODE_F12";
        case KEYCODE_NUM_LOCK:
            return "KEYCODE_NUM_LOCK";
        case KEYCODE_NUMPAD_0:
            return "KEYCODE_NUMPAD_0";
        case KEYCODE_NUMPAD_1:
            return "KEYCODE_NUMPAD_1";
        case KEYCODE_NUMPAD_2:
            return "KEYCODE_NUMPAD_2";
        case KEYCODE_NUMPAD_3:
            return "KEYCODE_NUMPAD_3";
        case KEYCODE_NUMPAD_4:
            return "KEYCODE_NUMPAD_4";
        case KEYCODE_NUMPAD_5:
            return "KEYCODE_NUMPAD_5";
        case KEYCODE_NUMPAD_6:
            return "KEYCODE_NUMPAD_6";
        case KEYCODE_NUMPAD_7:
            return "KEYCODE_NUMPAD_7";
        case KEYCODE_NUMPAD_8:
            return "KEYCODE_NUMPAD_8";
        case KEYCODE_NUMPAD_9:
            return "KEYCODE_NUMPAD_9";
        case KEYCODE_NUMPAD_DIVIDE:
            return "KEYCODE_NUMPAD_DIVIDE";
        case KEYCODE_NUMPAD_MULTIPLY:
            return "KEYCODE_NUMPAD_MULTIPLY";
        case KEYCODE_NUMPAD_SUBTRACT:
            return "KEYCODE_NUMPAD_SUBTRACT";
        case KEYCODE_NUMPAD_ADD:
            return "KEYCODE_NUMPAD_ADD";
        case KEYCODE_NUMPAD_DOT:
            return "KEYCODE_NUMPAD_DOT";
        case KEYCODE_NUMPAD_COMMA:
            return "KEYCODE_NUMPAD_COMMA";
        case KEYCODE_NUMPAD_ENTER:
            return "KEYCODE_NUMPAD_ENTER";
        case KEYCODE_NUMPAD_EQUALS:
            return "KEYCODE_NUMPAD_EQUALS";
        case KEYCODE_NUMPAD_LEFT_PAREN:
            return "KEYCODE_NUMPAD_LEFT_PAREN";
        case KEYCODE_NUMPAD_RIGHT_PAREN:
            return "KEYCODE_NUMPAD_RIGHT_PAREN";
        case KEYCODE_VIRTUAL_MULTITASK:
            return "KEYCODE_VIRTUAL_MULTITASK";
        case KEYCODE_BUTTON_A:
            return "KEYCODE_BUTTON_A";
        case KEYCODE_BUTTON_B:
            return "KEYCODE_BUTTON_B";
        case KEYCODE_BUTTON_C:
            return "KEYCODE_BUTTON_C";
        case KEYCODE_BUTTON_X:
            return "KEYCODE_BUTTON_X";
        case KEYCODE_BUTTON_Y:
            return "KEYCODE_BUTTON_Y";
        case KEYCODE_BUTTON_Z:
            return "KEYCODE_BUTTON_Z";
        case KEYCODE_BUTTON_L1:
            return "KEYCODE_BUTTON_L1";
        case KEYCODE_BUTTON_R1:
            return "KEYCODE_BUTTON_R1";
        case KEYCODE_BUTTON_L2:
            return "KEYCODE_BUTTON_L2";
        case KEYCODE_BUTTON_R2:
            return "KEYCODE_BUTTON_R2";
        case KEYCODE_BUTTON_SELECT:
            return "KEYCODE_BUTTON_SELECT";
        case KEYCODE_BUTTON_START:
            return "KEYCODE_BUTTON_START";
        case KEYCODE_BUTTON_MODE:
            return "KEYCODE_BUTTON_MODE";
        case KEYCODE_BUTTON_THUMBL:
            return "KEYCODE_BUTTON_THUMBL";
        case KEYCODE_BUTTON_THUMBR:
            return "KEYCODE_BUTTON_THUMBR";
        case KEYCODE_BUTTON_TRIGGER:
            return "KEYCODE_BUTTON_TRIGGER";
        case KEYCODE_BUTTON_THUMB:
            return "KEYCODE_BUTTON_THUMB";
        case KEYCODE_BUTTON_THUMB2:
            return "KEYCODE_BUTTON_THUMB2";
        case KEYCODE_BUTTON_TOP:
            return "KEYCODE_BUTTON_TOP";
        case KEYCODE_BUTTON_TOP2:
            return "KEYCODE_BUTTON_TOP2";
        case KEYCODE_BUTTON_PINKIE:
            return "KEYCODE_BUTTON_PINKIE";
        case KEYCODE_BUTTON_BASE1:
            return "KEYCODE_BUTTON_BASE1";
        case KEYCODE_BUTTON_BASE2:
            return "KEYCODE_BUTTON_BASE2";
        case KEYCODE_BUTTON_BASE3:
            return "KEYCODE_BUTTON_BASE3";
        case KEYCODE_BUTTON_BASE4:
            return "KEYCODE_BUTTON_BASE4";
        case KEYCODE_BUTTON_BASE5:
            return "KEYCODE_BUTTON_BASE5";
        case KEYCODE_BUTTON_BASE6:
            return "KEYCODE_BUTTON_BASE6";
        case KEYCODE_BUTTON_BASE7:
            return "KEYCODE_BUTTON_BASE7";
        case KEYCODE_BUTTON_BASE8:
            return "KEYCODE_BUTTON_BASE8";
        case KEYCODE_BUTTON_BASE9:
            return "KEYCODE_BUTTON_BASE9";
        case KEYCODE_BUTTON_DEAD:
            return "KEYCODE_BUTTON_DEAD";
        case KEYCODE_SLEEP:
            return "KEYCODE_SLEEP";
        case KEYCODE_ZENKAKU_HANKAKU:
            return "KEYCODE_ZENKAKU_HANKAKU";
        case KEYCODE_102ND:
            return "KEYCODE_102ND";
        case KEYCODE_RO:
            return "KEYCODE_RO";
        case KEYCODE_KATAKANA:
            return "KEYCODE_KATAKANA";
        case KEYCODE_HIRAGANA:
            return "KEYCODE_HIRAGANA";
        case KEYCODE_HENKAN:
            return "KEYCODE_HENKAN";
        case KEYCODE_KATAKANA_HIRAGANA:
            return "KEYCODE_KATAKANA_HIRAGANA";
        case KEYCODE_MUHENKAN:
            return "KEYCODE_MUHENKAN";
        case KEYCODE_LINEFEED:
            return "KEYCODE_LINEFEED";
        case KEYCODE_MACRO:
            return "KEYCODE_MACRO";
        case KEYCODE_NUMPAD_PLUSMINUS:
            return "KEYCODE_NUMPAD_PLUSMINUS";
        case KEYCODE_SCALE:
            return "KEYCODE_SCALE";
        case KEYCODE_HANGUEL:
            return "KEYCODE_HANGUEL";
        case KEYCODE_HANJA:
            return "KEYCODE_HANJA";
        case KEYCODE_YEN:
            return "KEYCODE_YEN";
        case KEYCODE_STOP:
            return "KEYCODE_STOP";
        case KEYCODE_AGAIN:
            return "KEYCODE_AGAIN";
        case KEYCODE_PROPS:
            return "KEYCODE_PROPS";
        case KEYCODE_UNDO:
            return "KEYCODE_UNDO";
        case KEYCODE_COPY:
            return "KEYCODE_COPY";
        case KEYCODE_OPEN:
            return "KEYCODE_OPEN";
        case KEYCODE_PASTE:
            return "KEYCODE_PASTE";
        case KEYCODE_FIND:
            return "KEYCODE_FIND";
        case KEYCODE_CUT:
            return "KEYCODE_CUT";
        case KEYCODE_HELP:
            return "KEYCODE_HELP";
        case KEYCODE_CALC:
            return "KEYCODE_CALC";
        case KEYCODE_FILE:
            return "KEYCODE_FILE";
        case KEYCODE_BOOKMARKS:
            return "KEYCODE_BOOKMARKS";
        case KEYCODE_NEXT:
            return "KEYCODE_NEXT";
        case KEYCODE_PLAYPAUSE:
            return "KEYCODE_PLAYPAUSE";
        case KEYCODE_PREVIOUS:
            return "KEYCODE_PREVIOUS";
        case KEYCODE_STOPCD:
            return "KEYCODE_STOPCD";
        case KEYCODE_CONFIG:
            return "KEYCODE_CONFIG";
        case KEYCODE_REFRESH:
            return "KEYCODE_REFRESH";
        case KEYCODE_EXIT:
            return "KEYCODE_EXIT";
        case KEYCODE_EDIT:
            return "KEYCODE_EDIT";
        case KEYCODE_SCROLLUP:
            return "KEYCODE_SCROLLUP";
        case KEYCODE_SCROLLDOWN:
            return "KEYCODE_SCROLLDOWN";
        case KEYCODE_NEW:
            return "KEYCODE_NEW";
        case KEYCODE_REDO:
            return "KEYCODE_REDO";
        case KEYCODE_CLOSE:
            return "KEYCODE_CLOSE";
        case KEYCODE_PLAY:
            return "KEYCODE_PLAY";
        case KEYCODE_BASSBOOST:
            return "KEYCODE_BASSBOOST";
        case KEYCODE_PRINT:
            return "KEYCODE_PRINT";
        case KEYCODE_CHAT:
            return "KEYCODE_CHAT";
        case KEYCODE_FINANCE:
            return "KEYCODE_FINANCE";
        case KEYCODE_CANCEL:
            return "KEYCODE_CANCEL";
        case KEYCODE_KBDILLUM_TOGGLE:
            return "KEYCODE_KBDILLUM_TOGGLE";
        case KEYCODE_KBDILLUM_DOWN:
            return "KEYCODE_KBDILLUM_DOWN";
        case KEYCODE_KBDILLUM_UP:
            return "KEYCODE_KBDILLUM_UP";
        case KEYCODE_SEND:
            return "KEYCODE_SEND";
        case KEYCODE_REPLY:
            return "KEYCODE_REPLY";
        case KEYCODE_FORWARDMAIL:
            return "KEYCODE_FORWARDMAIL";
        case KEYCODE_SAVE:
            return "KEYCODE_SAVE";
        case KEYCODE_DOCUMENTS:
            return "KEYCODE_DOCUMENTS";
        case KEYCODE_VIDEO_NEXT:
            return "KEYCODE_VIDEO_NEXT";
        case KEYCODE_VIDEO_PREV:
            return "KEYCODE_VIDEO_PREV";
        case KEYCODE_BRIGHTNESS_CYCLE:
            return "KEYCODE_BRIGHTNESS_CYCLE";
        case KEYCODE_BRIGHTNESS_ZERO:
            return "KEYCODE_BRIGHTNESS_ZERO";
        case KEYCODE_DISPLAY_OFF:
            return "KEYCODE_DISPLAY_OFF";
        case KEYCODE_BTN_MISC:
            return "KEYCODE_BTN_MISC";
        case KEYCODE_GOTO:
            return "KEYCODE_GOTO";
        case KEYCODE_INFO:
            return "KEYCODE_INFO";
        case KEYCODE_PROGRAM:
            return "KEYCODE_PROGRAM";
        case KEYCODE_PVR:
            return "KEYCODE_PVR";
        case KEYCODE_SUBTITLE:
            return "KEYCODE_SUBTITLE";
        case KEYCODE_FULL_SCREEN:
            return "KEYCODE_FULL_SCREEN";
        case KEYCODE_KEYBOARD:
            return "KEYCODE_KEYBOARD";
        case KEYCODE_ASPECT_RATIO:
            return "KEYCODE_ASPECT_RATIO";
        case KEYCODE_PC:
            return "KEYCODE_PC";
        case KEYCODE_TV:
            return "KEYCODE_TV";
        case KEYCODE_TV2:
            return "KEYCODE_TV2";
        case KEYCODE_VCR:
            return "KEYCODE_VCR";
        case KEYCODE_VCR2:
            return "KEYCODE_VCR2";
        case KEYCODE_SAT:
            return "KEYCODE_SAT";
        case KEYCODE_CD:
            return "KEYCODE_CD";
        case KEYCODE_TAPE:
            return "KEYCODE_TAPE";
        case KEYCODE_TUNER:
            return "KEYCODE_TUNER";
        case KEYCODE_PLAYER:
            return "KEYCODE_PLAYER";
        case KEYCODE_DVD:
            return "KEYCODE_DVD";
        case KEYCODE_AUDIO:
            return "KEYCODE_AUDIO";
        case KEYCODE_VIDEO:
            return "KEYCODE_VIDEO";
        case KEYCODE_MEMO:
            return "KEYCODE_MEMO";
        case KEYCODE_CALENDAR:
            return "KEYCODE_CALENDAR";
        case KEYCODE_RED:
            return "KEYCODE_RED";
        case KEYCODE_GREEN:
            return "KEYCODE_GREEN";
        case KEYCODE_YELLOW:
            return "KEYCODE_YELLOW";
        case KEYCODE_BLUE:
            return "KEYCODE_BLUE";
        case KEYCODE_CHANNELUP:
            return "KEYCODE_CHANNELUP";
        case KEYCODE_CHANNELDOWN:
            return "KEYCODE_CHANNELDOWN";
        case KEYCODE_LAST:
            return "KEYCODE_LAST";
        case KEYCODE_RESTART:
            return "KEYCODE_RESTART";
        case KEYCODE_SLOW:
            return "KEYCODE_SLOW";
        case KEYCODE_SHUFFLE:
            return "KEYCODE_SHUFFLE";
        case KEYCODE_VIDEOPHONE:
            return "KEYCODE_VIDEOPHONE";
        case KEYCODE_GAMES:
            return "KEYCODE_GAMES";
        case KEYCODE_ZOOMIN:
            return "KEYCODE_ZOOMIN";
        case KEYCODE_ZOOMOUT:
            return "KEYCODE_ZOOMOUT";
        case KEYCODE_ZOOMRESET:
            return "KEYCODE_ZOOMRESET";
        case KEYCODE_WORDPROCESSOR:
            return "KEYCODE_WORDPROCESSOR";
        case KEYCODE_EDITOR:
            return "KEYCODE_EDITOR";
        case KEYCODE_SPREADSHEET:
            return "KEYCODE_SPREADSHEET";
        case KEYCODE_GRAPHICSEDITOR:
            return "KEYCODE_GRAPHICSEDITOR";
        case KEYCODE_PRESENTATION:
            return "KEYCODE_PRESENTATION";
        case KEYCODE_DATABASE:
            return "KEYCODE_DATABASE";
        case KEYCODE_NEWS:
            return "KEYCODE_NEWS";
        case KEYCODE_VOICEMAIL:
            return "KEYCODE_VOICEMAIL";
        case KEYCODE_ADDRESSBOOK:
            return "KEYCODE_ADDRESSBOOK";
        case KEYCODE_MESSENGER:
            return "KEYCODE_MESSENGER";
        case KEYCODE_BRIGHTNESS_TOGGLE:
            return "KEYCODE_BRIGHTNESS_TOGGLE";
        case KEYCODE_SPELLCHECK:
            return "KEYCODE_SPELLCHECK";
        case KEYCODE_COFFEE:
            return "KEYCODE_COFFEE";
        case KEYCODE_MEDIA_REPEAT:
            return "KEYCODE_MEDIA_REPEAT";
        case KEYCODE_IMAGES:
            return "KEYCODE_IMAGES";
        case KEYCODE_BUTTONCONFIG:
            return "KEYCODE_BUTTONCONFIG";
        case KEYCODE_TASKMANAGER:
            return "KEYCODE_TASKMANAGER";
        case KEYCODE_JOURNAL:
            return "KEYCODE_JOURNAL";
        case KEYCODE_CONTROLPANEL:
            return "KEYCODE_CONTROLPANEL";
        case KEYCODE_APPSELECT:
            return "KEYCODE_APPSELECT";
        case KEYCODE_SCREENSAVER:
            return "KEYCODE_SCREENSAVER";
        case KEYCODE_ASSISTANT:
            return "KEYCODE_ASSISTANT";
        case KEYCODE_KBD_LAYOUT_NEXT:
            return "KEYCODE_KBD_LAYOUT_NEXT";
        case KEYCODE_BRIGHTNESS_MIN:
            return "KEYCODE_BRIGHTNESS_MIN";
        case KEYCODE_BRIGHTNESS_MAX:
            return "KEYCODE_BRIGHTNESS_MAX";
        case KEYCODE_KBDINPUTASSIST_PREV:
            return "KEYCODE_KBDINPUTASSIST_PREV";
        case KEYCODE_KBDINPUTASSIST_NEXT:
            return "KEYCODE_KBDINPUTASSIST_NEXT";
        case KEYCODE_KBDINPUTASSIST_PREVGROUP:
            return "KEYCODE_KBDINPUTASSIST_PREVGROUP";
        case KEYCODE_KBDINPUTASSIST_NEXTGROUP:
            return "KEYCODE_KBDINPUTASSIST_NEXTGROUP";
        case KEYCODE_KBDINPUTASSIST_ACCEPT:
            return "KEYCODE_KBDINPUTASSIST_ACCEPT";
        case KEYCODE_KBDINPUTASSIST_CANCEL:
            return "KEYCODE_KBDINPUTASSIST_CANCEL";
        case KEYCODE_FRONT:
            return "KEYCODE_FRONT";
        case KEYCODE_SETUP:
            return "KEYCODE_SETUP";
        case KEYCODE_WAKEUP:
            return "KEYCODE_WAKEUP";
        case KEYCODE_SENDFILE:
            return "KEYCODE_SENDFILE";
        case KEYCODE_DELETEFILE:
            return "KEYCODE_DELETEFILE";
        case KEYCODE_XFER:
            return "KEYCODE_XFER";
        case KEYCODE_PROG1:
            return "KEYCODE_PROG1";
        case KEYCODE_PROG2:
            return "KEYCODE_PROG2";
        case KEYCODE_MSDOS:
            return "KEYCODE_MSDOS";
        case KEYCODE_SCREENLOCK:
            return "KEYCODE_SCREENLOCK";
        case KEYCODE_DIRECTION_ROTATE_DISPLAY:
            return "KEYCODE_DIRECTION_ROTATE_DISPLAY";
        case KEYCODE_CYCLEWINDOWS:
            return "KEYCODE_CYCLEWINDOWS";
        case KEYCODE_COMPUTER:
            return "KEYCODE_COMPUTER";
        case KEYCODE_EJECTCLOSECD:
            return "KEYCODE_EJECTCLOSECD";
        case KEYCODE_ISO:
            return "KEYCODE_ISO";
        case KEYCODE_MOVE:
            return "KEYCODE_MOVE";
        case KEYCODE_F13:
            return "KEYCODE_F13";
        case KEYCODE_F14:
            return "KEYCODE_F14";
        case KEYCODE_F15:
            return "KEYCODE_F15";
        case KEYCODE_F16:
            return "KEYCODE_F16";
        case KEYCODE_F17:
            return "KEYCODE_F17";
        case KEYCODE_F18:
            return "KEYCODE_F18";
        case KEYCODE_F19:
            return "KEYCODE_F19";
        case KEYCODE_F20:
            return "KEYCODE_F20";
        case KEYCODE_F21:
            return "KEYCODE_F21";
        case KEYCODE_F22:
            return "KEYCODE_F22";
        case KEYCODE_F23:
            return "KEYCODE_F23";
        case KEYCODE_F24:
            return "KEYCODE_F24";
        case KEYCODE_PROG3:
            return "KEYCODE_PROG3";
        case KEYCODE_PROG4:
            return "KEYCODE_PROG4";
        case KEYCODE_DASHBOARD:
            return "KEYCODE_DASHBOARD";
        case KEYCODE_SUSPEND:
            return "KEYCODE_SUSPEND";
        case KEYCODE_HP:
            return "KEYCODE_HP";
        case KEYCODE_SOUND:
            return "KEYCODE_SOUND";
        case KEYCODE_QUESTION:
            return "KEYCODE_QUESTION";
        case KEYCODE_CONNECT:
            return "KEYCODE_CONNECT";
        case KEYCODE_SPORT:
            return "KEYCODE_SPORT";
        case KEYCODE_SHOP:
            return "KEYCODE_SHOP";
        case KEYCODE_ALTERASE:
            return "KEYCODE_ALTERASE";
        case KEYCODE_SWITCHVIDEOMODE:
            return "KEYCODE_SWITCHVIDEOMODE";
        case KEYCODE_BATTERY:
            return "KEYCODE_BATTERY";
        case KEYCODE_BLUETOOTH:
            return "KEYCODE_BLUETOOTH";
        case KEYCODE_WLAN:
            return "KEYCODE_WLAN";
        case KEYCODE_UWB:
            return "KEYCODE_UWB";
        case KEYCODE_WWAN_WIMAX:
            return "KEYCODE_WWAN_WIMAX";
        case KEYCODE_RFKILL:
            return "KEYCODE_RFKILL";
        case KEYCODE_CHANNEL:
            return "KEYCODE_CHANNEL";
        case KEYCODE_BTN_0:
            return "KEYCODE_BTN_0";
        case KEYCODE_BTN_1:
            return "KEYCODE_BTN_1";
        case KEYCODE_BTN_2:
            return "KEYCODE_BTN_2";
        case KEYCODE_BTN_3:
            return "KEYCODE_BTN_3";
        case KEYCODE_BTN_4:
            return "KEYCODE_BTN_4";
        case KEYCODE_BTN_5:
            return "KEYCODE_BTN_5";
        case KEYCODE_BTN_6:
            return "KEYCODE_BTN_6";
        case KEYCODE_BTN_7:
            return "KEYCODE_BTN_7";
        case KEYCODE_BTN_8:
            return "KEYCODE_BTN_8";
        case KEYCODE_BTN_9:
            return "KEYCODE_BTN_9";
        case KEYCODE_BRL_DOT1:
            return "KEYCODE_BRL_DOT1";
        case KEYCODE_BRL_DOT2:
            return "KEYCODE_BRL_DOT2";
        case KEYCODE_BRL_DOT3:
            return "KEYCODE_BRL_DOT3";
        case KEYCODE_BRL_DOT4:
            return "KEYCODE_BRL_DOT4";
        case KEYCODE_BRL_DOT5:
            return "KEYCODE_BRL_DOT5";
        case KEYCODE_BRL_DOT6:
            return "KEYCODE_BRL_DOT6";
        case KEYCODE_BRL_DOT7:
            return "KEYCODE_BRL_DOT7";
        case KEYCODE_BRL_DOT8:
            return "KEYCODE_BRL_DOT8";
        case KEYCODE_BRL_DOT9:
            return "KEYCODE_BRL_DOT9";
        case KEYCODE_BRL_DOT10:
            return "KEYCODE_BRL_DOT10";
        case KEYCODE_LEFT_KNOB_ROLL_UP:
            return "KEYCODE_LEFT_KNOB_ROLL_UP";
        case KEYCODE_LEFT_KNOB_ROLL_DOWN:
            return "KEYCODE_LEFT_KNOB_ROLL_DOWN";
        case KEYCODE_LEFT_KNOB:
            return "KEYCODE_LEFT_KNOB";
        case KEYCODE_RIGHT_KNOB_ROLL_UP:
            return "KEYCODE_RIGHT_KNOB_ROLL_UP";
        case KEYCODE_RIGHT_KNOB_ROLL_DOWN:
            return "KEYCODE_RIGHT_KNOB_ROLL_DOWN";
        case KEYCODE_RIGHT_KNOB:
            return "KEYCODE_RIGHT_KNOB";
        case KEYCODE_VOICE_SOURCE_SWITCH:
            return "KEYCODE_VOICE_SOURCE_SWITCH";
        case KEYCODE_LAUNCHER_MENU:
            return "KEYCODE_LAUNCHER_MENU";
        default:
            return "KEYCODE_INVALID";

    }
}

std::shared_ptr<KeyEvent> KeyEvent::Clone(std::shared_ptr<KeyEvent> keyEvent) {
    if (!keyEvent) {
        return nullptr;
    }

    return std::shared_ptr<KeyEvent>(new KeyEvent(*keyEvent.get()));
}

bool KeyEvent::IsValidKeyItem() const
{
    HiLog::Debug(LABEL, "KeyEvent::IsValidKeyItem begin");
    int32_t noPressNum = 0;
    int32_t keyCode = GetKeyCode();
    int32_t action = GetKeyAction();
    
    for (auto it = keys_.begin(); it != keys_.end(); it++) {
        if (it->GetKeyCode() <= KEYCODE_UNKNOWN) {
            HiLog::Error(LABEL, "keyCode is invalid");
            return false;
        }
        if (it->GetDownTime() <= 0) {
            HiLog::Error(LABEL, "downtime is invalid");
            return false;
        }
        if (action != KEY_ACTION_UP && it->IsPressed() == false) {
            HiLog::Error(LABEL, "isPressed is invalid");
            return false;
        }
        if (action == KEY_ACTION_UP && it->IsPressed() == false) {
            noPressNum++;
            if (it->GetKeyCode() != keyCode) {
                HiLog::Error(LABEL, "keyCode is invalid when isPressed is false");
                return false;
            }
        }
        
        auto item = it;
        for (++item; item != keys_.end(); item++) {
            if (it->GetKeyCode() == item->GetKeyCode()) {
                HiLog::Error(LABEL, "Keyitems keyCode exist same items");
                return false;
            }
        }
    }
    
    if (noPressNum != 1) {
        HiLog::Error(LABEL, "keyCode is not unique when isPressed is false");
        return false;
    }
    HiLog::Debug(LABEL, "KeyEvent::IsValidKeyItem end");
    return true;
}

bool KeyEvent::IsValid() const
{
    HiLog::Debug(LABEL, "KeyEvent::IsValid begin");
    int32_t keyCode = GetKeyCode();
    if (keyCode <= KEYCODE_UNKNOWN) {
        HiLog::Error(LABEL, "KeyCode_ is invalid");
        return false;
    }
    
    if (GetActionTime() <= 0) {
        HiLog::Error(LABEL, "Actiontime is invalid");
        return false;
    }
    
    int32_t action = GetKeyAction();
    if (action != KEY_ACTION_CANCEL && action != KEY_ACTION_UP &&
        action != KEY_ACTION_DOWN) {
        HiLog::Error(LABEL, "Action is invalid");
        return false;
    }
    
    if (!IsValidKeyItem()) {
        HiLog::Error(LABEL, "IsValidKeyItem is invalid");
        return false;
    }
    HiLog::Debug(LABEL, "KeyEvent::IsValid end");
    return true;
}


bool KeyEvent::WriteToParcel(Parcel &out) const
{
    if (!InputEvent::WriteToParcel(out)) {
        return false;
    }
    if (!out.WriteInt32(keyCode_)) {
        return false;
    }
    if (keys_.size() > INT_MAX) {
        return false;
    }
    if (!out.WriteInt32(static_cast<int32_t>(keys_.size()))) {
        return false;
    }
    for (const auto &item : keys_) {
        if (!item.WriteToParcel(out)) {
            return false;
        }
    }
    if (!out.WriteInt32(keyAction_)) {
        return false;
    }

    return true;
}

bool KeyEvent::ReadFromParcel(Parcel &in)
{
    if (!InputEvent::ReadFromParcel(in)) {
        return false;
    }
    if (!in.ReadInt32(keyCode_)) {
        return false;
    }
    const int32_t keysSize = in.ReadInt32();
    if (keysSize < 0) {
        return false;
    }
    for (int32_t i = 0; i < keysSize; ++i) {
        KeyItem val = {};
        if (!val.ReadFromParcel(in)) {
            return false;
        }
        keys_.push_back(val);
    }
    if (!in.ReadInt32(keyAction_)) {
        return false;
    }

    return true;
}
} // namespace MMI
} // namespace OHOS
