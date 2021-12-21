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

namespace OHOS {
namespace MMI {
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
    for (auto &item : keys_) {
        result.push_back(item.GetKeyCode());
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
    std::vector<int32_t> pressedkeys = GetPressedKeys();
    std::vector<KeyItem> tempKeyItems = keys_;
    std::vector<int32_t>::iterator result = std::find(pressedkeys.begin(),
        pressedkeys.end(), keyItem.GetKeyCode());
    if (result == pressedkeys.end()) {
        return;
    }
    keys_.clear();
    for (KeyItem &item : tempKeyItems) {
        if (item.GetKeyCode() != keyItem.GetKeyCode()) {
            keys_.push_back(item);
        }
    }
}
}
}
