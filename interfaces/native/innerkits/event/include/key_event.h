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
#include "nocopyable.h"
#include "parcel.h"
#include "input_event.h"

namespace OHOS {
namespace MMI {
class KeyEvent : public InputEvent {
public:
    // KEYCODE
    static const int32_t KEYCODE_FN;
    /* *
     * Keycode constant: unknown keycode
     * <p>The keycode is unknown.
     *
     * @since 1
     */
    static const int32_t KEYCODE_UNKNOWN;

    /* *
     * Keycode constant: Home key
     * <p>This key is processed by the framework and will never be sent to the application.
     *
     * @since 1
     */
    static const int32_t KEYCODE_HOME;

    /* *
     * Keycode constant: Back key
     *
     * @since 1
     */
    static const int32_t KEYCODE_BACK;

    /* *
     * Keycode constant: Call key
     *
     * @since 1
     */
    static const int32_t KEYCODE_CALL;

    /* *
     * Keycode constant: End Call key
     *
     * @since 1
     */
    static const int32_t KEYCODE_ENDCALL;

    /* *
     * Keycode constant: Clear key
     *
     * @since 1
     */
    static const int32_t KEYCODE_CLEAR;

    /* *
     * Keycode constant: Headset Hook key
     * <p>The key is used to end a call and stop media.
     *
     * @since 1
     */
    static const int32_t KEYCODE_HEADSETHOOK;

    /* *
     * Keycode constant: Camera Focus key
     * <p>This key is used to enable focus for the camera.
     *
     * @since 1
     */
    static const int32_t KEYCODE_FOCUS;

    /* *
     * Keycode constant: Notification key
     *
     * @since 1
     */
    static const int32_t KEYCODE_NOTIFICATION;

    /* *
     * Keycode constant: Search key
     *
     * @since 1
     */
    static const int32_t KEYCODE_SEARCH;

    /* *
     * Keycode constant: Play/Pause media key
     *
     * @since 1
     */
    static const int32_t KEYCODE_MEDIA_PLAY_PAUSE;

    /* *
     * Keycode constant: Stop media key
     *
     * @since 1
     */
    static const int32_t KEYCODE_MEDIA_STOP;

    /* *
     * Keycode constant: Play Next media key
     *
     * @since 1
     */
    static const int32_t KEYCODE_MEDIA_NEXT;

    /* *
     * Keycode constant: Play Previous media key
     *
     * @since 1
     */
    static const int32_t KEYCODE_MEDIA_PREVIOUS;

    /* *
     * Keycode constant: Rewind media key
     *
     * @since 1
     */
    static const int32_t KEYCODE_MEDIA_REWIND;

    /* *
     * Keycode constant: Fast Forward media key
     *
     * @since 1
     */
    static const int32_t KEYCODE_MEDIA_FAST_FORWARD;

    /* *
     * Turns up the volume.
     *
     * @since 1
     */
    static const int32_t KEYCODE_VOLUME_UP;

    /* *
     * Turns down the volume.
     *
     * @since 1
     */
    static const int32_t KEYCODE_VOLUME_DOWN;

    /* *
     * Presses the power button.
     *
     * @since 1
     */
    static const int32_t KEYCODE_POWER;

    /* *
     * Presses the camera key.
     * <p>It is used to start the camera or take photos.
     *
     * @since 1
     */
    static const int32_t KEYCODE_CAMERA;

    /* *
     * Voice Assistant key
     * <p>This key is used to wake up the voice assistant.
     *
     * @since 1
     */
    static const int32_t KEYCODE_VOICE_ASSISTANT;

    /* *
     * Custom key 1
     * <p>The actions mapping to the custom keys are user-defined. Key values 521-529 are reserved for custom keys.
     *
     * @since 1
     */
    static const int32_t KEYCODE_CUSTOM1;

    static const int32_t KEYCODE_VOLUME_MUTE;
    static const int32_t KEYCODE_MUTE;

    /* *
     * Brightness UP key
     *
     * @since 1
     */
    static const int32_t KEYCODE_BRIGHTNESS_UP;

    /* *
     * Brightness Down key
     *
     * @since 1
     */
    static const int32_t KEYCODE_BRIGHTNESS_DOWN;

    /* *
     * Indicates general-purpose key 1 on the wearables
     *
     * @since 3
     */
    static const int32_t KEYCODE_WEAR_1;

    /* *
     * Keycode constant: '0' key
     *
     * @since 1
     */
    static const int32_t KEYCODE_0;

    /* *
     * Keycode constant: '1' key
     *
     * @since 1
     */
    static const int32_t KEYCODE_1;

    /* *
     * Keycode constant: '2' key
     *
     * @since 1
     */
    static const int32_t KEYCODE_2;

    /* *
     * Keycode constant: '3' key
     *
     * @since 1
     */
    static const int32_t KEYCODE_3;

    /* *
     * Keycode constant: '4' key
     *
     * @since 1
     */
    static const int32_t KEYCODE_4;

    /* *
     * Keycode constant: '5' key
     *
     * @since 1
     */
    static const int32_t KEYCODE_5;

    /* *
     * Keycode constant: '6' key
     *
     * @since 1
     */
    static const int32_t KEYCODE_6;

    /* *
     * Keycode constant: '7' key
     *
     * @since 1
     */
    static const int32_t KEYCODE_7;

    /* *
     * Keycode constant: '8' key
     *
     * @since 1
     */
    static const int32_t KEYCODE_8;

    /* *
     * Keycode constant: '9' key
     *
     * @since 1
     */
    static const int32_t KEYCODE_9;

    /* *
     * Keycode constant: '*' key
     *
     * @since 1
     */
    static const int32_t KEYCODE_STAR;

    /* *
     * Keycode constant: '#' key
     *
     * @since 1
     */
    static const int32_t KEYCODE_POUND;

    /* *
     * Keycode constant: Directional Pad Up key
     * <p>The key may also be synthesized from trackball motions.
     *
     * @since 1
     */
    static const int32_t KEYCODE_DPAD_UP;

    /* *
     * Keycode constant: Directional Pad Down key
     * <p>The key may also be synthesized from trackball motions.
     *
     * @since 1
     */
    static const int32_t KEYCODE_DPAD_DOWN;

    /* *
     * Keycode constant: Directional Pad Left key
     * <p>The key may also be synthesized from trackball motions.
     *
     * @since 1
     */
    static const int32_t KEYCODE_DPAD_LEFT;

    /* *
     * Keycode constant: Directional Pad Right key
     * <p>The key may also be synthesized from trackball motions.
     *
     * @since 1
     */
    static const int32_t KEYCODE_DPAD_RIGHT;

    /* *
     * Keycode constant: Directional Pad Center key
     * <p>The key may also be synthesized from trackball motions.
     *
     * @since 1
     */
    static const int32_t KEYCODE_DPAD_CENTER;

    /* *
     * Keycode constant: 'A' key
     *
     * @since 1
     */
    static const int32_t KEYCODE_A;

    /* *
     * Keycode constant: 'B' key
     *
     * @since 1
     */
    static const int32_t KEYCODE_B;

    /* *
     * Keycode constant: 'C' key
     *
     * @since 1
     */
    static const int32_t KEYCODE_C;

    /* *
     * Keycode constant: 'D' key
     *
     * @since 1
     */
    static const int32_t KEYCODE_D;

    /* *
     * Keycode constant: 'E' key
     *
     * @since 1
     */
    static const int32_t KEYCODE_E;

    /* *
     * Keycode constant: 'F' key
     *
     * @since 1
     */
    static const int32_t KEYCODE_F;

    /* *
     * Keycode constant: 'G' key
     *
     * @since 1
     */
    static const int32_t KEYCODE_G;

    /* *
     * Keycode constant: 'H' key
     *
     * @since 1
     */
    static const int32_t KEYCODE_H;

    /* *
     * Keycode constant: 'I' key
     *
     * @since 1
     */
    static const int32_t KEYCODE_I;

    /* *
     * Keycode constant: 'J' key
     *
     * @since 1
     */
    static const int32_t KEYCODE_J;

    /* *
     * Keycode constant: 'K' key
     *
     * @since 1
     */
    static const int32_t KEYCODE_K;

    /* *
     * Keycode constant: 'L' key
     *
     * @since 1
     */
    static const int32_t KEYCODE_L;

    /* *
     * Keycode constant: 'M' key
     *
     * @since 1
     */
    static const int32_t KEYCODE_M;

    /* *
     * Keycode constant: 'N' key
     *
     * @since 1
     */
    static const int32_t KEYCODE_N;

    /* *
     * Keycode constant: 'O' key
     *
     * @since 1
     */
    static const int32_t KEYCODE_O;

    /* *
     * Keycode constant: 'P' key
     *
     * @since 1
     */
    static const int32_t KEYCODE_P;

    /* *
     * Keycode constant: 'Q' key
     *
     * @since 1
     */
    static const int32_t KEYCODE_Q;

    /* *
     * Keycode constant: 'R' key
     *
     * @since 1
     */
    static const int32_t KEYCODE_R;

    /* *
     * Keycode constant: 'S' key
     *
     * @since 1
     */
    static const int32_t KEYCODE_S;

    /* *
     * Keycode constant: 'T' key
     *
     * @since 1
     */
    static const int32_t KEYCODE_T;

    /* *
     * Keycode constant: 'U' key
     *
     * @since 1
     */
    static const int32_t KEYCODE_U;

    /* *
     * Keycode constant: 'V' key
     *
     * @since 1
     */
    static const int32_t KEYCODE_V;

    /* *
     * Keycode constant: 'W' key
     *
     * @since 1
     */
    static const int32_t KEYCODE_W;

    /* *
     * Keycode constant: 'X' key
     *
     * @since 1
     */
    static const int32_t KEYCODE_X;

    /* *
     * Keycode constant: 'Y' key
     *
     * @since 1
     */
    static const int32_t KEYCODE_Y;

    /* *
     * Keycode constant: 'Z' key
     *
     * @since 1
     */
    static const int32_t KEYCODE_Z;

    /* *
     * Keycode constant: ';' key
     *
     * @since 1
     */
    static const int32_t KEYCODE_COMMA;

    /* *
     * Keycode constant: '.' key
     *
     * @since 1
     */
    static const int32_t KEYCODE_PERIOD;

    /* *
     * Keycode constant: Left Alt modifier key
     *
     * @since 1
     */
    static const int32_t KEYCODE_ALT_LEFT;

    /* *
     * Keycode constant: Right Alt modifier key
     *
     * @since 1
     */
    static const int32_t KEYCODE_ALT_RIGHT;

    /* *
     * Keycode constant: Left Shift modifier key
     *
     * @since 1
     */
    static const int32_t KEYCODE_SHIFT_LEFT;

    /* *
     * Keycode constant: Right Shift modifier key
     *
     * @since 1
     */
    static const int32_t KEYCODE_SHIFT_RIGHT;

    /* *
     * Keycode constant: Tab key
     *
     * @since 1
     */
    static const int32_t KEYCODE_TAB;

    /* *
     * Keycode constant: Space key
     *
     * @since 1
     */
    static const int32_t KEYCODE_SPACE;

    /* *
     * Keycode constant: Symbol modifier key
     * <p>The key is used to input alternate symbols.
     *
     * @since 1
     */
    static const int32_t KEYCODE_SYM;

    /* *
     * Keycode constant: Explorer function key
     * <p>This key is used to launch a browser application.
     *
     * @since 1
     */
    static const int32_t KEYCODE_EXPLORER;

    /* *
     * Keycode constant: Email function key
     * <p>This key is used to launch an email application.
     *
     * @since 1
     */
    static const int32_t KEYCODE_ENVELOPE;

    /* *
     * Keycode constant: Enter key
     *
     * @since 1
     */
    static const int32_t KEYCODE_ENTER;

    /* *
     * Keycode constant: Backspace key
     * <p>Unlike {@link #static const int32_t KEYCODE_FORWARD_DEL}; this key is used to delete characters before the
     * insertion point.
     *
     * @since 1
     */
    static const int32_t KEYCODE_DEL;

    /* *
     * Keycode constant: '`' key (backtick key)
     *
     * @since 1
     */
    static const int32_t KEYCODE_GRAVE;

    /* *
     * Keycode constant: '-' key
     *
     * @since 1
     */
    static const int32_t KEYCODE_MINUS;

    /* *
     * Keycode constant: '=' key
     *
     * @since 1
     */
    static const int32_t KEYCODE_EQUALS;

    /* *
     * Keycode constant: '[' key
     *
     * @since 1
     */
    static const int32_t KEYCODE_LEFT_BRACKET;

    /* *
     * Keycode constant: ']' key
     *
     * @since 1
     */
    static const int32_t KEYCODE_RIGHT_BRACKET;

    /* *
     * Keycode constant: '\' key
     *
     * @since 1
     */
    static const int32_t KEYCODE_BACKSLASH;

    /* *
     * Keycode constant: ';' key
     *
     * @since 1
     */
    static const int32_t KEYCODE_SEMICOLON;

    /* *
     * Keycode constant: ''' key (apostrophe key)
     *
     * @since 1
     */
    static const int32_t KEYCODE_APOSTROPHE;

    /* *
     * Keycode constant: '/' key
     *
     * @since 1
     */
    static const int32_t KEYCODE_SLASH;

    /* *
     * Keycode constant: '{@literal @}' key
     *
     * @since 1
     */
    static const int32_t KEYCODE_AT;

    /* *
     * Keycode constant: '+' key
     *
     * @since 1
     */
    static const int32_t KEYCODE_PLUS;

    /* *
     * Keycode constant: Menu key
     *
     * @since 1
     */
    static const int32_t KEYCODE_MENU;

    /* *
     * Keycode constant: Page Up key
     *
     * @since 1
     */
    static const int32_t KEYCODE_PAGE_UP;

    /* *
     * Keycode constant: Page Down key
     *
     * @since 1
     */
    static const int32_t KEYCODE_PAGE_DOWN;

    /* *
     * Keycode constant: Escape key
     *
     * @since 1
     */
    static const int32_t KEYCODE_ESCAPE;

    /* *
     * Keycode constant: Forward Delete key
     * <p>Unlike {@link #static const int32_t KEYCODE_DEL}; this key is used to delete characters ahead of the insertion
     * point.
     *
     * @since 1
     */
    static const int32_t KEYCODE_FORWARD_DEL;

    /* *
     * Keycode constant: Left Control modifier key
     *
     * @since 1
     */
    static const int32_t KEYCODE_CTRL_LEFT;

    /* *
     * Keycode constant: Right Control modifier key
     *
     * @since 1
     */
    static const int32_t KEYCODE_CTRL_RIGHT;

    /* *
     * Keycode constant: Caps Lock key
     *
     * @since 1
     */
    static const int32_t KEYCODE_CAPS_LOCK;

    /* *
     * Keycode constant: Scroll Lock key
     *
     * @since 1
     */
    static const int32_t KEYCODE_SCROLL_LOCK;

    /* *
     * Keycode constant: Left Meta modifier key
     *
     * @since 1
     */
    static const int32_t KEYCODE_META_LEFT;

    /* *
     * Keycode constant: Right Meta modifier key
     *
     * @since 1
     */
    static const int32_t KEYCODE_META_RIGHT;

    /* *
     * Keycode constant: Function modifier key
     *
     * @since 1
     */
    static const int32_t KEYCODE_FUNCTION;

    /* *
     * Keycode constant: System Request/Print Screen key
     *
     * @since 1
     */
    static const int32_t KEYCODE_SYSRQ;

    /* *
     * Keycode constant: Break/Pause key
     *
     * @since 1
     */
    static const int32_t KEYCODE_BREAK;

    /* *
     * Keycode constant: Home Movement key
     * <p>This key is used to scroll or move the cursor around to the start of a line or to the
     * top of a list.
     *
     * @since 1
     */
    static const int32_t KEYCODE_MOVE_HOME;

    /* *
     * Keycode constant: End Movement key
     * <p>This key is used to scroll or move the cursor around to the end of a line or to the
     * bottom of a list.
     *
     * @since 1
     */
    static const int32_t KEYCODE_MOVE_END;

    /* *
     * Keycode constant: Insert key
     * <p>This key is used to toggle the insert or overwrite edit mode.
     *
     * @since 1
     */
    static const int32_t KEYCODE_INSERT;

    /* *
     * Keycode constant: Forward key
     * <p>This key is used to navigate forward in the history stack. It is a complement of
     * {@link #static const int32_t KEYCODE_BACK}.
     *
     * @since 1
     */
    static const int32_t KEYCODE_FORWARD;

    /* *
     * Keycode constant: Play media key
     *
     * @since 1
     */
    static const int32_t KEYCODE_MEDIA_PLAY;

    /* *
     * Keycode constant: Pause media key
     *
     * @since 1
     */
    static const int32_t KEYCODE_MEDIA_PAUSE;

    /* *
     * Keycode constant: Close media key
     * <p>This key can be used to close a CD tray; for example.
     *
     * @since 1
     */
    static const int32_t KEYCODE_MEDIA_CLOSE;

    /* *
     * Keycode constant: Eject media key
     * <p>This key can be used to eject a CD tray; for example.
     *
     * @since 1
     */
    static const int32_t KEYCODE_MEDIA_EJECT;

    /* *
     * Keycode constant: Record media key
     *
     * @since 1
     */
    static const int32_t KEYCODE_MEDIA_RECORD;

    /* *
     * Keycode constant: F1 key
     *
     * @since 1
     */
    static const int32_t KEYCODE_F1;

    /* *
     * Keycode constant: F2 key
     *
     * @since 1
     */
    static const int32_t KEYCODE_F2;

    /* *
     * Keycode constant: F3 key
     *
     * @since 1
     */
    static const int32_t KEYCODE_F3;

    /* *
     * Keycode constant: F4 key
     *
     * @since 1
     */
    static const int32_t KEYCODE_F4;

    /* *
     * Keycode constant: F5 key
     *
     * @since 1
     */
    static const int32_t KEYCODE_F5;

    /* *
     * Keycode constant: F6 key
     *
     * @since 1
     */
    static const int32_t KEYCODE_F6;

    /* *
     * Keycode constant: F7 key
     *
     * @since 1
     */
    static const int32_t KEYCODE_F7;

    /* *
     * Keycode constant: F8 key
     *
     * @since 1
     */
    static const int32_t KEYCODE_F8;

    /* *
     * Keycode constant: F9 key
     *
     * @since 1
     */
    static const int32_t KEYCODE_F9;

    /* *
     * Keycode constant: F10 key
     *
     * @since 1
     */
    static const int32_t KEYCODE_F10;

    /* *
     * Keycode constant: F11 key
     *
     * @since 1
     */
    static const int32_t KEYCODE_F11;

    /* *
     * Keycode constant: F12 key
     *
     * @since 1
     */
    static const int32_t KEYCODE_F12;

    /* *
     * Keycode constant: Num Lock key
     * <p>This key is used to alter the behavior of other keys on the numeric keypad.
     *
     * @since 1
     */
    static const int32_t KEYCODE_NUM_LOCK;

    /* *
     * Keycode constant: '0' key on the numeric keypad
     *
     * @since 1
     */
    static const int32_t KEYCODE_NUMPAD_0;

    /* *
     * Keycode constant: '1' key on the numeric keypad
     *
     * @since 1
     */
    static const int32_t KEYCODE_NUMPAD_1;

    /* *
     * Keycode constant: '2' key on the numeric keypad
     *
     * @since 1
     */
    static const int32_t KEYCODE_NUMPAD_2;

    /* *
     * Keycode constant: '3' key on the numeric keypad
     *
     * @since 1
     */
    static const int32_t KEYCODE_NUMPAD_3;

    /* *
     * Keycode constant: '4' key on the numeric keypad
     *
     * @since 1
     */
    static const int32_t KEYCODE_NUMPAD_4;

    /* *
     * Keycode constant: '5' key on the numeric keypad
     *
     * @since 1
     */
    static const int32_t KEYCODE_NUMPAD_5;

    /* *
     * Keycode constant: '6' key on the numeric keypad
     *
     * @since 1
     */
    static const int32_t KEYCODE_NUMPAD_6;

    /* *
     * Keycode constant: '7' key on the numeric keypad
     *
     * @since 1
     */
    static const int32_t KEYCODE_NUMPAD_7;

    /* *
     * Keycode constant: '8' key on the numeric keypad
     *
     * @since 1
     */
    static const int32_t KEYCODE_NUMPAD_8;

    /* *
     * Keycode constant: '9' key on the numeric keypad
     *
     * @since 1
     */
    static const int32_t KEYCODE_NUMPAD_9;

    /* *
     * Keycode constant: '/' key (for division) on the numeric keypad
     *
     * @since 1
     */
    static const int32_t KEYCODE_NUMPAD_DIVIDE;

    /* *
     * Keycode constant: '*' key (for multiplication) on the numeric keypad
     *
     * @since 1
     */
    static const int32_t KEYCODE_NUMPAD_MULTIPLY;

    /* *
     * Keycode constant: '-' key (for subtraction) on the numeric keypad
     *
     * @since 1
     */
    static const int32_t KEYCODE_NUMPAD_SUBTRACT;

    /* *
     * Keycode constant: '+' key (for addition) on the numeric keypad
     *
     * @since 1
     */
    static const int32_t KEYCODE_NUMPAD_ADD;

    /* *
     * Key code constant: '.' key (for decimals or digit grouping) on the
     * numeric keypad
     *
     * @since 1
     */
    static const int32_t KEYCODE_NUMPAD_DOT;

    /* *
     * Key code constant: ';' key (for decimals or digit grouping) on the
     * numeric keypad
     *
     * @since 1
     */
    static const int32_t KEYCODE_NUMPAD_COMMA;

    /* *
     * Keycode constant: Enter key on the numeric keypad
     *
     * @since 1
     */
    static const int32_t KEYCODE_NUMPAD_ENTER;

    /* *
     * Keycode constant: '=' key on the numeric keypad
     *
     * @since 1
     */
    static const int32_t KEYCODE_NUMPAD_EQUALS;

    /* *
     * Keycode constant: '(' key on the numeric keypad
     *
     * @since 1
     */
    static const int32_t KEYCODE_NUMPAD_LEFT_PAREN;

    /* *
     * Keycode constant: ')' key on the numeric keypad
     *
     * @since 1
     */
    static const int32_t KEYCODE_NUMPAD_RIGHT_PAREN;

    /* *
     * Key code:  The virtual multitask key
     *
     * @since 1
     */
    static const int32_t KEYCODE_VIRTUAL_MULTITASK;

    /* *
     * Key code:  The handle button key
     *
     * @since 1
     */
    static const int32_t KEYCODE_BUTTON_A;
    static const int32_t KEYCODE_BUTTON_B;
    static const int32_t KEYCODE_BUTTON_C;
    static const int32_t KEYCODE_BUTTON_X;
    static const int32_t KEYCODE_BUTTON_Y;
    static const int32_t KEYCODE_BUTTON_Z;
    static const int32_t KEYCODE_BUTTON_L1;
    static const int32_t KEYCODE_BUTTON_R1;
    static const int32_t KEYCODE_BUTTON_L2;
    static const int32_t KEYCODE_BUTTON_R2;
    static const int32_t KEYCODE_BUTTON_SELECT;
    static const int32_t KEYCODE_BUTTON_START;
    static const int32_t KEYCODE_BUTTON_MODE;
    static const int32_t KEYCODE_BUTTON_THUMBL;
    static const int32_t KEYCODE_BUTTON_THUMBR;

    /* *
     * Key code:  The joystick button key
     *
     * @since 1
     */
    static const int32_t KEYCODE_BUTTON_TRIGGER;
    static const int32_t KEYCODE_BUTTON_THUMB;
    static const int32_t KEYCODE_BUTTON_THUMB2;
    static const int32_t KEYCODE_BUTTON_TOP;
    static const int32_t KEYCODE_BUTTON_TOP2;
    static const int32_t KEYCODE_BUTTON_PINKIE;
    static const int32_t KEYCODE_BUTTON_BASE1;
    static const int32_t KEYCODE_BUTTON_BASE2;
    static const int32_t KEYCODE_BUTTON_BASE3;
    static const int32_t KEYCODE_BUTTON_BASE4;
    static const int32_t KEYCODE_BUTTON_BASE5;
    static const int32_t KEYCODE_BUTTON_BASE6;
    static const int32_t KEYCODE_BUTTON_BASE7;
    static const int32_t KEYCODE_BUTTON_BASE8;
    static const int32_t KEYCODE_BUTTON_BASE9;
    static const int32_t KEYCODE_BUTTON_DEAD;

    static const int32_t KEYCODE_SLEEP;
    static const int32_t KEYCODE_ZENKAKU_HANKAKU;
    static const int32_t KEYCODE_102ND;
    static const int32_t KEYCODE_RO;
    static const int32_t KEYCODE_KATAKANA;
    static const int32_t KEYCODE_HIRAGANA;
    static const int32_t KEYCODE_HENKAN;
    static const int32_t KEYCODE_KATAKANA_HIRAGANA;
    static const int32_t KEYCODE_MUHENKAN;
    static const int32_t KEYCODE_LINEFEED;
    static const int32_t KEYCODE_MACRO;
    static const int32_t KEYCODE_NUMPAD_PLUSMINUS;
    static const int32_t KEYCODE_SCALE;
    static const int32_t KEYCODE_HANGUEL;
    static const int32_t KEYCODE_HANJA;
    static const int32_t KEYCODE_YEN;
    static const int32_t KEYCODE_STOP;
    static const int32_t KEYCODE_AGAIN;
    static const int32_t KEYCODE_PROPS;
    static const int32_t KEYCODE_UNDO;
    static const int32_t KEYCODE_COPY;
    static const int32_t KEYCODE_OPEN;
    static const int32_t KEYCODE_PASTE;
    static const int32_t KEYCODE_FIND;
    static const int32_t KEYCODE_CUT;
    static const int32_t KEYCODE_HELP;
    static const int32_t KEYCODE_CALC;
    static const int32_t KEYCODE_FILE;
    static const int32_t KEYCODE_BOOKMARKS;
    static const int32_t KEYCODE_NEXT;
    static const int32_t KEYCODE_PLAYPAUSE;
    static const int32_t KEYCODE_PREVIOUS;
    static const int32_t KEYCODE_STOPCD;
    static const int32_t KEYCODE_CONFIG;
    static const int32_t KEYCODE_REFRESH;
    static const int32_t KEYCODE_EXIT;
    static const int32_t KEYCODE_EDIT;
    static const int32_t KEYCODE_SCROLLUP;
    static const int32_t KEYCODE_SCROLLDOWN;
    static const int32_t KEYCODE_NEW;
    static const int32_t KEYCODE_REDO;
    static const int32_t KEYCODE_CLOSE;
    static const int32_t KEYCODE_PLAY;
    static const int32_t KEYCODE_BASSBOOST;
    static const int32_t KEYCODE_PRINT;
    static const int32_t KEYCODE_CHAT;
    static const int32_t KEYCODE_FINANCE;
    static const int32_t KEYCODE_CANCEL;
    static const int32_t KEYCODE_KBDILLUM_TOGGLE;
    static const int32_t KEYCODE_KBDILLUM_DOWN;
    static const int32_t KEYCODE_KBDILLUM_UP;
    static const int32_t KEYCODE_SEND;
    static const int32_t KEYCODE_REPLY;
    static const int32_t KEYCODE_FORWARDMAIL;
    static const int32_t KEYCODE_SAVE;
    static const int32_t KEYCODE_DOCUMENTS;
    static const int32_t KEYCODE_VIDEO_NEXT;
    static const int32_t KEYCODE_VIDEO_PREV;
    static const int32_t KEYCODE_BRIGHTNESS_CYCLE;
    static const int32_t KEYCODE_BRIGHTNESS_ZERO;
    static const int32_t KEYCODE_DISPLAY_OFF;
    static const int32_t KEYCODE_BTN_MISC;
    static const int32_t KEYCODE_GOTO;
    static const int32_t KEYCODE_INFO;
    static const int32_t KEYCODE_PROGRAM;
    static const int32_t KEYCODE_PVR;
    static const int32_t KEYCODE_SUBTITLE;
    static const int32_t KEYCODE_FULL_SCREEN;
    static const int32_t KEYCODE_KEYBOARD;
    static const int32_t KEYCODE_ASPECT_RATIO;
    static const int32_t KEYCODE_PC;
    static const int32_t KEYCODE_TV;
    static const int32_t KEYCODE_TV2;
    static const int32_t KEYCODE_VCR;
    static const int32_t KEYCODE_VCR2;
    static const int32_t KEYCODE_SAT;
    static const int32_t KEYCODE_CD;
    static const int32_t KEYCODE_TAPE;
    static const int32_t KEYCODE_TUNER;
    static const int32_t KEYCODE_PLAYER;
    static const int32_t KEYCODE_DVD;
    static const int32_t KEYCODE_AUDIO;
    static const int32_t KEYCODE_VIDEO;
    static const int32_t KEYCODE_MEMO;
    static const int32_t KEYCODE_CALENDAR;
    static const int32_t KEYCODE_RED;
    static const int32_t KEYCODE_GREEN;
    static const int32_t KEYCODE_YELLOW;
    static const int32_t KEYCODE_BLUE;
    static const int32_t KEYCODE_CHANNELUP;
    static const int32_t KEYCODE_CHANNELDOWN;
    static const int32_t KEYCODE_LAST;
    static const int32_t KEYCODE_RESTART;
    static const int32_t KEYCODE_SLOW;
    static const int32_t KEYCODE_SHUFFLE;
    static const int32_t KEYCODE_VIDEOPHONE;
    static const int32_t KEYCODE_GAMES;
    static const int32_t KEYCODE_ZOOMIN;
    static const int32_t KEYCODE_ZOOMOUT;
    static const int32_t KEYCODE_ZOOMRESET;
    static const int32_t KEYCODE_WORDPROCESSOR;
    static const int32_t KEYCODE_EDITOR;
    static const int32_t KEYCODE_SPREADSHEET;
    static const int32_t KEYCODE_GRAPHICSEDITOR;
    static const int32_t KEYCODE_PRESENTATION;
    static const int32_t KEYCODE_DATABASE;
    static const int32_t KEYCODE_NEWS;
    static const int32_t KEYCODE_VOICEMAIL;
    static const int32_t KEYCODE_ADDRESSBOOK;
    static const int32_t KEYCODE_MESSENGER;
    static const int32_t KEYCODE_BRIGHTNESS_TOGGLE;
    static const int32_t KEYCODE_SPELLCHECK;
    static const int32_t KEYCODE_COFFEE;
    static const int32_t KEYCODE_MEDIA_REPEAT;
    static const int32_t KEYCODE_IMAGES;
    static const int32_t KEYCODE_BUTTONCONFIG;
    static const int32_t KEYCODE_TASKMANAGER;
    static const int32_t KEYCODE_JOURNAL;
    static const int32_t KEYCODE_CONTROLPANEL;
    static const int32_t KEYCODE_APPSELECT;
    static const int32_t KEYCODE_SCREENSAVER;
    static const int32_t KEYCODE_ASSISTANT;
    static const int32_t KEYCODE_KBD_LAYOUT_NEXT;
    static const int32_t KEYCODE_BRIGHTNESS_MIN;
    static const int32_t KEYCODE_BRIGHTNESS_MAX;
    static const int32_t KEYCODE_KBDINPUTASSIST_PREV;
    static const int32_t KEYCODE_KBDINPUTASSIST_NEXT;
    static const int32_t KEYCODE_KBDINPUTASSIST_PREVGROUP;
    static const int32_t KEYCODE_KBDINPUTASSIST_NEXTGROUP;
    static const int32_t KEYCODE_KBDINPUTASSIST_ACCEPT;
    static const int32_t KEYCODE_KBDINPUTASSIST_CANCEL;

    static const int32_t KEYCODE_FRONT;
    static const int32_t KEYCODE_SETUP;
    static const int32_t KEYCODE_WAKEUP;
    static const int32_t KEYCODE_SENDFILE;
    static const int32_t KEYCODE_DELETEFILE;
    static const int32_t KEYCODE_XFER;
    static const int32_t KEYCODE_PROG1;
    static const int32_t KEYCODE_PROG2;
    static const int32_t KEYCODE_MSDOS;
    static const int32_t KEYCODE_SCREENLOCK;
    static const int32_t KEYCODE_DIRECTION_ROTATE_DISPLAY;
    static const int32_t KEYCODE_CYCLEWINDOWS;
    static const int32_t KEYCODE_COMPUTER;
    static const int32_t KEYCODE_EJECTCLOSECD;
    static const int32_t KEYCODE_ISO;
    static const int32_t KEYCODE_MOVE;
    static const int32_t KEYCODE_F13;
    static const int32_t KEYCODE_F14;
    static const int32_t KEYCODE_F15;
    static const int32_t KEYCODE_F16;
    static const int32_t KEYCODE_F17;
    static const int32_t KEYCODE_F18;
    static const int32_t KEYCODE_F19;
    static const int32_t KEYCODE_F20;
    static const int32_t KEYCODE_F21;
    static const int32_t KEYCODE_F22;
    static const int32_t KEYCODE_F23;
    static const int32_t KEYCODE_F24;
    static const int32_t KEYCODE_PROG3;
    static const int32_t KEYCODE_PROG4;
    static const int32_t KEYCODE_DASHBOARD;
    static const int32_t KEYCODE_SUSPEND;
    static const int32_t KEYCODE_HP;
    static const int32_t KEYCODE_SOUND;
    static const int32_t KEYCODE_QUESTION;
    static const int32_t KEYCODE_CONNECT;
    static const int32_t KEYCODE_SPORT;
    static const int32_t KEYCODE_SHOP;
    static const int32_t KEYCODE_ALTERASE;
    static const int32_t KEYCODE_SWITCHVIDEOMODE;
    static const int32_t KEYCODE_BATTERY;
    static const int32_t KEYCODE_BLUETOOTH;
    static const int32_t KEYCODE_WLAN;
    static const int32_t KEYCODE_UWB;
    static const int32_t KEYCODE_WWAN_WIMAX;
    static const int32_t KEYCODE_RFKILL;

    static const int32_t KEYCODE_CHANNEL;
    static const int32_t KEYCODE_BTN_0;
    static const int32_t KEYCODE_BTN_1;
    static const int32_t KEYCODE_BTN_2;
    static const int32_t KEYCODE_BTN_3;
    static const int32_t KEYCODE_BTN_4;
    static const int32_t KEYCODE_BTN_5;
    static const int32_t KEYCODE_BTN_6;
    static const int32_t KEYCODE_BTN_7;
    static const int32_t KEYCODE_BTN_8;
    static const int32_t KEYCODE_BTN_9;

    static const int32_t KEYCODE_BRL_DOT1;
    static const int32_t KEYCODE_BRL_DOT2;
    static const int32_t KEYCODE_BRL_DOT3;
    static const int32_t KEYCODE_BRL_DOT4;
    static const int32_t KEYCODE_BRL_DOT5;
    static const int32_t KEYCODE_BRL_DOT6;
    static const int32_t KEYCODE_BRL_DOT7;
    static const int32_t KEYCODE_BRL_DOT8;
    static const int32_t KEYCODE_BRL_DOT9;
    static const int32_t KEYCODE_BRL_DOT10;

    /* *
     * Left Knob roll-up
     * <p>In contrast to {@link #static const int32_t KEYCODE_LEFT_KNOB_ROLL_DOWN}; it means rolling
     * the left knob upwards. The knob functionis scenario-specific; for example;
     * increasing the volume or air conditioner temperature.
     *
     * @since 1
     */
    static const int32_t KEYCODE_LEFT_KNOB_ROLL_UP;
    /* *
     * Left Knob roll-down
     * <p>In contrast to {@link #static const int32_t KEYCODE_LEFT_KNOB_ROLL_UP};
     * it means rolling the left knob downwards. The knob function is
     * scenario-specific; for example; reducing the volume or air
     * conditioner temperature.
     * @since 1
     */
    static const int32_t KEYCODE_LEFT_KNOB_ROLL_DOWN;

    /* *
     * Left Knob
     * <p>Pressing the knob will activate its adjustment function.
     *
     * @since 1
     */
    static const int32_t KEYCODE_LEFT_KNOB;
    /* *
     * Right Knob roll-up
     * <p>In contrast to {@link #static const int32_t KEYCODE_RIGHT_KNOB_ROLL_DOWN}; it means rolling
     * the right knob upwards. The knobfunction is scenario-specific; for example;
     * increasing the volume or air conditioner temperature.
     *
     *
     * @since 1
     */
    static const int32_t KEYCODE_RIGHT_KNOB_ROLL_UP;
    /* *
     * Right Knob roll-down
     * <p>In contrast to {@link #static const int32_t KEYCODE_RIGHT_KNOB_ROLL_UP}; it means rolling
     * the right knob downwards. The knobfunction is scenario-specific;
     * for example; reducing the volume or air conditioner temperature.
     *
     * @since 1
     */
    static const int32_t KEYCODE_RIGHT_KNOB_ROLL_DOWN;
    /* *
     * Right Knob
     * <p>Pressing the knob will activate its adjustment function.
     *
     * @since 1
     */
    static const int32_t KEYCODE_RIGHT_KNOB;
    /* *
     * Audio Source Switch button
     * <p>Pressing this button will enable the audio source. Depending on the
     * actual scenario; it may also indicate that the Bluetooth call control
     * button is pressed.
     * @since 1
     */
    static const int32_t KEYCODE_VOICE_SOURCE_SWITCH;
    /* *
     * Menu key
     * <p>Pressing this key will display the launcher page.
     *
     * @since 1
     */
    static const int32_t KEYCODE_LAUNCHER_MENU;

    // Unknown key action. Usually used to indicate the initial invalid value
    static const int32_t KEY_ACTION_UNKNOWN;
    // Indicates cancel action.
    // When the button is pressed, and the lifting action cannot be reported normally, report the key event of this
    // action
    static const int32_t KEY_ACTION_CANCEL;

    // Indicates key press action
    static const int32_t KEY_ACTION_DOWN;
    // Indicates key release action
    static const int32_t KEY_ACTION_UP;

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
    KeyEvent(const KeyEvent& other);
    KeyEvent& operator=(const KeyEvent& other) = delete;
    DISALLOW_MOVE(KeyEvent);
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
} // namespace MMI
} // namespace OHOS
#endif // KEY_EVENT_H