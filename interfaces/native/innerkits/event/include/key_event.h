/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include <optional>
#include "parcel.h"

#include "input_event.h"

namespace OHOS {
namespace MMI {
class KeyEvent : public InputEvent {
public:
    /**
     * Unknown function key
     *
     * @since 9
     */
    static const int32_t UNKNOWN_FUNCTION_KEY;

    /**
     * Num Lock key
     *
     * @since 9
     */
    static const int32_t NUM_LOCK_FUNCTION_KEY;

    /**
     * Caps Lock key
     *
     * @since 9
     */
    static const int32_t CAPS_LOCK_FUNCTION_KEY;

    /**
     * Scroll Lock key
     *
     * @since 9
     */
    static const int32_t SCROLL_LOCK_FUNCTION_KEY;

    /**
     * Function (Fn) key
     *
     * @since 9
     */
    static const int32_t KEYCODE_FN;

    /**
     * Unknown keycode
     *
     *
     * @since 9
     */
    static const int32_t KEYCODE_UNKNOWN;

    /**
     * Home key
     * <p>This key is processed by the framework and will never be sent to the application.
     *
     * @since 9
     */
    static const int32_t KEYCODE_HOME;

    /**
     * Back key
     *
     * @since 9
     */
    static const int32_t KEYCODE_BACK;

    /**
     * Call key
     *
     * @since 9
     */
    static const int32_t KEYCODE_CALL;

    /**
     * End Call key
     *
     * @since 9
     */
    static const int32_t KEYCODE_ENDCALL;

    /**
     * Clear key
     *
     * @since 9
     */
    static const int32_t KEYCODE_CLEAR;

    /**
     * Headset Hook key
     * <p>This key is used to end a call and stop media.
     *
     * @since 9
     */
    static const int32_t KEYCODE_HEADSETHOOK;

    /**
     * Focus key
     * <p>This key is used to enable focus for the camera.
     *
     * @since 9
     */
    static const int32_t KEYCODE_FOCUS;

    /**
     * Notification key
     *
     * @since 9
     */
    static const int32_t KEYCODE_NOTIFICATION;

    /**
     * Search key
     *
     * @since 9
     */
    static const int32_t KEYCODE_SEARCH;

    /**
     * Play/Pause media key
     *
     * @since 9
     */
    static const int32_t KEYCODE_MEDIA_PLAY_PAUSE;

    /**
     * Stop media key
     *
     * @since 9
     */
    static const int32_t KEYCODE_MEDIA_STOP;

    /**
     * Play Next media key
     *
     * @since 9
     */
    static const int32_t KEYCODE_MEDIA_NEXT;

    /**
     * Play Previous media key
     *
     * @since 9
     */
    static const int32_t KEYCODE_MEDIA_PREVIOUS;

    /**
     * Rewind media key
     *
     * @since 9
     */
    static const int32_t KEYCODE_MEDIA_REWIND;

    /**
     * Fast Forward media key
     *
     * @since 9
     */
    static const int32_t KEYCODE_MEDIA_FAST_FORWARD;

    /**
     * Volume Up key
     *
     * @since 9
     */
    static const int32_t KEYCODE_VOLUME_UP;

    /**
     * Volume Down key
     *
     * @since 9
     */
    static const int32_t KEYCODE_VOLUME_DOWN;

    /**
     * Power key
     *
     * @since 9
     */
    static const int32_t KEYCODE_POWER;

    /**
     * Remote Power KeyCode
     *
     * @since 9
     */
    static const int32_t KEYCODE_REMOTE_POWER;

    /**
     * Camera key
     * <p>This key is used to start the camera or take photos.
     *
     * @since 9
     */
    static const int32_t KEYCODE_CAMERA;

    /**
     * Voice Assistant key
     * <p>This key is used to wake up the voice assistant.
     *
     * @since 9
     */
    static const int32_t KEYCODE_VOICE_ASSISTANT;

    /**
     * Custom key 1
     * <p>The actions mapping to the custom keys are user-defined.
     * Key values 521-529 are reserved for custom keys.
     *
     * @since 9
     */
    static const int32_t KEYCODE_CUSTOM1;

    /**
     * Volume Mute key
     *
     * @since 9
     */
    static const int32_t KEYCODE_VOLUME_MUTE;

    /**
     * Mute key
     *
     * @since 9
     */
    static const int32_t KEYCODE_MUTE;

    /**
     * Brightness Up key
     *
     * @since 9
     */
    static const int32_t KEYCODE_BRIGHTNESS_UP;

    /**
     * Brightness Down key
     *
     * @since 9
     */
    static const int32_t KEYCODE_BRIGHTNESS_DOWN;

    /**
     * General-purpose key 1 on wearables
     *
     * @since 3
     */
    static const int32_t KEYCODE_WEAR_1;

    /**
     * Number 0 key
     *
     * @since 9
     */
    static const int32_t KEYCODE_0;

    /**
     * Number 1 key
     *
     * @since 9
     */
    static const int32_t KEYCODE_1;

    /**
     * Number 2 key
     *
     * @since 9
     */
    static const int32_t KEYCODE_2;

    /**
     * Number 3 key
     *
     * @since 9
     */
    static const int32_t KEYCODE_3;

    /**
     * Number 4 key
     *
     * @since 9
     */
    static const int32_t KEYCODE_4;

    /**
     * Number 5 key
     *
     * @since 9
     */
    static const int32_t KEYCODE_5;

    /**
     * Number 6 key
     *
     * @since 9
     */
    static const int32_t KEYCODE_6;

    /**
     * Number 7 key
     *
     * @since 9
     */
    static const int32_t KEYCODE_7;

    /**
     * Number 8 key
     *
     * @since 9
     */
    static const int32_t KEYCODE_8;

    /**
     * Number 9 key
     *
     * @since 9
     */
    static const int32_t KEYCODE_9;

    /**
     * Star (*) key
     *
     * @since 9
     */
    static const int32_t KEYCODE_STAR;

    /**
     * Pound (#) key
     *
     * @since 9
     */
    static const int32_t KEYCODE_POUND;

    /**
     * Directional Pad Up key
     * <p>This key may be synthesized from trackball motions.
     *
     * @since 9
     */
    static const int32_t KEYCODE_DPAD_UP;

    /**
     * Directional Pad Down key
     * <p>This key may be synthesized from trackball motions.
     *
     * @since 9
     */
    static const int32_t KEYCODE_DPAD_DOWN;

    /**
     * Directional Pad Left key
     * <p>This key may be synthesized from trackball motions.
     *
     * @since 9
     */
    static const int32_t KEYCODE_DPAD_LEFT;

    /**
     * Directional Pad Right key
     * <p>This key may be synthesized from trackball motions.
     *
     * @since 9
     */
    static const int32_t KEYCODE_DPAD_RIGHT;

    /**
     * Directional Pad Center key
     * <p>This key may be synthesized from trackball motions.
     *
     * @since 9
     */
    static const int32_t KEYCODE_DPAD_CENTER;

    /**
     * Letter A key
     *
     * @since 9
     */
    static const int32_t KEYCODE_A;

    /**
     * Letter B key
     *
     * @since 9
     */
    static const int32_t KEYCODE_B;

    /**
     * Letter C key
     *
     * @since 9
     */
    static const int32_t KEYCODE_C;

    /**
     * Letter D key
     *
     * @since 9
     */
    static const int32_t KEYCODE_D;

    /**
     * Letter E key
     *
     * @since 9
     */
    static const int32_t KEYCODE_E;

    /**
     * Letter F key
     *
     * @since 9
     */
    static const int32_t KEYCODE_F;

    /**
     * Letter G key
     *
     * @since 9
     */
    static const int32_t KEYCODE_G;

    /**
     * Letter H key
     *
     * @since 9
     */
    static const int32_t KEYCODE_H;

    /**
     * Letter I key
     *
     * @since 9
     */
    static const int32_t KEYCODE_I;

    /**
     * Letter J key
     *
     * @since 9
     */
    static const int32_t KEYCODE_J;

    /**
     * Letter K key
     *
     * @since 9
     */
    static const int32_t KEYCODE_K;

    /**
     * Letter L key
     *
     * @since 9
     */
    static const int32_t KEYCODE_L;

    /**
     * Letter M key
     *
     * @since 9
     */
    static const int32_t KEYCODE_M;

    /**
     * Letter N key
     *
     * @since 9
     */
    static const int32_t KEYCODE_N;

    /**
     * Letter O key
     *
     * @since 9
     */
    static const int32_t KEYCODE_O;

    /**
     * Letter P key
     *
     * @since 9
     */
    static const int32_t KEYCODE_P;

    /**
     * Letter Q key
     *
     * @since 9
     */
    static const int32_t KEYCODE_Q;

    /**
     * Letter R key
     *
     * @since 9
     */
    static const int32_t KEYCODE_R;

    /**
     * Letter S key
     *
     * @since 9
     */
    static const int32_t KEYCODE_S;

    /**
     * Letter T key
     *
     * @since 9
     */
    static const int32_t KEYCODE_T;

    /**
     * Letter U key
     *
     * @since 9
     */
    static const int32_t KEYCODE_U;

    /**
     * Letter V key
     *
     * @since 9
     */
    static const int32_t KEYCODE_V;

    /**
     * Letter W key
     *
     * @since 9
     */
    static const int32_t KEYCODE_W;

    /**
     * Letter X key
     *
     * @since 9
     */
    static const int32_t KEYCODE_X;

    /**
     * Letter Y key
     *
     * @since 9
     */
    static const int32_t KEYCODE_Y;

    /**
     * Letter Z key
     *
     * @since 9
     */
    static const int32_t KEYCODE_Z;

    /**
     * Semicolon (;) key
     *
     * @since 9
     */
    static const int32_t KEYCODE_COMMA;

    /**
     * Period (.) key
     *
     * @since 9
     */
    static const int32_t KEYCODE_PERIOD;

    /**
     * Left Alt modifier key
     *
     * @since 9
     */
    static const int32_t KEYCODE_ALT_LEFT;

    /**
     * Right Alt modifier key
     *
     * @since 9
     */
    static const int32_t KEYCODE_ALT_RIGHT;

    /**
     * Left Shift modifier key
     *
     * @since 9
     */
    static const int32_t KEYCODE_SHIFT_LEFT;

    /**
     * Right Shift modifier key
     *
     * @since 9
     */
    static const int32_t KEYCODE_SHIFT_RIGHT;

    /**
     * Tab key
     *
     * @since 9
     */
    static const int32_t KEYCODE_TAB;

    /**
     * Space key
     *
     * @since 9
     */
    static const int32_t KEYCODE_SPACE;

    /**
     * Symbol modifier key
     * <p>This key is used to input alternate symbols.
     *
     * @since 9
     */
    static const int32_t KEYCODE_SYM;

    /**
     * Explorer function key
     * <p>This key is used to launch a browser application.
     *
     * @since 9
     */
    static const int32_t KEYCODE_EXPLORER;

    /**
     * Email function key
     * <p>This key is used to launch an email application.
     *
     * @since 9
     */
    static const int32_t KEYCODE_ENVELOPE;

    /**
     * Enter key
     *
     * @since 9
     */
    static const int32_t KEYCODE_ENTER;

    /**
     * Backspace key
     * <p>Unlike {@link #static const int32_t KEYCODE_FORWARD_DEL},
     * this key is used to delete characters before the insertion point.
     *
     * @since 9
     */
    static const int32_t KEYCODE_DEL;

    /**
     * Backtick (') key
     *
     * @since 9
     */
    static const int32_t KEYCODE_GRAVE;

    /**
     * Minus (-) key
     *
     * @since 9
     */
    static const int32_t KEYCODE_MINUS;

    /**
     * Equals (=) key
     *
     * @since 9
     */
    static const int32_t KEYCODE_EQUALS;

    /**
     * Left bracket ([) key
     *
     * @since 9
     */
    static const int32_t KEYCODE_LEFT_BRACKET;

    /**
     * Right bracket (]) key
     *
     * @since 9
     */
    static const int32_t KEYCODE_RIGHT_BRACKET;

    /**
     * Backslash (\) key
     *
     * @since 9
     */
    static const int32_t KEYCODE_BACKSLASH;

    /**
     * Semicolon (;) key
     *
     * @since 9
     */
    static const int32_t KEYCODE_SEMICOLON;

    /**
     * Apostrophe (') key
     *
     * @since 9
     */
    static const int32_t KEYCODE_APOSTROPHE;

    /**
     * Slash (/) key
     *
     * @since 9
     */
    static const int32_t KEYCODE_SLASH;

    /**
     * At (@) key
     *
     * @since 9
     */
    static const int32_t KEYCODE_AT;

    /**
     * Plus (+) key
     *
     * @since 9
     */
    static const int32_t KEYCODE_PLUS;

    /**
     * Menu key
     *
     * @since 9
     */
    static const int32_t KEYCODE_MENU;

    /**
     * Page Up key
     *
     * @since 9
     */
    static const int32_t KEYCODE_PAGE_UP;

    /**
     * Page Down key
     *
     * @since 9
     */
    static const int32_t KEYCODE_PAGE_DOWN;

    /**
     * Escape key
     *
     * @since 9
     */
    static const int32_t KEYCODE_ESCAPE;

    /**
     * Forward Delete key
     * <p>Unlike {@link #static const int32_t KEYCODE_DEL},
     * this key is used to delete characters ahead of the insertion point.
     *
     * @since 9
     */
    static const int32_t KEYCODE_FORWARD_DEL;

    /**
     * Left Control modifier key
     *
     * @since 9
     */
    static const int32_t KEYCODE_CTRL_LEFT;

    /**
     * Right Control modifier key
     *
     * @since 9
     */
    static const int32_t KEYCODE_CTRL_RIGHT;

    /**
     * Caps Lock key
     *
     * @since 9
     */
    static const int32_t KEYCODE_CAPS_LOCK;

    /**
     * Scroll Lock key
     *
     * @since 9
     */
    static const int32_t KEYCODE_SCROLL_LOCK;

    /**
     * Left Meta modifier key
     *
     * @since 9
     */
    static const int32_t KEYCODE_META_LEFT;

    /**
     * Right Meta modifier key
     *
     * @since 9
     */
    static const int32_t KEYCODE_META_RIGHT;

    /**
     * Function modifier key
     *
     * @since 9
     */
    static const int32_t KEYCODE_FUNCTION;

    /**
     * System Request/Print Screen key
     *
     * @since 9
     */
    static const int32_t KEYCODE_SYSRQ;

    /**
     * Break/Pause key
     *
     * @since 9
     */
    static const int32_t KEYCODE_BREAK;

    /**
     * Home Movement key
     * <p>This key is used to scroll or move the cursor around to the start of a line or to the
     * top of a list.
     *
     * @since 9
     */
    static const int32_t KEYCODE_MOVE_HOME;

    /**
     * End Movement key
     * <p>This key is used to scroll or move the cursor around to the end of a line or to the
     * bottom of a list.
     *
     * @since 9
     */
    static const int32_t KEYCODE_MOVE_END;

    /**
     * Insert key
     * <p>This key is used to toggle the insert or overwrite edit mode.
     *
     * @since 9
     */
    static const int32_t KEYCODE_INSERT;

    /**
     * Forward key
     * <p>This key is used to navigate forward in the history stack.
     * It is a complement of {@link #static const int32_t KEYCODE_BACK}.
     *
     * @since 9
     */
    static const int32_t KEYCODE_FORWARD;

    /**
     * Play media key
     *
     * @since 9
     */
    static const int32_t KEYCODE_MEDIA_PLAY;

    /**
     * Pause media key
     *
     * @since 9
     */
    static const int32_t KEYCODE_MEDIA_PAUSE;

    /**
     * Close media key
     * <p>This key can be used to close a CD tray, for example.
     *
     * @since 9
     */
    static const int32_t KEYCODE_MEDIA_CLOSE;

    /**
     * Eject media key
     * <p>This key can be used to eject a CD tray, for example.
     *
     * @since 9
     */
    static const int32_t KEYCODE_MEDIA_EJECT;

    /**
     * Record media key
     *
     * @since 9
     */
    static const int32_t KEYCODE_MEDIA_RECORD;

    /**
     * F1 key
     *
     * @since 9
     */
    static const int32_t KEYCODE_F1;

    /**
     * F2 key
     *
     * @since 9
     */
    static const int32_t KEYCODE_F2;

    /**
     * F3 key
     *
     * @since 9
     */
    static const int32_t KEYCODE_F3;

    /**
     * F4 key
     *
     * @since 9
     */
    static const int32_t KEYCODE_F4;

    /**
     * F5 key
     *
     * @since 9
     */
    static const int32_t KEYCODE_F5;

    /**
     * F6 key
     *
     * @since 9
     */
    static const int32_t KEYCODE_F6;

    /**
     * F7 key
     *
     * @since 9
     */
    static const int32_t KEYCODE_F7;

    /**
     * F8 key
     *
     * @since 9
     */
    static const int32_t KEYCODE_F8;

    /**
     * F9 key
     *
     * @since 9
     */
    static const int32_t KEYCODE_F9;

    /**
     * F10 key
     *
     * @since 9
     */
    static const int32_t KEYCODE_F10;

    /**
     * F11 key
     *
     * @since 9
     */
    static const int32_t KEYCODE_F11;

    /**
     * F12 key
     *
     * @since 9
     */
    static const int32_t KEYCODE_F12;

    /**
     * Number Lock key
     * <p>This key is used to alter the behavior of other keys on the numeric keypad.
     *
     * @since 9
     */
    static const int32_t KEYCODE_NUM_LOCK;

    /**
     * Number 0 key on the numeric keypad
     *
     * @since 9
     */
    static const int32_t KEYCODE_NUMPAD_0;

    /**
     * Number 1 key on the numeric keypad
     *
     * @since 9
     */
    static const int32_t KEYCODE_NUMPAD_1;

    /**
     * Number 2 key on the numeric keypad
     *
     * @since 9
     */
    static const int32_t KEYCODE_NUMPAD_2;

    /**
     * Number 3 key on the numeric keypad
     *
     * @since 9
     */
    static const int32_t KEYCODE_NUMPAD_3;

    /**
     * Number 4 key on the numeric keypad
     *
     * @since 9
     */
    static const int32_t KEYCODE_NUMPAD_4;

    /**
     * Number 5 key on the numeric keypad
     *
     * @since 9
     */
    static const int32_t KEYCODE_NUMPAD_5;

    /**
     * Number 6 key on the numeric keypad
     *
     * @since 9
     */
    static const int32_t KEYCODE_NUMPAD_6;

    /**
     * Number 7 key on the numeric keypad
     *
     * @since 9
     */
    static const int32_t KEYCODE_NUMPAD_7;

    /**
     * Number 8 key on the numeric keypad
     *
     * @since 9
     */
    static const int32_t KEYCODE_NUMPAD_8;

    /**
     * Number 9 key on the numeric keypad
     *
     * @since 9
     */
    static const int32_t KEYCODE_NUMPAD_9;

    /**
     * Slash (/) key (for division) on the numeric keypad
     *
     * @since 9
     */
    static const int32_t KEYCODE_NUMPAD_DIVIDE;

    /**
     * Star (*) key (for multiplication) on the numeric keypad
     *
     * @since 9
     */
    static const int32_t KEYCODE_NUMPAD_MULTIPLY;

    /**
     * Minus (-) key (for subtraction) on the numeric keypad
     *
     * @since 9
     */
    static const int32_t KEYCODE_NUMPAD_SUBTRACT;

    /**
     * Plus (+) key (for addition) on the numeric keypad
     *
     * @since 9
     */
    static const int32_t KEYCODE_NUMPAD_ADD;

    /**
     * Dot (.) key (for decimals or digit grouping) on the
     * numeric keypad
     *
     * @since 9
     */
    static const int32_t KEYCODE_NUMPAD_DOT;

    /**
     * Comma (,) key (for decimals or digit grouping) on the
     * numeric keypad
     *
     * @since 9
     */
    static const int32_t KEYCODE_NUMPAD_COMMA;

    /**
     * Enter key on the numeric keypad
     *
     * @since 9
     */
    static const int32_t KEYCODE_NUMPAD_ENTER;

    /**
     * Equals (=) key on the numeric keypad
     *
     * @since 9
     */
    static const int32_t KEYCODE_NUMPAD_EQUALS;

    /**
     * Left parentheses (() key on the numeric keypad
     *
     * @since 9
     */
    static const int32_t KEYCODE_NUMPAD_LEFT_PAREN;

    /**
     * Right parentheses ()) key on the numeric keypad
     *
     * @since 9
     */
    static const int32_t KEYCODE_NUMPAD_RIGHT_PAREN;

    /**
     * Virtual multitask key
     *
     * @since 9
     */
    static const int32_t KEYCODE_VIRTUAL_MULTITASK;

    /**
     * Button A on the gamepad
     *
     * @since 9
     */
    static const int32_t KEYCODE_BUTTON_A;

    /**
     * Button B on the gamepad
     *
     * @since 9
     */
    static const int32_t KEYCODE_BUTTON_B;

    /**
     * Button C on the gamepad
     *
     * @since 9
     */
    static const int32_t KEYCODE_BUTTON_C;

    /**
     * Button X on the gamepad
     *
     * @since 9
     */
    static const int32_t KEYCODE_BUTTON_X;

    /**
     * Button Y on the gamepad
     *
     * @since 9
     */
    static const int32_t KEYCODE_BUTTON_Y;

    /**
     * Button Z on the gamepad
     *
     * @since 9
     */
    static const int32_t KEYCODE_BUTTON_Z;

    /**
     * Button L1 on the gamepad
     *
     * @since 9
     */
    static const int32_t KEYCODE_BUTTON_L1;

    /**
     * Button R1 on the gamepad
     *
     * @since 9
     */
    static const int32_t KEYCODE_BUTTON_R1;

    /**
     * Button L2 on the gamepad
     *
     * @since 9
     */
    static const int32_t KEYCODE_BUTTON_L2;

    /**
     * Button R2 on the gamepad
     *
     * @since 9
     */
    static const int32_t KEYCODE_BUTTON_R2;

    /**
     * Select button on the gamepad
     *
     * @since 9
     */
    static const int32_t KEYCODE_BUTTON_SELECT;

    /**
     * Start button on the gamepad
     *
     * @since 9
     */
    static const int32_t KEYCODE_BUTTON_START;

    /**
     * Mode button on the gamepad
     *
     * @since 9
     */
    static const int32_t KEYCODE_BUTTON_MODE;

    /**
     * Left Thumb button on the gamepad
     *
     * @since 9
     */
    static const int32_t KEYCODE_BUTTON_THUMBL;

    /**
     * Right Thumb button on the gamepad
     *
     * @since 9
     */
    static const int32_t KEYCODE_BUTTON_THUMBR;

    /**
     * Trigger button on the joystick
     *
     * @since 9
     */
    static const int32_t KEYCODE_BUTTON_TRIGGER;

    /**
     * Thumb button on the joystick
     *
     * @since 9
     */
    static const int32_t KEYCODE_BUTTON_THUMB;

    /**
     * Thumb button 2 on the joystick
     *
     * @since 9
     */
    static const int32_t KEYCODE_BUTTON_THUMB2;

    /**
     * Top button on the joystick
     *
     * @since 9
     */
    static const int32_t KEYCODE_BUTTON_TOP;

    /**
     * Top button 2 on the joystick
     *
     * @since 9
     */
    static const int32_t KEYCODE_BUTTON_TOP2;

    /**
     * Pinkie button on the joystick
     *
     * @since 9
     */
    static const int32_t KEYCODE_BUTTON_PINKIE;

    /**
     * Base button 1 on the joystick
     *
     * @since 9
     */
    static const int32_t KEYCODE_BUTTON_BASE1;

    /**
     * Base button 2 on the joystick
     *
     * @since 9
     */
    static const int32_t KEYCODE_BUTTON_BASE2;

    /**
     * Base button 3 on the joystick
     *
     * @since 9
     */
    static const int32_t KEYCODE_BUTTON_BASE3;

    /**
     * Base button 4 on the joystick
     *
     * @since 9
     */
    static const int32_t KEYCODE_BUTTON_BASE4;

    /**
     * Base button 5 on the joystick
     *
     * @since 9
     */
    static const int32_t KEYCODE_BUTTON_BASE5;

    /**
     * Base button 6 on the joystick
     *
     * @since 9
     */
    static const int32_t KEYCODE_BUTTON_BASE6;

    /**
     * Base button 7 on the joystick
     *
     * @since 9
     */
    static const int32_t KEYCODE_BUTTON_BASE7;

    /**
     * Base button 8 on the joystick
     *
     * @since 9
     */
    static const int32_t KEYCODE_BUTTON_BASE8;

    /**
     * Base button 9 on the joystick
     *
     * @since 9
     */
    static const int32_t KEYCODE_BUTTON_BASE9;

    /**
     * Dead button on the joystick
     *
     * @since 9
     */
    static const int32_t KEYCODE_BUTTON_DEAD;

    /**
     *  List Menu key on keyboard
     *
     * @since 9
     */
    static const int32_t KEYCODE_COMPOSE;

    /**
     * Sleep key
     *
     * @since 9
     */
    static const int32_t KEYCODE_SLEEP;

    /**
     * Zenkaku_Hankaku, a Japanese modifier key that toggles between
     * Hankaku (half-width) and Zenkaku (full-width) characters
     *
     * @since 9
     */
    static const int32_t KEYCODE_ZENKAKU_HANKAKU;

    /**
     * 102nd key
     *
     * @since 9
     */
    static const int32_t KEYCODE_102ND;

    /**
     * Japanese Ro key
     *
     * @since 9
     */
    static const int32_t KEYCODE_RO;

    /**
     * Japanese katakana key
     *
     * @since 9
     */
    static const int32_t KEYCODE_KATAKANA;

    /**
     * Japanese hiragana key
     *
     * @since 9
     */
    static const int32_t KEYCODE_HIRAGANA;

    /**
     * Japanese conversion key
     *
     * @since 9
     */
    static const int32_t KEYCODE_HENKAN;

    /**
     * Japanese katakana/hiragana key
     *
     * @since 9
     */
    static const int32_t KEYCODE_KATAKANA_HIRAGANA;

    /**
     * Japanese non-conversion key
     *
     * @since 9
     */
    static const int32_t KEYCODE_MUHENKAN;

    /**
     * Line Feed key
     *
     * @since 9
     */
    static const int32_t KEYCODE_LINEFEED;

    /**
     * Macro key
     *
     * @since 9
     */
    static const int32_t KEYCODE_MACRO;

    /**
     * Plus/Minus key on the numeric keypad
     *
     * @since 9
     */
    static const int32_t KEYCODE_NUMPAD_PLUSMINUS;

    /**
     * Extension
     *
     * @since 9
     */
    static const int32_t KEYCODE_SCALE;

    /**
     * Japanese Hanguel key
     *
     * @since 9
     */
    static const int32_t KEYCODE_HANGUEL;

    /**
     * Japanese hanja key
     *
     * @since 9
     */
    static const int32_t KEYCODE_HANJA;

    /**
     * Japanese YEN key
     *
     * @since 9
     */
    static const int32_t KEYCODE_YEN;

    /**
     * Stop key
     *
     * @since 9
     */
    static const int32_t KEYCODE_STOP;

    /**
     * Again key
     *
     * @since 9
     */
    static const int32_t KEYCODE_AGAIN;

    /**
     * Props key
     *
     * @since 9
     */
    static const int32_t KEYCODE_PROPS;

    /**
     * Undo key
     *
     * @since 9
     */
    static const int32_t KEYCODE_UNDO;

    /**
     * Copy key
     *
     * @since 9
     */
    static const int32_t KEYCODE_COPY;

    /**
     * Open key
     *
     * @since 9
     */
    static const int32_t KEYCODE_OPEN;

    /**
     * Paste key
     *
     * @since 9
     */
    static const int32_t KEYCODE_PASTE;

    /**
     * Find key
     *
     * @since 9
     */
    static const int32_t KEYCODE_FIND;

    /**
     * Cut key
     *
     * @since 9
     */
    static const int32_t KEYCODE_CUT;

    /**
     * Help key
     *
     * @since 9
     */
    static const int32_t KEYCODE_HELP;

    /**
     * Calculate key
     *
     * @since 9
     */
    static const int32_t KEYCODE_CALC;

    /**
     * File key
     *
     * @since 9
     */
    static const int32_t KEYCODE_FILE;

    /**
     * Bookmarks key
     *
     * @since 9
     */
    static const int32_t KEYCODE_BOOKMARKS;

    /**
     * Next key
     *
     * @since 9
     */
    static const int32_t KEYCODE_NEXT;

    /**
     * Play/Pause key
     *
     * @since 9
     */
    static const int32_t KEYCODE_PLAYPAUSE;

    /**
     * Previous key
     *
     * @since 9
     */
    static const int32_t KEYCODE_PREVIOUS;

    /**
     * CD Stop key
     *
     * @since 9
     */
    static const int32_t KEYCODE_STOPCD;

    /**
     * Configuration key
     *
     * @since 9
     */
    static const int32_t KEYCODE_CONFIG;

    /**
     * Refresh key
     *
     * @since 9
     */
    static const int32_t KEYCODE_REFRESH;

    /**
     * Exit key
     *
     * @since 9
     */
    static const int32_t KEYCODE_EXIT;

    /**
     * Edit key
     *
     * @since 9
     */
    static const int32_t KEYCODE_EDIT;

    /**
     * Scroll Up key
     *
     * @since 9
     */
    static const int32_t KEYCODE_SCROLLUP;

    /**
     * Scroll Down key
     *
     * @since 9
     */
    static const int32_t KEYCODE_SCROLLDOWN;

    /**
     * New key
     *
     * @since 9
     */
    static const int32_t KEYCODE_NEW;

    /**
     * Redo key
     *
     * @since 9
     */
    static const int32_t KEYCODE_REDO;

    /**
     * Close key
     *
     * @since 9
     */
    static const int32_t KEYCODE_CLOSE;

    /**
     * Play key
     *
     * @since 9
     */
    static const int32_t KEYCODE_PLAY;

    /**
     * Bass boost key
     *
     * @since 9
     */
    static const int32_t KEYCODE_BASSBOOST;

    /**
     * Print key
     *
     * @since 9
     */
    static const int32_t KEYCODE_PRINT;

    /**
     * Chat key
     *
     * @since 9
     */
    static const int32_t KEYCODE_CHAT;

    /**
     * Finance key
     *
     * @since 9
     */
    static const int32_t KEYCODE_FINANCE;

    /**
     * Cancel key
     *
     * @since 9
     */
    static const int32_t KEYCODE_CANCEL;

    /**
     * Keyboard Illumination Toggle key
     *
     * @since 9
     */
    static const int32_t KEYCODE_KBDILLUM_TOGGLE;

    /**
     * Keyboard Illumination Down key
     *
     * @since 9
     */
    static const int32_t KEYCODE_KBDILLUM_DOWN;

    /**
     * Keyboard Illumination Up key
     *
     * @since 9
     */
    static const int32_t KEYCODE_KBDILLUM_UP;

    /**
     * Send key
     *
     * @since 9
     */
    static const int32_t KEYCODE_SEND;

    /**
     * Reply key
     *
     * @since 9
     */
    static const int32_t KEYCODE_REPLY;

    /**
     * Mail Forward key
     *
     * @since 9
     */
    static const int32_t KEYCODE_FORWARDMAIL;

    /**
     * Save key
     *
     * @since 9
     */
    static const int32_t KEYCODE_SAVE;

    /**
     * Documents key
     *
     * @since 9
     */
    static const int32_t KEYCODE_DOCUMENTS;

    /**
     * Next Video key
     *
     * @since 9
     */
    static const int32_t KEYCODE_VIDEO_NEXT;

    /**
     * Previous Video key
     *
     * @since 9
     */
    static const int32_t KEYCODE_VIDEO_PREV;

    /**
     * Brightness Cycle key
     *
     * @since 9
     */
    static const int32_t KEYCODE_BRIGHTNESS_CYCLE;

    /**
     * Brightness 0 key
     *
     * @since 9
     */
    static const int32_t KEYCODE_BRIGHTNESS_ZERO;

    /**
     * Display Off key
     *
     * @since 9
     */
    static const int32_t KEYCODE_DISPLAY_OFF;

    /**
     * Miscellaneous buttons on the gamepad
     *
     * @since 9
     */
    static const int32_t KEYCODE_BTN_MISC;

    /**
     * Go To key
     *
     * @since 9
     */
    static const int32_t KEYCODE_GOTO;

    /**
     * Info key
     *
     * @since 9
     */
    static const int32_t KEYCODE_INFO;

    /**
     * Program key
     *
     * @since 9
     */
    static const int32_t KEYCODE_PROGRAM;

    /**
     * Personal Video Recorder (PVR) key
     *
     * @since 9
     */
    static const int32_t KEYCODE_PVR;

    /**
     * Subtitle key
     *
     * @since 9
     */
    static const int32_t KEYCODE_SUBTITLE;

    /**
     * Full Screen key
     *
     * @since 9
     */
    static const int32_t KEYCODE_FULL_SCREEN;

    /**
     * Keyboard
     *
     * @since 9
     */
    static const int32_t KEYCODE_KEYBOARD;

    /**
     * Aspect Ratio key
     *
     * @since 9
     */
    static const int32_t KEYCODE_ASPECT_RATIO;

    /**
     * Port Control key
     *
     * @since 9
     */
    static const int32_t KEYCODE_PC;

    /**
     * TV key
     *
     * @since 9
     */
    static const int32_t KEYCODE_TV;

    /**
     * TV key 2
     *
     * @since 9
     */
    static const int32_t KEYCODE_TV2;

    /**
     * VCR key
     *
     * @since 9
     */
    static const int32_t KEYCODE_VCR;

    /**
     * VCR key 2
     *
     * @since 9
     */
    static const int32_t KEYCODE_VCR2;

    /**
     * SIM Application Toolkit (SAT) key
     *
     * @since 9
     */
    static const int32_t KEYCODE_SAT;

    /**
     * CD key
     *
     * @since 9
     */
    static const int32_t KEYCODE_CD;

    /**
     * Tape key
     *
     * @since 9
     */
    static const int32_t KEYCODE_TAPE;

    /**
     * Tuner key
     *
     * @since 9
     */
    static const int32_t KEYCODE_TUNER;

    /**
     * Player key
     *
     * @since 9
     */
    static const int32_t KEYCODE_PLAYER;

    /**
     * DVD key
     *
     * @since 9
     */
    static const int32_t KEYCODE_DVD;

    /**
     * Audio key
     *
     * @since 9
     */
    static const int32_t KEYCODE_AUDIO;

    /**
     * Video key
     *
     * @since 9
     */
    static const int32_t KEYCODE_VIDEO;

    /**
     * Memo key
     *
     * @since 9
     */
    static const int32_t KEYCODE_MEMO;

    /**
     * Calendar key
     *
     * @since 9
     */
    static const int32_t KEYCODE_CALENDAR;

    /**
     * Red indicator
     *
     * @since 9
     */
    static const int32_t KEYCODE_RED;

    /**
     * Green indicator
     *
     * @since 9
     */
    static const int32_t KEYCODE_GREEN;

    /**
     * Yellow indicator
     *
     * @since 9
     */
    static const int32_t KEYCODE_YELLOW;

    /**
     * Blue indicator
     *
     * @since 9
     */
    static const int32_t KEYCODE_BLUE;

    /**
     * Channel Up key
     *
     * @since 9
     */
    static const int32_t KEYCODE_CHANNELUP;

    /**
     * Channel Down key
     *
     * @since 9
     */
    static const int32_t KEYCODE_CHANNELDOWN;

    /**
     * Last key
     *
     * @since 9
     */
    static const int32_t KEYCODE_LAST;

    /**
     * Restart key
     *
     * @since 9
     */
    static const int32_t KEYCODE_RESTART;

    /**
     * Slow key
     *
     * @since 9
     */
    static const int32_t KEYCODE_SLOW;

    /**
     * Shuffle key
     *
     * @since 9
     */
    static const int32_t KEYCODE_SHUFFLE;

    /**
     * Videophone key
     *
     * @since 9
     */
    static const int32_t KEYCODE_VIDEOPHONE;

    /**
     * Games key
     *
     * @since 9
     */
    static const int32_t KEYCODE_GAMES;

    /**
     * Zoom In key
     *
     * @since 9
     */
    static const int32_t KEYCODE_ZOOMIN;

    /**
     * Zoom Out key
     *
     * @since 9
     */
    static const int32_t KEYCODE_ZOOMOUT;

    /**
     * Zoom Reset key
     *
     * @since 9
     */
    static const int32_t KEYCODE_ZOOMRESET;

    /**
     * Word Processor key
     *
     * @since 9
     */
    static const int32_t KEYCODE_WORDPROCESSOR;

    /**
     * Editor key
     *
     * @since 9
     */
    static const int32_t KEYCODE_EDITOR;

    /**
     * Spreadsheet key
     *
     * @since 9
     */
    static const int32_t KEYCODE_SPREADSHEET;

    /**
     * Graphics Editor key
     *
     * @since 9
     */
    static const int32_t KEYCODE_GRAPHICSEDITOR;

    /**
     * Presentation key
     *
     * @since 9
     */
    static const int32_t KEYCODE_PRESENTATION;

    /**
     * Database key
     *
     * @since 9
     */
    static const int32_t KEYCODE_DATABASE;

    /**
     * News key
     *
     * @since 9
     */
    static const int32_t KEYCODE_NEWS;

    /**
     * Voice mailbox
     *
     * @since 9
     */
    static const int32_t KEYCODE_VOICEMAIL;

    /**
     * Address Book key
     *
     * @since 9
     */
    static const int32_t KEYCODE_ADDRESSBOOK;

    /**
     * Messenger key
     *
     * @since 9
     */
    static const int32_t KEYCODE_MESSENGER;

    /**
     * Brightness Toggle key
     *
     * @since 9
     */
    static const int32_t KEYCODE_BRIGHTNESS_TOGGLE;

    /**
     * Spell Check key
     *
     * @since 9
     */
    static const int32_t KEYCODE_SPELLCHECK;

    /**
     * Coffee key
     *
     * @since 9
     */
    static const int32_t KEYCODE_COFFEE;

    /**
     * Media Repeat key
     *
     * @since 9
     */
    static const int32_t KEYCODE_MEDIA_REPEAT;

    /**
     * Images key
     *
     * @since 9
     */
    static const int32_t KEYCODE_IMAGES;

    /**
     * Button Configuration key
     *
     * @since 9
     */
    static const int32_t KEYCODE_BUTTONCONFIG;

    /**
     * Task Manager key
     *
     * @since 9
     */
    static const int32_t KEYCODE_TASKMANAGER;

    /**
     * Journal key
     *
     * @since 9
     */
    static const int32_t KEYCODE_JOURNAL;

    /**
     * Control Panel key
     *
     * @since 9
     */
    static const int32_t KEYCODE_CONTROLPANEL;

    /**
     * Application Select key
     *
     * @since 9
     */
    static const int32_t KEYCODE_APPSELECT;

    /**
     * Screen Saver key
     *
     * @since 9
     */
    static const int32_t KEYCODE_SCREENSAVER;

    /**
     * Assistant key
     *
     * @since 9
     */
    static const int32_t KEYCODE_ASSISTANT;

    /**
     * Next Keyboard Layout key
     *
     * @since 9
     */
    static const int32_t KEYCODE_KBD_LAYOUT_NEXT;

    /**
     * Minimum Brightness key
     *
     * @since 9
     */
    static const int32_t KEYCODE_BRIGHTNESS_MIN;

    /**
     * Maximum Brightness key
     *
     * @since 9
     */
    static const int32_t KEYCODE_BRIGHTNESS_MAX;

    /**
     * Keyboard Input Assist_Previous
     *
     * @since 9
     */
    static const int32_t KEYCODE_KBDINPUTASSIST_PREV;

    /**
     * Keyboard Input Assist_Next
     *
     * @since 9
     */
    static const int32_t KEYCODE_KBDINPUTASSIST_NEXT;

    /**
     * Keyboard Input Assist_Previous Group
     *
     * @since 9
     */
    static const int32_t KEYCODE_KBDINPUTASSIST_PREVGROUP;

    /**
     * Keyboard Input Assist_Next Group
     *
     * @since 9
     */
    static const int32_t KEYCODE_KBDINPUTASSIST_NEXTGROUP;

    /**
     * Keyboard Input Assist_Accept
     *
     * @since 9
     */
    static const int32_t KEYCODE_KBDINPUTASSIST_ACCEPT;

    /**
     * Keyboard Input Assist_Cancel
     *
     * @since 9
     */
    static const int32_t KEYCODE_KBDINPUTASSIST_CANCEL;

    /**
     * Front key
     *
     * @since 9
     */
    static const int32_t KEYCODE_FRONT;

    /**
     * Setup key
     *
     * @since 9
     */
    static const int32_t KEYCODE_SETUP;

    /**
     * Wakeup key
     *
     * @since 9
     */
    static const int32_t KEYCODE_WAKEUP;

    /**
     * Send File key
     *
     * @since 9
     */
    static const int32_t KEYCODE_SENDFILE;

    /**
     * Delete File key
     *
     * @since 9
     */
    static const int32_t KEYCODE_DELETEFILE;

    /**
     * File Transfer (XFER) key
     *
     * @since 9
     */
    static const int32_t KEYCODE_XFER;

    /**
     * Program key 1
     *
     * @since 9
     */
    static const int32_t KEYCODE_PROG1;

    /**
     * Program key 2
     *
     * @since 9
     */
    static const int32_t KEYCODE_PROG2;

    /**
     * MS-DOS key
     *
     * @since 9
     */
    static const int32_t KEYCODE_MSDOS;

    /**
     * Screen Lock key
     *
     * @since 9
     */
    static const int32_t KEYCODE_SCREENLOCK;

    /**
     * Direction Rotation Display key
     *
     * @since 9
     */
    static const int32_t KEYCODE_DIRECTION_ROTATE_DISPLAY;

    /**
     * Cycle Windows key
     *
     * @since 9
     */
    static const int32_t KEYCODE_CYCLEWINDOWS;

    /**
     * Computer key
     *
     * @since 9
     */
    static const int32_t KEYCODE_COMPUTER;

    /**
     * Eject Close CD key
     *
     * @since 9
     */
    static const int32_t KEYCODE_EJECTCLOSECD;

    /**
     * ISO key
     *
     * @since 9
     */
    static const int32_t KEYCODE_ISO;

    /**
     * Move key
     *
     * @since 9
     */
    static const int32_t KEYCODE_MOVE;

    /**
     * F13 key
     *
     * @since 9
     */
    static const int32_t KEYCODE_F13;

    /**
     * F14 key
     *
     * @since 9
     */
    static const int32_t KEYCODE_F14;

    /**
     * F15 key
     *
     * @since 9
     */
    static const int32_t KEYCODE_F15;

    /**
     * F16 key
     *
     * @since 9
     */
    static const int32_t KEYCODE_F16;

    /**
     * F17 key
     *
     * @since 9
     */
    static const int32_t KEYCODE_F17;

    /**
     * F18 key
     *
     * @since 9
     */
    static const int32_t KEYCODE_F18;

    /**
     * F19 key
     *
     * @since 9
     */
    static const int32_t KEYCODE_F19;

    /**
     * F20 key
     *
     * @since 9
     */
    static const int32_t KEYCODE_F20;

    /**
     * F21 key
     *
     * @since 9
     */
    static const int32_t KEYCODE_F21;

    /**
     * F22 key
     *
     * @since 9
     */
    static const int32_t KEYCODE_F22;

    /**
     * F23 key
     *
     * @since 9
     */
    static const int32_t KEYCODE_F23;

    /**
     * F24 key
     *
     * @since 9
     */
    static const int32_t KEYCODE_F24;

    /**
     * Program key 3
     *
     * @since 9
     */
    static const int32_t KEYCODE_PROG3;

    /**
     * Program key 4
     *
     * @since 9
     */
    static const int32_t KEYCODE_PROG4;

    /**
     * Dashboard key
     *
     * @since 9
     */
    static const int32_t KEYCODE_DASHBOARD;

    /**
     * Suspend key
     *
     * @since 9
     */
    static const int32_t KEYCODE_SUSPEND;

    /**
     * Higher Order Path key
     *
     * @since 9
     */
    static const int32_t KEYCODE_HP;

    /**
     * Sound key
     *
     * @since 9
     */
    static const int32_t KEYCODE_SOUND;

    /**
     * Question key
     *
     * @since 9
     */
    static const int32_t KEYCODE_QUESTION;

    /**
     * Connect key
     *
     * @since 9
     */
    static const int32_t KEYCODE_CONNECT;

    /**
     * Sport key
     *
     * @since 9
     */
    static const int32_t KEYCODE_SPORT;

    /**
     * Shop key
     *
     * @since 9
     */
    static const int32_t KEYCODE_SHOP;

    /**
     * Alterase key
     *
     * @since 9
     */
    static const int32_t KEYCODE_ALTERASE;

    /**
     * Enable/Disable Video Mode key
     *
     * @since 9
     */
    static const int32_t KEYCODE_SWITCHVIDEOMODE;

    /**
     * Battery key
     *
     * @since 9
     */
    static const int32_t KEYCODE_BATTERY;

    /**
     * Bluetooth key
     *
     * @since 9
     */
    static const int32_t KEYCODE_BLUETOOTH;

    /**
     * WLAN key
     *
     * @since 9
     */
    static const int32_t KEYCODE_WLAN;

    /**
     * Ultra-wideband (UWB) key
     *
     * @since 9
     */
    static const int32_t KEYCODE_UWB;

    /**
     * WWAN WiMAX key
     *
     * @since 9
     */
    static const int32_t KEYCODE_WWAN_WIMAX;

    /**
     * RF Kill key
     *
     * @since 9
     */
    static const int32_t KEYCODE_RFKILL;

    /**
     * Channel key
     *
     * @since 9
     */
    static const int32_t KEYCODE_CHANNEL;

    /**
     * Button 0
     *
     * @since 9
     */
    static const int32_t KEYCODE_BTN_0;

    /**
     * Button 1
     *
     * @since 9
     */
    static const int32_t KEYCODE_BTN_1;

    /**
     * Button 2
     *
     * @since 9
     */
    static const int32_t KEYCODE_BTN_2;

    /**
     * Button 3
     *
     * @since 9
     */
    static const int32_t KEYCODE_BTN_3;

    /**
     * Button 4
     *
     * @since 9
     */
    static const int32_t KEYCODE_BTN_4;

    /**
     * Button 5
     *
     * @since 9
     */
    static const int32_t KEYCODE_BTN_5;

    /**
     * Button 6
     *
     * @since 9
     */
    static const int32_t KEYCODE_BTN_6;

    /**
     * Button 7
     *
     * @since 9
     */
    static const int32_t KEYCODE_BTN_7;

    /**
     * Button 8
     *
     * @since 9
     */
    static const int32_t KEYCODE_BTN_8;

    /**
     * Button 9
     *
     * @since 9
     */
    static const int32_t KEYCODE_BTN_9;

    /**
     * Virtual keyboard 1
     *
     * @since 9
     */
    static const int32_t KEYCODE_BRL_DOT1;

    /**
     * Virtual keyboard 2
     *
     * @since 9
     */
    static const int32_t KEYCODE_BRL_DOT2;

    /**
     * Virtual keyboard 3
     *
     * @since 9
     */
    static const int32_t KEYCODE_BRL_DOT3;

    /**
     * Virtual keyboard 4
     *
     * @since 9
     */
    static const int32_t KEYCODE_BRL_DOT4;

    /**
     * Virtual keyboard 5
     *
     * @since 9
     */
    static const int32_t KEYCODE_BRL_DOT5;

    /**
     * Virtual keyboard 6
     *
     * @since 9
     */
    static const int32_t KEYCODE_BRL_DOT6;

    /**
     * Virtual keyboard 7
     *
     * @since 9
     */
    static const int32_t KEYCODE_BRL_DOT7;

    /**
     * Virtual keyboard 8
     *
     * @since 9
     */
    static const int32_t KEYCODE_BRL_DOT8;

    /**
     * Virtual keyboard 9
     *
     * @since 9
     */
    static const int32_t KEYCODE_BRL_DOT9;

    /**
     * Virtual keyboard 10
     *
     * @since 9
     */
    static const int32_t KEYCODE_BRL_DOT10;

   /**
     * PEN_AIR_MOUSE
     *
     * @since 9
     */
    static const int32_t KEYCODE_KEY_PEN_AIR_MOUSE;

    /**
     * PEN_LIGHT_PINCH
     *
     * @since 9
     */
    static const int32_t KEYCODE_KEY_PEN_LIGHT_PINCH;

    /**
     * KEYCODE_PEN_AI
     *
     * @since 9
     */
    static const int32_t KEYCODE_KEY_PEN_AI;

    /**
     * KEYCODE_PEN_AI
     *
     * @since 9
     */
    static const int32_t KEYCODE_KEY_PEN_END_CLICK;

    /**
     * KEYCODE_PEN_AI
     *
     * @since 9
     */
    static const int32_t KEYCODE_KEY_PEN_END_DOUBLE_CLICK;

    /**
     * KEYCODE_PEN_AI
     *
     * @since 9
     */
    static const int32_t KEYCODE_KEY_PEN_MODE_SWITCH;

    /**
     * Left Knob roll-up
     * <p>In contrast to {@link #static const int32_t KEYCODE_LEFT_KNOB_ROLL_DOWN},
     * this key is used to roll the left knob upwards. The knob function is scenario-specific,
     * for example, increasing the volume or air conditioner temperature.
     *
     * @since 9
     */
    static const int32_t KEYCODE_LEFT_KNOB_ROLL_UP;

    /**
     * Left Knob roll-down
     * <p>In contrast to {@link #static const int32_t KEYCODE_LEFT_KNOB_ROLL_UP},
     * this key is used to roll the left knob downwards. The knob function is
     * scenario-specific, for example, reducing the volume or air
     * conditioner temperature.
     * @since 9
     */
    static const int32_t KEYCODE_LEFT_KNOB_ROLL_DOWN;

    /**
     * Left Knob
     * <p>Pressing the knob will activate its adjustment function.
     *
     * @since 9
     */
    static const int32_t KEYCODE_LEFT_KNOB;

    /**
     * Right Knob roll-up
     * <p>In contrast to {@link #static const int32_t KEYCODE_RIGHT_KNOB_ROLL_DOWN},
     * this key is used to roll the right knob upwards. The knobfunction is scenario-specific,
     * for example, increasing the volume or air conditioner temperature.
     *
     * @since 9
     */
    static const int32_t KEYCODE_RIGHT_KNOB_ROLL_UP;

    /**
     * Right Knob roll-down
     * <p>In contrast to {@link #static const int32_t KEYCODE_RIGHT_KNOB_ROLL_UP},
     * this key is used to roll the right knob downwards. The knobfunction is scenario-specific,
     * for example, reducing the volume or air conditioner temperature.
     *
     * @since 9
     */
    static const int32_t KEYCODE_RIGHT_KNOB_ROLL_DOWN;

    /**
     * Right Knob
     * <p>Pressing the knob will activate its adjustment function.
     *
     * @since 9
     */
    static const int32_t KEYCODE_RIGHT_KNOB;

    /**
     * Audio Source Switch button
     * <p>Pressing this button will enable the audio source. Depending on the
     * actual scenario, it may also indicate that the Bluetooth call control
     * button is pressed.
     * @since 9
     */
    static const int32_t KEYCODE_VOICE_SOURCE_SWITCH;

    /**
     * Menu key
     * <p>Pressing this key will display the launcher page.
     *
     * @since 9
     */
    static const int32_t KEYCODE_LAUNCHER_MENU;

    /**
     * Stylus key
     *
     * @since 12
     */
    static const int32_t KEYCODE_STYLUS_SCREEN;

    /**
     * Unknown key operation, which is usually used to indicate the initial invalid value.
     *
     * @since 9
     */
    static const int32_t KEY_ACTION_UNKNOWN;

    /**
     * Action Cancel
     * Pressing this key will cause the failure in reporting the Action Up event.
     * Instead, the action of pressing the Action Cancel key is reported.
     *
     * @since 9
     */
    static const int32_t KEY_ACTION_CANCEL;

    /**
     * Action Down
     *
     * @since 9
     */
    static const int32_t KEY_ACTION_DOWN;

    /**
     * Action Up
     *
     * @since 9
     */
    static const int32_t KEY_ACTION_UP;

    /**
     * Unknown intention
     *
     * @since 9
     */
    static const int32_t INTENTION_UNKNOWN;

    /**
     * Up intention
     *
     * @since 9
     */
    static const int32_t INTENTION_UP;

    /**
     * Down intention
     *
     * @since 9
     */
    static const int32_t INTENTION_DOWN;

    /**
     * Left intention
     *
     * @since 9
     */
    static const int32_t INTENTION_LEFT;

    /**
     * Right intention
     *
     * @since 9
     */
    static const int32_t INTENTION_RIGHT;

    /**
     * Select intention
     *
     * @since 9
     */
    static const int32_t INTENTION_SELECT;

    /**
     * Escape intention
     *
     * @since 9
     */
    static const int32_t INTENTION_ESCAPE;

    /**
     * Back intention
     *
     * @since 9
     */
    static const int32_t INTENTION_BACK;

    /**
     * Forward intention
     *
     * @since 9
     */
    static const int32_t INTENTION_FORWARD;

    /**
     * Menu intention
     *
     * @since 9
     */
    static const int32_t INTENTION_MENU;

    /**
     * Home intention
     *
     * @since 9
     */
    static const int32_t INTENTION_HOME;

    /**
     * Page Up intention
     *
     * @since 9
     */
    static const int32_t INTENTION_PAGE_UP;

    /**
     * Page down intention
     *
     * @since 9
     */
    static const int32_t INTENTION_PAGE_DOWN;

    /**
     * Zoom out intention
     *
     * @since 9
     */
    static const int32_t INTENTION_ZOOM_OUT;

    /**
     * Zoom in intention
     *
     * @since 9
     */
    static const int32_t INTENTION_ZOOM_IN;

    /**
     * Media play/pause intention
     *
     * @since 9
     */
    static const int32_t INTENTION_MEDIA_PLAY_PAUSE;

    /**
     * Media fast forward intention
     *
     * @since 9
     */
    static const int32_t INTENTION_MEDIA_FAST_FORWARD;

    /**
     * Media fast rewind intention
     *
     * @since 9
     */
    static const int32_t INTENTION_MEDIA_FAST_REWIND;

    /**
     * Media fast playback intention
     *
     * @since 9
     */
    static const int32_t INTENTION_MEDIA_FAST_PLAYBACK;

    /**
     * Media next intention
     *
     * @since 9
     */
    static const int32_t INTENTION_MEDIA_NEXT;

    /**
     * Media previous intention
     *
     * @since 9
     */
    static const int32_t INTENTION_MEDIA_PREVIOUS;

    /**
     * Media mute intention
     *
     * @since 9
     */
    static const int32_t INTENTION_MEDIA_MUTE;

    /**
     * Volume up intention
     *
     * @since 9
     */
    static const int32_t INTENTION_VOLUTE_UP;

    /**
     * Volume down intention
     *
     * @since 9
     */
    static const int32_t INTENTION_VOLUTE_DOWN;

    /**
     * Call intention
     *
     * @since 9
     */
    static const int32_t INTENTION_CALL;

    /**
     * End call intention
     *
     * @since 9
     */
    static const int32_t INTENTION_ENDCALL;

    /**
     * Reject call intention
     *
     * @since 9
     */
    static const int32_t INTENTION_REJECTCALL;

    /**
     * Camera intention
     *
     * @since 9
     */
    static const int32_t INTENTION_CAMERA;

    /**
     * Outbound Notification Center
     *
     * @since 11
     */
    static const int32_t KEYCODE_CALL_NOTIFICATION_CENTER;

    /**
     * Outbound Control Center
     *
     * @since 11
     */
    static const int32_t KEYCODE_CALL_CONTROL_CENTER;

    /**
     * Dagger Press
     *
     * @since 12
     */
    static const int32_t KEYCODE_DAGGER_CLICK;

    /**
     * Dagger Click
     *
     * @since 13
     */
    static const int32_t KEYCODE_DAGGER_DOUBLE_CLICK;

    /**
     * Dagger Long Press
     *
     * @since 14
     */
    static const int32_t KEYCODE_DAGGER_LONG_PRESS;

    /**
     * Aod slide unlock
     *
     * @since 16
     */
    static const int32_t KEYCODE_AOD_SLIDE_UNLOCK;

    /**
     * Recent
     *
     * @since 18
     */
    static const int32_t KEYCODE_RECENT;

    /**
     * Floating back
     *
     * @since 18
     */
    static const int32_t KEYCODE_FLOATING_BACK;
    /**
     * Div key
     *
     * @since 20
     */
    static const int32_t KEYCODE_DIV;
public:
    class KeyItem {
    public:
        KeyItem();
        ~KeyItem();

        /**
         * @brief Obtains the key code of the key.
         * @return Returns the key code.
         * @since 9
         */
        int32_t GetKeyCode() const;

        /**
         * @brief Sets a key code for the key.
         * @param keyCode Indicates the key code to set.
         * @return void
         * @since 9
         */
        void SetKeyCode(int32_t keyCode);

        /**
         * @brief Obtains the time when the key is pressed.
         * @return Returns the time.
         * @since 9
         */
        int64_t GetDownTime() const;

        /**
         * @brief Sets the time when the key is pressed.
         * @param downTime Indicates the time to set.
         * @return void
         * @since 9
         */
        void SetDownTime(int64_t downTime);

        /**
         * @brief Obtains the unique identifier of the device that reports this event.
         * @return Returns the device ID.
         * @since 9
         */
        int32_t GetDeviceId() const;

        /**
         * @brief Sets a unique identifier for the device that reports this event.
         * @param deviceId Indicates the device ID to set.
         * @return void
         * @since 9
         */
        void SetDeviceId(int32_t deviceId);

        /**
         * @brief Checks whether the key is pressed.
         * @return Returns <b>true</b> if the key is pressed; returns <b>false</b> otherwise.
         * @since 9
         */
        bool IsPressed() const;

        /**
         * @brief Sets whether to enable the pressed state for the key.
         * @param pressed Specifies whether to set the pressed state for the key.
         * The value <b>true</b> means to set the pressed state for the key,
         * and the <b>false</b> means the opposite.
         * @return void
         * @since 9
         */
        void SetPressed(bool pressed);

        /**
         * @brief Sets the Unicode value corresponding to the current key.
         * @param unicode Unicode value.
         * @return Null
         * @since 9
         */
        void SetUnicode(uint32_t unicode);

        /**
         * @brief Obtains the Unicode value of the current key.
         * @return Returns the Unicode value.
         * @since 9
         */
        uint32_t GetUnicode() const;

    public:
        /**
         * @brief Writes data to a <b>Parcel</b> object.
         * @param out Indicates the object into which data will be written.
         * @return Returns <b>true</b> if the data is successfully written; returns <b>false</b> otherwise.
         * @since 9
         */
        bool WriteToParcel(Parcel &out) const;

        /**
         * @brief Reads data from a <b>Parcel</b> object.
         * @param in Indicates the object from which data will be read.
         * @return Returns <b>true</b> if the data is successfully read; returns <b>false</b> otherwise.
         * @since 9
         */
        bool ReadFromParcel(Parcel &in);

    private:
        bool pressed_ = false;
        int32_t deviceId_ = -1;
        int32_t keyCode_ = -1;
        int64_t downTime_ = 0;
        uint32_t unicode_ { 0 };
    };

public:
     static std::shared_ptr<KeyEvent> from(std::shared_ptr<InputEvent> inputEvent);

    /**
     * @brief Converts the action of this key event as a string.
     * @param action Indicates the action represented by pressing a key.
     * @return Returns the pointer to the action string.
     * @since 9
     */
    static const char* ActionToString(int32_t action);

    /**
     * @brief Converts the key code of this key event as a string.
     * @param keyCode Indicates the code that identifies the key.
     * @return Returns the pointer to the key code string.
     * @since 9
     */
    static const char* KeyCodeToString(int32_t keyCode);

    static std::shared_ptr<KeyEvent> Clone(std::shared_ptr<KeyEvent> keyEvent);

public:
    /**
     * @brief Constructor of KeyEvent.
     * @since 9
     */
    KeyEvent(const KeyEvent& other);

    /**
     * @brief Virtual destructor of KeyEvent.
     * @since 9
     */
    virtual ~KeyEvent();

    KeyEvent& operator=(const KeyEvent& other) = delete;
    DISALLOW_MOVE(KeyEvent);

    /**
     * @brief Creates a key event.
     * @since 9
     */
    static std::shared_ptr<KeyEvent> Create();

    virtual void Reset() override;

    virtual std::string ToString() override;

    /**
     * @brief Get the hash value.
     * @return size_t
     * @since 21
     */
    virtual size_t Hash() override;

    /**
     * @brief Obtains the key code of this key event.
     * @return Returns the key code.
     * @since 9
     */
    int32_t GetKeyCode() const;

    /**
     * @brief Sets a key code for this key event.
     * @param keyCode Indicates the key code to set.
     * @return void
     * @since 9
     */
    void SetKeyCode(int32_t keyCode);

    /**
     * @brief Obtains the key action of this key event.
     * @return Returns the key action.
     * @since 9
     */
    int32_t GetKeyAction() const;

    /**
     * @brief Sets a key action for this key event.
     * @param keyAction Indicates the key action to set.
     * @return void
     * @since 9
     */
    void SetKeyAction(int32_t keyAction);

    /**
     * @brief Obtains the list of pressed keys in this key event.
     * @return Returns the list of pressed keys.
     * @since 9
     */
    std::vector<int32_t> GetPressedKeys() const;

    /**
     * @brief Adds a key item.
     * @param keyItem Indicates the key item to add.
     * @return void
     * @since 9
     */
    void AddKeyItem(const KeyItem& keyItem);

    /**
     * @brief Set key item.
     * @param keyItem Indicates the key item to set.
     * @return void
     * @since 13
     */
    void SetKeyItem(std::vector<KeyItem> keyItem);

    /**
     * @brief Obtains the key item.
     * @return Returns the key item.
     * @since 9
     */
    std::vector<KeyEvent::KeyItem> GetKeyItems() const;

    /**
     * @brief Adds the pressed key items.
     * @param keyItem Indicates the key item to add.
     * @return void
     * @since 9
     */
    void AddPressedKeyItems(const KeyItem& keyItem);

    /**
     * @brief Removes the released key Items.
     * @param keyItem Indicates the key item to remove.
     * @return void
     * @since 9
     */
    void RemoveReleasedKeyItems(const KeyItem& keyItem);

    /**
     * @brief Obtains the key item of this key event.
     * @return Returns the key item.
     * @since 9
     */
    std::optional<KeyEvent::KeyItem> GetKeyItem() const;

    /**
     * @brief Obtains the key item based on a key code.
     * @param keyCode Indicates the key code.
     * @return Returns the key item.
     * @since 9
     */
    std::optional<KeyEvent::KeyItem> GetKeyItem(int32_t keyCode) const;

    /**
     * @brief Checks whether this key event is valid.
     * @return Returns <b>true</b> if the key event is valid; returns <b>false</b> otherwise.
     * @since 9
     */
    bool IsValid() const;

    /**
     * @brief Converts a specific key to a function key.
     * @param keyCode Indicates the keycode of the key to convert.
     * @return Returns the converted function key.
     * @since 9
     */
    int32_t TransitionFunctionKey(int32_t keyCode);

    /**
     * @brief Sets the enable status of the specified function key.
     * @param funcKey Indicates the function key.
     * @param value Indicates the enable status of the function key.
     * @return Returns the result indicating whether the setting is successful.
     * @since 9
     */
    int32_t SetFunctionKey(int32_t funcKey, int32_t value);

    /**
     * @brief Obtains the enable status of the specified function key.
     * @param funcKey Indicates the function key.
     * @return Returns the enable status of the function key.
     * @since 9
     */
    bool GetFunctionKey(int32_t funcKey) const;

    /**
     * @brief Obtains the key intention of the current event.
     * @param void
     * @return Returns the key intention of the current event.
     * @since 9
     */
    int32_t GetKeyIntention() const;

    /**
     * @brief Sets the key intention for the current key event.
     * @param keyIntention Specified key intention.
     * @return void
     * @since 9
     */
    void SetKeyIntention(int32_t keyIntention);

    /**
     * @brief Gets the automatic keystroke repeat status.
     * @return bool
     * @since 10
     */
    bool IsRepeat() const;

    /**
     * @brief Sets the injection key to repeat automatically.
     * @param repeat Key injection automatic repeat identification.
     * @return void
     * @since 10
     */
    void SetRepeat(bool repeat);

    /**
     * @brief Gets the real-time operation keystroke repeat status.
     * @return bool
     * @since 13
     */
    bool IsRepeatKey() const;

    /**
     * @brief Sets the injection key to repeat practical real-time operation.
     * @param repeat Key injection automatic repeat identification.
     * @return void
     * @since 13
     */
    void SetRepeatKey(bool repeatKey);

    bool IsKeyPressed(int32_t keyCode) const;

    bool HasKeyItem(int32_t keyCode) const;
#ifdef OHOS_BUILD_ENABLE_SECURITY_COMPONENT
    /**
     * @brief Set the enhance data.
     * @return void.
     * @since 11
     */
    void SetEnhanceData(std::vector<uint8_t> enhanceData);
    /**
     * @brief Obtains the enhance data.
     * @return Returns the enhance data.
     * @since 11
     */
    std::vector<uint8_t> GetEnhanceData() const;
#endif // OHOS_BUILD_ENABLE_SECURITY_COMPONENT
public:
    /**
     * @brief Writes data to a <b>Parcel</b> object.
     * @param out Indicates the object into which data will be written.
     * @return Returns <b>true</b> if the data is successfully written; returns <b>false</b> otherwise.
     * @since 9
     */
    bool WriteToParcel(Parcel &out) const;
    bool Marshalling(Parcel &out) const override;

    /**
     * @brief Reads data from a <b>Parcel</b> object.
     * @param in Indicates the object from which data will be read.
     * @return Returns <b>true</b> if the data is successfully read; returns <b>false</b> otherwise.
     * @since 9
     */
    bool ReadFromParcel(Parcel &in);
    static KeyEvent *Unmarshalling(Parcel &in);

    /**
     * @brief Converts a key event action into a short string.
     * @param Indicates the key event action.
     * @return Returns the string converted from the key action.
     * @since 12
    */
    static std::string_view ActionToShortStr(int32_t action);
protected:
    /**
     * @brief Constructs an input event object by using the specified input event type. Generally, this method
     * is used to construct a base class object when constructing a derived class object.
     * @since 9
     */
    explicit KeyEvent(int32_t eventType);

public:
    void SetFourceMonitorFlag(bool fourceMonitorFlag);
    bool GetFourceMonitorFlag();

private:
#ifdef OHOS_BUILD_ENABLE_SECURITY_COMPONENT
    bool ReadEnhanceDataFromParcel(Parcel &in);
#endif // OHOS_BUILD_ENABLE_SECURITY_COMPONENT
    bool IsValidKeyItem() const;

private:
    int32_t keyCode_ { -1 };
    std::vector<KeyItem> keys_;
    int32_t keyAction_ { 0 };
    int32_t keyIntention_ { -1 };
    bool numLock_ { false };
    bool capsLock_ { false };
    bool scrollLock_ { false };
#ifdef OHOS_BUILD_ENABLE_SECURITY_COMPONENT
    std::vector<uint8_t> enhanceData_;
#endif // OHOS_BUILD_ENABLE_SECURITY_COMPONENT
    bool repeat_ { false };
    bool repeatKey_ { false };
    bool fourceMonitorFlag_ { false };
};
} // namespace MMI
} // namespace OHOS
#endif // KEY_EVENT_H
