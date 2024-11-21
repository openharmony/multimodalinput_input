/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef MMI_VKEYBOARD_H
#define MMI_VKEYBOARD_H
#include <string>

namespace OHOS {
namespace MMI {
using namespace std;
struct TOUCHPOINT
{
    /// <summary>
    /// Button name.
    /// </summary>
    string ButtonName;

    /// <summary>
    /// Button width.
    /// </summary>
    double ButtonWidth = 0.0;

    /// <summary>
    /// Button height.
    /// </summary>
    double ButtonHeight = 0.0;

    /// <summary>
    /// touch area width (0 if not supported).
    /// </summary>
    int Width = 0;

    /// <summary>
    /// touch area height (0 if not supported).
    /// </summary>
    int Height = 0;

    /// <summary>
    /// raw touch x. (previous lower case x).
    /// </summary>
    int RawX = 0;

    /// <summary>
    /// raw touch y. (previous lower case y).
    /// </summary>
    int RawY = 0;

    /// <summary>
    /// canvas max x.
    /// </summary>
    int MaxX = 0;

    /// <summary>
    /// canvas max y.
    /// </summary>
    int MaxY = 0;

    /// <summary>
    /// canvas min x.
    /// </summary>
    int MinX = 0;

    /// <summary>
    /// canvas min y.
    /// </summary>
    int MinY = 0;

    /// <summary>
    /// scaled screen x. (previous upper case X).
    /// </summary>
    double ScreenX = 0.0;

    /// <summary>
    /// scaled screen y. (previous upper case Y).
    /// </summary>
    double ScreenY = 0.0;

    /// <summary>
    /// if the touch inside the keyboard.
    /// </summary>
    bool InKeyboard;

    /// <summary>
    /// if the touch inside the trackpad.
    /// </summary>
    bool InTrackpad;

    /// <summary>
    /// touch id.
    /// </summary>
    int TouchId = 0;

    /// <summary>
    /// true - touch down; false - touch up.
    /// </summary>
    bool TipDown;

    /// <summary>
    /// if Bayesian model effective.
    /// </summary>
    bool IsBayesian;

    /// <summary>
    /// If Palm is Detected. (not implemented).
    /// </summary>
    bool IsPalmDetected;
};

struct MMITouchpoint
{
    int PointerId;
    double X;
    double Y;
    string ButtonName;
};

enum StateMachineMessageType
{
    NoMessage = -1,
    KeyPressed = 0,
    CombinationKeyPressed,
    ButtonSound,
    TogglePinOn,
    TogglePinOff,
    DisableProtection,
    BuildButtonMotionSpace,
    ButtonHaptic,
    EnableTrackpadSeparator,
    DisableTrackpadSeparator,
    ShowTaskbar,
    SetButtonContent,
    StartBackspace,
    StopBackspace,
    ResetButtonColor,
    DelayUpdateButtonTouchDownVisual,
    StartLongPressControl,
    StopLongPressControl,
    SwitchLayout,
    SwipeUp,
    BackSwipeLeft,
    BackSwipeRight,
    BackspaceSwipeRelease,
    Idle,
};

class StateMachineMessage
{
public:
    StateMachineMessageType type;
    string buttonName;
    string toggleButtonName;
    int buttonMode = 0;
    string RestList;
    double interval = 0.0;
    double locX = 0.0;
    double locY = 0.0;
};

enum class MotionSpaceType : int32_t {
    // Full keyboard with narrow key gap.
    NARROW = 0,
    // Full keyboard with wide key gap.
    WIDE = 1,
    // Floating keyboard
    FLOATING = 2,
    // Trackpad UI-related motion space.
    TRACKPAD = 3,
    // Init value.
    OTHERS = 10,
};

class MotionSpacePatternIndex {
public:
	// Access to inside values from IPC package motion space pattern.
    // Top left x.
	static const int PATTERN_X = 0;
    // Top left y.
    static const int PATTERN_Y = 1;
    // Width.
    static const int PATTERN_WIDTH = 2;
    // Height.
    static const int PATTERN_HEIGHT = 3;
    // Key code.
    static const int PATTERN_KEYCODE = 4;
    // Motion space type id.
    static const int PATTERN_MST_ID = 5;
    // Page type id.
    static const int PATTERN_PT_ID = 6;
    // Size of the entire motion space pattern.
    static const size_t PATTERN_SIZE = 7;
};

enum TouchMode {
    NO_TOUCH = 0,
    TOUCH_ENTER_MODE = 1,
    LIGHT_TOUCH_MODE = 2,
    HEAVY_TOUCH_MODE = 3,
    REST_TOUCH_MODE = 4,
    ANCHORING_MODE = 5,
    FITTING_MODE = 6,
    LEAVE_SCREEN_MODE = 7,
    MULTI_TOUCH_MODE = 8,
};

/// <summary>
/// GestureMode stands for a working pattern of gesture in a given time duration
/// </summary>
enum class VGestureMode : int32_t {
    NO_GESTURE = 0,
    // Generic mode
    MOTION_MODE = 1,
    // Gestures in detailed defines
    // Gtart of window operation gesture
    WINDOW_GESTURE_BEGIN = 2,
    ONE_HAND_TAP = 2,
    ONE_HAND_UP = 3,
    ONE_HAND_DOWN = 4,
    TWO_HANDS_LOWER_TAP = 5,
    TWO_HANDS_UPPER_TAP = 6,
    TWO_HANDS_UP = 7,
    TWO_HANDS_DOWN = 8,
    TWO_HANDS_INWARDS = 9,
    TWO_HANDS_OUTWARDS = 10,
    // End of window operation gesture
    WINDOW_GESTURE_END = 10,
    PINCHING_MODE = 11,
    PANNING_MODE = 12,
    SWIPING_MODE = 13,
    SWIPE_BACKSPACE_LEFT = 14,
    SWIPE_BACKSPACE_RIGHT = 15,
};

enum class VTPStateMachineMessageType : int32_t {
    UNKNOWN = 0,
    POINTER_MOVE = 1,
    LEFT_CLICK_DOWN = 2,
    LEFT_CLICK_UP = 3,
    RIGHT_CLICK_DOWN = 4,
    RIGHT_CLICK_UP = 5,
};
} // namespace MMI
} // namespace OHOS
#endif // MMI_VKEYBOARD_H
