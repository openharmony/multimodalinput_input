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
    NARROW = 0, 	// full keyboard with narrow key gap.
    WIDE = 1, 		// full keyboard with wide key gap.
    FLOATING = 2,	// floating keyboard
    TRACKPAD = 3,	// trackpad UI-related motion space.
    OTHERS = 10, 	// init value.
};

class MotionSpacePatternIndex {
public:
	// access to inside values from IPC package motion space pattern.
	static const int PATTERN_X = 0; // top left x.
    static const int PATTERN_Y = 1; // top left y.
    static const int PATTERN_WIDTH = 2; // width.
    static const int PATTERN_HEIGHT = 3; // height.
    static const int PATTERN_KEYCODE = 4; // key code.
    static const int PATTERN_MST_ID = 5; // motion space type id.
    static const int PATTERN_PT_ID = 6; // page type id.
    static const size_t PATTERN_SIZE = 7; // size of the entire motion space pattern.
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
    MOTION_MODE = 1,   // generic mode

    // gestures in detailed defines
    WINDOW_GESTURE_BEGIN = 2,   // start of window operation gesture
    ONE_HAND_TAP = 2,
    ONE_HAND_UP = 3, //
    ONE_HAND_DOWN = 4, //
    TWO_HANDS_LOWER_TAP = 5,
    TWO_HANDS_UPPER_TAP = 6,
    TWO_HANDS_UP = 7, //
    TWO_HANDS_DOWN = 8, //
    TWO_HANDS_INWARDS = 9,
    TWO_HANDS_OUTWARDS = 10,
    WINDOW_GESTURE_END = 10,   // end of window operation gesture

    PINCHING_MODE = 11,
    PANNING_MODE = 12,
    SWIPING_MODE = 13,

    SWIPE_BACKSPACE_LEFT = 14,
    SWIPE_BACKSPACE_RIGHT = 15,
};
} // namespace MMI
} // namespace OHOS
#endif // MMI_VKEYBOARD_H
