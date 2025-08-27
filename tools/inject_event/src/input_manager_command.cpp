/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "input_manager_command.h"

#include <getopt.h>

#include <iostream>

#include "string_ex.h"

#include "event_log_helper.h"
#include "hos_key_event.h"
#include "input_manager.h"
#include "product_name_definition.h"
#include "product_type_parser.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputManagerCommand"

class InputManagerCommand {
public:
    int32_t ParseCommand(int32_t argc, char *argv[]);
    int32_t ConnectService();
    void ShowUsage();
private:
    void InitializeMouseDeathStub();
};
namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t SLEEPTIME = 20;
constexpr int32_t MOUSE_ID = 7;
constexpr int32_t JOYSTICK_BUTTON_ID = 25;
constexpr int32_t TWO_MORE_COMMAND = 2;
constexpr int32_t THREE_MORE_COMMAND = 3;
constexpr int32_t MAX_PRESSED_COUNT = 30;
constexpr int32_t ACTION_TIME = 3000;
constexpr int32_t BLOCK_TIME_MS = 7;
constexpr int32_t TIME_TRANSITION = 1000;
constexpr int64_t MIN_TAKTTIME_MS = 1;
constexpr int64_t MAX_TAKTTIME_MS = 15000;
constexpr int32_t DEFAULT_DELAY = 200;
constexpr int32_t KNUCKLE_PARAM_SIZE = 9;
constexpr int32_t DEFAULT_POINTER_ID_FIRST = 0;
constexpr int32_t TOTAL_TIME_MS = 1000;
constexpr int32_t BUTTON_PARAM_SIZE = 8;
constexpr int32_t KEY_PARAM_SIZE = 5;
constexpr int32_t KEY_TIME_PARAM_SIZE = 6;
constexpr int32_t INTERVAL_TIME_MS = 100;
constexpr int32_t FINGER_LOCATION_NUMS = 4;
constexpr int32_t MOVE_POS_ONE = 1;
constexpr int32_t MOVE_POS_TWO = 2;
constexpr int32_t MOVE_POS_THREE = 3;
constexpr int32_t MAX_KEEP_TIME = 60000;
constexpr int32_t NUM_KEEP_ARGC = 2;
constexpr int32_t MAX_ARGC = 18;
constexpr int32_t ONE_ARGC = 1;
constexpr int32_t TWO_ARGC = 2;
constexpr int32_t THREE_ARGC = 3;
constexpr int32_t FOUR_ARGC = 4;
const std::string PRODUCT_TYPE_HYM = OHOS::system::GetParameter("const.build.product", "HYM");

enum JoystickEvent {
    JOYSTICK_BUTTON_UP,
    JOYSTICK_BUTTON_PRESS,
    JOYSTICK_MOVE,
    JOYSTICK_CLICK,
    JOYSTICK_INTERVAL
};
struct JoystickInfo {
    int32_t buttonId { -1 };
    int32_t absValue { -1 };
    int32_t taktTime { 0 };
    PointerEvent::AxisType absType;
};

struct KeyUnicode {
    uint32_t original { 0 };
    uint32_t transitioned { 0 };
};

constexpr uint32_t DEFAULT_UNICODE = 0x0000;

const std::map<int32_t, KeyUnicode> KEY_UNICODE_TRANSFORMATION = {
    { HOS_KEY_A,                { 0x0061, 0x0041 } },
    { HOS_KEY_B,                { 0x0062, 0x0042 } },
    { HOS_KEY_C,                { 0x0063, 0x0043 } },
    { HOS_KEY_D,                { 0x0064, 0x0044 } },
    { HOS_KEY_E,                { 0x0065, 0x0045 } },
    { HOS_KEY_F,                { 0x0066, 0x0046 } },
    { HOS_KEY_G,                { 0x0067, 0x0047 } },
    { HOS_KEY_H,                { 0x0068, 0x0048 } },
    { HOS_KEY_I,                { 0x0069, 0x0049 } },
    { HOS_KEY_J,                { 0x006A, 0x004A } },
    { HOS_KEY_K,                { 0x006B, 0x004B } },
    { HOS_KEY_L,                { 0x006C, 0x004C } },
    { HOS_KEY_M,                { 0x006D, 0x004D } },
    { HOS_KEY_N,                { 0x006E, 0x004E } },
    { HOS_KEY_O,                { 0x006F, 0x004F } },
    { HOS_KEY_P,                { 0x0070, 0x0050 } },
    { HOS_KEY_Q,                { 0x0071, 0x0051 } },
    { HOS_KEY_R,                { 0x0072, 0x0052 } },
    { HOS_KEY_S,                { 0x0073, 0x0053 } },
    { HOS_KEY_T,                { 0x0074, 0x0054 } },
    { HOS_KEY_U,                { 0x0075, 0x0055 } },
    { HOS_KEY_V,                { 0x0076, 0x0056 } },
    { HOS_KEY_W,                { 0x0077, 0x0057 } },
    { HOS_KEY_X,                { 0x0078, 0x0058 } },
    { HOS_KEY_Y,                { 0x0079, 0x0059 } },
    { HOS_KEY_Z,                { 0x007A, 0x005A } },
    { HOS_KEY_0,                { 0x0030, 0x0029 } },
    { HOS_KEY_1,                { 0x0031, 0x0021 } },
    { HOS_KEY_2,                { 0x0032, 0x0040 } },
    { HOS_KEY_3,                { 0x0033, 0x0023 } },
    { HOS_KEY_4,                { 0x0034, 0x0024 } },
    { HOS_KEY_5,                { 0x0035, 0x0025 } },
    { HOS_KEY_6,                { 0x0036, 0x005E } },
    { HOS_KEY_7,                { 0x0037, 0x0026 } },
    { HOS_KEY_8,                { 0x0038, 0x002A } },
    { HOS_KEY_9,                { 0x0039, 0x0028 } },
    { HOS_KEY_GRAVE,            { 0x0060, 0x007E } },
    { HOS_KEY_MINUS,            { 0x002D, 0x005F } },
    { HOS_KEY_EQUALS,           { 0x002B, 0x003D } },
    { HOS_KEY_LEFT_BRACKET,     { 0x005B, 0x007B } },
    { HOS_KEY_RIGHT_BRACKET,    { 0x005D, 0x007D } },
    { HOS_KEY_BACKSLASH,        { 0x005C, 0x007C } },
    { HOS_KEY_SEMICOLON,        { 0x003B, 0x003A } },
    { HOS_KEY_APOSTROPHE,       { 0x0027, 0x0022 } },
    { HOS_KEY_SLASH,            { 0x002F, 0x003F } },
    { HOS_KEY_COMMA,            { 0x002C, 0x003C } },
    { HOS_KEY_PERIOD,           { 0x002E, 0x003E } },
    { HOS_KEY_NUMPAD_0,         { 0x0030, 0x0000 } },
    { HOS_KEY_NUMPAD_1,         { 0x0031, 0x0000 } },
    { HOS_KEY_NUMPAD_2,         { 0x0032, 0x0000 } },
    { HOS_KEY_NUMPAD_3,         { 0x0033, 0x0000 } },
    { HOS_KEY_NUMPAD_4,         { 0x0034, 0x0000 } },
    { HOS_KEY_NUMPAD_5,         { 0x0035, 0x0000 } },
    { HOS_KEY_NUMPAD_6,         { 0x0036, 0x0000 } },
    { HOS_KEY_NUMPAD_7,         { 0x0037, 0x0000 } },
    { HOS_KEY_NUMPAD_8,         { 0x0038, 0x0000 } },
    { HOS_KEY_NUMPAD_9,         { 0x0039, 0x0000 } },
    { HOS_KEY_NUMPAD_DIVIDE,    { 0x002F, 0x0000 } },
    { HOS_KEY_NUMPAD_MULTIPLY,  { 0x0038, 0x0000 } },
    { HOS_KEY_NUMPAD_SUBTRACT,  { 0x002D, 0x0000 } },
    { HOS_KEY_NUMPAD_ADD,       { 0x002B, 0x0000 } },
    { HOS_KEY_NUMPAD_DOT,       { 0x002E, 0x0000 } }
};
} // namespace

void InputManagerCommand::SleepAndUpdateTime(int64_t &currentTimeMs)
{
    int64_t nowEndSysTimeMs = GetSysClockTime() / TIME_TRANSITION;
    int64_t sleepTimeMs = BLOCK_TIME_MS - (nowEndSysTimeMs - currentTimeMs) % BLOCK_TIME_MS;
    std::this_thread::sleep_for(std::chrono::milliseconds(sleepTimeMs));
    currentTimeMs = nowEndSysTimeMs + sleepTimeMs;
}

int32_t InputManagerCommand::NextPos(int64_t begTimeMs, int64_t curtTimeMs, int32_t totalTimeMs,
    int32_t begPos, int32_t endPos)
{
    int64_t endTimeMs = 0;
    if (!AddInt64(begTimeMs, totalTimeMs, endTimeMs)) {
        return begPos;
    }
    if (curtTimeMs < begTimeMs || curtTimeMs > endTimeMs) {
        return begPos;
    }
    if (totalTimeMs == 0) {
        std::cout << "invalid totalTimeMs" << std::endl;
        return begPos;
    }
    double tmpTimeMs = static_cast<double>(curtTimeMs - begTimeMs) / totalTimeMs;
    int32_t offsetPos = std::ceil(tmpTimeMs * (endPos - begPos));
    int32_t retPos = 0;
    if (offsetPos == 0) {
        return begPos;
    } else if (offsetPos > 0) {
        if (!AddInt32(begPos, offsetPos, retPos)) {
            return begPos;
        }
        return retPos > endPos ? endPos : retPos;
    }
    if (!AddInt32(begPos, offsetPos, retPos)) {
        return begPos;
    }
    return retPos < endPos ? endPos : retPos;
}

int32_t InputManagerCommand::ParseCommand(int32_t argc, char *argv[])
{
    struct option headOptions[] = {
        {"mouse", no_argument, nullptr, 'M'},
        {"keyboard", no_argument, nullptr, 'K'},
        {"stylus", no_argument, nullptr, 'S'},
        {"touch", no_argument, nullptr, 'T'},
        {"touchpad", no_argument, nullptr, 'P'},
        {"joystick", no_argument, nullptr, 'J'},
        {"help", no_argument, nullptr, '?'},
        {nullptr, 0, nullptr, 0}
    };

    struct option mouseSensorOptions[] = {
        {"move", required_argument, nullptr, 'm'},
        {"click", required_argument, nullptr, 'c'},
        {"double_click", required_argument, nullptr, 'b'},
        {"down", required_argument, nullptr, 'd'},
        {"up", required_argument, nullptr, 'u'},
        {"scroll", required_argument, nullptr, 's'},
        {"drag", required_argument, nullptr, 'g'},
        {"interval", required_argument, nullptr, 'i'},
        {nullptr, 0, nullptr, 0}
    };
    struct option keyboardSensorOptions[] = {
        {"down", required_argument, nullptr, 'd'},
        {"up", required_argument, nullptr, 'u'},
        {"long_press", required_argument, nullptr, 'l'},
        {"repeat", required_argument, nullptr, 'r'},
        {"interval", required_argument, nullptr, 'i'},
        {"text", required_argument, nullptr, 't'},
        {nullptr, 0, nullptr, 0}
    };
    struct option touchSensorOptions[] = {
        {"move", required_argument, nullptr, 'm'},
        {"down", required_argument, nullptr, 'd'},
        {"up", required_argument, nullptr, 'u'},
        {"click", required_argument, nullptr, 'c'},
        {"interval", required_argument, nullptr, 'i'},
        {"drag", required_argument, nullptr, 'g'},
        {"knuckle", no_argument, nullptr, 'k'},
        {nullptr, 0, nullptr, 0}
    };
    struct option joystickSensorOptions[] = {
        {"move", required_argument, nullptr, 'm'},
        {"down", required_argument, nullptr, 'd'},
        {"up", required_argument, nullptr, 'u'},
        {"click", required_argument, nullptr, 'c'},
        {"interval", required_argument, nullptr, 'i'},
        {nullptr, 0, nullptr, 0}
    };
    int32_t c = 0;
    int32_t optionIndex = 0;
    optind = 0;
    if ((c = getopt_long(argc, argv, "JKMPST?", headOptions, &optionIndex)) != -1) {
        switch (c) {
            case 'M': {
                int32_t px = 0;
                int32_t py = 0;
                int32_t buttonId;
                int32_t scrollValue;

                int32_t ppx = 0;
                int32_t ppy = 0;
                auto simulateMouseEvent = [&ppx, &ppy](std::shared_ptr<PointerEvent> pointerEvent) {
                    PointerEvent::PointerItem item;
                    pointerEvent->GetPointerItem(0, item);
                    int32_t x = item.GetDisplayX();
                    int32_t y = item.GetDisplayY();
                    item.SetRawDx(x - ppx);
                    item.SetRawDy(y - ppy);
                    pointerEvent->UpdatePointerItem(0, item);
                    ppx = x;
                    ppy = y;
                    return InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
                };
                while ((c = getopt_long(argc, argv, "m:d:u:c:b:s:g:i:", mouseSensorOptions, &optionIndex)) != -1) {
                    switch (c) {
                        case 'm': {
                            if (argc - optind < 1) {
                                std::cout << "too few arguments to function" << std::endl;
                                return RET_ERR;
                            }
                            auto isTraceOption = [](const std::string &opt1) {
                                return opt1 == std::string("--trace");
                            };
                            auto traceMode = [isTraceOption](int32_t argCount, char *argvOffset[]) -> bool {
                                if (argCount <= 3) {
                                    return false;
                                }
                                std::string arg3 = argvOffset[2];
                                if (!arg3.empty() && arg3.at(0) == '-') {
                                    return false;
                                }
                                if ((argCount >= 5) && isTraceOption(std::string(argvOffset[4]))) {
                                    return true;
                                }
                                if ((argCount >= 6) && isTraceOption(std::string(argvOffset[5]))) {
                                    return true;
                                }
                                return false;
                            }(argc - optind + 1, &argv[optind - 1]);
                            if (!traceMode) {
                                if (!StrToInt(optarg, px) || !StrToInt(argv[optind], py)) {
                                    std::cout << "invalid parameter to move mouse" << std::endl;
                                    return RET_ERR;
                                }
                                if ((px < 0) || (py < 0)) {
                                    std::cout << "Coordinate value must be greater or equal than 0" << std::endl;
                                    return RET_ERR;
                                }
                                std::cout << "move to " << px << " " << py << std::endl;
                                auto pointerEvent = PointerEvent::Create();
                                CHKPR(pointerEvent, ERROR_NULL_POINTER);
                                PointerEvent::PointerItem item;
                                item.SetPointerId(0);
                                item.SetDisplayX(px);
                                item.SetDisplayY(py);
                                pointerEvent->AddPointerItem(item);
                                pointerEvent->SetPointerId(0);
                                pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
                                pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
                                simulateMouseEvent(pointerEvent);
                                optind++;
                            } else {
                                int32_t px1 = 0;
                                int32_t py1 = 0;
                                int32_t px2 = 0;
                                int32_t py2 = 0;
                                int32_t totalTimeMs = 1000;
                                bool foundTraceOption = false;
                                if (argc - optind >= 3) {
                                    if ((!StrToInt(optarg, px1)) ||
                                        (!StrToInt(argv[optind], py1)) ||
                                        (!StrToInt(argv[optind + 1], px2)) ||
                                        (!StrToInt(argv[optind + 2], py2))) {
                                            std::cout << "invalid coordinate value" << std::endl;
                                            return RET_ERR;
                                    }
                                    optind += 3;
                                }
                                if ((px1 < 0) || (py1 < 0) || (px2 < 0) || (py2 < 0)) {
                                    std::cout << "Coordinate value must be greater or equal than 0" << std::endl;
                                    return RET_ERR;
                                }
                                if (argc - optind >= 1) {
                                    std::string arg5 = argv[optind];
                                    if (!arg5.empty() && arg5.at(0) == '-') {
                                        if (isTraceOption(arg5)) {
                                            foundTraceOption = true;
                                        } else {
                                            std::cout << "invalid option, the 5th position parameter must be --trace"
                                                << std::endl;
                                            return RET_ERR;
                                        }
                                    } else if (!StrToInt(arg5, totalTimeMs)) {
                                        std::cout << "invalid smooth times" << std::endl;
                                        return RET_ERR;
                                    }
                                    optind++;
                                }
                                if (!foundTraceOption) {
                                    if (argc - optind < 1) {
                                        std::cout << "missing 6th position parameter --trace" << std::endl;
                                        return RET_ERR;
                                    }
                                    std::string arg6 = argv[optind];
                                    if (!isTraceOption(arg6)) {
                                        std::cout << "invalid option, the 6th position parameter must be --trace"
                                            << std::endl;
                                        return RET_ERR;
                                    }
                                    optind++;
                                    foundTraceOption = true;
                                }
                                static const int64_t minTotalTimeMs = 1;
                                static const int64_t maxTotalTimeMs = 15000;
                                if ((totalTimeMs < minTotalTimeMs) || (totalTimeMs > maxTotalTimeMs)) {
                                    std::cout << "total time is out of range:"
                                        << minTotalTimeMs << " <= " << totalTimeMs << " <= " << maxTotalTimeMs
                                        << std::endl;
                                    return RET_ERR;
                                }
                                std::cout << "start coordinate: (" << px1 << ", " << py1 << ")" << std::endl;
                                std::cout << "  end coordinate: (" << px2 << ", " << py2 << ")" << std::endl;
                                std::cout << "     smooth time: "  << totalTimeMs << " ms"      << std::endl;
                                std::cout << "      trace mode: " << std::boolalpha << foundTraceOption << std::endl;
                                auto pointerEvent = PointerEvent::Create();
                                CHKPR(pointerEvent, ERROR_NULL_POINTER);
                                px = px1;
                                py = py1;
                                PointerEvent::PointerItem item;
                                item.SetPointerId(0);
                                item.SetDisplayX(px);
                                item.SetDisplayY(py);
                                pointerEvent->SetPointerId(0);
                                pointerEvent->AddPointerItem(item);
                                pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
                                pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
                                simulateMouseEvent(pointerEvent);

                                int64_t startTimeUs = GetSysClockTime();
                                int64_t startTimeMs = startTimeUs / TIME_TRANSITION;
                                int64_t endTimeMs = 0;
                                if (!AddInt64(startTimeMs, totalTimeMs, endTimeMs)) {
                                    std::cout << "system time error" << std::endl;
                                    return RET_ERR;
                                }
                                int64_t currentTimeMs = startTimeMs;
                                while (currentTimeMs < endTimeMs) {
                                    item.SetDisplayX(NextPos(startTimeMs, currentTimeMs, totalTimeMs, px1, px2));
                                    item.SetDisplayY(NextPos(startTimeMs, currentTimeMs, totalTimeMs, py1, py2));
                                    pointerEvent->SetActionTime(currentTimeMs * TIME_TRANSITION);
                                    pointerEvent->UpdatePointerItem(0, item);
                                    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
                                    simulateMouseEvent(pointerEvent);
                                    SleepAndUpdateTime(currentTimeMs);
                                }

                                px = px2;
                                py = py2;
                                item.SetDisplayX(px);
                                item.SetDisplayY(py);
                                pointerEvent->SetActionTime(endTimeMs * TIME_TRANSITION);
                                pointerEvent->UpdatePointerItem(0, item);
                                pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
                                simulateMouseEvent(pointerEvent);
                            }
                            break;
                        }
                        case 'd': {
                            if (!StrToInt(optarg, buttonId)) {
                                std::cout << "invalid button press command" << std::endl;
                                return EVENT_REG_FAIL;
                            }
                            if (buttonId > MOUSE_ID || buttonId < 0) {
                                std::cout << "invalid button press command" << std::endl;
                                return EVENT_REG_FAIL;
                            }
                            std::cout << "press down " << buttonId << std::endl;
                            auto pointerEvent = PointerEvent::Create();
                            CHKPR(pointerEvent, ERROR_NULL_POINTER);
                            PointerEvent::PointerItem item;
                            item.SetPointerId(0);
                            item.SetDisplayX(px);
                            item.SetDisplayY(py);
                            item.SetPressed(true);
                            pointerEvent->SetPointerId(0);
                            pointerEvent->AddPointerItem(item);
                            pointerEvent->SetButtonId(buttonId);
                            pointerEvent->SetButtonPressed(buttonId);
                            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_DOWN);
                            pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
                            simulateMouseEvent(pointerEvent);
                            break;
                        }
                        case 'u': {
                            if (!StrToInt(optarg, buttonId)) {
                                std::cout << "invalid raise button command" << std::endl;
                                return EVENT_REG_FAIL;
                            }
                            if (buttonId > MOUSE_ID || buttonId < 0) {
                                std::cout << "invalid raise button command" << std::endl;
                                return EVENT_REG_FAIL;
                            }
                            std::cout << "lift up button " << buttonId << std::endl;
                            auto pointerEvent = PointerEvent::Create();
                            CHKPR(pointerEvent, ERROR_NULL_POINTER);
                            PointerEvent::PointerItem item;
                            item.SetPointerId(0);
                            item.SetDisplayX(px);
                            item.SetDisplayY(py);
                            item.SetPressed(false);
                            pointerEvent->SetPointerId(0);
                            pointerEvent->AddPointerItem(item);
                            pointerEvent->DeleteReleaseButton(buttonId);
                            pointerEvent->SetButtonId(buttonId);
                            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_UP);
                            pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
                            simulateMouseEvent(pointerEvent);
                            break;
                        }
                        case 's': {
                            if (!StrToInt(optarg, scrollValue)) {
                                std::cout << "invalid scroll button command" << std::endl;
                                return EVENT_REG_FAIL;
                            }
                            if (buttonId > MOUSE_ID) {
                                std::cout << "invalid raise button command" << std::endl;
                                return EVENT_REG_FAIL;
                            }
                            std::cout << "scroll wheel " << scrollValue << std::endl;
                            auto pointerEvent = PointerEvent::Create();
                            CHKPR(pointerEvent, ERROR_NULL_POINTER);
                            PointerEvent::PointerItem item;
                            item.SetPointerId(0);
                            item.SetDisplayX(px);
                            item.SetDisplayY(py);
                            item.SetPressed(false);
                            int64_t time = pointerEvent->GetActionStartTime();
                            pointerEvent->SetActionTime(time + ACTION_TIME);
                            pointerEvent->SetPointerId(0);
                            pointerEvent->AddPointerItem(item);
                            pointerEvent->SetButtonPressed(buttonId);
                            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_BEGIN);
                            pointerEvent->SetAxisValue(PointerEvent::AxisType::AXIS_TYPE_SCROLL_VERTICAL, scrollValue);
                            pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
                            simulateMouseEvent(pointerEvent);

                            time = pointerEvent->GetActionStartTime();
                            pointerEvent->SetActionTime(time + ACTION_TIME);
                            pointerEvent->SetPointerId(0);
                            pointerEvent->AddPointerItem(item);
                            pointerEvent->SetButtonPressed(buttonId);
                            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_UPDATE);
                            pointerEvent->SetAxisValue(PointerEvent::AxisType::AXIS_TYPE_SCROLL_VERTICAL, scrollValue);
                            pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
                            simulateMouseEvent(pointerEvent);

                            time = pointerEvent->GetActionStartTime();
                            pointerEvent->SetActionTime(time + ACTION_TIME);
                            pointerEvent->SetPointerId(0);
                            pointerEvent->AddPointerItem(item);
                            pointerEvent->DeleteReleaseButton(buttonId);
                            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_END);
                            pointerEvent->SetAxisValue(PointerEvent::AxisType::AXIS_TYPE_SCROLL_VERTICAL, scrollValue);
                            pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
                            simulateMouseEvent(pointerEvent);
                            break;
                        }
                        case 'c': {
                            if (!StrToInt(optarg, buttonId)) {
                                std::cout << "invalid click button command" << std::endl;
                                return EVENT_REG_FAIL;
                            }
                            if (buttonId > MOUSE_ID || buttonId < 0) {
                                std::cout << "invalid button press command" << std::endl;
                                return EVENT_REG_FAIL;
                            }
                            std::cout << "click " << buttonId << std::endl;
                            auto pointerEvent = PointerEvent::Create();
                            CHKPR(pointerEvent, ERROR_NULL_POINTER);
                            PointerEvent::PointerItem item;
                            item.SetDisplayY(py);
                            item.SetPressed(true);
                            item.SetPointerId(0);
                            item.SetDisplayX(px);
                            pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
                            pointerEvent->AddPointerItem(item);
                            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_DOWN);
                            pointerEvent->SetButtonId(buttonId);
                            pointerEvent->SetButtonPressed(buttonId);
                            pointerEvent->SetPointerId(0);
                            simulateMouseEvent(pointerEvent);
                            item.SetPointerId(0);
                            item.SetPressed(false);
                            item.SetDisplayX(px);
                            item.SetDisplayY(py);
                            pointerEvent->SetPointerId(0);
                            pointerEvent->UpdatePointerItem(0, item);
                            pointerEvent->DeleteReleaseButton(buttonId);
                            pointerEvent->SetButtonId(buttonId);
                            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_UP);
                            pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
                            simulateMouseEvent(pointerEvent);
                            break;
                        }
                        case 'b': {
                            int32_t pressTimeMs = 50;
                            int32_t clickIntervalTimeMs = 300;
                            static constexpr int32_t minButtonId = 0;
                            static constexpr int32_t maxButtonId = 7;
                            static constexpr int32_t minPressTimeMs = 1;
                            static constexpr int32_t maxPressTimeMs = 300;
                            static constexpr int32_t minClickIntervalTimeMs = 1;
                            static constexpr int32_t maxClickIntervalTimeMs = 450;
                            if (argc < 6 || argc > 8) {
                                std::cout << "wrong number of parameters" << std::endl;
                                return RET_ERR;
                            }
                            if (!StrToInt(optarg, px) ||
                                !StrToInt(argv[optind], py)) {
                                std::cout << "invalid coordinate value" << std::endl;
                                return RET_ERR;
                            }
                            if ((px < 0) || (py < 0)) {
                                std::cout << "Coordinate value must be greater or equal than 0" << std::endl;
                                return RET_ERR;
                            }
                            if (!StrToInt(argv[optind + 1], buttonId)) {
                                std::cout << "invalid key" << std::endl;
                                return RET_ERR;
                            }
                            if (argc >= 7) {
                                if (!StrToInt(argv[optind + 2], pressTimeMs)) {
                                    std::cout << "invalid press time" << std::endl;
                                    return RET_ERR;
                                }
                            }
                            if (argc == BUTTON_PARAM_SIZE) {
                                if (!StrToInt(argv[optind + 3], clickIntervalTimeMs)) {
                                    std::cout << "invalid click interval time" << std::endl;
                                    return RET_ERR;
                                }
                            }
                            if ((buttonId < minButtonId) || (buttonId > maxButtonId)) {
                                std::cout << "button is out of range:" << minButtonId << " < " << buttonId << " < "
                                    << maxButtonId << std::endl;
                                return RET_ERR;
                            }
                            if ((pressTimeMs < minPressTimeMs) || (pressTimeMs > maxPressTimeMs)) {
                                std::cout << "press time is out of range:" << minPressTimeMs << " ms" << " < "
                                    << pressTimeMs << " < " << maxPressTimeMs << " ms" << std::endl;
                                return RET_ERR;
                            }
                            if ((clickIntervalTimeMs < minClickIntervalTimeMs) ||
                                (clickIntervalTimeMs > maxClickIntervalTimeMs)) {
                                std::cout << "click interval time is out of range:" << minClickIntervalTimeMs << " ms"
                                    " < " << clickIntervalTimeMs << " < " << maxClickIntervalTimeMs << " ms"
                                    << std::endl;
                                return RET_ERR;
                            }
                            std::cout << "   coordinate: ("<< px << ", "  << py << ")" << std::endl;
                            std::cout << "    button id: " << buttonId    << std::endl;
                            std::cout << "   press time: " << pressTimeMs << " ms" << std::endl;
                            std::cout << "interval time: " << clickIntervalTimeMs  << " ms" << std::endl;
                            auto pointerEvent = PointerEvent::Create();
                            CHKPR(pointerEvent, ERROR_NULL_POINTER);
                            pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
                            PointerEvent::PointerItem item;
                            item.SetPressed(true);
                            item.SetPointerId(0);
                            item.SetDisplayX(px);
                            item.SetDisplayY(py);
                            pointerEvent->SetPointerId(0);
                            pointerEvent->SetButtonId(buttonId);
                            pointerEvent->SetButtonPressed(buttonId);
                            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_DOWN);
                            pointerEvent->AddPointerItem(item);
                            simulateMouseEvent(pointerEvent);
                            std::this_thread::sleep_for(std::chrono::milliseconds(pressTimeMs));
                            item.SetPressed(false);
                            pointerEvent->UpdatePointerItem(0, item);
                            pointerEvent->DeleteReleaseButton(buttonId);
                            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_UP);
                            simulateMouseEvent(pointerEvent);
                            std::this_thread::sleep_for(std::chrono::milliseconds(clickIntervalTimeMs));

                            item.SetPressed(true);
                            pointerEvent->UpdatePointerItem(0, item);
                            pointerEvent->SetButtonPressed(buttonId);
                            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_DOWN);
                            simulateMouseEvent(pointerEvent);
                            std::this_thread::sleep_for(std::chrono::milliseconds(pressTimeMs));
                            item.SetPressed(false);
                            pointerEvent->UpdatePointerItem(0, item);
                            pointerEvent->DeleteReleaseButton(buttonId);
                            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_UP);
                            simulateMouseEvent(pointerEvent);
                            break;
                        }
                        case 'g': {
                            int32_t px1 = 0;
                            int32_t py1 = 0;
                            int32_t px2 = 0;
                            int32_t py2 = 0;
                            int32_t buttonsId = 0;
                            int32_t totalTimeMs = 1000;
                            if (argc < 7) {
                                std::cout << "argc:" << argc << std::endl;
                                std::cout << "Wrong number of parameters" << std::endl;
                                return RET_ERR;
                            }
                            if (argc >= 7) {
                                if ((!StrToInt(optarg, px1)) ||
                                    (!StrToInt(argv[optind], py1)) ||
                                    (!StrToInt(argv[optind + 1], px2)) ||
                                    (!StrToInt(argv[optind + 2], py2))) {
                                        std::cout << "Invalid coordinate value" << std::endl;
                                        return RET_ERR;
                                }
                            }
                            if ((px1 < 0) || (py1 < 0) || (px2 < 0) || (py2 < 0)) {
                                std::cout << "Coordinate value must be greater or equal than 0" << std::endl;
                                return RET_ERR;
                            }
                            if (argc >= 8) {
                                if (!StrToInt(argv[optind + 3], totalTimeMs)) {
                                    std::cout << "Invalid total times" << std::endl;
                                    return RET_ERR;
                                }
                            }
                            static const int64_t minTotalTimeMs = 1;
                            static const int64_t maxTotalTimeMs = 15000;
                            if ((totalTimeMs < minTotalTimeMs) || (totalTimeMs > maxTotalTimeMs)) {
                                std::cout << "Total time is out of range:"
                                    << minTotalTimeMs << "ms" << " <= " << totalTimeMs << "ms" << " <= "
                                    << maxTotalTimeMs << "ms" << std::endl;
                                return RET_ERR;
                            }
                            std::cout << "start coordinate: (" << px1 << ", "  << py1 << ")" << std::endl;
                            std::cout << "  end coordinate: (" << px2 << ", "  << py2 << ")" << std::endl;
                            std::cout << "      total time: "  << totalTimeMs  << "ms"       << std::endl;
                            auto pointerEvent = PointerEvent::Create();
                            CHKPR(pointerEvent, ERROR_NULL_POINTER);
                            PointerEvent::PointerItem item;
                            item.SetDisplayY(py1);
                            item.SetDisplayX(px1);
                            item.SetPressed(false);
                            item.SetPointerId(0);
                            pointerEvent->SetButtonPressed(0);
                            pointerEvent->AddPointerItem(item);
                            pointerEvent->SetButtonId(buttonsId);
                            pointerEvent->SetButtonPressed(buttonsId);
                            pointerEvent->SetPointerId(0);
                            pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
                            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_DOWN);
                            simulateMouseEvent(pointerEvent);

                            int64_t startTimeMs = GetSysClockTime() / TIME_TRANSITION;
                            int64_t endTimeMs = 0;
                            if (!AddInt64(startTimeMs, totalTimeMs, endTimeMs)) {
                                std::cout << "System time error" << std::endl;
                                return RET_ERR;
                            }
                            int64_t currentTimeMs = startTimeMs;
                            while (currentTimeMs < endTimeMs) {
                                item.SetDisplayX(NextPos(startTimeMs, currentTimeMs, totalTimeMs, px1, px2));
                                item.SetDisplayY(NextPos(startTimeMs, currentTimeMs, totalTimeMs, py1, py2));
                                pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
                                pointerEvent->UpdatePointerItem(0, item);
                                pointerEvent->SetActionTime(currentTimeMs * TIME_TRANSITION);
                                simulateMouseEvent(pointerEvent);
                                SleepAndUpdateTime(currentTimeMs);
                            }
                            item.SetDisplayY(py2);
                            item.SetDisplayX(px2);
                            pointerEvent->UpdatePointerItem(0, item);
                            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
                            pointerEvent->SetActionTime(endTimeMs * TIME_TRANSITION);
                            simulateMouseEvent(pointerEvent);
                            std::this_thread::sleep_for(std::chrono::milliseconds(BLOCK_TIME_MS));

                            item.SetPressed(true);
                            item.SetDisplayY(py2);
                            item.SetDisplayX(px2);
                            pointerEvent->UpdatePointerItem(0, item);
                            pointerEvent->SetActionTime(endTimeMs * TIME_TRANSITION);
                            pointerEvent->DeleteReleaseButton(buttonsId);
                            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_UP);
                            simulateMouseEvent(pointerEvent);
                            break;
                        }
                        case 'i': {
                            int32_t tookTime = 0;
                            if (!StrToInt(optarg, tookTime)) {
                                std::cout << "invalid command to interval time" << std::endl;
                                return EVENT_REG_FAIL;
                            }
                            const int64_t minTaktTimeMs = 1;
                            const int64_t maxTaktTimeMs = 15000;
                            if ((minTaktTimeMs > tookTime) || (maxTaktTimeMs < tookTime)) {
                                std::cout << "tookTime is out of range" << std::endl;
                                std::cout << minTaktTimeMs << " < tookTime < " << maxTaktTimeMs;
                                std::cout << std::endl;
                                return EVENT_REG_FAIL;
                            }
                            std::this_thread::sleep_for(std::chrono::milliseconds(tookTime));
                            break;
                        }
                        default: {
                            std::cout << "invalid command to virtual mouse" << std::endl;
                            ShowUsage();
                            return EVENT_REG_FAIL;
                        }
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEPTIME));
                }
                break;
            }
            case 'K': {
                std::vector<int32_t> downKey;
                int32_t keyCode = 0;
                int32_t isCombinationKey = 0;
                int64_t time = GetSysClockTime();
                int32_t count = 0;
                bool inputText = false;
                while ((c = getopt_long(argc, argv, "d:u:l:r:i:t:", keyboardSensorOptions, &optionIndex)) != -1) {
                    // Prompt when combining other commands after using the text command. Ex: "uinput -d 2017 -t text"
                    if (inputText) {
                        std::cout << "The text command cannot be used with other commands." << std::endl;
                        return RET_ERR;
                    }
                    switch (c) {
                        case 'd': {
                            if (!StrToInt(optarg, keyCode)) {
                                std::cout << "invalid command to down key" << std::endl;
                            }
                            if (optind == isCombinationKey + TWO_MORE_COMMAND) {
                                downKey.push_back(keyCode);
                                isCombinationKey = optind;
                                auto KeyEvent = KeyEvent::Create();
                                CHKPR(KeyEvent, ERROR_NULL_POINTER);
                                if (downKey.size() > MAX_PRESSED_COUNT) {
                                    std::cout << "pressed button count should less than 30" << std::endl;
                                    return EVENT_REG_FAIL;
                                }
                                KeyEvent::KeyItem item[downKey.size()];
                                for (size_t i = 0; i < downKey.size(); i++) {
                                    KeyEvent->SetKeyCode(keyCode);
                                    KeyEvent->SetActionTime(time);
                                    KeyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
                                    item[i].SetKeyCode(downKey[i]);
                                    item[i].SetUnicode(KeyCodeToUnicode(downKey[i]));
                                    item[i].SetDownTime(time);
                                    item[i].SetPressed(true);
                                    KeyEvent->AddKeyItem(item[i]);
                                }
                                InputManager::GetInstance()->SimulateInputEvent(KeyEvent);
                                break;
                            }
                            downKey.push_back(keyCode);
                            auto KeyEvent = KeyEvent::Create();
                            CHKPR(KeyEvent, ERROR_NULL_POINTER);
                            KeyEvent->SetKeyCode(keyCode);
                            KeyEvent->SetActionTime(time);
                            KeyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
                            KeyEvent::KeyItem item1;
                            item1.SetPressed(true);
                            item1.SetKeyCode(keyCode);
                            item1.SetUnicode(KeyCodeToUnicode(keyCode));
                            item1.SetDownTime(time);
                            KeyEvent->AddKeyItem(item1);
                            InputManager::GetInstance()->SimulateInputEvent(KeyEvent);
                            isCombinationKey = optind;
                            break;
                        }
                        case 'u': {
                            if (!StrToInt(optarg, keyCode)) {
                                std::cout << "invalid button press command" << std::endl;
                                return EVENT_REG_FAIL;
                            }
                            std::vector<int32_t>::iterator iter = std::find(downKey.begin(), downKey.end(), keyCode);
                            if (iter != downKey.end()) {
                                std::cout << "you raised the key " << keyCode << std::endl;
                                auto KeyEvent = KeyEvent::Create();
                                CHKPR(KeyEvent, ERROR_NULL_POINTER);
                                KeyEvent->SetKeyCode(keyCode);
                                KeyEvent->SetActionTime(time);
                                KeyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
                                KeyEvent::KeyItem item1;
                                item1.SetPressed(false);
                                item1.SetKeyCode(keyCode);
                                item1.SetUnicode(KeyCodeToUnicode(keyCode));
                                item1.SetDownTime(time);
                                KeyEvent->AddKeyItem(item1);
                                InputManager::GetInstance()->SimulateInputEvent(KeyEvent);
                                iter = downKey.erase(iter);
                                break;
                            } else {
                                std::cout << "please press the " << keyCode << " key first "<< std::endl;
                                return EVENT_REG_FAIL;
                            }
                        }
                        case 'l': {
                            if (argc < 4) {
                                std::cout << "argc:" << argc << std::endl;
                                std::cout << "wrong number of parameters" << std::endl;
                                return RET_ERR;
                            }
                            if (argc >= 4) {
                                if (!StrToInt(optarg, keyCode)) {
                                    std::cout << "invalid key code value" << std::endl;
                                    return RET_ERR;
                                }
                            }
                            int32_t pressTimeMs = 3000;
                            if (argc >= 5) {
                                if (!StrToInt(argv[optind], pressTimeMs)) {
                                    std::cout << "invalid key code value or press time" << std::endl;
                                    return RET_ERR;
                                }
                            }
                            static constexpr int32_t minKeyCode = 0;
                            static constexpr int32_t maxKeyCode = 5000;
                            if ((keyCode < minKeyCode) || (keyCode > maxKeyCode)) {
                                std::cout << "key code is out of range:" << minKeyCode << " <= "
                                    << keyCode << " <= " << maxKeyCode << std::endl;
                                return RET_ERR;
                            }
                            static constexpr int32_t minPressTimeMs = 3000;
                            static constexpr int32_t maxPressTimeMs = 15000;
                            if ((pressTimeMs < minPressTimeMs) || (pressTimeMs > maxPressTimeMs)) {
                                std::cout << "press time is out of range:" << minPressTimeMs << " ms" << " <= "
                                    << pressTimeMs << " <= " << maxPressTimeMs << " ms" << std::endl;
                                return RET_ERR;
                            }
                            std::cout << " key code: " << keyCode << std::endl
                                << "long press time: " << pressTimeMs << " ms" << std::endl;
                            auto keyEvent = KeyEvent::Create();
                            if (keyEvent == nullptr) {
                                std::cout << "failed to create input event object" << std::endl;
                                return RET_ERR;
                            }
                            keyEvent->SetKeyCode(keyCode);
                            keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
                            KeyEvent::KeyItem item;
                            item.SetKeyCode(keyCode);
                            item.SetUnicode(KeyCodeToUnicode(keyCode));
                            item.SetPressed(true);
                            auto keyEventTemp = KeyEvent::Clone(keyEvent);
                            if (keyEventTemp == nullptr) {
                                std::cout << "failed to clone key event object" << std::endl;
                                return RET_ERR;
                            }
                            keyEventTemp->AddKeyItem(item);
                            InputManager::GetInstance()->SimulateInputEvent(keyEventTemp);
                            std::this_thread::sleep_for(std::chrono::milliseconds(pressTimeMs));

                            keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
                            item.SetPressed(false);
                            keyEvent->AddKeyItem(item);
                            InputManager::GetInstance()->SimulateInputEvent(keyEvent);
                            break;
                        }
                        case 'r': {
                            constexpr int32_t ARGC_MIN = 4;
                            if (argc < ARGC_MIN) {
                                std::cout << "argc:" << argc << std::endl;
                                std::cout << "wrong number of parameters" << std::endl;
                                return RET_ERR;
                            }
                            if (argc >= ARGC_MIN) {
                                if (!StrToInt(optarg, keyCode)) {
                                    std::cout << "invalid key code value" << std::endl;
                                    return RET_ERR;
                                }
                            }
                            int32_t pressTimeMs = 3000;
                            constexpr int32_t ARGC_MAX = 5;
                            if (argc >= ARGC_MAX) {
                                if (!StrToInt(argv[optind], pressTimeMs)) {
                                    std::cout << "invalid key code value or press time" << std::endl;
                                    return RET_ERR;
                                }
                            }
                            static constexpr int32_t minKeyCode = 0;
                            static constexpr int32_t maxKeyCode = 5000;
                            if ((keyCode < minKeyCode) || (keyCode > maxKeyCode)) {
                                std::cout << "key code is out of range:" << minKeyCode << " <= "
                                    << keyCode << " <= " << maxKeyCode << std::endl;
                                return RET_ERR;
                            }
                            static constexpr int32_t minPressTimeMs = 3000;
                            static constexpr int32_t maxPressTimeMs = 15000;
                            if ((pressTimeMs < minPressTimeMs) || (pressTimeMs > maxPressTimeMs)) {
                                std::cout << "press time is out of range:" << minPressTimeMs << " ms" << " <= "
                                    << pressTimeMs << " <= " << maxPressTimeMs << " ms" << std::endl;
                                return RET_ERR;
                            }
                            std::cout << " key code: " << keyCode << std::endl
                                << "long press time: " << pressTimeMs << " ms" << std::endl;
                            auto keyEvent = KeyEvent::Create();
                            if (keyEvent == nullptr) {
                                std::cout << "failed to create input event object" << std::endl;
                                return RET_ERR;
                            }
                            keyEvent->SetKeyCode(keyCode);
                            keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
                            KeyEvent::KeyItem item;
                            item.SetKeyCode(keyCode);
                            item.SetUnicode(KeyCodeToUnicode(keyCode));
                            int64_t time = GetSysClockTime();
                            item.SetPressed(true);
                            auto keyEventTemp = KeyEvent::Clone(keyEvent);
                            if (keyEventTemp == nullptr) {
                                std::cout << "failed to clone key event object" << std::endl;
                                return RET_ERR;
                            }
                            keyEventTemp->SetActionTime(time);
                            keyEventTemp->AddKeyItem(item);
                            keyEventTemp->SetRepeat(true);
                            std::string isRepeat = keyEventTemp->IsRepeat() ? "true" : "false";
                            if (!EventLogHelper::IsBetaVersion()) {
                                MMI_HILOGI("KeyAction:%{public}s, IsRepeat:%{public}s",
                                    KeyEvent::ActionToString(keyEventTemp->GetKeyAction()), isRepeat.c_str());
                            } else {
                                MMI_HILOGI("KeyCode:%{private}d, ActionTime:%{public}" PRId64
                                    ",KeyAction:%{public}s, IsRepeat:%{public}s",
                                    keyEventTemp->GetKeyCode(), keyEventTemp->GetActionTime(),
                                    KeyEvent::ActionToString(keyEventTemp->GetKeyAction()), isRepeat.c_str());
                            }
                            InputManager::GetInstance()->SimulateInputEvent(keyEventTemp);
                            std::this_thread::sleep_for(std::chrono::milliseconds(pressTimeMs));

                            keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
                            item.SetPressed(false);
                            keyEvent->AddKeyItem(item);
                            time = GetSysClockTime();
                            keyEvent->SetActionTime(time);
                            keyEvent->SetRepeat(true);
                            isRepeat = keyEvent->IsRepeat() ? "true" : "false";
                            if (!OHOS::MMI::EventLogHelper::IsBetaVersion()) {
                                MMI_HILOGI("KeyAction:%{public}s, IsRepeat:%{public}s",
                                    KeyEvent::ActionToString(keyEvent->GetKeyAction()), isRepeat.c_str());
                            } else {
                                MMI_HILOGI("KeyCode:%{private}d, ActionTime:%{public}" PRId64
                                    ",KeyAction:%{public}s, IsRepeat:%{public}s",
                                    keyEvent->GetKeyCode(), keyEvent->GetActionTime(),
                                    KeyEvent::ActionToString(keyEvent->GetKeyAction()), isRepeat.c_str());
                            }
                            InputManager::GetInstance()->SimulateInputEvent(keyEvent);
                            break;
                        }
                        case 'i': {
                            int32_t taktTime = 0;
                            if (!StrToInt(optarg, taktTime)) {
                                std::cout << "invalid command to interval time" << std::endl;
                                return EVENT_REG_FAIL;
                            }
                            const int64_t minTaktTimeMs = 1;
                            const int64_t maxTaktTimeMs = 15000;
                            if ((minTaktTimeMs > taktTime) || (maxTaktTimeMs < taktTime)) {
                                std::cout << "taktTime is error" << std::endl;
                                std::cout << minTaktTimeMs << " < taktTime < " << maxTaktTimeMs;
                                std::cout << std::endl;
                                return EVENT_REG_FAIL;
                            }
                            std::this_thread::sleep_for(std::chrono::milliseconds(taktTime));
                            break;
                        }
                        case 't': {
                            int32_t ret = ProcessKeyboardTextInput(optarg, count);
                            if (ret != ERR_OK) {
                                return ret;
                            }
                            inputText = true;
                            break;
                        }
                        default: {
                            std::cout << "invalid command to keyboard key" << std::endl;
                            ShowUsage();
                            return EVENT_REG_FAIL;
                        }
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEPTIME));
                    count++;
                }
                for (size_t i = 0; i < downKey.size(); i++) {
                    std::cout << "you have a key " << downKey[i] << " not release" << std::endl;
                }
                break;
            }
            case 'S':
            case 'T': {
                int32_t px1 = 0;
                int32_t py1 = 0;
                int32_t px2 = 0;
                int32_t py2 = 0;
                int32_t totalTimeMs = 0;
                int32_t moveArgcSeven = 7;
                int32_t firstOpt = c;
                while ((c = getopt_long(argc, argv, "m:d:u:c:i:g:k", touchSensorOptions, &optionIndex)) != -1) {
                    switch (c) {
                        case 'm': {
                            if (argc < moveArgcSeven || argc > MAX_ARGC) {
                                std::cout << "wrong number of parameters:" << argc << std::endl;
                                return EVENT_REG_FAIL;
                            }
                            struct FingerInfo {
                                int32_t startX = 0;
                                int32_t startY = 0;
                                int32_t endX = 0;
                                int32_t endY = 0;
                            };
                            int32_t startX = 0;
                            int32_t startY = 0;
                            int32_t endX = 0;
                            int32_t endY = 0;
                            int32_t totalTimeMs = 0;
                            int32_t keepTimeMs = 0;
                            int32_t fingerCount = 0;
                            std::vector<FingerInfo> fingerList;
                            int32_t startPos = optind - MOVE_POS_ONE;
                            while (true) {
                                int32_t residueArgc = argc - startPos;
                                if (residueArgc == 0) {
                                    totalTimeMs = TOTAL_TIME_MS;
                                    optind = startPos;
                                    break;
                                } else if (residueArgc == ONE_ARGC) {
                                    if (!StrToInt(argv[startPos], totalTimeMs)) {
                                        std::cout << "invalid total times" << std::endl;
                                        return EVENT_REG_FAIL;
                                    }
                                    optind = startPos + MOVE_POS_ONE;
                                    break;
                                } else if (residueArgc == TWO_ARGC) {
                                    totalTimeMs = TOTAL_TIME_MS;
                                    if ((strlen(argv[startPos]) != NUM_KEEP_ARGC) ||
                                        (argv[startPos][0] != '-') ||
                                        (argv[startPos][1] != 'k') ||
                                        (!StrToInt(argv[startPos + MOVE_POS_ONE], keepTimeMs))) {
                                        std::cout << "invalid keep times" << std::endl;
                                        return EVENT_REG_FAIL;
                                    }
                                    optind = startPos + MOVE_POS_TWO;
                                    break;
                                } else if (residueArgc == THREE_ARGC) {
                                    if (strlen(argv[startPos]) == NUM_KEEP_ARGC) {
                                        if ((argv[startPos][0] != '-') ||
                                            (argv[startPos][1] != 'k') ||
                                            (!StrToInt(argv[startPos + MOVE_POS_ONE], keepTimeMs))) {
                                            std::cout << "invalid keep times" << std::endl;
                                            return EVENT_REG_FAIL;
                                        }
                                        if (!StrToInt(argv[startPos + MOVE_POS_TWO], totalTimeMs)) {
                                            std::cout << "invalid total times" << std::endl;
                                            return EVENT_REG_FAIL;
                                        }
                                    } else {
                                        if (!StrToInt(argv[startPos], totalTimeMs)) {
                                            std::cout << "invalid total times" << std::endl;
                                            return EVENT_REG_FAIL;
                                        }
                                        if ((argv[startPos + MOVE_POS_ONE][0] != '-') ||
                                            (argv[startPos + MOVE_POS_ONE][1] != 'k') ||
                                            (!StrToInt(argv[startPos + MOVE_POS_TWO], keepTimeMs))) {
                                            std::cout << "invalid keep times" << std::endl;
                                            return EVENT_REG_FAIL;
                                        }
                                    }
                                    optind = startPos + MOVE_POS_THREE;
                                    break;
                                } else if (residueArgc >= FOUR_ARGC) {
                                    if ((!StrToInt(argv[startPos], startX)) ||
                                        (!StrToInt(argv[startPos + MOVE_POS_ONE], startY)) ||
                                        (!StrToInt(argv[startPos + MOVE_POS_TWO], endX)) ||
                                        (!StrToInt(argv[startPos + MOVE_POS_THREE], endY))) {
                                            std::cout << "invalid coordinate value" << std::endl;
                                            return EVENT_REG_FAIL;
                                    }
                                    if ((startX < 0) || (startY < 0) || (endX < 0) || (endY < 0)) {
                                        std::cout << "Coordinate value must be greater or equal than 0" << std::endl;
                                        return RET_ERR;
                                    }
                                    FingerInfo fingerInfoTemp {
                                        .startX = startX,
                                        .startY = startY,
                                        .endX = endX,
                                        .endY = endY
                                    };
                                    fingerList.push_back(fingerInfoTemp);
                                    fingerCount += 1;
                                    startPos += FINGER_LOCATION_NUMS;
                                    optind += THREE_MORE_COMMAND;
                                } else {
                                    std::cout << "invalid total times" << std::endl;
                                    return EVENT_REG_FAIL;
                                }
                            }

                            for (const auto &finger : fingerList) {
                                std::cout << "startX:" << finger.startX << ", startY:" << finger.startY <<
                                ", endX:" << finger.endX << ", endY:" << finger.endY << std::endl;
                            }
                            if (keepTimeMs > MAX_KEEP_TIME || keepTimeMs < 0) {
                                std::cout << "invalid keep times" << std::endl;
                                return EVENT_REG_FAIL;
                            }
                            if (totalTimeMs < 0) {
                                std::cout << "invalid total times" << std::endl;
                                return EVENT_REG_FAIL;
                            }
                            std::cout << "fingerCount:" << fingerCount <<std::endl;
                            std::cout << "keepTimeMs:" << keepTimeMs <<std::endl;
                            std::cout << "smoothTimeMs:" << totalTimeMs <<std::endl;

                            const int64_t minTotalTimeMs = 1;
                            const int64_t maxTotalTimeMs = 15000;
                            if ((totalTimeMs < minTotalTimeMs) || (totalTimeMs > maxTotalTimeMs)) {
                                std::cout << "total time is out of range:" << std::endl;
                                std::cout << minTotalTimeMs << " <= " << "total times" << " <= " << maxTotalTimeMs;
                                std::cout << std::endl;
                                return EVENT_REG_FAIL;
                            }

                            auto pointerEvent = PointerEvent::Create();
                            CHKPR(pointerEvent, ERROR_NULL_POINTER);
                            pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
                            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
                            for (int32_t i = 0; i < fingerCount; i++) {
                                PointerEvent::PointerItem item;
                                item.SetDisplayX(fingerList[i].startX);
                                item.SetDisplayY(fingerList[i].startY);
                                item.SetRawDisplayX(fingerList[i].startX);
                                item.SetRawDisplayY(fingerList[i].startY);
                                item.SetPointerId(DEFAULT_POINTER_ID_FIRST + i);
                                pointerEvent->AddPointerItem(item);
                                pointerEvent->SetPointerId(DEFAULT_POINTER_ID_FIRST + i);
                                InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
                                isFoldPC_ = PRODUCT_TYPE_HYM == DEVICE_TYPE_FOLD_PC;
                                if (isFoldPC_) {
                                    pointerEvent->AddFlag(InputEvent::EVENT_FLAG_DISABLE_PULL_THROW);
                                }
                            }

                            int64_t startTimeUs = pointerEvent->GetActionStartTime();
                            int64_t startTimeMs = startTimeUs / TIME_TRANSITION;
                            int64_t endTimeMs = 0;
                            if (!AddInt64(startTimeMs, totalTimeMs, endTimeMs)) {
                                std::cout << "system time error." << std::endl;
                                return EVENT_REG_FAIL;
                            }
                            int64_t currentTimeMs = startTimeMs;
                            int64_t nowSysTimeUs = 0;
                            int64_t nowSysTimeMs = 0;
                            int64_t sleepTimeMs = 0;

                            std::vector<int32_t> pointerIds = pointerEvent->GetPointerIds();
                            if (pointerIds.size() != static_cast<size_t>(fingerCount)) {
                                std::cout << "pointerIds size is error" << std::endl;
                                return EVENT_REG_FAIL;
                            }
                            
                            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
                            while (currentTimeMs < endTimeMs) {
                                for (size_t i = 0; i < pointerIds.size(); i++) {
                                    int32_t pointerId = pointerIds[i];
                                    PointerEvent::PointerItem item;
                                    if (!pointerEvent->GetPointerItem(pointerId, item)) {
                                        std::cout << "Invalid pointer:" << pointerId << std::endl;
                                        return EVENT_REG_FAIL;
                                    }
                                    item.SetDisplayX(NextPos(startTimeMs, currentTimeMs, totalTimeMs,
                                        fingerList[i].startX, fingerList[i].endX));
                                    item.SetDisplayY(NextPos(startTimeMs, currentTimeMs, totalTimeMs,
                                        fingerList[i].startY, fingerList[i].endY));
                                    item.SetRawDisplayX(NextPos(startTimeMs, currentTimeMs, totalTimeMs,
                                        fingerList[i].startX, fingerList[i].endX));
                                    item.SetRawDisplayY(NextPos(startTimeMs, currentTimeMs, totalTimeMs,
                                        fingerList[i].startY, fingerList[i].endY));
                                    pointerEvent->UpdatePointerItem(pointerId, item);
                                    pointerEvent->SetPointerId(pointerId);
                                    pointerEvent->SetActionTime(currentTimeMs * TIME_TRANSITION);
                                    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
                                    isFoldPC_ = PRODUCT_TYPE_HYM == DEVICE_TYPE_FOLD_PC;
                                    if (isFoldPC_) {
                                        pointerEvent->AddFlag(InputEvent::EVENT_FLAG_DISABLE_PULL_THROW);
                                    }
                                }
                                nowSysTimeUs = GetSysClockTime();
                                nowSysTimeMs = nowSysTimeUs / TIME_TRANSITION;
                                sleepTimeMs = (currentTimeMs + BLOCK_TIME_MS) - nowSysTimeMs;
                                std::this_thread::sleep_for(std::chrono::milliseconds(sleepTimeMs));
                                currentTimeMs += BLOCK_TIME_MS;
                            }

                            for (size_t i = 0; i < pointerIds.size(); i++) {
                                int32_t pointerId = pointerIds[i];
                                PointerEvent::PointerItem item;
                                if (!pointerEvent->GetPointerItem(pointerId, item)) {
                                    std::cout << "Invalid pointer:" << pointerId << std::endl;
                                    return EVENT_REG_FAIL;
                                }
                                item.SetDisplayX(fingerList[i].endX);
                                item.SetDisplayY(fingerList[i].endY);
                                item.SetRawDisplayX(fingerList[i].endX);
                                item.SetRawDisplayY(fingerList[i].endY);
                                pointerEvent->UpdatePointerItem(pointerId, item);
                                pointerEvent->SetPointerId(pointerId);
                                pointerEvent->SetActionTime(currentTimeMs * TIME_TRANSITION);
                                InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
                                isFoldPC_ = PRODUCT_TYPE_HYM == DEVICE_TYPE_FOLD_PC;
                                if (isFoldPC_) {
                                    pointerEvent->AddFlag(InputEvent::EVENT_FLAG_DISABLE_PULL_THROW);
                                }
                            }
                            std::this_thread::sleep_for(std::chrono::milliseconds(BLOCK_TIME_MS));

                            if (keepTimeMs > 0) {
                                currentTimeMs = GetSysClockTime() / TIME_TRANSITION;
                                int64_t keepEndTimeMs = 0;
                                if (!AddInt64(currentTimeMs, keepTimeMs, keepEndTimeMs)) {
                                    std::cout << "system time error." << std::endl;
                                    return EVENT_REG_FAIL;
                                }
                                while (currentTimeMs < keepEndTimeMs) {
                                    for (size_t i = 0; i < pointerIds.size(); i++) {
                                        int32_t pointerId = pointerIds[i];
                                        PointerEvent::PointerItem item;
                                        if (!pointerEvent->GetPointerItem(pointerId, item)) {
                                            std::cout << "Invalid pointer:" << pointerId << std::endl;
                                            return EVENT_REG_FAIL;
                                        }
                                        item.SetDisplayX(fingerList[i].endX);
                                        item.SetDisplayY(fingerList[i].endY);
                                        item.SetRawDisplayX(fingerList[i].endX);
                                        item.SetRawDisplayY(fingerList[i].endY);
                                        pointerEvent->UpdatePointerItem(pointerId, item);
                                        pointerEvent->SetPointerId(pointerId);
                                        pointerEvent->SetActionTime(currentTimeMs * TIME_TRANSITION);
                                        InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
                                        isFoldPC_ = PRODUCT_TYPE_HYM == DEVICE_TYPE_FOLD_PC;
                                        if (isFoldPC_) {
                                            pointerEvent->AddFlag(InputEvent::EVENT_FLAG_DISABLE_PULL_THROW);
                                        }
                                    }
                                    nowSysTimeUs = GetSysClockTime();
                                    nowSysTimeMs = nowSysTimeUs / TIME_TRANSITION;
                                    sleepTimeMs = (currentTimeMs + BLOCK_TIME_MS) - nowSysTimeMs;
                                    std::this_thread::sleep_for(std::chrono::milliseconds(sleepTimeMs));
                                    currentTimeMs += BLOCK_TIME_MS;
                                }
                            }
                            
                            pointerEvent->SetActionTime((endTimeMs + BLOCK_TIME_MS) * TIME_TRANSITION);
                            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
                            for (size_t i = 0; i < pointerIds.size(); i++) {
                                int32_t pointerId = pointerIds[i];
                                PointerEvent::PointerItem item;
                                if (!pointerEvent->GetPointerItem(pointerId, item)) {
                                    std::cout << "Invalid pointer:" << pointerId << std::endl;
                                    return EVENT_REG_FAIL;
                                }
                                pointerEvent->UpdatePointerItem(pointerId, item);
                                pointerEvent->SetPointerId(pointerId);
                                InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
                                isFoldPC_ = PRODUCT_TYPE_HYM == DEVICE_TYPE_FOLD_PC;
                                if (isFoldPC_) {
                                    pointerEvent->AddFlag(InputEvent::EVENT_FLAG_DISABLE_PULL_THROW);
                                }
                                pointerEvent->RemovePointerItem(pointerId);
                            }
                            break;
                        }
                        case 'd': {
                            if (optind >= argc) {
                                std::cout << "too few arguments to function" << std::endl;
                                return EVENT_REG_FAIL;
                            }
                            if (!StrToInt(optarg, px1) || !StrToInt(argv[optind], py1)) {
                                std::cout << "invalid coordinate value" << std::endl;
                                return EVENT_REG_FAIL;
                            }
                            if ((px1 < 0) || (py1 < 0)) {
                                std::cout << "Coordinate value must be greater or equal than 0" << std::endl;
                                return RET_ERR;
                            }
                            std::cout << "touch down " << px1 << " " << py1 << std::endl;
                            auto pointerEvent = PointerEvent::Create();
                            CHKPR(pointerEvent, ERROR_NULL_POINTER);
                            PointerEvent::PointerItem item;
                            item.SetDisplayY(py1);
                            item.SetRawDisplayY(py1);
                            item.SetPointerId(DEFAULT_POINTER_ID_FIRST);
                            item.SetDisplayX(px1);
                            item.SetRawDisplayX(px1);
                            pointerEvent->SetPointerId(DEFAULT_POINTER_ID_FIRST);
                            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
                            pointerEvent->AddPointerItem(item);
                            pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
                            InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
                            optind++;
                            break;
                        }
                        case 'u': {
                            if (optind >= argc) {
                                std::cout << "too few arguments to function" << std::endl;
                                return EVENT_REG_FAIL;
                            }
                            if (!StrToInt(optarg, px1) || !StrToInt(argv[optind], py1)) {
                                std::cout << "invalid coordinate value" << std::endl;
                                return EVENT_REG_FAIL;
                            }
                            if ((px1 < 0) || (py1 < 0)) {
                                std::cout << "Coordinate value must be greater or equal than 0" << std::endl;
                                return RET_ERR;
                            }
                            std::cout << "touch up " << px1 << " " << py1 << std::endl;
                            auto pointerEvent = PointerEvent::Create();
                            CHKPR(pointerEvent, ERROR_NULL_POINTER);
                            PointerEvent::PointerItem item;
                            item.SetDisplayY(py1);
                            item.SetRawDisplayY(py1);
                            item.SetPointerId(DEFAULT_POINTER_ID_FIRST);
                            item.SetDisplayX(px1);
                            item.SetRawDisplayX(px1);
                            pointerEvent->SetPointerId(DEFAULT_POINTER_ID_FIRST);
                            pointerEvent->AddPointerItem(item);
                            pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
                            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
                            InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
                            optind++;
                            break;
                        }
                        case 'c': {
                            int32_t intervalTimeMs = 0;
                            if (argc == KEY_PARAM_SIZE) {
                                if (!StrToInt(optarg, px1) ||
                                    !StrToInt(argv[optind], py1)) {
                                    std::cout << "input coordinate error" << std::endl;
                                    return RET_ERR;
                                }
                                intervalTimeMs = INTERVAL_TIME_MS;
                            } else if (argc == KEY_TIME_PARAM_SIZE) {
                                if (!StrToInt(optarg, px1) ||
                                    !StrToInt(argv[optind], py1) ||
                                    !StrToInt(argv[optind + 1], intervalTimeMs)) {
                                    std::cout << "input coordinate or time error" << std::endl;
                                    return RET_ERR;
                                }
                                const int64_t minIntervalTimeMs = 1;
                                const int64_t maxIntervalTimeMs = 450;
                                if ((minIntervalTimeMs > intervalTimeMs) || (maxIntervalTimeMs < intervalTimeMs)) {
                                    std::cout << "interval time is out of range: " << minIntervalTimeMs << "ms";
                                    std::cout << " < interval time < " << maxIntervalTimeMs << "ms" << std::endl;
                                    return RET_ERR;
                                }
                            } else {
                                std::cout << "parameter error, unable to run" << std::endl;
                                return RET_ERR;
                            }
                            if ((px1 < 0) || (py1 < 0)) {
                                std::cout << "Coordinate value must be greater or equal than 0" << std::endl;
                                return RET_ERR;
                            }
                            std::cout << "   click coordinate: ("<< px1 << ", "  << py1 << ")" << std::endl;
                            std::cout << "click interval time: " << intervalTimeMs      << "ms" << std::endl;
                            auto pointerEvent = PointerEvent::Create();
                            CHKPR(pointerEvent, ERROR_NULL_POINTER);
                            PointerEvent::PointerItem item;
                            item.SetPointerId(DEFAULT_POINTER_ID_FIRST);
                            item.SetDisplayX(px1);
                            item.SetDisplayY(py1);
                            item.SetRawDisplayX(px1);
                            item.SetRawDisplayY(py1);
                            item.SetPressed(true);
                            pointerEvent->SetPointerId(DEFAULT_POINTER_ID_FIRST);
                            pointerEvent->AddPointerItem(item);
                            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
                            pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
                            InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
                            std::this_thread::sleep_for(std::chrono::milliseconds(intervalTimeMs));

                            item.SetPressed(false);
                            item.SetDisplayY(py1);
                            item.SetDisplayX(px1);
                            item.SetRawDisplayY(py1);
                            item.SetRawDisplayX(px1);
                            pointerEvent->UpdatePointerItem(DEFAULT_POINTER_ID_FIRST, item);
                            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
                            InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
                            break;
                        }
                        case 'i': {
                            int32_t takeTime = 0;
                            if (!StrToInt(optarg, takeTime)) {
                                std::cout << "invalid command to interval time" << std::endl;
                                return EVENT_REG_FAIL;
                            }
                            const int64_t minTakeTimeMs = 1;
                            const int64_t maxTakeTimeMs = 15000;
                            if ((minTakeTimeMs > takeTime) || (maxTakeTimeMs < takeTime)) {
                                std::cout << "takeTime is out of range. ";
                                std::cout << minTakeTimeMs << " < takeTime < " << maxTakeTimeMs;
                                std::cout << std::endl;
                                return EVENT_REG_FAIL;
                            }
                            std::this_thread::sleep_for(std::chrono::milliseconds(takeTime));
                            break;
                        }
                        case 'g': {
                            const int32_t dragArgcSeven = 7;
                            const int32_t dragArgcCommandNine = 9;
                            if ((argc != dragArgcSeven) && (argc != dragArgcCommandNine)) {
                                std::cout << "argc:" << argc << std::endl;
                                std::cout << "wrong number of parameters" << std::endl;
                                return RET_ERR;
                            }
                            totalTimeMs = TOTAL_TIME_MS;
                            int32_t pressTimems = 500;
                            if (argc == moveArgcSeven) {
                                if ((!StrToInt(optarg, px1)) ||
                                    (!StrToInt(argv[optind], py1)) ||
                                    (!StrToInt(argv[optind + 1], px2)) ||
                                    (!StrToInt(argv[optind + 2], py2))) {
                                        std::cout << "invalid coordinate value" << std::endl;
                                        return RET_ERR;
                                }
                            } else {
                                if ((!StrToInt(optarg, px1)) ||
                                    (!StrToInt(argv[optind], py1)) ||
                                    (!StrToInt(argv[optind + 1], px2)) ||
                                    (!StrToInt(argv[optind + 2], py2)) ||
                                    (!StrToInt(argv[optind + 3], pressTimems)) ||
                                    (!StrToInt(argv[optind + 4], totalTimeMs))) {
                                        std::cout << "invalid input coordinate or time" << std::endl;
                                        return RET_ERR;
                                }
                            }
                            if ((px1 < 0) || (py1 < 0) || (px2 < 0) || (py2 < 0)) {
                                std::cout << "Coordinate value must be greater or equal than 0" << std::endl;
                                return RET_ERR;
                            }
                            const int32_t minTotalTimeMs = 1000;
                            const int32_t maxTotalTimeMs = 15000;
                            if ((minTotalTimeMs > totalTimeMs) || (maxTotalTimeMs < totalTimeMs)) {
                                std::cout << "total time input is error" << std::endl;
                                return RET_ERR;
                            }
                            const int32_t minPressTimeMs = 500;
                            const int32_t maxPressTimeMs = 14500;
                            if ((minPressTimeMs > pressTimems) || (maxPressTimeMs < pressTimems)) {
                                std::cout << "press time is out of range" << std::endl;
                                return RET_ERR;
                            }
                            const int32_t minMoveTimeMs = 500;
                            if ((totalTimeMs -  pressTimems) <  minMoveTimeMs) {
                                std::cout << "[total time] - [Press time] not less than 500ms" << std::endl;
                                return RET_ERR;
                            }

                            std::cout << "pressTimems:" << pressTimems <<std::endl;
                            std::cout << "totalTimeMs:" << totalTimeMs <<std::endl;

                            auto pointerEvent = PointerEvent::Create();
                            CHKPR(pointerEvent, ERROR_NULL_POINTER);
                            PointerEvent::PointerItem item;
                            item.SetPointerId(DEFAULT_POINTER_ID_FIRST);
                            item.SetDisplayY(py1);
                            item.SetDisplayX(px1);
                            item.SetRawDisplayY(py1);
                            item.SetRawDisplayX(px1);
                            pointerEvent->AddPointerItem(item);
                            pointerEvent->SetPointerId(DEFAULT_POINTER_ID_FIRST);
                            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
                            pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
                            InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
                            const int32_t conversionRate = 1000;
                            int64_t startTimeMs = GetSysClockTime() / conversionRate;
                            int64_t endTimeMs = 0;
                            if (!AddInt64(startTimeMs, totalTimeMs, endTimeMs)) {
                                std::cout << "end time count error" << std::endl;
                                return RET_ERR;
                            }
                            int64_t downTimeMs = 0;
                            if (!AddInt64(startTimeMs, pressTimems, downTimeMs)) {
                                std::cout << "down time count error" << std::endl;
                                return RET_ERR;
                            }
                            int64_t currentTimeMs = startTimeMs;
                            const int32_t moveTimeMs = totalTimeMs - pressTimems;
                            while ((currentTimeMs < endTimeMs)) {
                                if (currentTimeMs > downTimeMs) {
                                    item.SetDisplayX(NextPos(downTimeMs, currentTimeMs, moveTimeMs, px1, px2));
                                    item.SetDisplayY(NextPos(downTimeMs, currentTimeMs, moveTimeMs, py1, py2));
                                    item.SetRawDisplayX(NextPos(downTimeMs, currentTimeMs, moveTimeMs, px1, px2));
                                    item.SetRawDisplayY(NextPos(downTimeMs, currentTimeMs, moveTimeMs, py1, py2));
                                    pointerEvent->UpdatePointerItem(DEFAULT_POINTER_ID_FIRST, item);
                                    pointerEvent->SetActionTime(currentTimeMs * TIME_TRANSITION);
                                    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
                                    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
                                }
                                std::this_thread::sleep_for(std::chrono::milliseconds(BLOCK_TIME_MS));
                                currentTimeMs = GetSysClockTime() / conversionRate;
                            }
                            item.SetDisplayX(px2);
                            item.SetDisplayY(py2);
                            item.SetRawDisplayX(px2);
                            item.SetRawDisplayY(py2);
                            pointerEvent->UpdatePointerItem(DEFAULT_POINTER_ID_FIRST, item);
                            pointerEvent->SetActionTime(endTimeMs * TIME_TRANSITION);
                            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
                            InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
                            break;
                        }
                        case 'k': {
                            if (firstOpt == 'S') {
                                std::cout << "invalid argument k" << std::endl;
                                return EVENT_REG_FAIL;
                            }
                            KnuckleGestureInputProcess(argc, argv, c, optionIndex);
                            break;
                        }
                        default: {
                            std::cout << "invalid command" << std::endl;
                            ShowUsage();
                            return EVENT_REG_FAIL;
                        }
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEPTIME));
                }
                std::cout << "If the command does not work as expected, check whether the specified coordinates exceed"
                    " the screen boundary" << std::endl;
                break;
            }
            case 'J': {
                JoystickInfo joyInfo;
                std::vector<std::pair<int32_t, JoystickInfo>> state;
                while ((c = getopt_long(argc, argv, "m:d:u:c:i:", joystickSensorOptions, &optionIndex)) != -1) {
                    switch (c) {
                        case 'm': {
                            std::string arg(optarg);
                            std::string::size_type pos = arg.find('=');
                            if (pos == std::string::npos) {
                                std::cout << "Parameter format is error" << std::endl;
                                return EVENT_REG_FAIL;
                            }
                            std::string absAction = arg.substr(0, pos);
                            if (absAction == "x") {
                                joyInfo.absType = PointerEvent::AxisType::AXIS_TYPE_ABS_X;
                            } else if (absAction == "y") {
                                joyInfo.absType = PointerEvent::AxisType::AXIS_TYPE_ABS_Y;
                            } else if (absAction == "z") {
                                joyInfo.absType = PointerEvent::AxisType::AXIS_TYPE_ABS_Z;
                            } else if (absAction == "rz") {
                                joyInfo.absType = PointerEvent::AxisType::AXIS_TYPE_ABS_RZ;
                            } else if (absAction == "gas") {
                                joyInfo.absType = PointerEvent::AxisType::AXIS_TYPE_ABS_GAS;
                            } else if (absAction == "brake") {
                                joyInfo.absType = PointerEvent::AxisType::AXIS_TYPE_ABS_BRAKE;
                            } else if (absAction == "hat0x") {
                                joyInfo.absType = PointerEvent::AxisType::AXIS_TYPE_ABS_HAT0X;
                            } else if (absAction == "hat0y") {
                                joyInfo.absType = PointerEvent::AxisType::AXIS_TYPE_ABS_HAT0Y;
                            } else if (absAction == "throttle") {
                                joyInfo.absType = PointerEvent::AxisType::AXIS_TYPE_ABS_THROTTLE;
                            } else {
                                std::cout << "Invalid abstype" << std::endl;
                                return RET_ERR;
                            }
                            if (!StrToInt(arg.substr(pos + 1), joyInfo.absValue)) {
                                std::cout << "Invalid parameter to move absValue" << std::endl;
                                return EVENT_REG_FAIL;
                            }
                            state.push_back(std::pair<int32_t, JoystickInfo>(JOYSTICK_MOVE, joyInfo));
                            break;
                        }
                        case 'd': {
                            if (!StrToInt(optarg, joyInfo.buttonId)) {
                                std::cout << "Invalid button press command" << std::endl;
                                return EVENT_REG_FAIL;
                            }
                            if (joyInfo.buttonId > JOYSTICK_BUTTON_ID) {
                                std::cout << "Pressed button value is greater than the max value" << std::endl;
                                return EVENT_REG_FAIL;
                            }
                            state.push_back(std::pair<int32_t, JoystickInfo>(JOYSTICK_BUTTON_PRESS, joyInfo));
                            break;
                        }
                        case 'u': {
                            if (!StrToInt(optarg, joyInfo.buttonId)) {
                                std::cout << "Invalid raise button command" << std::endl;
                                return EVENT_REG_FAIL;
                            }
                            if (joyInfo.buttonId > JOYSTICK_BUTTON_ID) {
                                std::cout << "Raise button value is greater than the max value" << std::endl;
                                return EVENT_REG_FAIL;
                            }
                            state.push_back(std::pair<int32_t, JoystickInfo>(JOYSTICK_BUTTON_UP, joyInfo));
                            break;
                        }
                        case 'c': {
                            if (!StrToInt(optarg, joyInfo.buttonId)) {
                                std::cout << "Invalid click button command" << std::endl;
                                return EVENT_REG_FAIL;
                            }
                            if (joyInfo.buttonId > JOYSTICK_BUTTON_ID) {
                                std::cout << "Click button value is greater than the max value" << std::endl;
                                return EVENT_REG_FAIL;
                            }
                            state.push_back(std::pair<int32_t, JoystickInfo>(JOYSTICK_CLICK, joyInfo));
                            break;
                        }
                        case 'i': {
                            if (!StrToInt(optarg, joyInfo.taktTime)) {
                                std::cout << "Invalid command to interval time" << std::endl;
                                return EVENT_REG_FAIL;
                            }
                            state.push_back(std::pair<int32_t, JoystickInfo>(JOYSTICK_INTERVAL, joyInfo));
                            break;
                        }
                        default: {
                            std::cout << "Invalid options" << std::endl;
                            ShowUsage();
                            return EVENT_REG_FAIL;
                        }
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEPTIME));
                }
                auto pointerEvent = PointerEvent::Create();
                if (pointerEvent != nullptr) {
                    if (optind < argc) {
                        std::cout << "non-option argv elements: ";
                        while (optind < argc) {
                            std::cout << argv[optind++] << "\t";
                        }
                        std::cout << std::endl;
                        return EVENT_REG_FAIL;
                    }
                    if (state.empty()) {
                        std::cout << "Injection failed" << std::endl;
                        return EVENT_REG_FAIL;
                    }
                    for (const auto &it : state) {
                        if (it.first == JOYSTICK_BUTTON_PRESS) {
                            std::cout << "Press down " << it.second.buttonId <<std::endl;
                            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_DOWN);
                            pointerEvent->SetButtonId(it.second.buttonId);
                            pointerEvent->SetButtonPressed(it.second.buttonId);
                        } else if (it.first == JOYSTICK_BUTTON_UP) {
                            std::cout << "Lift up button " << it.second.buttonId << std::endl;
                            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_UP);
                            pointerEvent->SetButtonPressed(it.second.buttonId);
                            pointerEvent->SetButtonId(it.second.buttonId);
                        } else if (it.first == JOYSTICK_MOVE) {
                            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_UPDATE);
                            pointerEvent->SetAxisValue(it.second.absType, it.second.absValue);
                        } else if (it.first == JOYSTICK_CLICK) {
                            std::cout << "Click " << it.second.buttonId << std::endl;
                            pointerEvent->SetButtonId(it.second.buttonId);
                            pointerEvent->SetPointerId(0);
                            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_DOWN);
                            pointerEvent->SetButtonPressed(it.second.buttonId);
                            pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_JOYSTICK);
                            InputManager::GetInstance()->SimulateInputEvent(pointerEvent);

                            pointerEvent->SetButtonPressed(it.second.buttonId);
                            pointerEvent->SetButtonId(it.second.buttonId);
                            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_UP);
                        } else if (it.first == JOYSTICK_INTERVAL) {
                            if ((MIN_TAKTTIME_MS > joyInfo.taktTime) || (MAX_TAKTTIME_MS < joyInfo.taktTime)) {
                                std::cout << "TaktTime is out of range" << std::endl;
                                return EVENT_REG_FAIL;
                            }
                            std::this_thread::sleep_for(std::chrono::milliseconds(joyInfo.taktTime));
                            continue;
                        }
                        pointerEvent->SetPointerId(0);
                        pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_JOYSTICK);
                        InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
                    }
                }
                break;
            }
            case 'P': {
                int32_t ret = ProcessTouchPadGestureInput(argc, argv, optionIndex);
                if (ret != ERR_OK) {
                    return ret;
                }
                break;
            }
            case '?': {
                ShowUsage();
                return ERR_OK;
            }
            default: {
                std::cout << "invalid command" << std::endl;
                ShowUsage();
                return EVENT_REG_FAIL;
            }
        }
    } else {
        std::cout << "too few arguments to function" << std::endl;
        ShowUsage();
        return EVENT_REG_FAIL;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEPTIME));
    return ERR_OK;
}

struct SpecialChar {
    int32_t keyCode = 0;
    bool isPressShift = false;
};

const std::map<char, SpecialChar> CHAR_TO_KEYCODE = {
    { ' ',  { KeyEvent::KEYCODE_SPACE, false} },
    { '!',  { KeyEvent::KEYCODE_1, true} },
    { '\"', { KeyEvent::KEYCODE_APOSTROPHE, true} },
    { '#',  { KeyEvent::KEYCODE_3, true} },
    { '$',  { KeyEvent::KEYCODE_4, true} },
    { '%',  { KeyEvent::KEYCODE_5, true} },
    { '&',  { KeyEvent::KEYCODE_7, true} },
    { '\'', { KeyEvent::KEYCODE_APOSTROPHE, false} },
    { '(',  { KeyEvent::KEYCODE_9, true} },
    { ')',  { KeyEvent::KEYCODE_0, true} },
    { '*',  { KeyEvent::KEYCODE_8, true} },
    { '+',  { KeyEvent::KEYCODE_EQUALS, true} },
    { ',',  { KeyEvent::KEYCODE_COMMA, false} },
    { '-',  { KeyEvent::KEYCODE_MINUS, false} },
    { '.',  { KeyEvent::KEYCODE_PERIOD, false} },
    { '/',  { KeyEvent::KEYCODE_SLASH, false} },
    { ':',  { KeyEvent::KEYCODE_SEMICOLON, true} },
    { ';',  { KeyEvent::KEYCODE_SEMICOLON, false} },
    { '<',  { KeyEvent::KEYCODE_COMMA, true} },
    { '=',  { KeyEvent::KEYCODE_EQUALS, false} },
    { '>',  { KeyEvent::KEYCODE_PERIOD, true} },
    { '?',  { KeyEvent::KEYCODE_SLASH, true} },
    { '@',  { KeyEvent::KEYCODE_2, true} },
    { '[',  { KeyEvent::KEYCODE_LEFT_BRACKET, false} },
    { '\\', { KeyEvent::KEYCODE_BACKSLASH, false} },
    { ']',  { KeyEvent::KEYCODE_RIGHT_BRACKET, false} },
    { '^',  { KeyEvent::KEYCODE_6, true} },
    { '_',  { KeyEvent::KEYCODE_MINUS, true} },
    { '`',  { KeyEvent::KEYCODE_GRAVE, false} },
    { '{',  { KeyEvent::KEYCODE_LEFT_BRACKET, true} },
    { '|',  { KeyEvent::KEYCODE_BACKSLASH, true} },
    { '}',  { KeyEvent::KEYCODE_RIGHT_BRACKET, true} },
    { '~',  { KeyEvent::KEYCODE_GRAVE, true} },
};

bool InputManagerCommand::IsSpecialChar(char character, int32_t &keyCode, bool &isPressShift)
{
    CALL_DEBUG_ENTER;
    auto iter = CHAR_TO_KEYCODE.find(character);
    if (iter == CHAR_TO_KEYCODE.end()) {
        return false;
    }
    keyCode = iter->second.keyCode;
    isPressShift = iter->second.isPressShift;
    return true;
}

int32_t InputManagerCommand::PrintKeyboardTextChar(int32_t keyCode, bool isPressShift)
{
    auto keyEvent = KeyEvent::Create();
    if (keyEvent == nullptr) {
        std::cout << "Failed to create input event object" << std::endl;
        return RET_ERR;
    }
    KeyEvent::KeyItem item;

    if (isPressShift) {
        keyEvent->SetKeyCode(KeyEvent::KEYCODE_SHIFT_LEFT);
        keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
        item.SetKeyCode(KeyEvent::KEYCODE_SHIFT_LEFT);
        item.SetPressed(true);
        keyEvent->AddKeyItem(item);
        InputManager::GetInstance()->SimulateInputEvent(keyEvent);
    }

    keyEvent->SetKeyCode(keyCode);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    item.SetKeyCode(keyCode);
    item.SetPressed(true);
    keyEvent->AddKeyItem(item);
    InputManager::GetInstance()->SimulateInputEvent(keyEvent);

    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEPTIME));

    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    item.SetPressed(false);
    keyEvent->AddKeyItem(item);
    InputManager::GetInstance()->SimulateInputEvent(keyEvent);

    if (isPressShift) {
        keyEvent->SetKeyCode(KeyEvent::KEYCODE_SHIFT_LEFT);
        keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
        item.SetKeyCode(KeyEvent::KEYCODE_SHIFT_LEFT);
        item.SetPressed(false);
        keyEvent->AddKeyItem(item);
        InputManager::GetInstance()->SimulateInputEvent(keyEvent);
    }
    return RET_OK;
}

int32_t InputManagerCommand::ProcessKeyboardTextInput(char *optarg, int32_t count)
{
    if (count != 0) { // Prompt when combining the text command after using other commands. Ex: "uinput -t text -t text"
        std::cout << "The text command cannot be used with other commands." << std::endl;
        return RET_ERR;
    }
    constexpr int32_t textMaxLen = 2000; // 2000: max number of ascii characters

    int32_t len = strlen(optarg);
    if (len <= 0) {
        std::cout << "The input is empty." << std::endl;
        return RET_ERR;
    } else if (len > textMaxLen) {
        std::cout << "The input text length is "<< len;
        std::cout << ", and it is processed according to the maximum processing length of ";
        std::cout << textMaxLen << " bytes." << std::endl;
        len = textMaxLen;
    }

    char textChar = optarg[0];
    bool isPressShift = false;
    int32_t keyCode = -1;
    for (int32_t i = 0; i < len; ++i) {
        textChar = optarg[i];
        if ((textChar >= '0') && (textChar <= '9')) {
            isPressShift = false;
            keyCode = textChar - '0' + KeyEvent::KEYCODE_0;
        } else if ((textChar >= 'a') && (textChar <= 'z')) {
            isPressShift = false;
            keyCode = textChar - 'a' + KeyEvent::KEYCODE_A;
        } else if ((textChar >= 'A') && (textChar <= 'Z')) {
            isPressShift = true;
            keyCode = textChar - 'A' + KeyEvent::KEYCODE_A;
        } else if (!IsSpecialChar(textChar, keyCode, isPressShift)) {
            std::cout << "The character of index  "<< i << " is invalid." << std::endl;
            return RET_ERR;
        }

        if (PrintKeyboardTextChar(keyCode, isPressShift) == RET_ERR) {
            return RET_ERR;
        }
    }
    return RET_OK;
}

int32_t InputManagerCommand::KnuckleGestureInputProcess(int32_t argc, char *argv[], int32_t c, int32_t optionIndex)
{
    struct option knuckleGestureSensorOptions[] = {
        {"single_finger_double_click", required_argument, nullptr, 's'},
        {"double_finger_double_click", required_argument, nullptr, 'd'},
        {nullptr, 0, nullptr, 0}
    };

    while ((c = getopt_long(argc, argv, "s:d:", knuckleGestureSensorOptions, &optionIndex)) != -1) {
        switch (c) {
            case 's': {
                SingleKnuckleGestureProcesser(argc, argv);
                break;
            }
            case 'd': {
                DoubleKnuckleGestureProcesser(argc, argv);
                break;
            }
            default: {
                std::cout << "invalid command" << std::endl;
                ShowUsage();
                return EVENT_REG_FAIL;
            }
        }
    }
    return ERR_OK;
}

int32_t InputManagerCommand::SingleKnuckleGestureProcesser(int32_t argc, char *argv[])
{
    int32_t knuckleUinputArgc = 8;
    int32_t intervalTimeMs = 0;
    int32_t firstDownX = 0;
    int32_t firstDownY = 0;
    int32_t secondDownX = 0;
    int32_t secondDownY = 0;
    if (optind < 0 || optind > argc) {
        std::cout << "wrong optind pointer index" << std::endl;
        return EVENT_REG_FAIL;
    }
    if (argc == knuckleUinputArgc) {
        if ((!StrToInt(optarg, firstDownX)) || !StrToInt(argv[optind], firstDownY) ||
            !StrToInt(argv[optind + 1], secondDownX) || !StrToInt(argv[optind + TWO_MORE_COMMAND], secondDownY)) {
            std::cout << "invalid coordinate value" << std::endl;
            return EVENT_REG_FAIL;
        }
        intervalTimeMs = DEFAULT_DELAY;
    } else if (argc == KNUCKLE_PARAM_SIZE) {
        if ((!StrToInt(optarg, firstDownX)) || !StrToInt(argv[optind], firstDownY) ||
            !StrToInt(argv[optind + 1], secondDownX) || !StrToInt(argv[optind + TWO_MORE_COMMAND], secondDownY) ||
            !StrToInt(argv[optind + THREE_MORE_COMMAND], intervalTimeMs)) {
            std::cout << "input coordinate or time error" << std::endl;
            return RET_ERR;
        }
        const int64_t minIntervalTimeMs = 1;
        const int64_t maxIntervalTimeMs = 250;
        if ((minIntervalTimeMs > intervalTimeMs) || (maxIntervalTimeMs < intervalTimeMs)) {
            std::cout << "interval time is out of range: " << minIntervalTimeMs << "ms";
            std::cout << " < interval time < " << maxIntervalTimeMs << "ms" << std::endl;
            return RET_ERR;
        }
    } else {
        std::cout << "wrong number of parameters:" << argc << std::endl;
        return EVENT_REG_FAIL;
    }
    if (IsCoordinateInvalid(firstDownX, firstDownY, secondDownX, secondDownY)) {
        std::cout << "Coordinate value must be greater or equal than 0" << std::endl;
        return RET_ERR;
    }
    std::cout << "single knuckle first down coordinate: ("<< firstDownX << ", " << firstDownY << ")" << std::endl;
    std::cout << "single knuckle second down coordinate: ("<< secondDownX << ", "  << secondDownY << ")" << std::endl;
    std::cout << "single knuckle interval time: " << intervalTimeMs << "ms" << std::endl;
    SingleKnuckleClickEvent(firstDownX, firstDownY);
    std::this_thread::sleep_for(std::chrono::milliseconds(intervalTimeMs));
    SingleKnuckleClickEvent(secondDownX, secondDownY);
    return ERR_OK;
}

int32_t InputManagerCommand::DoubleKnuckleGestureProcesser(int32_t argc, char *argv[])
{
    int32_t knuckleUinputArgc = 8;
    int32_t intervalTimeMs = 0;
    int32_t firstDownX = 0;
    int32_t firstDownY = 0;
    int32_t secondDownX = 0;
    int32_t secondDownY = 0;
    if (optind < 0 || optind > argc) {
        std::cout << "wrong optind pointer index" << std::endl;
        return EVENT_REG_FAIL;
    }
    if (argc == knuckleUinputArgc) {
        if (!StrToInt(optarg, firstDownX) || !StrToInt(argv[optind], firstDownY) ||
            !StrToInt(argv[optind + 1], secondDownX) || !StrToInt(argv[optind + TWO_MORE_COMMAND], secondDownY)) {
            std::cout << "invalid coordinate value" << std::endl;
            return EVENT_REG_FAIL;
        }
        intervalTimeMs = DEFAULT_DELAY;
    } else if (argc == KNUCKLE_PARAM_SIZE) {
        if ((!StrToInt(optarg, firstDownX)) || !StrToInt(argv[optind], firstDownY) ||
            !StrToInt(argv[optind + 1], secondDownX) || !StrToInt(argv[optind + TWO_MORE_COMMAND], secondDownY) ||
            !StrToInt(argv[optind + THREE_MORE_COMMAND], intervalTimeMs)) {
            std::cout << "input coordinate or time error" << std::endl;
            return RET_ERR;
        }
        const int64_t minIntervalTimeMs = 1;
        const int64_t maxIntervalTimeMs = 250;
        if ((minIntervalTimeMs > intervalTimeMs) || (maxIntervalTimeMs < intervalTimeMs)) {
            std::cout << "interval time is out of range: " << minIntervalTimeMs << "ms";
            std::cout << " < interval time < " << maxIntervalTimeMs << "ms" << std::endl;
            return RET_ERR;
        }
    } else {
        std::cout << "wrong number of parameters: " << argc << std::endl;
        return EVENT_REG_FAIL;
    }
    if (IsCoordinateInvalid(firstDownX, firstDownY, secondDownX, secondDownY)) {
        std::cout << "Coordinate value must be greater or equal than 0" << std::endl;
        return RET_ERR;
    }
    std::cout << "double knukle first click coordinate: ("<< firstDownX << ", "  << firstDownY << ")" << std::endl;
    std::cout << "double knukle second click coordinate: ("<< secondDownX << ", "  << secondDownY << ")" << std::endl;
    std::cout << "double knuckle interval time: " << intervalTimeMs << "ms" << std::endl;

    DoubleKnuckleClickEvent(firstDownX, firstDownY);
    std::this_thread::sleep_for(std::chrono::milliseconds(intervalTimeMs));
    DoubleKnuckleClickEvent(secondDownX, secondDownY);
    return ERR_OK;
}

bool InputManagerCommand::IsCoordinateInvalid(int32_t firstDownX, int32_t firstDownY, int32_t secondDownX,
    int32_t secondDownY)
{
    return firstDownX < 0 || firstDownY < 0 || secondDownX < 0 || secondDownY < 0;
}

int32_t InputManagerCommand::SingleKnuckleClickEvent(int32_t downX, int32_t downY)
{
    auto pointerEvent = PointerEvent::Create();
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetToolType(PointerEvent::TOOL_TYPE_KNUCKLE);
    item.SetDisplayX(downX);
    item.SetDisplayY(downY);
    item.SetRawDisplayX(downX);
    item.SetRawDisplayY(downY);
    item.SetPressed(true);
    pointerEvent->SetPointerId(0);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);

    item.SetPressed(false);
    item.SetDisplayY(downY);
    item.SetDisplayX(downX);
    item.SetRawDisplayY(downY);
    item.SetRawDisplayX(downX);
    item.SetToolType(PointerEvent::TOOL_TYPE_KNUCKLE);
    pointerEvent->UpdatePointerItem(0, item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    return ERR_OK;
}

int32_t InputManagerCommand::DoubleKnuckleClickEvent(int32_t downX, int32_t downY)
{
    auto pointerEvent = PointerEvent::Create();
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    PointerEvent::PointerItem item;
    PointerEvent::PointerItem item2;
    item.SetPointerId(0);
    item.SetToolType(PointerEvent::TOOL_TYPE_KNUCKLE);
    item.SetDisplayX(downX);
    item.SetDisplayY(downY);
    item.SetRawDisplayX(downX);
    item.SetRawDisplayY(downY);
    item.SetPressed(true);
    pointerEvent->SetPointerId(0);
    pointerEvent->AddPointerItem(item);

    item2.SetPointerId(1);
    item2.SetToolType(PointerEvent::TOOL_TYPE_KNUCKLE);
    item2.SetDisplayX(downX);
    item2.SetDisplayY(downY);
    item2.SetRawDisplayX(downX);
    item2.SetRawDisplayY(downY);
    item2.SetPressed(true);
    pointerEvent->SetPointerId(1);
    pointerEvent->AddPointerItem(item2);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);

    item.SetPressed(false);
    item.SetDisplayY(downY);
    item.SetDisplayX(downX);
    item.SetRawDisplayY(downY);
    item.SetRawDisplayX(downX);
    item.SetToolType(PointerEvent::TOOL_TYPE_KNUCKLE);
    item2.SetPressed(false);
    item2.SetDisplayY(downY);
    item2.SetDisplayX(downX);
    item2.SetRawDisplayY(downY);
    item2.SetRawDisplayX(downX);
    item2.SetToolType(PointerEvent::TOOL_TYPE_KNUCKLE);
    pointerEvent->UpdatePointerItem(0, item);
    pointerEvent->UpdatePointerItem(1, item2);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    return ERR_OK;
}

int32_t InputManagerCommand::ProcessTouchPadGestureInput(int32_t argc, char *argv[], int32_t optionIndex)
{
    struct option touchPadSensorOptions[] = {
        {"rotate", required_argument, nullptr, 'r'},
        {"swipe", required_argument, nullptr, 's'},
        {"pinch", required_argument, nullptr, 'p'},
        {nullptr, 0, nullptr, 0}
    };
    int32_t opt = 0;
    if ((opt = getopt_long(argc, argv, "r:s:p:", touchPadSensorOptions, &optionIndex)) != -1) {
        switch (opt) {
            case 'r': {
                int32_t ret = ProcessRotateGesture(argc, argv);
                if (ret != ERR_OK) {
                    return ret;
                }
                break;
            }
            case 's': {
                int32_t ret = ProcessTouchPadFingerSwipe(argc, argv);
                if (ret != ERR_OK) {
                    return ret;
                }
                break;
            }
            case 'p': {
                // uinput -P -p <finger count> <scale percent numerator> e.g. uinput -P -p 2 200
                int32_t ret = ProcessPinchGesture(argc, argv);
                if (ret != ERR_OK) {
                    return ret;
                }
                break;
            }
            default: {
                std::cout << "invalid command" << std::endl;
                ShowUsage();
                return EVENT_REG_FAIL;
            }
        }
    }
    return ERR_OK;
}

int32_t InputManagerCommand::ProcessRotateGesture(int32_t argc, char *argv[])
{
    auto pointerEvent = PointerEvent::Create();
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    int32_t rotateValue = 0;
    constexpr int32_t paramNum = 4;
    constexpr int32_t conversionValue = 360;
    if (argc == paramNum) {
        if (!StrToInt(optarg, rotateValue)) {
            std::cout << "Invalid angle data" << std::endl;
            return RET_ERR;
        }
        if ((rotateValue >= conversionValue) || (rotateValue <= -(conversionValue))) {
            std::cout << "Rotate value must be within (-360,360)" << std::endl;
            return RET_ERR;
        }
        std::cout << "Input rotate value:"<<rotateValue << std::endl;
        pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_ROTATE, rotateValue);
        pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_ROTATE_END);
        pointerEvent->SetPointerId(0);
        PointerEvent::PointerItem item;
        item.SetPointerId(0);
        pointerEvent->AddPointerItem(item);
        pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
        InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    } else {
        std::cout << "Invalid angle data,Input parameter example: uinput - P - r 45" << std::endl;
        return RET_ERR;
    }
    return ERR_OK;
}

int32_t InputManagerCommand::ProcessPinchGesture(int32_t argc, char *argv[])
{
    CHKPR(argv, ERROR_NULL_POINTER);
    constexpr int32_t actionInputArgc = 6;
    constexpr int32_t minScaleNumerator = 0;
    constexpr int32_t maxScaleNumerator = 500;
    int32_t centerX = 0;
    int32_t centerY = 0;
    int32_t scalePercentNumerator = 0;
    std::string tips = "uinput -P -p dx, dy, scalePercent; dx, dy, scalePercent are all number.";
    std::string extralTips = " dx is bigger than 0 and dy is bigger than 0. 0 < scalePercent <= 500;";
    if (optind < 0 || optind > argc) {
        std::cout << "wrong optind pointer index" << std::endl;
        std::cout << tips << extralTips << std::endl;
        return RET_ERR;
    }
    int32_t startPos = optind - MOVE_POS_ONE;
    if (argc == actionInputArgc) {
        if ((!StrToInt(argv[startPos], centerX)) ||
            (!StrToInt(argv[startPos + MOVE_POS_ONE], centerY)) ||
            (!StrToInt(argv[startPos + MOVE_POS_TWO], scalePercentNumerator))) {
            std::cout << tips << extralTips << std::endl;
            return RET_ERR;
        }
    } else {
        std::cout << tips << extralTips << std::endl;
        return RET_ERR;
    }
    if ((scalePercentNumerator <= minScaleNumerator) || (scalePercentNumerator > maxScaleNumerator)) {
        std::cout << "Invalid scalePercent:" << scalePercentNumerator << std::endl;
        std::cout << tips << extralTips << std::endl;
        return RET_ERR;
    }
    bool check = (centerX > 0) && (centerY > 0);
    if (!check) {
        std::cout << tips << extralTips << std::endl;
        return RET_ERR;
    }

    std::cout << "scalePercent:" << scalePercentNumerator << std::endl;
    return ActionPinchEvent(centerX, centerY, scalePercentNumerator);
}

int32_t InputManagerCommand::SwipeActionEvent(int32_t startX, int32_t startY, int32_t endX, int32_t endY)
{
    constexpr int32_t fingerCount = 3;
    constexpr int32_t times = 10;
    constexpr int32_t thousand = 1000;
    int32_t disY = static_cast<int32_t>(static_cast<double>(endY - startY) / times);
    int32_t disX = static_cast<int32_t>(static_cast<double>(endX - startX) / times);
    int32_t actionType[10] = {PointerEvent::POINTER_ACTION_SWIPE_BEGIN};
    int64_t actionTimeBase = GetSysClockTime() - times * thousand * thousand;
    int64_t actionTimeStartTimeDis = fingerCount * thousand;
    int64_t actionStartTime[10] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    int64_t actionTime[10] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    int32_t sourceType = PointerEvent::SOURCE_TYPE_TOUCHPAD;
    actionTime[0] = actionTimeBase;
    actionStartTime[0] = (actionTimeBase - actionTimeStartTimeDis) / thousand;
    for (int32_t i = 1; i < times; i++) {
        actionStartTime[i] = actionStartTime[i - 1] + times - fingerCount;
        actionTime[i] = actionTime[i - 1] + times - fingerCount;
        actionType[i] = PointerEvent::POINTER_ACTION_SWIPE_UPDATE;
    }
    actionType[times - 1] = PointerEvent::POINTER_ACTION_SWIPE_END;
    for (int32_t i = 0; i < times; i++) {
        auto pointerEvent = CreateEvent(0, actionType[i], 0, sourceType, fingerCount);
        CHKPR(pointerEvent, ERROR_NULL_POINTER);
        pointerEvent->SetActionTime(actionTime[i]);
        pointerEvent->SetActionStartTime(actionStartTime[i]);
        PointerEvent::PointerItem item;
        item.SetDownTime(pointerEvent->GetActionStartTime());
        item.SetDisplayX(startX + disX * i);
        item.SetDisplayY(startY + disY * i);
        item.SetPointerId(0);
        pointerEvent->SetSourceType(sourceType);
        pointerEvent->AddPointerItem(item);
        pointerEvent->AddPointerItem(item);
        std::this_thread::sleep_for(std::chrono::microseconds(SLEEPTIME));
        InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    }
    return ERR_OK;
}

int32_t InputManagerCommand::ProcessTouchPadFingerSwipe(int32_t argc, char *argv[])
{
    constexpr int32_t actionInputArgc = 7;
    int32_t startX = 0;
    int32_t startY = 0;
    int32_t endX = 0;
    int32_t endY = 0;
    if (optind < 0 || optind > argc) {
        std::cout << "wrong optind pointer index" << std::endl;
        return RET_ERR;
    }
    int32_t startPos = optind - MOVE_POS_ONE;
    std::string tip = "uinput -P -s startX, startY, endX, endY;";
    std::string extralTip = "And startX, startY, endX, endY are all number which is bigger than 0;";
    if (argc == actionInputArgc) {
        if ((!StrToInt(argv[startPos], startX)) ||
            (!StrToInt(argv[startPos + MOVE_POS_ONE], startY)) ||
            (!StrToInt(argv[startPos + MOVE_POS_TWO], endX)) ||
            (!StrToInt(argv[startPos + MOVE_POS_THREE], endY))) {
            std::cout << tip << extralTip << std::endl;
            return RET_ERR;
        }
    } else {
        std::cout << tip << extralTip << std::endl;
        return RET_ERR;
    }
    bool check = (startX > 0) && (endX > 0) && (startY > 0) && (endY > 0);
    if (!check) {
        std::cout << tip << extralTip << std::endl;
        return RET_ERR;
    }
    return SwipeActionEvent(startX, startY, endX, endY);
}

std::shared_ptr<PointerEvent> InputManagerCommand::CreateEvent(int32_t id, int32_t type, int32_t pointerId,
    int32_t sourceType, int32_t fingerCount)
{
    auto pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);
    pointerEvent->SetId(id);
    pointerEvent->SetOriginPointerAction(type);
    pointerEvent->SetPointerAction(type);
    pointerEvent->SetPointerId(pointerId);
    pointerEvent->SetSourceType(sourceType);
    pointerEvent->SetFingerCount(fingerCount);
    return pointerEvent;
}

void InputManagerCommand::FillPointerItem(PointerEvent::PointerItem &item, int32_t pointX, int32_t pointY,
    int32_t id, bool press)
{
    item.SetDisplayX(pointX);
    item.SetDisplayY(pointY);
    item.SetDisplayXPos(pointX);
    item.SetDisplayYPos(pointY);
    item.SetWindowX(pointX);
    item.SetWindowY(pointY);
    item.SetWindowXPos(pointX);
    item.SetWindowYPos(pointY);
    item.SetPointerId(id);
    item.SetPressed(press);
}

int32_t InputManagerCommand::ActionPinchEvent(int32_t centerX, int32_t centerY, int32_t scalePercentNumerator)
{
    CALL_DEBUG_ENTER;
    int32_t hundred = 100;
    int32_t fingerCount = 2;
    int32_t timesForSleep = hundred * hundred;
    int32_t times = hundred / (fingerCount * fingerCount * fingerCount);
    int32_t actionType = PointerEvent::POINTER_ACTION_AXIS_BEGIN;
    double scalePinch = 1.0;
    double scalePinchChange = ((static_cast<double>(scalePercentNumerator) / hundred) - 1) / (times - 1);
    for (int32_t index = 0; index < times; index++) {
        if (index == times - 1) {
            actionType = PointerEvent::POINTER_ACTION_AXIS_END;
            scalePinch = 0.0;
        } else if (index != 0) {
            actionType = PointerEvent::POINTER_ACTION_AXIS_UPDATE;
            scalePinch = scalePinch + scalePinchChange;
        }
        auto pointerEvent = CreateEvent(0, actionType, 0, PointerEvent::SOURCE_TYPE_MOUSE, fingerCount);
        CHKPR(pointerEvent, ERROR_NULL_POINTER);
        pointerEvent->SetAxisEventType(PointerEvent::AXIS_EVENT_TYPE_PINCH);
        pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_PINCH, scalePinch);
        PointerEvent::PointerItem itemFirst;
        FillPointerItem(itemFirst, centerX, centerY, 0, false);
        itemFirst.SetToolType(PointerEvent::TOOL_TYPE_TOUCHPAD);
        pointerEvent->AddPointerItem(itemFirst);
        pointerEvent->SetPointerId(0);
        InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
        std::this_thread::sleep_for(std::chrono::microseconds(SLEEPTIME * timesForSleep));
    }
    return RET_OK;
}

void InputManagerCommand::SendTouchDownForPinch(int32_t topX, int32_t topY, int32_t bottomX, int32_t bottomY)
{
    constexpr int32_t fingerCount = 2;
    int32_t itemId = 0;
    auto pointerEvent = CreateEvent(0, PointerEvent::POINTER_ACTION_DOWN, 0,
        PointerEvent::SOURCE_TYPE_TOUCHPAD, fingerCount);
    CHKPV(pointerEvent);
    pointerEvent->SetPointerId(itemId);
    PointerEvent::PointerItem itemFirst;
    FillPointerItem(itemFirst, topX, topY, itemId, true);
    itemFirst.SetToolType(PointerEvent::TOOL_TYPE_MOUSE);
    pointerEvent->AddPointerItem(itemFirst);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    std::this_thread::sleep_for(std::chrono::microseconds(SLEEPTIME));
    pointerEvent = CreateEvent(0, PointerEvent::POINTER_ACTION_DOWN, 0,
        PointerEvent::SOURCE_TYPE_TOUCHPAD, fingerCount);
    CHKPV(pointerEvent);
    itemId = itemId + 1;
    pointerEvent->SetPointerId(itemId);
    PointerEvent::PointerItem itemSecond;
    FillPointerItem(itemSecond, bottomX, bottomY, itemId, true);
    pointerEvent->AddPointerItem(itemFirst);
    pointerEvent->AddPointerItem(itemSecond);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
}

uint32_t InputManagerCommand::KeyCodeToUnicode(int32_t keyCode)
{
    auto iter = KEY_UNICODE_TRANSFORMATION.find(keyCode);
    if (iter == KEY_UNICODE_TRANSFORMATION.end()) {
        return DEFAULT_UNICODE;
    }
    return iter->second.transitioned;
}

void InputManagerCommand::PrintMouseUsage()
{
    std::cout << "-m <dx> <dy>              --move   <dx> <dy>  -move to relative position (dx,dy),"    << std::endl;
    std::cout << "   <dx1> <dy1> <dx2> <dy2> [smooth time] --trace -dx1 dy1 to dx2 dy2 smooth movement" << std::endl;
    std::cout << "-d <key>                  --down   key        -press down a button, "                 << std::endl;
    std::cout << "                                               0 is the left button, 1 is the right," << std::endl;
    std::cout << "                                               2 is the middle"   << std::endl;
    std::cout << "-u <key>                  --up     <key>      -release a button " << std::endl;
    std::cout << "-c <key>                  --click  <key>      -click button" << std::endl;
    std::cout << "-b <dx1> <dy1> <id> [press time] [click interval time]                --double click" << std::endl;
    std::cout << "   [press time] the time range is more than 1ms but less than 300ms, "       << std::endl;
    std::cout << "   [click interval time] the time range is more than 1ms but less than 450ms, " << std::endl;
    std::cout << "   Otherwise the operation result may produce error or invalid operation"       << std::endl;
    std::cout << "-s <key>                  --scroll <key>      -positive values are sliding backwards," << std::endl;
    std::cout << "                                               negative values are sliding forwards"  << std::endl;
    std::cout << "-g <dx1> <dy1> <dx2> <dy2> [total time]       --drag <dx1> <dy1> <dx2> <dy2> [total time],";
    std::cout << std::endl;
    std::cout << "                                              dx1 dy1 to dx2 dy2 smooth drag"         << std::endl;
    std::cout << "-i <time>                 --interval <time>   -the program interval for the (time) milliseconds";
    std::cout << std::endl;
    std::cout << "Mouse button type:" << std::endl;
    std::cout << "   key value:0 - button left"     << std::endl;
    std::cout << "   key value:1 - button right"    << std::endl;
    std::cout << "   key value:2 - button middle"   << std::endl;
    std::cout << "   key value:3 - button side"     << std::endl;
    std::cout << "   key value:4 - button extra"    << std::endl;
    std::cout << "   key value:5 - button forward"  << std::endl;
    std::cout << "   key value:6 - button back"     << std::endl;
    std::cout << "   key value:7 - button task"     << std::endl;
}

void InputManagerCommand::PrintKeyboardUsage()
{
    std::cout << "-d <key>                   --down   <key>     -press down a key" << std::endl;
    std::cout << "-u <key>                   --up     <key>     -release a key   " << std::endl;
    std::cout << "-l <key> [long press time] --long_press <key> [long press time] -press and hold the key";
    std::cout << std::endl;
    std::cout << "-r <key> [repeat output time] --repeat output <key> [repeat output time] -press and hold the key";
    std::cout << std::endl;
    std::cout << "-i <time>                  --interval <time>  -the program interval for the (time) milliseconds";
    std::cout << std::endl;
    std::cout << "-t <text>                  --text <text>      -input text content. ";
    std::cout << "The text command cannot be used with other commands." << std::endl;
}

void InputManagerCommand::PrintStylusUsage()
{
    std::cout << "-d <dx1> <dy1>             --down   <dx1> <dy1> -press down a position  dx1 dy1, " << std::endl;
    std::cout << "-u <dx1> <dy1>             --up     <dx1> <dy1> -release a position dx1 dy1, "     << std::endl;
    std::cout << "-i <time>                  --interval <time>  -the program interval for the (time) milliseconds";
    std::cout << std::endl;
    std::cout << "-m <dx1> <dy1> <dx2> <dy2> [smooth time]      --smooth movement"   << std::endl;
    std::cout << "                                              dx1 dy1 to dx2 dy2 smooth movement"  << std::endl;
    std::cout << "-c <dx1> <dy1> [click interval]               -stylus click dx1 dy1"         << std::endl;
    std::cout << "-g <dx1> <dy1> <dx2> <dy2> [press time] [total time]     -drag, "                       << std::endl;
    std::cout << "  [Press time] not less than 500ms and [total time] - [Press time] not less than 500ms" << std::endl;
    std::cout << "  Otherwise the operation result may produce error or invalid operation"                << std::endl;
}

void InputManagerCommand::PrintTouchUsage()
{
    std::cout << "-d <dx1> <dy1>             --down   <dx1> <dy1> -press down a position  dx1 dy1, " << std::endl;
    std::cout << "-u <dx1> <dy1>             --up     <dx1> <dy1> -release a position dx1 dy1, "     << std::endl;
    std::cout << "-i <time>                  --interval <time>  -the program interval for the (time) milliseconds";
    std::cout << std::endl;
    std::cout << "-m <dx1> <dy1> <dx2> <dy2> [-k keep time] [smooth time]      --smooth movement, keep time:keep time";
    std::cout << std::endl;
    std::cout << "                                                             after moving, the max value is 60000 ";
    std::cout << std::endl;
    std::cout << "                                                             ms, default value is 0; smooth time:";
    std::cout << std::endl;
    std::cout << "                                                             move time, default value is 1000 ms,";
    std::cout << std::endl;
    std::cout << "                                                             the max value is 15000 ms";
    std::cout << std::endl;
    std::cout << "   Supports up to three finger movement at the same time, for example:" << std::endl;
    std::cout << "   uinput -T -m 300 900 600 900 900 900 600 900, (300, 900) move to (600, 900), (900, 900) move to";
    std::cout << std::endl;
    std::cout << "   (600, 900)" << std::endl;
    std::cout << "-c <dx1> <dy1> [click interval]               -touch screen click dx1 dy1"         << std::endl;
    std::cout << "-g <dx1> <dy1> <dx2> <dy2> [press time] [total time]     -drag, "                       << std::endl;
    std::cout << "   [Press time] not less than 500ms and [total time] - [Press time] not less than 500ms" << std::endl;
    std::cout << "   Otherwise the operation result may produce error or invalid operation"                << std::endl;
    std::cout << std::endl;

    std::cout << "-k --knuckle                                                  " << std::endl;
    std::cout << "commands for knucle:                                          " << std::endl;
    PrintKnuckleUsage();
    std::cout << std::endl;
}

void InputManagerCommand::PrintKnuckleUsage()
{
    std::cout << "-s <dx1> <dy1> <dx2> <dy2> [interval time]  --single knuckle double click interval time" << std::endl;
    std::cout << "-d <dx1> <dy1> <dx2> <dy2> [interval time]  --double knuckle double click interval time" << std::endl;
    std::cout << "-i <time>                  --interval <time>  -the program interval for the (time) milliseconds";
}

void InputManagerCommand::PrintTouchPadUsage()
{
    std::cout << "-p <dx> <dy> <scalePercent>  --dx, dy, scalePercent are all number."                    << std::endl;
    std::cout << "   dx is bigger than 0 and dy is bigger than 200. 0 < scalePercent < 500;"           << std::endl;
    std::cout << "   While simulate this, make sure that a picture is on the top of the desktop."      << std::endl;
    std::cout << "-s <startX> <startY> <endX> <endY>  --startX, startY, endX, endY are all greater than 0";
    std::cout << std::endl;
    std::cout << "   While simulate this, make sure that your actual action is available"              << std::endl;
    std::cout << "-r <rotateValue> --rotateValue must be within (-360,360)"                         << std::endl;
}

void InputManagerCommand::ShowUsage()
{
    std::cout << "Usage: uinput <option> <command> <arg>..." << std::endl;
    std::cout << "The option are:                                " << std::endl;
    std::cout << "-K  --keyboard                                                " << std::endl;
    std::cout << "commands for keyboard:                                        " << std::endl;
    PrintKeyboardUsage();
    std::cout << std::endl;

    std::cout << "-M  --mouse                                    " << std::endl;
    std::cout << "commands for mouse:                            " << std::endl;
    PrintMouseUsage();
    std::cout << std::endl;

    std::cout << "-P  --touchpad                                                " << std::endl;
    std::cout << "commands for touchpad:                                        " << std::endl;
    PrintTouchPadUsage();
    std::cout << std::endl;

    std::cout << "-S  --stylus                                                   " << std::endl;
    std::cout << "commands for stylus:                                           " << std::endl;
    PrintStylusUsage();
    std::cout << std::endl;

    std::cout << "-T  --touch                                                   " << std::endl;
    std::cout << "commands for touch:                                           " << std::endl;
    PrintTouchUsage();
    std::cout << std::endl;

    std::cout << "                                                              " << std::endl;
    std::cout << "-?  --help                                                    " << std::endl;
}
} // namespace MMI
} // namespace OHOS