/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "input_manager_command.h"

#include <getopt.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <iostream>
#include <limits>
#include <thread>

#include <sys/time.h>
#include <unistd.h>

#include "string_ex.h"

#include "error_multimodal.h"
#include "input_manager.h"
#include "mmi_log.h"
#include "multimodal_event_handler.h"
#include "pointer_event.h"
#include "util.h"

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
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "InputManagerCommand"};
constexpr int32_t SLEEPTIME = 20;
constexpr int32_t MOUSE_ID = 7;
constexpr int32_t TWO_MORE_COMMAND = 2;
constexpr int32_t THREE_MORE_COMMAND = 3;
constexpr int32_t MAX_PRESSED_COUNT = 30;
constexpr int32_t ACTION_TIME = 3000;
constexpr int32_t BLOCK_TIME_MS = 16;
} // namespace

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
    if (offsetPos > 0) {
        if (!AddInt32(offsetPos, begPos, retPos)) {
            return begPos;
        }
        return retPos > endPos ? endPos : retPos;
    } else {
        if (!AddInt32(offsetPos, begPos, retPos)) {
            return begPos;
        }
        return retPos < endPos ? endPos : retPos;
    }
    return begPos;
}

int32_t InputManagerCommand::ParseCommand(int32_t argc, char *argv[])
{
    struct option headOptions[] = {
        {"mouse", no_argument, NULL, 'M'},
        {"keyboard", no_argument, NULL, 'K'},
        {"touch", no_argument, NULL, 'T'},
        {"help", no_argument, NULL, '?'},
        {NULL, 0, NULL, 0}
    };

    struct option mouseSensorOptions[] = {
        {"move", required_argument, NULL, 'm'},
        {"click", required_argument, NULL, 'c'},
        {"down", required_argument, NULL, 'd'},
        {"up", required_argument, NULL, 'u'},
        {"scroll", required_argument, NULL, 's'},
        {"interval", required_argument, NULL, 'i'},
        {NULL, 0, NULL, 0}
    };
    struct option keyboardSensorOptions[] = {
        {"down", required_argument, NULL, 'd'},
        {"up", required_argument, NULL, 'u'},
        {"interval", required_argument, NULL, 'i'},
        {NULL, 0, NULL, 0}
    };
    struct option touchSensorOptions[] = {
        {"move", required_argument, NULL, 'm'},
        {"down", required_argument, NULL, 'd'},
        {"up", required_argument, NULL, 'u'},
        {"click", required_argument, NULL, 'c'},
        {"interval", required_argument, NULL, 'i'},
        {"drag", required_argument, NULL, 'g'},
        {NULL, 0, NULL, 0}
    };
    int32_t c = 0;
    int32_t optionIndex = 0;
    optind = 0;
    if ((c = getopt_long(argc, argv, "MKT?", headOptions, &optionIndex)) != -1) {
        switch (c) {
            case 'M': {
                int32_t px = 0;
                int32_t py = 0;
                int32_t buttonId;
                int32_t scrollValue;
                while ((c = getopt_long(argc, argv, "m:d:u:c:s:i:", mouseSensorOptions, &optionIndex)) != -1) {
                    switch (c) {
                        case 'm': {
                            if (optind >= argc) {
                                std::cout << "too few arguments to function" << std::endl;
                                ShowUsage();
                                return EVENT_REG_FAIL;
                            }
                            if (!StrToInt(optarg, px) || !StrToInt(argv[optind], py)) {
                                std::cout << "invalid paremeter to move mouse" << std::endl;
                                return EVENT_REG_FAIL;
                            }
                            std::cout << "move to " << px << " " << py << std::endl;
                            auto pointerEvent = PointerEvent::Create();
                            CHKPR(pointerEvent, ERROR_NULL_POINTER);
                            PointerEvent::PointerItem item;
                            item.SetPointerId(0);
                            item.SetGlobalX(px);
                            item.SetGlobalY(py);
                            pointerEvent->AddPointerItem(item);
                            pointerEvent->SetPointerId(0);
                            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
                            pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
                            InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
                            optind++;
                            break;
                        }
                        case 'd': {
                            if (!StrToInt(optarg, buttonId)) {
                                std::cout << "invalid button press command" << std::endl;
                                ShowUsage();
                                return EVENT_REG_FAIL;
                            }
                            if (buttonId > MOUSE_ID) {
                                std::cout << "invalid button press command" << std::endl;
                                ShowUsage();
                                return EVENT_REG_FAIL;
                            }
                            std::cout << "press down" << buttonId << std::endl;
                            auto pointerEvent = PointerEvent::Create();
                            CHKPR(pointerEvent, ERROR_NULL_POINTER);
                            PointerEvent::PointerItem item;
                            item.SetPointerId(0);
                            item.SetGlobalX(px);
                            item.SetGlobalY(py);
                            item.SetPressed(true);
                            pointerEvent->SetPointerId(0);
                            pointerEvent->AddPointerItem(item);
                            pointerEvent->SetButtonId(buttonId);
                            pointerEvent->SetButtonPressed(buttonId);
                            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_DOWN);
                            pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
                            InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
                            break;
                        }
                        case 'u': {
                            if (!StrToInt(optarg, buttonId)) {
                                std::cout << "invalid raise button command" << std::endl;
                                ShowUsage();
                                return EVENT_REG_FAIL;
                            }
                            if (buttonId > MOUSE_ID) {
                                std::cout << "invalid raise button command" << std::endl;
                                ShowUsage();
                                return EVENT_REG_FAIL;
                            }
                            std::cout << "lift up button " << buttonId << std::endl;
                            auto pointerEvent = PointerEvent::Create();
                            CHKPR(pointerEvent, ERROR_NULL_POINTER);
                            PointerEvent::PointerItem item;
                            item.SetPointerId(0);
                            item.SetGlobalX(px);
                            item.SetGlobalY(py);
                            item.SetPressed(false);
                            pointerEvent->SetPointerId(0);
                            pointerEvent->AddPointerItem(item);
                            pointerEvent->SetButtonPressed(buttonId);
                            pointerEvent->SetButtonId(buttonId);
                            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_UP);
                            pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
                            InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
                            break;
                        }
                        case 's': {
                            if (!StrToInt(optarg, scrollValue)) {
                                std::cout << "invalid  scroll button command" << std::endl;
                                ShowUsage();
                                return EVENT_REG_FAIL;
                            }
                            std::cout << "scroll wheel " << scrollValue << std::endl;
                            auto pointerEvent = PointerEvent::Create();
                            CHKPR(pointerEvent, ERROR_NULL_POINTER);
                            PointerEvent::PointerItem item;
                            item.SetPointerId(0);
                            item.SetGlobalX(px);
                            item.SetGlobalY(py);
                            item.SetPressed(false);
                            int64_t time = pointerEvent->GetActionStartTime();
                            pointerEvent->SetActionTime(time + ACTION_TIME);
                            pointerEvent->SetPointerId(0);
                            pointerEvent->AddPointerItem(item);
                            pointerEvent->SetButtonPressed(buttonId);
                            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_BEGIN);
                            pointerEvent->SetAxisValue(PointerEvent::AxisType::AXIS_TYPE_SCROLL_VERTICAL,
                                scrollValue);
                            pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
                            InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
                            time = pointerEvent->GetActionStartTime();

                            time = pointerEvent->GetActionStartTime();
                            pointerEvent->SetActionTime(time + ACTION_TIME);
                            pointerEvent->SetPointerId(0);
                            pointerEvent->AddPointerItem(item);
                            pointerEvent->SetButtonPressed(buttonId);
                            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_UPDATE);
                            pointerEvent->SetAxisValue(PointerEvent::AxisType::AXIS_TYPE_SCROLL_VERTICAL,
                                scrollValue);
                            pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
                            InputManager::GetInstance()->SimulateInputEvent(pointerEvent);

                            time = pointerEvent->GetActionStartTime();
                            pointerEvent->SetActionTime(time + ACTION_TIME);
                            pointerEvent->SetPointerId(0);
                            pointerEvent->AddPointerItem(item);
                            pointerEvent->SetButtonPressed(buttonId);
                            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_END);
                            pointerEvent->SetAxisValue(PointerEvent::AxisType::AXIS_TYPE_SCROLL_VERTICAL,
                                scrollValue);
                            pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
                            InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
                            break;
                        }
                        case 'c': {
                            if (!StrToInt(optarg, buttonId)) {
                                std::cout << "invalid click button command" << std::endl;
                                ShowUsage();
                                return EVENT_REG_FAIL;
                            }
                            if (buttonId > MOUSE_ID) {
                                std::cout << "invalid button press command" << std::endl;
                                ShowUsage();
                                return EVENT_REG_FAIL;
                            }
                            std::cout << "click   " << buttonId << std::endl;
                            auto pointerEvent = PointerEvent::Create();
                            CHKPR(pointerEvent, ERROR_NULL_POINTER);
                            PointerEvent::PointerItem item;
                            item.SetPointerId(0);
                            item.SetPressed(true);
                            item.SetGlobalX(px);
                            item.SetGlobalY(py);
                            pointerEvent->SetPointerId(0);
                            pointerEvent->AddPointerItem(item);
                            pointerEvent->SetButtonId(buttonId);
                            pointerEvent->SetButtonPressed(buttonId);
                            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_DOWN);
                            pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
                            InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
                            item.SetPointerId(0);
                            item.SetPressed(false);
                            item.SetGlobalX(px);
                            item.SetGlobalY(py);
                            pointerEvent->SetPointerId(0);
                            pointerEvent->UpdatePointerItem(0, item);
                            pointerEvent->SetButtonPressed(buttonId);
                            pointerEvent->SetButtonId(buttonId);
                            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_UP);
                            pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
                            InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
                            break;
                        }
                        case 'i': {
                            int32_t taktTime = 0;
                            if (!StrToInt(optarg, taktTime)) {
                                std::cout << "invalid command to interval time" << std::endl;
                                ShowUsage();
                                return EVENT_REG_FAIL;
                            }
                            const int64_t minTaktTimeMs = 1;
                            const int64_t maxTaktTimeMs = 15000;
                            if ((minTaktTimeMs > taktTime) || (maxTaktTimeMs < taktTime)) {
                                std::cout << "taktTime is out of range" << std::endl;
                                std::cout << minTaktTimeMs << " < taktTime < " << maxTaktTimeMs;
                                std::cout << std::endl;
                                return EVENT_REG_FAIL;
                            }
                            std::this_thread::sleep_for(std::chrono::milliseconds(taktTime));
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
                while ((c = getopt_long(argc, argv, "d:u:i:", keyboardSensorOptions, &optionIndex)) != -1) {
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
                                    KeyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
                                    item[i].SetKeyCode(downKey[i]);
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
                            KeyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
                            KeyEvent::KeyItem item1;
                            item1.SetKeyCode(keyCode);
                            item1.SetPressed(true);
                            KeyEvent->AddKeyItem(item1);
                            InputManager::GetInstance()->SimulateInputEvent(KeyEvent);
                            isCombinationKey = optind;
                            break;
                        }
                        case 'u': {
                            if (!StrToInt(optarg, keyCode)) {
                                std::cout << "invalid button press command" << std::endl;
                                ShowUsage();
                                return EVENT_REG_FAIL;
                            }
                            std::vector<int32_t>::iterator iter = std::find(downKey.begin(), downKey.end(), keyCode);
                            if (iter != downKey.end()) {
                                std::cout << "You raised the key " << keyCode << std::endl;
                                auto KeyEvent = KeyEvent::Create();
                                CHKPR(KeyEvent, ERROR_NULL_POINTER);
                                KeyEvent->SetKeyCode(keyCode);
                                KeyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
                                KeyEvent::KeyItem item1;
                                item1.SetKeyCode(keyCode);
                                item1.SetPressed(true);
                                KeyEvent->AddKeyItem(item1);
                                InputManager::GetInstance()->SimulateInputEvent(KeyEvent);
                                iter = downKey.erase(iter);
                                break;
                            } else {
                                std::cout << "Please press the " << keyCode << " key first "<< std::endl;
                                return EVENT_REG_FAIL;
                            }
                        }
                        case 'i': {
                            int32_t taktTime = 0;
                            if (!StrToInt(optarg, taktTime)) {
                                std::cout << "invalid command to interval time" << std::endl;
                                ShowUsage();
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
                        default: {
                            std::cout << "invalid command to keyboard key" << std::endl;
                            ShowUsage();
                            return EVENT_REG_FAIL;
                        }
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEPTIME));
                }
                for (size_t i = 0; i < downKey.size(); i++) {
                    std::cout << "you have a key " << downKey[i] << " not release" << std::endl;
                }
                break;
            }
            case 'T': {
                int32_t px1 = 0;
                int32_t py1 = 0;
                int32_t px2 = 0;
                int32_t py2 = 0;
                int32_t totalTimeMs = 0;
                int32_t moveArgcSeven = 7;
                while ((c = getopt_long(argc, argv, "m:d:u:c:i:g:", touchSensorOptions, &optionIndex)) != -1) {
                    switch (c) {
                        case 'm': {
                            if (argc < moveArgcSeven) {
                                std::cout << "argc:" << argc << std::endl;
                                std::cout << "wrong number of parameters" << std::endl;
                                ShowUsage();
                                return EVENT_REG_FAIL;
                            }
                            if (argv[optind + 3] == nullptr || argv[optind + 3][0] == '-') {
                                totalTimeMs = 1000;
                                if ((!StrToInt(optarg, px1)) ||
                                    (!StrToInt(argv[optind], py1)) ||
                                    (!StrToInt(argv[optind + 1], px2)) ||
                                    (!StrToInt(argv[optind + 2], py2))) {
                                        std::cout << "invalid command to input value" << std::endl;
                                        ShowUsage();
                                        return EVENT_REG_FAIL;
                                }
                            } else {
                                if ((!StrToInt(optarg, px1)) ||
                                    (!StrToInt(argv[optind], py1)) ||
                                    (!StrToInt(argv[optind + 1], px2)) ||
                                    (!StrToInt(argv[optind + 2], py2)) ||
                                    (!StrToInt(argv[optind + 3], totalTimeMs))) {
                                        std::cout << "invalid command to input value" << std::endl;
                                        ShowUsage();
                                        return EVENT_REG_FAIL;
                                }
                            }
                            const int64_t minTotalTimeMs = 1;
                            const int64_t maxTotalTimeMs = 15000;
                            if ((minTotalTimeMs > totalTimeMs) || (maxTotalTimeMs < totalTimeMs)) {
                                std::cout << "totalTime is out of range" << std::endl;
                                std::cout << minTotalTimeMs << " < totalTimeMs < " << maxTotalTimeMs;
                                std::cout << std::endl;
                                return EVENT_REG_FAIL;
                            }
                            auto pointerEvent = PointerEvent::Create();
                            CHKPR(pointerEvent, ERROR_NULL_POINTER);
                            PointerEvent::PointerItem item;
                            item.SetPointerId(0);
                            item.SetGlobalX(px1);
                            item.SetGlobalY(py1);
                            pointerEvent->SetPointerId(0);
                            pointerEvent->AddPointerItem(item);
                            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
                            pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
                            InputManager::GetInstance()->SimulateInputEvent(pointerEvent);

                            int64_t startTimeUs = pointerEvent->GetActionStartTime();
                            int64_t startTimeMs = startTimeUs / 1000;
                            int64_t endTimeMs = 0;
                            if (!AddInt64(startTimeMs, totalTimeMs, endTimeMs)) {
                                std::cout << "system time error." << std::endl;
                                return EVENT_REG_FAIL;
                            }
                            int64_t currentTimeMs = startTimeMs;
                            int64_t nowSysTimeUs = 0;
                            int64_t nowSysTimeMs = 0;
                            int64_t sleepTimeMs = 0;
                            while (currentTimeMs < endTimeMs) {
                                item.SetGlobalX(NextPos(startTimeMs, currentTimeMs, totalTimeMs, px1, px2));
                                item.SetGlobalY(NextPos(startTimeMs, currentTimeMs, totalTimeMs, py1, py2));
                                pointerEvent->SetActionTime(currentTimeMs);
                                pointerEvent->UpdatePointerItem(0, item);
                                pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
                                InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
                                nowSysTimeUs = GetSysClockTime();
                                nowSysTimeMs = nowSysTimeUs / 1000;
                                sleepTimeMs = (currentTimeMs + BLOCK_TIME_MS) - nowSysTimeMs;
                                std::this_thread::sleep_for(std::chrono::milliseconds(sleepTimeMs));
                                currentTimeMs += BLOCK_TIME_MS;
                            }

                            item.SetGlobalX(px2);
                            item.SetGlobalY(py2);
                            pointerEvent->SetActionTime(endTimeMs);
                            pointerEvent->UpdatePointerItem(0, item);
                            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
                            InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
                            optind =  optind + THREE_MORE_COMMAND;
                            break;
                        }
                        case 'd': {
                            if (optind >= argc) {
                                std::cout << "too few arguments to function" << std::endl;
                                ShowUsage();
                                return EVENT_REG_FAIL;
                            }
                            if (!StrToInt(optarg, px1) || !StrToInt(argv[optind], py1)) {
                                std::cout << "invalid command to input value" << std::endl;
                                return EVENT_REG_FAIL;
                            }
                            std::cout << "touch down " << px1 << " " << py1 << std::endl;
                            auto pointerEvent = PointerEvent::Create();
                            CHKPR(pointerEvent, ERROR_NULL_POINTER);
                            PointerEvent::PointerItem item;
                            item.SetPointerId(0);
                            item.SetGlobalX(px1);
                            item.SetGlobalY(py1);
                            pointerEvent->SetPointerId(0);
                            pointerEvent->AddPointerItem(item);
                            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
                            pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
                            InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
                            optind++;
                            break;
                        }
                        case 'u': {
                            if (optind >= argc) {
                                ShowUsage();
                                return EVENT_REG_FAIL;
                            }
                            if (!StrToInt(optarg, px1) || !StrToInt(argv[optind], py1)) {
                                std::cout << "invalid command to input value" << std::endl;
                                return EVENT_REG_FAIL;
                            }
                            std::cout << "touch up " << px1 << " " << py1 << std::endl;
                            auto pointerEvent = PointerEvent::Create();
                            CHKPR(pointerEvent, ERROR_NULL_POINTER);
                            PointerEvent::PointerItem item;
                            item.SetPointerId(0);
                            item.SetGlobalX(px1);
                            item.SetGlobalY(py1);
                            pointerEvent->SetPointerId(0);
                            pointerEvent->AddPointerItem(item);
                            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
                            pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
                            InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
                            optind++;
                            break;
                        }
                        case 'c': {
                            int32_t intervalTimeMs = 0;
                            if (argc == 5) {
                                if (!StrToInt(optarg, px1) ||
                                    !StrToInt(argv[optind], py1)) {
                                    std::cout << "input coordinate error" << std::endl;
                                    return RET_ERR;
                                }
                                intervalTimeMs = 100;
                            } else if (argc == 6) {
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
                                ShowUsage();
                                return RET_ERR;
                            }
                            std::cout << "touch screen click interval time:" << intervalTimeMs << "ms" << std::endl;
                            std::cout << "single finger touch screen click " << px1 << " " << py1 << std::endl;
                            auto pointerEvent = PointerEvent::Create();
                            CHKPR(pointerEvent, ERROR_NULL_POINTER);
                            PointerEvent::PointerItem item;
                            item.SetPointerId(0);
                            item.SetPressed(true);
                            item.SetGlobalX(px1);
                            item.SetGlobalY(py1);
                            pointerEvent->SetPointerId(0);
                            pointerEvent->AddPointerItem(item);
                            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
                            pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
                            InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
                            std::this_thread::sleep_for(std::chrono::milliseconds(intervalTimeMs));

                            item.SetPressed(false);
                            item.SetGlobalX(px1);
                            item.SetGlobalY(py1);
                            pointerEvent->UpdatePointerItem(0, item);
                            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
                            InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
                            break;
                        }
                        case 'i': {
                            int32_t taktTime = 0;
                            if (!StrToInt(optarg, taktTime)) {
                                std::cout << "invalid command to interval time" << std::endl;
                                ShowUsage();
                                return EVENT_REG_FAIL;
                            }
                            const int64_t minTaktTimeMs = 1;
                            const int64_t maxTaktTimeMs = 15000;
                            if ((minTaktTimeMs > taktTime) || (maxTaktTimeMs < taktTime)) {
                                std::cout << "taktTime is out of range. ";
                                std::cout << minTaktTimeMs << " < taktTime < " << maxTaktTimeMs;
                                std::cout << std::endl;
                                return EVENT_REG_FAIL;
                            }
                            std::this_thread::sleep_for(std::chrono::milliseconds(taktTime));
                            break;
                        }
                        case 'g': {
                            const int32_t dragArgcSeven = 7;
                            const int32_t dragArgcCommandNine = 9;
                            if ((argc != dragArgcSeven) && (argc != dragArgcCommandNine)) {
                                std::cout << "argc:" << argc << std::endl;
                                std::cout << "wrong number of parameters" << std::endl;
                                ShowUsage();
                                return RET_ERR;
                            }
                            totalTimeMs = 1000;
                            int32_t pressTimems = 500;
                            if (argc == moveArgcSeven) {
                                if ((!StrToInt(optarg, px1)) ||
                                    (!StrToInt(argv[optind], py1)) ||
                                    (!StrToInt(argv[optind + 1], px2)) ||
                                    (!StrToInt(argv[optind + 2], py2))) {
                                        std::cout << "Invalid input command" << std::endl;
                                        ShowUsage();
                                        return RET_ERR;
                                }
                            } else {
                                if ((!StrToInt(optarg, px1)) ||
                                    (!StrToInt(argv[optind], py1)) ||
                                    (!StrToInt(argv[optind + 1], px2)) ||
                                    (!StrToInt(argv[optind + 2], py2)) ||
                                    (!StrToInt(argv[optind + 3], pressTimems)) ||
                                    (!StrToInt(argv[optind + 4], totalTimeMs))) {
                                        std::cout << "Invalid input coordinate or time" << std::endl;
                                        ShowUsage();
                                        return RET_ERR;
                                }
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
                                std::cout << "move time is out of range" << std::endl;
                                return RET_ERR;
                            }
                            auto pointerEvent = PointerEvent::Create();
                            CHKPR(pointerEvent, ERROR_NULL_POINTER);
                            PointerEvent::PointerItem item;
                            item.SetGlobalX(px1);
                            item.SetGlobalY(py1);
                            pointerEvent->AddPointerItem(item);
                            pointerEvent->SetPointerId(0);
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
                                    item.SetGlobalX(NextPos(downTimeMs, currentTimeMs, moveTimeMs, px1, px2));
                                    item.SetGlobalY(NextPos(downTimeMs, currentTimeMs, moveTimeMs, py1, py2));
                                    pointerEvent->UpdatePointerItem(0, item);
                                    pointerEvent->SetActionTime(currentTimeMs);
                                    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
                                    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
                                }
                                std::this_thread::sleep_for(std::chrono::milliseconds(BLOCK_TIME_MS));
                                currentTimeMs = GetSysClockTime() / conversionRate;
                            }
                            item.SetGlobalX(px2);
                            item.SetGlobalY(py2);
                            pointerEvent->UpdatePointerItem(0, item);
                            pointerEvent->SetActionTime(endTimeMs);
                            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
                            InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
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

void InputManagerCommand::ShowUsage()
{
    std::cout << "Usage: uinput <option> <command> <arg>..." << std::endl;
    std::cout << "The option are:                                " << std::endl;
    std::cout << "-M  --mouse                                    " << std::endl;
    std::cout << "commands for mouse:                            " << std::endl;
    std::cout << "-m <dx> <dy>              --move   <dx> <dy>  -move to relative position (dx,dy) "    << std::endl;
    std::cout << "-d <key>                  --down   key        -press down a button, "                 << std::endl;
    std::cout << "                                               0 is the left button, 1 is the right," << std::endl;
    std::cout << "                                               2 is the middle"   << std::endl;
    std::cout << "-u <key>                  --up     <key>      -release a button " << std::endl;
    std::cout << "-c <key>                  --click  <key>      -press the left button down,then raise" << std::endl;
    std::cout << "   key value:0 - button left"     << std::endl;
    std::cout << "   key value:1 - button right"    << std::endl;
    std::cout << "   key value:2 - button middle"   << std::endl;
    std::cout << "   key value:3 - button side"     << std::endl;
    std::cout << "   key value:4 - button extra"    << std::endl;
    std::cout << "   key value:5 - button forward"  << std::endl;
    std::cout << "   key value:6 - button back"     << std::endl;
    std::cout << "   key value:7 - button task"     << std::endl;
    std::cout << "-s <key>                  --scroll <key>      -positive values are sliding backwards" << std::endl;
    std::cout << "-i <time>                 --interval <time>   -the program interval for the (time) milliseconds";
    std::cout << std::endl;
    std::cout << "                                               negative values are sliding forwards"  << std::endl;
    std::cout << "-K  --keyboard                                                " << std::endl;
    std::cout << "commands for keyboard:                                        " << std::endl;
    std::cout << "-d <key>                   --down   <key>     -press down a key" << std::endl;
    std::cout << "-u <key>                   --up     <key>     -release a key   " << std::endl;
    std::cout << "-i <time>                  --interval <time>  -the program interval for the (time) milliseconds";
    std::cout << std::endl;
    std::cout << "-T  --touch                                                   " << std::endl;
    std::cout << "commands for touch:                                           " << std::endl;
    std::cout << "-d <dx1> <dy1>             --down   <dx1> <dy1> -press down a position  dx1 dy1, " << std::endl;
    std::cout << "-u <dx1> <dy1>             --up     <dx1> <dy1> -release a position dx1 dy1, "     << std::endl;
    std::cout << "-m <dx1> <dy1> <dx2> <dy2> [smooth time]      --smooth movement"   << std::endl;
    std::cout << "   <dx1> <dy1> <dx2> <dy2> [smooth time]      -smooth movement, "  << std::endl;
    std::cout << "                                              dx1 dy1 to dx2 dy2 smooth movement"  << std::endl;
    std::cout << "-c <dx1> <dy1> [click interval]               -touch screen click dx1 dy1"         << std::endl;
    std::cout << "-i <time>                  --interval <time>  -the program interval for the (time) milliseconds";
    std::cout << std::endl;
    std::cout << "-g <dx1> <dy1> <dx2> <dy2> [Press time] [total time]     -drag, "                       << std::endl;
    std::cout << "  [Press time] not less than 500ms and [total time] - [Press time] not less than 500ms" << std::endl;
    std::cout << "  Otherwise the operation result may produce error or invalid operation"              << std::endl;
    std::cout << "                                                              " << std::endl;
    std::cout << "-?  --help                                                    " << std::endl;
}
} // namespace MMI
} // namespace OHOS