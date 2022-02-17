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

#include "input_manager_command.h"
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <iostream>
#include <thread>
#include <algorithm>
#include "multimodal_event_handler.h"
#include "error_multimodal.h"
#include "getopt.h"
#include "string_ex.h"
#include "pointer_event.h"
#include "input_manager.h"

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
constexpr int32_t MOUSE_ID = 2;
constexpr int32_t TWO_MORE_COMMAND = 3;
constexpr int32_t THREE_MORE_COMMAND = 3;
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
        {NULL, 0, NULL, 0}
    };
    struct option keyboardSensorOptions[] = {
        {"down", required_argument, NULL, 'd'},
        {"up", required_argument, NULL, 'u'},
        {NULL, 0, NULL, 0}
    };
    struct option touchSensorOptions[] = {
        {"move", required_argument, NULL, 'm'},
        {"down", required_argument, NULL, 'd'},
        {"up", required_argument, NULL, 'u'},
        {NULL, 0, NULL, 0}
    };
    int32_t c;
    int32_t optionIndex;
    optind = 0;
    /* parse the first word of the command */
    if ((c = getopt_long(argc, argv, "MKT?", headOptions, &optionIndex)) != -1) {
        switch (c) {
            case 'M': {
                int32_t px;
                int32_t py;
                int32_t buttonId;
                int32_t scrollValue;
                /* parse commands for virtual mouse */
                while ((c = getopt_long(argc, argv, "m:d:u:c:s:", mouseSensorOptions, &optionIndex)) != -1) {
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
                            PointerEvent::PointerItem item;
                            item.SetPointerId(0);
                            item.SetPressed(false);
                            pointerEvent->SetPointerId(0);
                            pointerEvent->AddPointerItem(item);
                            pointerEvent->SetButtonPressed(buttonId);
                            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_UPDATE);
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
                            pointerEvent->AddPointerItem(item);
                            pointerEvent->SetButtonPressed(buttonId);
                            pointerEvent->SetButtonId(buttonId);
                            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_UP);
                            pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
                            InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
                            break;
                        }
                        default: {
                            std::cout << "invalid command to virtual mouse" << std::endl;
                            ShowUsage();
                            return EVENT_REG_FAIL;
                        }
                    }
                }
                break;
            }
            /* parse commands for keyboard */
            case 'K': {
                std::vector<int32_t> downKey;
                int32_t keyCode;
                int32_t isCombinationKey = 0;
                while ((c = getopt_long(argc, argv, "d:u:", keyboardSensorOptions, &optionIndex)) != -1) {
                    switch (c) {
                        case 'd': {
                            if (!StrToInt(optarg, keyCode)) {
                                std::cout << "invalid command to down key" << std::endl;
                            }
                            if (optind == isCombinationKey + TWO_MORE_COMMAND) {
                                downKey.push_back(keyCode);
                                isCombinationKey = optind;
                                for (size_t i = 0; i < downKey.size(); i++) {
                                    auto KeyEvent = MMI::KeyEvent::Create();
                                    KeyEvent->SetKeyCode(downKey[i]);
                                    KeyEvent->SetKeyAction(MMI::KeyEvent::KEY_ACTION_DOWN);
                                    KeyEvent::KeyItem item1;
                                    item1.SetKeyCode(downKey[i]);
                                    item1.SetPressed(true);
                                    KeyEvent->AddKeyItem(item1);
                                    InputManager::GetInstance()->SimulateInputEvent(KeyEvent);
                                }
                                break;
                            }
                            downKey.push_back(keyCode);
                            auto KeyEvent = MMI::KeyEvent::Create();
                            KeyEvent->SetKeyCode(keyCode);
                            KeyEvent->SetKeyAction(MMI::KeyEvent::KEY_ACTION_DOWN);
                            KeyEvent::KeyItem item1;
                            item1.SetKeyCode(keyCode);
                            item1.SetPressed(true);
                            KeyEvent->AddKeyItem(item1);
                            InputManager::GetInstance()->SimulateInputEvent(KeyEvent);
                            for (size_t i = 0; i < downKey.size(); i++) {
                                if (keyCode != downKey[i]) {
                                    std::cout << "downKey value is" << downKey[i] << std::endl;
                                }
                            }
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
                                auto KeyEvent = MMI::KeyEvent::Create();
                                KeyEvent->SetKeyCode(keyCode);
                                KeyEvent->SetKeyAction(MMI::KeyEvent::KEY_ACTION_UP);
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
                        default: {
                            std::cout << "invalid command to keyboard key" << std::endl;
                            ShowUsage();
                            return EVENT_REG_FAIL;
                        }
                    }
                }
                for (size_t i = 0; i < downKey.size(); i++) {
                    std::cout << "you have a key " << downKey[i]<<" not release"<< std::endl;
                }
                break;
            }
            /* parse commands for touch */
            case 'T': {
                int32_t px1;
                int32_t py1;
                int32_t px2;
                int32_t py2;
                int32_t oneNumber = 1;
                int32_t twoNumber = 2;
                while ((c = getopt_long(argc, argv, "m:d:u:", touchSensorOptions, &optionIndex)) != -1) {
                    switch (c) {
                        case 'm': {
                            if (optind + twoNumber>= argc) {
                                std::cout << "too few arguments to function" << std::endl;
                                ShowUsage();
                                return EVENT_REG_FAIL;
                            }
                            if (!StrToInt(optarg, px1) || !StrToInt(argv[optind], py1) || !StrToInt(
                                argv[optind + oneNumber], px2) || !StrToInt(argv[optind + twoNumber], py2)) {
                                std::cout << "invalid command to input value" << std::endl;
                                return EVENT_REG_FAIL;
                            }
                            auto pointerEvent = PointerEvent::Create();
                            PointerEvent::PointerItem item;
                            item.SetPointerId(0);
                            item.SetGlobalX(px1);
                            item.SetGlobalY(py1);
                            pointerEvent->SetPointerId(0);
                            pointerEvent->AddPointerItem(item);
                            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
                            pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
                            InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
                            item.SetGlobalX(px2);
                            item.SetGlobalY(py2);
                            pointerEvent->AddPointerItem(item);
                            pointerEvent->SetPointerAction(MMI::PointerEvent::POINTER_ACTION_MOVE);
                            pointerEvent->SetSourceType(MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
                            MMI::InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
                            item.SetGlobalX(px2);
                            item.SetGlobalY(py2);
                            pointerEvent->AddPointerItem(item);
                            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
                            pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
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
                            auto pointerEvent = MMI::PointerEvent::Create();
                            MMI::PointerEvent::PointerItem item;
                            item.SetPointerId(0);
                            item.SetGlobalX(px1);
                            item.SetGlobalY(py1);
                            pointerEvent->SetPointerId(0);
                            pointerEvent->AddPointerItem(item);
                            pointerEvent->SetPointerAction(MMI::PointerEvent::POINTER_ACTION_DOWN);
                            pointerEvent->SetSourceType(MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
                            MMI::InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
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
                            auto pointerEvent = MMI::PointerEvent::Create();
                            MMI::PointerEvent::PointerItem item;
                            item.SetPointerId(0);
                            item.SetGlobalX(px2);
                            item.SetGlobalY(py2);
                            pointerEvent->SetPointerId(0);
                            pointerEvent->AddPointerItem(item);
                            pointerEvent->SetPointerAction(MMI::PointerEvent::POINTER_ACTION_UP);
                            pointerEvent->SetSourceType(MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
                            MMI::InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
                            optind++;
                            break;
                        }
                        default: {
                            std::cout << "invalid command" << std::endl;
                            ShowUsage();
                            return EVENT_REG_FAIL;
                        }
                    }
                    /* sleep for a short time after every step to give the divice some time to react */
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
    return ERR_OK;
}


void InputManagerCommand::ShowUsage()
{
    std::cout << "Usage: injectevent <option> <command> <arg>..." << std::endl;
    std::cout << "The option are:                                " << std::endl;
    std::cout << "-M   --mouse                                                  " << std::endl;
    std::cout << "commands for  mouse:                           " << std::endl;
    std::cout << "-m <dx> <dy>              --move   <dx> <dy>  -move to relative position (dx,dy) " << std::endl;
    std::cout << "-d <key>                  --down   key        -press down a button,        " << std::endl;
    std::cout << "                                               0 is the left button,1 is the middle," << std::endl;
    std::cout << "                                               2 is the right" << std::endl;
    std::cout << "-u <key>                  --up     <key>      -release a button " << std::endl;
    std::cout << "-c <key>                  --click  <key>      -press the left button down,then raise" << std::endl;
    std::cout << "-s <key>                  --scroll <key>      -Positive values are sliding backwards "<<std::endl;
    std::cout << "                                               negative values are sliding forwards" << std::endl;
    std::cout << "-K   --keyboard                                                  " << std::endl;
    std::cout << "commands for  keyboard:                                        " << std::endl;
    std::cout << "-d <key>                   --down   <key>    -press down a key" << std::endl;
    std::cout << "                                                               " << std::endl;
    std::cout << "                                                               " << std::endl;
    std::cout << "-u <key>                   --up     <key>    -release a key " << std::endl;
    std::cout << "-T   --touch                                                      " << std::endl;
    std::cout << "commands for  touch:                                            " << std::endl;
    std::cout << "-d <dx1> <dy1>             --down   <dx1> <dy1> -press down a position  dx1 dy1, " << std::endl;
    std::cout << "-u <dx1> <dy1>             --up     <dx1> <dy1> -release a position dx1 dy1" << std::endl;
    std::cout << "-m <dx1> <dy1> <dx2> <dy2> --move   <dx1> <dy1> <dx2> <dy2> -move dx1 dy1 to dx2 dy2 " << std::endl;
    std::cout << "                                                                  " << std::endl;
    std::cout << "-?  --help                                                        " << std::endl;
}
} // namespace MMI
} // namespace OHOS