/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "processing_keyboard_device.h"

using namespace std;
using namespace OHOS::MMI;

namespace {
    static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "ProcessingKeyboardDevice" };
}

int32_t ProcessingKeyboardDevice::TransformJsonDataToInputData(const Json& fingerEventArrays,
    InputEventArray& inputEventArray)
{
    MMI_LOGI("Enter TransformJsonDataForKeyBoard function.");
    if (fingerEventArrays.empty()) {
        return RET_ERR;
    }
    Json inputData = fingerEventArrays.at("events");
    if (inputData.empty()) {
        MMI_LOGE("manage KeyBoard array faild, inputData is empty.");
        return RET_ERR;
    }
    vector<KeyBoardEvent> keyBoardEventArray;
    if (AnalysisKeyBoardEvent(inputData, keyBoardEventArray) == RET_ERR) {
        return RET_ERR;
    }
    TransformKeyBoardEventToInputEvent(keyBoardEventArray, inputEventArray);
    MMI_LOGI("Leave TransformJsonDataForKeyBoard function.");

    return RET_OK;
}

void ProcessingKeyboardDevice::TransformKeyBoardEventToInputEvent(const std::vector<KeyBoardEvent>& keyBoardEventArray,
                                                                  InputEventArray& inputEventArray)
{
    for (KeyBoardEvent keyBoardEvent : keyBoardEventArray) {
        if (keyBoardEvent.eventType == "KEY_EVENT_PRESS") {
            TransformKeyPressEvent(keyBoardEvent, inputEventArray);
        } else if (keyBoardEvent.eventType == "KEY_EVENT_RELEASE") {
            TransformKeyReleaseEvent(keyBoardEvent, inputEventArray);
        } else if (keyBoardEvent.eventType == "KEY_EVENT_CLICK") {
            TransformKeyClickEvent(keyBoardEvent, inputEventArray);
        } else if (keyBoardEvent.eventType == "KEY_EVENT_LONG_PRESS") {
            TransformKeyLongPressEvent(keyBoardEvent, inputEventArray);
        } else {
            // nothing to do.
        }
    }
}

int32_t ProcessingKeyboardDevice::AnalysisKeyBoardEvent(const Json& inputData,
                                                        std::vector<KeyBoardEvent>& keyBoardEventArray)
{
    KeyBoardEvent keyBoardEvent = {};
    for (auto item : inputData) {
        keyBoardEvent = {};
        keyBoardEvent.eventType = item.at("eventType").get<std::string>();
        if ((item.find("keyValue")) != item.end()) {
            keyBoardEvent.keyValue = item.at("keyValue").get<int32_t>();
        }
        if ((item.find("blockTime")) != item.end()) {
            keyBoardEvent.blockTime = item.at("blockTime").get<int32_t>();
        }
        keyBoardEventArray.push_back(keyBoardEvent);
    }

    return RET_OK;
}

void ProcessingKeyboardDevice::TransformKeyPressEvent(const KeyBoardEvent& keyBoardEvent,
                                                      InputEventArray& inputEventArray)
{
    uint16_t keyValue = static_cast<uint16_t>(keyBoardEvent.keyValue);
    SetKeyPressEvent(inputEventArray, keyBoardEvent.blockTime, keyValue);
    SetSynReport(inputEventArray);
}

void ProcessingKeyboardDevice::TransformKeyLongPressEvent(const KeyBoardEvent& keyBoardEvent,
                                                          InputEventArray& inputEventArray)
{
    int32_t keyEventNum = (keyBoardEvent.blockTime / EVENT_REPROT_COUNTS) + 1;
    uint16_t keyValue = static_cast<uint16_t>(keyBoardEvent.keyValue);
    SetKeyPressEvent(inputEventArray, EVENT_REPROT_TIMES, keyValue);
    SetSynReport(inputEventArray);
    int32_t count = 0;
    while (count++ < keyEventNum) {
        SetKeyLongPressEvent(inputEventArray, EVENT_REPROT_TIMES, keyValue);
        SetSynConfigReport(inputEventArray, EVENT_REPROT_TIMES);
    }
    SetKeyReleaseEvent(inputEventArray, EVENT_REPROT_TIMES, keyValue);
    SetSynReport(inputEventArray);
}

void ProcessingKeyboardDevice::TransformKeyReleaseEvent(const KeyBoardEvent& keyBoardEvent,
                                                        InputEventArray& inputEventArray)
{
    uint16_t keyValue = static_cast<uint16_t>(keyBoardEvent.keyValue);
    SetKeyReleaseEvent(inputEventArray, keyBoardEvent.blockTime, keyValue);
    SetSynReport(inputEventArray);
}

void ProcessingKeyboardDevice::TransformKeyClickEvent(const KeyBoardEvent& keyBoardEvent,
                                                      InputEventArray& inputEventArray)
{
    uint16_t keyValue = static_cast<uint16_t>(keyBoardEvent.keyValue);
    SetKeyPressEvent(inputEventArray, keyBoardEvent.blockTime, keyValue);
    SetSynReport(inputEventArray);
    SetKeyReleaseEvent(inputEventArray, keyBoardEvent.blockTime, keyValue);
    SetSynReport(inputEventArray);
}