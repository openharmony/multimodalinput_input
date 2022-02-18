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

#include "send_message.h"
#include "message_send_recv_stat_mgr.h"
#include "proto.h"
#include "sys/file.h"
#include "test_aux_tool_client.h"

using namespace std;
using namespace OHOS::MMI;

namespace {
    static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "SendMessage"};
}

int32_t SendMessage::GetDevIndexByName(const std::string& deviceName)
{
    static const std::map<std::string, INPUT_DEVICE_INDEX> deviceTypeToIndexMap = {
        {"keyboard model1", INPUT_DEVICE_KEYBOARD_INDEX},
        {"keyboard model2", INPUT_DEVICE_KEYBOARD_INDEX},
        {"keyboard model3", INPUT_DEVICE_KEYBOARD_INDEX},
        {"mouse", INPUT_DEVICE_POINTER_INDEX},
        {"trackball", INPUT_DEVICE_POINTER_INDEX},
        {"touch", INPUT_DEVICE_TOUCH_INDEX},
        {"pen", INPUT_DEVICE_TABLET_TOOL_INDEX},
        {"pad", INPUT_DEVICE_TABLET_PAD_INDEX},
        {"joystick", INPUT_DEVICE_JOYSTICK_INDEX},
        {"gamePad", INPUT_DEVICE_GAMEPAD_INDEX},
        {"finger", INPUT_DEVICE_FINGER_INDEX},
        {"knob model1", INPUT_DEVICE_SWITCH_INDEX},
        {"knob model2", INPUT_DEVICE_SWITCH_INDEX},
        {"knob model3", INPUT_DEVICE_SWITCH_INDEX},
        {"remoteControl", INPUT_DEVICE_REMOTE_CONTROL},
        {"trackpad model1", INPUT_DEVICE_TRACKPAD5_INDEX},
        {"trackpad model2", INPUT_DEVICE_TRACKPAD5_INDEX},
    };

    auto iter = deviceTypeToIndexMap.find(deviceName);
    if (iter == deviceTypeToIndexMap.end()) {
        return RET_ERR;
    }
    return static_cast<int32_t>(iter->second);
}

int32_t SendMessage::SendToHdi(const InputEventArray& inputEventArray)
{
    int32_t devIndex = GetDevIndexByName(inputEventArray.deviceName);
    if (devIndex == RET_ERR) {
        MMI_LOGE("Get devIndex error by name:%{public}s", inputEventArray.deviceName.c_str());
        return RET_ERR;
    }
    RawInputEvent speechEvent = {};
    for (const auto &item : inputEventArray.events) {
        TransitionHdiEvent(item.event, speechEvent);
        SendToHdi(devIndex, speechEvent);
        int32_t blockTime = (item.blockTime == 0) ? INJECT_SLEEP_TIMES : item.blockTime;
        std::this_thread::sleep_for(std::chrono::milliseconds(blockTime));
    }
    return RET_OK;
}

/*
 * Sending Event Injection information to HDI
 */
int32_t SendMessage::SendToHdi(const int32_t& devIndex, const RawInputEvent& event)
{
    int32_t sendType = static_cast<int32_t>(SET_EVENT_INJECT);
    NetPacket cktToHdf(MmiMessageId::HDI_INJECT);
    cktToHdf << sendType << devIndex << event;

    if (!(SendMsg(cktToHdf))) {
        MMI_LOGE("inject hdi send event to server error");
        return RET_ERR;
    }
    return RET_OK;
}

bool SendMessage::SendMsg(const NetPacket& ckt)
{
    if (TestAuxToolClient::GetInstance().SendMsg(ckt)) {
        MessageSendRecvStatMgr::GetInstance().Increase();
        return true;
    }

    return false;
}

void SendMessage::TransitionHdiEvent(const input_event& event, RawInputEvent& speechEvent)
{
    speechEvent.ev_type = event.type;
    speechEvent.ev_code = event.code;
    speechEvent.ev_value =  static_cast<uint32_t>(event.value);
    speechEvent.stamp = static_cast<uint32_t>(event.input_event_usec);
}