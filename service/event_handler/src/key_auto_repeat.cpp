/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "key_auto_repeat.h"

#include <array>

#include "define_multimodal.h"
#include "error_multimodal.h"
#include "input_device_manager.h"
#include "input_event_handler.h"
#include "mmi_log.h"
#include "timer_manager.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "KeyAutoRepeat" };
constexpr int32_t INVALID_DEVICE_ID = -1;
constexpr int32_t OPEN_AUTO_REPEAT = 1;
} // namespace

KeyAutoRepeat::KeyAutoRepeat() {}
KeyAutoRepeat::~KeyAutoRepeat() {}

std::map<int32_t, DeviceConfig> KeyAutoRepeat::GetDeviceConfig() const
{
    return deviceConfig_;
}

int32_t KeyAutoRepeat::AddDeviceConfig(struct libinput_device *device)
{
    CALL_DEBUG_ENTER;
    CHKPR(device, ERROR_NULL_POINTER);
    std::string fileName = KeyMapMgr->GetKeyEventFileName(device);
    DeviceConfig devConf;
    auto ret = ReadTomlFile(GetTomlFilePath(fileName), devConf);
    if (ret == RET_ERR) {
        MMI_HILOGI("Can not read device config file");
        return RET_ERR;
    }
    int32_t deviceId = InputDevMgr->FindInputDeviceId(device);
    if (deviceId == INVALID_DEVICE_ID) {
        MMI_HILOGE("Find to device failed");
        return RET_ERR;
    }
    deviceConfig_[deviceId] = devConf;
    return RET_OK;
}

void KeyAutoRepeat::SelectAutoRepeat(std::shared_ptr<KeyEvent>& keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(keyEvent);
    DeviceConfig devConf = GetAutoSwitch(keyEvent->GetDeviceId());
    if (devConf.autoSwitch != OPEN_AUTO_REPEAT) {
        return;
    }
    keyEvent_ = keyEvent;
    if (keyEvent_->GetKeyAction() == KeyEvent::KEY_ACTION_DOWN) {
        if (TimerMgr->IsExist(timerId_)) {
            MMI_HILOGI("Keyboard down but timer exists, timerId:%{public}d, keyCode:%{public}d",
                timerId_, keyEvent_->GetKeyCode());
            TimerMgr->RemoveTimer(timerId_);
            timerId_ = -1;
        }
        AddHandleTimer(devConf.delayTime);
        repeatKeyCode_ = keyEvent_->GetKeyCode();
        MMI_HILOGI("Add a timer, keyCode:%{public}d", keyEvent_->GetKeyCode());
    }
    if (keyEvent_->GetKeyAction() == KeyEvent::KEY_ACTION_UP && TimerMgr->IsExist(timerId_)) {
        TimerMgr->RemoveTimer(timerId_);
        timerId_ = -1;
        MMI_HILOGI("Stop kayboard autorepeat, keyCode:%{public}d", keyEvent_->GetKeyCode());
        if (repeatKeyCode_ != keyEvent_->GetKeyCode()) {
            auto pressedKeyItem = keyEvent_->GetKeyItem(keyEvent_->GetKeyCode());
            if (pressedKeyItem != nullptr) {
                keyEvent_->RemoveReleasedKeyItems(*pressedKeyItem);
            } else {
                MMI_HILOGW("The pressedKeyItem is nullptr");
            }
            keyEvent_->SetKeyCode(repeatKeyCode_);
            keyEvent_->SetAction(KeyEvent::KEY_ACTION_DOWN);
            keyEvent_->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
            AddHandleTimer(devConf.delayTime);
            MMI_HILOGD("The end keyboard autorepeat, keyCode:%{public}d", keyEvent_->GetKeyCode());
        }
    }
}

void KeyAutoRepeat::AddHandleTimer(int32_t timeout)
{
    CALL_DEBUG_ENTER;
    timerId_ = TimerMgr->AddTimer(timeout, 1, [this]() {
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
        auto inputEventNormalizeHandler = InputHandler->GetEventNormalizeHandler();
        CHKPV(inputEventNormalizeHandler);
        inputEventNormalizeHandler->HandleKeyEvent(this->keyEvent_);
        this->keyEvent_->UpdateId();
#endif // OHOS_BUILD_ENABLE_KEYBOARD
        int32_t triggertime = KeyRepeat->GetIntervalTime(keyEvent_->GetDeviceId());
        this->AddHandleTimer(triggertime);
    });
}

std::string KeyAutoRepeat::GetTomlFilePath(const std::string &fileName) const
{
    return "/vendor/etc/keymap/" + fileName + ".TOML";
}

int32_t KeyAutoRepeat::GetIntervalTime(int32_t deviceId) const
{
    auto iter = deviceConfig_.find(deviceId);
    int32_t triggertime = 100;
    if (iter != deviceConfig_.end()) {
        triggertime = iter->second.intervalTime;
    }
    return triggertime;
}

DeviceConfig KeyAutoRepeat::GetAutoSwitch(int32_t deviceId)
{
    auto iter = deviceConfig_.find(deviceId);
    if (iter == deviceConfig_.end()) {
        return {};
    }
    MMI_HILOGD("Open autorepeat:%{public}d", iter->second.autoSwitch);
    return iter->second;
}

void KeyAutoRepeat::RemoveDeviceConfig(struct libinput_device *device)
{
    CALL_DEBUG_ENTER;
    CHKPV(device);
    int32_t deviceId = InputDevMgr->FindInputDeviceId(device);
    auto iter = deviceConfig_.find(deviceId);
    if (iter == deviceConfig_.end()) {
        MMI_HILOGI("Can not remove device config file");
        return;
    }
    deviceConfig_.erase(iter);
}

void KeyAutoRepeat::RemoveTimer()
{
    CALL_DEBUG_ENTER;
    TimerMgr->RemoveTimer(timerId_);
}
} // namespace MMI
} // namespace OHOS