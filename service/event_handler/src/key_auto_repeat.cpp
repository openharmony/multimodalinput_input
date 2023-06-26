/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
constexpr int32_t DEFAULT_KEY_REPEAT_DELAY = 500;
constexpr int32_t MIN_KEY_REPEAT_DELAY = 300;
constexpr int32_t MAX_KEY_REPEAT_DELAY = 1000;
constexpr int32_t DEFAULT_KEY_REPEAT_RATE = 50;
constexpr int32_t MIN_KEY_REPEAT_RATE = 36;
constexpr int32_t MAX_KEY_REPEAT_RATE = 100;
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
        int32_t delayTime = GetDelayTime(keyEvent_->GetDeviceId());
        AddHandleTimer(delayTime);
        repeatKeyCode_ = keyEvent_->GetKeyCode();
        MMI_HILOGI("Add a timer, keyCode:%{public}d", keyEvent_->GetKeyCode());
    }
    if (keyEvent_->GetKeyAction() == KeyEvent::KEY_ACTION_UP && TimerMgr->IsExist(timerId_)) {
        TimerMgr->RemoveTimer(timerId_);
        timerId_ = -1;
        MMI_HILOGI("Stop keyboard autorepeat, keyCode:%{public}d", keyEvent_->GetKeyCode());
        if (repeatKeyCode_ != keyEvent_->GetKeyCode()) {
            std::optional<KeyEvent::KeyItem> pressedKeyItem = keyEvent_->GetKeyItem(keyEvent_->GetKeyCode());
            if (pressedKeyItem) {
                keyEvent_->RemoveReleasedKeyItems(*pressedKeyItem);
            } else {
                MMI_HILOGW("The pressedKeyItem is nullopt");
            }
            keyEvent_->SetKeyCode(repeatKeyCode_);
            keyEvent_->SetAction(KeyEvent::KEY_ACTION_DOWN);
            keyEvent_->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
            int32_t delayTime = GetDelayTime(keyEvent_->GetDeviceId());
            AddHandleTimer(delayTime);
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
    if (isUserSetRepeatRateStatus_) {
        return repeatRateTime_;
    }
    auto iter = deviceConfig_.find(deviceId);
    int32_t triggertime = DEFAULT_KEY_REPEAT_RATE;
    if (iter != deviceConfig_.end()) {
        triggertime = iter->second.intervalTime;
    }
    return triggertime;
}

int32_t KeyAutoRepeat::GetDelayTime(int32_t deviceId) const
{
    if (isUserSetRepeatDelayStatus_) {
        return repeatDelayTime_;
    }
    auto iter = deviceConfig_.find(deviceId);
    int32_t delayTime = DEFAULT_KEY_REPEAT_DELAY;
    if (iter != deviceConfig_.end()) {
        delayTime = iter->second.delayTime;
    }
    return delayTime;
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

int32_t KeyAutoRepeat::SetKeyboardRepeatDelay(int32_t delay)
{
    CALL_DEBUG_ENTER;
    if (delay < MIN_KEY_REPEAT_DELAY) {
        repeatDelayTime_ = MIN_KEY_REPEAT_DELAY;
    } else if (delay > MAX_KEY_REPEAT_DELAY) {
        repeatDelayTime_ = MAX_KEY_REPEAT_DELAY;
    } else {
        repeatDelayTime_ = delay;
    }
    isUserSetRepeatDelayStatus_ = true;
    MMI_HILOGD("Set keyboard repeat delay delay:%{public}d", delay);
    return RET_OK;
}

int32_t KeyAutoRepeat::SetKeyboardRepeatRate(int32_t rate)
{
    CALL_DEBUG_ENTER;
    if (rate < MIN_KEY_REPEAT_RATE) {
        repeatRateTime_ = MIN_KEY_REPEAT_RATE;
    } else if (rate > MAX_KEY_REPEAT_RATE) {
        repeatRateTime_ = MAX_KEY_REPEAT_RATE;
    } else {
        repeatRateTime_ = rate;
    }
    isUserSetRepeatRateStatus_ = true;
    MMI_HILOGD("Set keyboard repeat rate rate:%{public}d", rate);
    return RET_OK;
}
} // namespace MMI
} // namespace OHOS