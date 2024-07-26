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
#include "event_log_helper.h"
#include "input_device_manager.h"
#include "input_event_handler.h"
#include "i_preference_manager.h"
#include "mmi_log.h"
#include "timer_manager.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeyAutoRepeat"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t INVALID_DEVICE_ID { -1 };
constexpr int32_t OPEN_AUTO_REPEAT { 1 };
constexpr int32_t DEFAULT_KEY_REPEAT_DELAY { 500 };
constexpr int32_t MIN_KEY_REPEAT_DELAY { 300 };
constexpr int32_t MAX_KEY_REPEAT_DELAY { 1000 };
constexpr int32_t DEFAULT_KEY_REPEAT_RATE { 50 };
constexpr int32_t MIN_KEY_REPEAT_RATE { 36 };
constexpr int32_t MAX_KEY_REPEAT_RATE { 100 };
const std::string KEYBOARD_FILE_NAME { "keyboard_settings.xml" };
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
    if (ReadTomlFile(GetTomlFilePath(fileName), devConf) != RET_OK) {
        MMI_HILOGI("Can not read device config file");
        return RET_ERR;
    }
    int32_t deviceId = INPUT_DEV_MGR->FindInputDeviceId(device);
    if (deviceId == INVALID_DEVICE_ID) {
        MMI_HILOGE("Find to device failed");
        return RET_ERR;
    }
    deviceConfig_[deviceId] = devConf;
    return RET_OK;
}

void KeyAutoRepeat::SelectAutoRepeat(const std::shared_ptr<KeyEvent>& keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(keyEvent);
    DeviceConfig devConf = GetAutoSwitch(keyEvent->GetDeviceId());
    MMI_HILOGD("AutoRepeatSwitch:%{public}d, keyEvent flag:%{public}x", devConf.autoSwitch, keyEvent->GetFlag());
    if (devConf.autoSwitch != OPEN_AUTO_REPEAT && !keyEvent->HasFlag(InputEvent::EVENT_FLAG_SIMULATE)) {
        MMI_HILOGI("AutoRepeatSwitch not open and is not simulate event");
        return;
    }
    keyEvent_ = keyEvent;
    if (keyEvent_->GetKeyAction() == KeyEvent::KEY_ACTION_DOWN) {
        if (TimerMgr->IsExist(timerId_)) {
            if (!EventLogHelper::IsBetaVersion()) {
                MMI_HILOGI("Keyboard down but timer exists, timerId:%{public}d", timerId_);
            } else {
                if (keyEvent_->HasFlag(InputEvent::EVENT_FLAG_PRIVACY_MODE)) {
                    MMI_HILOGI("Keyboard down but timer exists, timerId:%{public}d, keyCode:%d",
                        timerId_, keyEvent_->GetKeyCode());
                } else {
                    MMI_HILOGI("Keyboard down but timer exists, timerId:%{public}d, keyCode:%{public}d",
                        timerId_, keyEvent_->GetKeyCode());
                }
            }
            TimerMgr->RemoveTimer(timerId_);
            timerId_ = -1;
        }
        int32_t delayTime = GetDelayTime();
        AddHandleTimer(delayTime);
        repeatKeyCode_ = keyEvent_->GetKeyCode();
    }
    if (keyEvent_->GetKeyAction() == KeyEvent::KEY_ACTION_UP && TimerMgr->IsExist(timerId_)) {
        TimerMgr->RemoveTimer(timerId_);
        timerId_ = -1;
        if (EventLogHelper::IsBetaVersion() && !keyEvent->HasFlag(InputEvent::EVENT_FLAG_PRIVACY_MODE)) {
            MMI_HILOGI("Stop autorepeat, keyCode:%{public}d, repeatKeyCode:%{public}d",
                keyEvent_->GetKeyCode(), repeatKeyCode_);
        } else {
            MMI_HILOGI("Stop autorepeat, keyCode:%d, repeatKeyCode:%d",
                keyEvent_->GetKeyCode(), repeatKeyCode_);
        }
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
            int32_t delayTime = GetDelayTime();
            AddHandleTimer(delayTime);
            if (EventLogHelper::IsBetaVersion() && !keyEvent->HasFlag(InputEvent::EVENT_FLAG_PRIVACY_MODE)) {
                MMI_HILOGD("The end keyboard autorepeat, keyCode:%{public}d", keyEvent_->GetKeyCode());
            } else {
                MMI_HILOGD("The end keyboard autorepeat, keyCode:%d", keyEvent_->GetKeyCode());
            }
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
        LogTracer lt(this->keyEvent_->GetId(), this->keyEvent_->GetEventType(), this->keyEvent_->GetKeyAction());
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

int32_t KeyAutoRepeat::GetIntervalTime(int32_t deviceId)
{
    int32_t triggertime = DEFAULT_KEY_REPEAT_RATE;
    GetKeyboardRepeatRate(triggertime);
    return triggertime;
}

int32_t KeyAutoRepeat::GetDelayTime()
{
    int32_t delaytime = DEFAULT_KEY_REPEAT_DELAY;
    GetKeyboardRepeatDelay(delaytime);
    return delaytime;
}

int32_t KeyAutoRepeat::GetKeyboardRepeatTime(int32_t deviceId, bool isDelay)
{
    CALL_DEBUG_ENTER;
    auto iter = deviceConfig_.find(deviceId);
    int32_t repeatTime = isDelay ? DEFAULT_KEY_REPEAT_DELAY : DEFAULT_KEY_REPEAT_RATE;
    if (iter != deviceConfig_.end()) {
        repeatTime = isDelay ? iter->second.delayTime : iter->second.intervalTime;
    }
    return repeatTime;
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
    int32_t deviceId = INPUT_DEV_MGR->FindInputDeviceId(device);
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
    int32_t repeatDelayTime = delay;
    if (delay < MIN_KEY_REPEAT_DELAY) {
        repeatDelayTime = MIN_KEY_REPEAT_DELAY;
    }
    if (delay > MAX_KEY_REPEAT_DELAY) {
        repeatDelayTime = MAX_KEY_REPEAT_DELAY;
    }
    std::string name = "keyboardRepeatDelay";
    if (PutConfigDataToDatabase(name, repeatDelayTime) != RET_OK) {
        MMI_HILOGE("Failed to set keyboard repeat delay");
        return RET_ERR;
    }
    MMI_HILOGD("Set keyboard repeat delay:%{public}d", repeatDelayTime);
    return RET_OK;
}

int32_t KeyAutoRepeat::SetKeyboardRepeatRate(int32_t rate)
{
    CALL_DEBUG_ENTER;
    int32_t repeatRateTime = rate;
    if (rate < MIN_KEY_REPEAT_RATE) {
        repeatRateTime = MIN_KEY_REPEAT_RATE;
    }
    if (rate > MAX_KEY_REPEAT_RATE) {
        repeatRateTime = MAX_KEY_REPEAT_RATE;
    }
    std::string name = "keyboardRepeatRate";
    if (PutConfigDataToDatabase(name, repeatRateTime) != RET_OK) {
        MMI_HILOGE("Failed to set keyboard repeat rate");
        return RET_ERR;
    }
    MMI_HILOGD("Successfully set keyboard repeat for rate:%{public}d", repeatRateTime);
    return RET_OK;
}

int32_t KeyAutoRepeat::GetKeyboardRepeatDelay(int32_t &delay)
{
    CALL_DEBUG_ENTER;
    std::string name = "keyboardRepeatDelay";
    if (GetConfigDataFromDatabase(name, delay) != RET_OK) {
        MMI_HILOGE("Failed to get keyboard repeat delay");
        return RET_ERR;
    }
    if (delay == 0) {
        delay = DEFAULT_KEY_REPEAT_DELAY;
        if (keyEvent_ != nullptr) {
            delay = GetKeyboardRepeatTime(keyEvent_->GetDeviceId(), true);
        }
    }
    MMI_HILOGD("Get keyboard repeat delay:%{public}d", delay);
    return RET_OK;
}

int32_t KeyAutoRepeat::GetKeyboardRepeatRate(int32_t &rate)
{
    CALL_DEBUG_ENTER;
    std::string name = "keyboardRepeatRate";
    if (GetConfigDataFromDatabase(name, rate) != RET_OK) {
        MMI_HILOGE("Failed to get keyboard repeat rate");
        return RET_ERR;
    }
    if (rate == 0) {
        rate = DEFAULT_KEY_REPEAT_RATE;
        if (keyEvent_ != nullptr) {
            rate = GetKeyboardRepeatTime(keyEvent_->GetDeviceId(), false);
        }
    }
    MMI_HILOGD("Get keyboard repeat rate:%{public}d", rate);
    return RET_OK;
}

int32_t KeyAutoRepeat::PutConfigDataToDatabase(std::string &key, int32_t value)
{
    return PREFERENCES_MGR->SetIntValue(key, KEYBOARD_FILE_NAME, value);
}

int32_t KeyAutoRepeat::GetConfigDataFromDatabase(std::string &key, int32_t &value)
{
    value = PREFERENCES_MGR->GetIntValue(key, value);
    return RET_OK;
}
} // namespace MMI
} // namespace OHOS