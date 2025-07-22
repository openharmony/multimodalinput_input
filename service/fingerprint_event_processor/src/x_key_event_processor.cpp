/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <iostream>
#include <thread>
#include <chrono>
#include "ability_manager_client.h"
#include "system_ability_definition.h"
#include "x_key_event_processor.h"
#include "input_event_handler.h"
#include "setting_datashare.h"
#include "pointer_event.h"
#include "account_manager.h"
#include "timer_manager.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_DISPATCH
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "XKeyEventProcessor"

namespace OHOS {
namespace MMI {
#ifdef OHOS_BUILD_ENABLE_X_KEY
namespace {
    const std::string X_KEY_DOUBLE_CLICK_ENABLE_KEY = "double_click_enable_status";
    const std::string DOUBLE_CLICK_ENABLE_STATUS = "0";
    const std::string X_KEY_APP_BUNDLE_NAME = "";
    const std::string X_KEY_APP_ABILITY_NAME = "";
    const std::string SETTINGS_DATA_SECURE_PRE_URI =
    	"datashare:///com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_SECURE_";
    const std::string SETTINGS_DATA_SECURE_POST_URI = "?Proxy=true";
    const int32_t X_KEY_DOUBLE_CLICK_ENABLE_COUNT = 2;
    constexpr int32_t DOUBLE_CLICK_DELAY { 300 };
    constexpr int32_t LONG_PRESS_DELAY { 500 };

    constexpr int32_t X_KEY_DOWN { 0 };
    constexpr int32_t X_KEY_UP { 1 };
    constexpr int32_t SINGLE_CLICK { 2 };
    constexpr int32_t DOUBLE_CLICK { 3 };
    constexpr int32_t LONG_PRESS { 4 };
}

XKeyEventProcessor::XKeyEventProcessor()
{}

XKeyEventProcessor::~XKeyEventProcessor()
{}

bool XKeyEventProcessor::IsXKeyEvent(struct libinput_event* event)
{
    CALL_DEBUG_ENTER;
    CHKPF(event);
    auto device = libinput_event_get_device(event);
    CHKPF(device);
    std::string name = libinput_device_get_name(device);
    if (X_KEY_SOURCE_KEY != name) {
        MMI_HILOGD("Not X-key");
        return false;
    }
    return true;
}

int32_t XKeyEventProcessor::HandleXKeyEvent(struct libinput_event* event)
{
    CALL_DEBUG_ENTER;
    CHKPR(event, ERROR_NULL_POINTER);
    auto device = libinput_event_get_device(event);
    CHKPR(device, PARAM_INPUT_INVALID);
    std::string name = libinput_device_get_name(device);
    if (X_KEY_SOURCE_KEY == name) {
        return AnalyseKeyEvent(event);
    }
    return PARAM_INPUT_INVALID;
}

int32_t XKeyEventProcessor::AnalyseKeyEvent(struct libinput_event* event)
{
    CALL_DEBUG_ENTER;
    CHKPR(event, ERROR_NULL_POINTER);
    struct libinput_event_keyboard* keyEvent = libinput_event_get_keyboard_event(event);
    CHKPR(keyEvent, ERROR_NULL_POINTER);
    auto keyCode = libinput_event_keyboard_get_key(keyEvent);
    int32_t keyState = libinput_event_keyboard_get_key_state(keyEvent);
    MMI_HILOGD("keyCode:%{private}d, keyState:%{private}d", keyCode, keyState);
    int32_t keyAction = keyState == 0 ? KeyEvent::KEY_ACTION_UP : KeyEvent::KEY_ACTION_DOWN;
    if (KeyEvent::KEY_ACTION_DOWN == keyAction) {
        InterceptXKeyDown();
    } else {
        InterceptXKeyUp();
    }
    return ERR_OK;
}

void XKeyEventProcessor::InterceptXKeyDown()
{
    handledLongPress_ = false;
    HandleQuickAccessMenu(X_KEY_DOWN);

    if (pressCount_ == 0) {
        StartLongPressTimer();
    }

    pressCount_++;
}

void XKeyEventProcessor::StartLongPressTimer()
{
    MMI_HILOGD("start long press timer.");
    longPressTimerId_ = TimerMgr->AddTimer(LONG_PRESS_DELAY, 1, [this] () {
        if (this->pressCount_ == 1 && !this->handledLongPress_) {
            HandleQuickAccessMenu(LONG_PRESS);
            MMI_HILOGI("X-key is long press.");
        }
    }, "XKeyEventProcessor");
}

void XKeyEventProcessor::InterceptXKeyUp()
{
    handledLongPress_ = true;
    HandleQuickAccessMenu(X_KEY_UP);
    if (pressCount_ == 1) {
        if (IsRemoveDelaySingleClick()) {
            MMI_HILOGI("X-key is single click after remove delayed click.");
            HandleQuickAccessMenu(SINGLE_CLICK);
            return;
        }
        StartSingleClickTimer();
    } else if (pressCount_ == X_KEY_DOUBLE_CLICK_ENABLE_COUNT) {
        HandleQuickAccessMenu(DOUBLE_CLICK);
        MMI_HILOGI("X-key is double click.");
    }
}

bool XKeyEventProcessor::IsRemoveDelaySingleClick()
{
    std::string value = DOUBLE_CLICK_ENABLE_STATUS;
    int32_t userId = ACCOUNT_MGR->GetCurrentAccountSetting().GetAccountId();
    std::string uri = SETTINGS_DATA_SECURE_PRE_URI + std::to_string(userId) + SETTINGS_DATA_SECURE_POST_URI;
    MMI_HILOGI("settings data uri:%{public}s", uri.c_str());
    SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID)
        .SettingDataShare::GetStringValue(X_KEY_DOUBLE_CLICK_ENABLE_KEY, value, uri);
    MMI_HILOGI("double click enable state:%{public}s", value.c_str());
    return value == DOUBLE_CLICK_ENABLE_STATUS;
}

void XKeyEventProcessor::StartSingleClickTimer()
{
    MMI_HILOGD("start single click timer.");
    singleClickTimerId_ = TimerMgr->AddTimer(DOUBLE_CLICK_DELAY, 1, [this] () {
        if (this->pressCount_ == 1) {
            HandleQuickAccessMenu(SINGLE_CLICK);
            MMI_HILOGI("X-key is single click.");
        }
    }, "XKeyEventProcessor");
}

void XKeyEventProcessor::RemoveTimer()
{
    if (singleClickTimerId_ != -1) {
        TimerMgr->RemoveTimer(singleClickTimerId_);
        singleClickTimerId_ = -1;
    }
    if (longPressTimerId_ != -1) {
        TimerMgr->RemoveTimer(longPressTimerId_);
        longPressTimerId_ = -1;
    }
}

void XKeyEventProcessor::ResetCount()
{
    MMI_HILOGD("reset press count");
    pressCount_ = 0;
}

int32_t XKeyEventProcessor::HandleQuickAccessMenu(int32_t xKeyEventType)
{
    if (X_KEY_DOWN != xKeyEventType && X_KEY_UP != xKeyEventType) {
        StartXKeyIfNeeded(xKeyEventType);
        ResetCount();
        RemoveTimer();
    }
    auto pointerEvent = PointerEvent::Create();
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    pointerEvent->SetPointerAction(xKeyEventType);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_X_KEY);
#if (defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)) && defined(OHOS_BUILD_ENABLE_MONITOR)
    auto eventMonitorHandler_ = InputHandler->GetMonitorHandler();
    if (eventMonitorHandler_ != nullptr) {
        eventMonitorHandler_->OnHandleEvent(pointerEvent);
    }
#endif // (OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH) && OHOS_BUILD_ENABLE_MONITOR
    return RET_OK;
}

void XKeyEventProcessor::StartXKeyIfNeeded(int32_t xKeyEventType)
{
    if (!isStartedXKey_) {
        isStartedXKey_ = true;
        MMI_HILOGI("start x-key.");
        AAFwk::Want want;
        want.SetElementName(X_KEY_APP_BUNDLE_NAME, X_KEY_APP_ABILITY_NAME);
        want.SetParam("xKeyEventType", xKeyEventType);
        ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want);
        if (err != ERR_OK) {
            MMI_HILOGI("start ability fail.");
        }
    }
}
#endif // OHOS_BUILD_ENABLE_X_KEY
} // namespace MMI
} // namespace OHOS