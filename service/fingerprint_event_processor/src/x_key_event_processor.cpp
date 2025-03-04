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
#include <os_account_manager.h>
#include "ability_manager_client.h"
#include "system_ability_definition.h"
#include "x_key_event_processor.h"
#include "input_event_handler.h"
#include "setting_datashare.h"
#include "pointer_event.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_DISPATCH
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "XKeyEventProcessor"

namespace OHOS {
namespace MMI {
#ifdef OHOS_BUILD_ENABLE_X_KEY
namespace {
    const std::string X_KEY_DOUBLE_CLICK_ENABLE_KEY { "double_click_enable_status" };
    const std::string DOUBLE_CLICK_ENABLE_STATUS { "0" };
    const std::string X_KEY_APP_BUNDLE_NAME { "" };
    const std::string X_KEY_APP_ABILITY_NAME { "" };
    const std::string SETTING_URI_USER_SECURE_PROXY {
        "datashare:///com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_SECURE_100?Proxy=true"
    };
    const int32_t X_KEY_DOUBLE_CLICK_ENABLE_COUNT { 2 };
}

XKeyEventProcessor::XKeyEventProcessor()
{}

XKeyEventProcessor::~XKeyEventProcessor()
{}

bool XKeyEventProcessor::IsXkeyEvent(struct libinput_event* event)
{
    CALL_DEBUG_ENTER;
    CHKPR(event, false);
    auto device = libinput_event_get_device(event);
    CHKPR(device, false);
    std::string name = libinput_device_get_name(device);
    MMI_HILOGI("service name is:%{public}s", name.c_str());
    if (X_KEY_SOURCE_KEY != name) {
        MMI_HILOGI("Not X-key");
        return false;
    }
    // 拉起X键进程
    StartXkeyIfNeeded();
    // 监听settingsdata数据库字段
    if (!isCreatedObserver_) {
        MMI_HILOGI("create observer.");
        doubleClickSwitch_.keyString = X_KEY_DOUBLE_CLICK_ENABLE_KEY;
        CreateStatusConfigObserver(doubleClickSwitch_);
        isCreatedObserver_ = true;
    }
    return true;
}

void XKeyEventProcessor::StartXkeyIfNeeded()
{
    if (!isStartedXkey_) {
        isStartedXkey_ = true;
        MMI_HILOGI("start nine-square grid panel.");
        AAFwk::Want want;
        want.SetElementName(X_KEY_APP_BUNDLE_NAME, X_KEY_APP_ABILITY_NAME);
        ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want);
        if (err != ERR_OK) {
            MMI_HILOGI("start ability fail.");
        }
    }
}

template <class T>
void XKeyEventProcessor::CreateStatusConfigObserver(T& item)
{
    CALL_DEBUG_ENTER;
    SettingObserver::UpdateFunc updateFunc = [&item](const std::string& key) {
        std::string value = DOUBLE_CLICK_ENABLE_STATUS;
        MMI_HILOGI("settings data key is:%{public}s", key.c_str());
        auto ret = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID)
            .GetStringValue(key, value, SETTING_URI_USER_SECURE_PROXY);
        if (ret != RET_OK) {
            MMI_HILOGE("Get value from settings db failed, ret:%{public}d", ret);
            return;
        }
        MMI_HILOGI("Config changed, key:%{public}s, value:%{public}s", key.c_str(), value.c_str());
        item.valueString = value;
    };

    sptr<SettingObserver> statusObserver = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID)
        .CreateObserver(item.keyString, updateFunc);
    ErrCode ret = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID).RegisterObserver(statusObserver);
    if (ret != RET_OK) {
        MMI_HILOGE("Register setting observer failed, ret:%{public}d", ret);
        statusObserver = nullptr;
    }

    std::string value = DOUBLE_CLICK_ENABLE_STATUS;
    ret = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID)
        .SettingDataShare::GetStringValue(item.keyString, value, SETTING_URI_USER_SECURE_PROXY);
    if (ret != RET_OK) {
        MMI_HILOGE("Get value from settings db failed, ret:%{public}d", ret);
        return;
    }
    MMI_HILOGI("Get value success, key:%{public}s, value:%{public}s", item.keyString.c_str(), value.c_str());
    item.valueString = value;
}

int32_t XKeyEventProcessor::HandleXkeyEvent(struct libinput_event* event)
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
    MMI_HILOGI("keyCode:%{public}d, keyState:%{public}d", keyCode, keyState);
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
    HandleQuickAccessMenu(X_KEY_DOWN);
    auto currentTime = std::chrono::steady_clock::now();
    // 记录按下时间
    lastDownTime_ = currentTime;

    //如果是第一次按下，启动长安检测
    if (pressCount_ == 0) {
        std::thread([this, currentTime]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(LONG_PRESS_DELAY));
            if (pressCount_ == 1 && lastDownTime_ == currentTime) {
                // 如果按下时间超过长按阈值，判定为长按
                HandleQuickAccessMenu(LONG_PRESS);
                MMI_HILOGI("X-key is long press.");
            }
        }).detach();
    }

    // 增加按压次数
    pressCount_++;
}

void XKeyEventProcessor::InterceptXKeyUp()
{
    HandleQuickAccessMenu(X_KEY_UP);
    // 如果按压次数为1，启动单击/双击检测
    if (pressCount_ == 1) {
        if (doubleClickSwitch_.valueString.empty() || doubleClickSwitch_.valueString == DOUBLE_CLICK_ENABLE_STATUS) {
            // 未设置双击拉起的应用，不做延迟单击处理，直接触发单击
            HandleQuickAccessMenu(SINGLE_CLICK);
            MMI_HILOGI("X-key is single click after remove delayed click.");
            return;
        }
        std::thread([this]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(DOUBLE_CLICK_DELAY));
            if (pressCount_ == 1) {
                // 如果没有第二次按下，判定为单击
                HandleQuickAccessMenu(SINGLE_CLICK);
                MMI_HILOGI("X-key is single click.");
            }
        }).detach();
    } else if (pressCount_ == X_KEY_DOUBLE_CLICK_ENABLE_COUNT) {
        // 如果按压次数为2次，判定为双击
        HandleQuickAccessMenu(DOUBLE_CLICK);
        MMI_HILOGI("X-key is double click.");
    }
}

void XKeyEventProcessor::ResetCount()
{
    pressCount_ == 0;
}

int32_t XKeyEventProcessor::HandleQuickAccessMenu(int32_t xKeyEventType)
{
    if (X_KEY_DOWN != xKeyEventType && X_KEY_UP != xKeyEventType) {
        ResetCount();
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
#endif // OHOS_BUILD_ENABLE_X_KEY
} // namespace MMI
} // namespace OHOS