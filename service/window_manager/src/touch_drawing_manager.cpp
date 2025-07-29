/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "touch_drawing_manager.h"

#include "bytrace_adapter.h"
#include "parameters.h"
#include "setting_datashare.h"

#include <system_ability_definition.h>
#include "input_windows_manager.h"
#include "table_dump.h"
#include "timer_manager.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_CURSOR
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TouchDrawingManager"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t REPEAT_ONCE { 1 };
constexpr int32_t REPEAT_COOLING_TIME { 500 };
const std::string SHOW_CURSOR_SWITCH_NAME { "settings.input.show_touch_hint" };
const std::string POINTER_POSITION_SWITCH_NAME { "settings.developer.show_touch_track" };
const int32_t ROTATE_POLICY = system::GetIntParameter("const.window.device.rotate_policy", 0);
const std::string FOLDABLE_DEVICE_POLICY = system::GetParameter("const.window.foldabledevice.rotate_policy", "");
constexpr int32_t WINDOW_ROTATE { 0 };
constexpr char ROTATE_WINDOW_ROTATE { '0' };
constexpr int32_t FOLDABLE_DEVICE { 2 };
constexpr char LIB_TOUCH_DRAWING_HANDLER_PATH[] { "libmmi_touch_drawing_handler.z.so" };
} // namespace

TouchDrawingManager::TouchDrawingManager() {}

TouchDrawingManager::~TouchDrawingManager() {}

void TouchDrawingManager::Initialize()
{
    int32_t nRetries { 60 };
    SetupSettingObserver(nRetries);
}

void TouchDrawingManager::SetupSettingObserver(int32_t nRetries)
{
    CreateObserver();
    if (hasBubbleObserver_ && hasPointerObserver_) {
        return;
    }
    if (nRetries <= 0) {
        MMI_HILOGE("Failed to setup setting observer after tens of retries");
        return;
    }
    auto timerId = TimerMgr->AddTimer(REPEAT_COOLING_TIME, REPEAT_ONCE,
        [this, nRetries]() {
            SetupSettingObserver(nRetries - 1);
        }, "TouchDrawingManager");
    if (timerId < 0) {
        MMI_HILOGE("AddTimer fail");
    }
}

void TouchDrawingManager::TouchDrawHandler(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(pointerEvent);
    auto touchDrawingHandler = GetTouchDrawingHandler();
    if (touchDrawingHandler != nullptr) {
        touchDrawingHandler->TouchDrawHandler(pointerEvent);
    }
}

void TouchDrawingManager::UpdateDisplayInfo(const OLD::DisplayInfo& displayInfo)
{
    CALL_DEBUG_ENTER;
    auto touchDrawingHandler = GetTouchDrawingHandler();
    if (touchDrawingHandler != nullptr) {
        touchDrawingHandler->UpdateDisplayInfo(displayInfo);

        static std::once_flag flag;
        std::call_once(flag, [this]() {
            UpdateLabels();
        });
    } else {
        displayInfo_ = displayInfo;
    }
}

void TouchDrawingManager::GetOriginalTouchScreenCoordinates(Direction direction, int32_t width, int32_t height,
    int32_t &physicalX, int32_t &physicalY)
{
    MMI_HILOGD("direction:%{public}d", direction);
    switch (direction) {
        case DIRECTION0: {
            break;
        }
        case DIRECTION90: {
            int32_t temp = physicalY;
            physicalY = width - physicalX;
            physicalX = temp;
            break;
        }
        case DIRECTION180: {
            physicalX = width - physicalX;
            physicalY = height - physicalY;
            break;
        }
        case DIRECTION270: {
            int32_t temp = physicalX;
            physicalX = height - physicalY;
            physicalY = temp;
            break;
        }
        default: {
            break;
        }
    }
}

int32_t TouchDrawingManager::UpdateLabels()
{
    CALL_DEBUG_ENTER;
    if (pointerMode_.isShow) {
        auto touchDrawingHandler = LoadTouchDrawingHandler();
        if (touchDrawingHandler == nullptr) {
            MMI_HILOGW("Failed to load touch drawing handler");
            return RET_ERR;
        }
        touchDrawingHandler->UpdateLabels(true);
    } else {
        auto touchDrawingHandler = GetTouchDrawingHandler();
        if (touchDrawingHandler == nullptr) {
            MMI_HILOGD("No touch drawing handler");
            return RET_ERR;
        }
        touchDrawingHandler->UpdateLabels(false);
        UnloadTouchDrawingHandler();
    }
    return RET_OK;
}

int32_t TouchDrawingManager::UpdateBubbleData()
{
    CALL_DEBUG_ENTER;
    if (bubbleMode_.isShow) {
        auto touchDrawingHandler = LoadTouchDrawingHandler();
        if (touchDrawingHandler == nullptr) {
            MMI_HILOGE("Failed to load touch drawing handler");
            return RET_ERR;
        }
        touchDrawingHandler->UpdateBubbleData(true);
    } else {
        auto touchDrawingHandler = GetTouchDrawingHandler();
        if (touchDrawingHandler == nullptr) {
            MMI_HILOGD("No touch drawing handler");
            return RET_ERR;
        }
        touchDrawingHandler->UpdateBubbleData(false);
        UnloadTouchDrawingHandler();
    }
    return RET_OK;
}

void TouchDrawingManager::RotationScreen()
{
    CALL_DEBUG_ENTER;
    auto touchDrawingHandler = GetTouchDrawingHandler();
    if (touchDrawingHandler != nullptr) {
        touchDrawingHandler->RotationScreen();
    }
}

void TouchDrawingManager::CreateObserver()
{
    CALL_DEBUG_ENTER;
    if (!hasBubbleObserver_) {
        MMI_HILOGI("Setup observer of show-touch-track");
        bubbleMode_.SwitchName = SHOW_CURSOR_SWITCH_NAME;
        CreateBubbleObserver(bubbleMode_);
    }
    if (!hasPointerObserver_) {
        MMI_HILOGI("Setup observer of show-touch-position");
        pointerMode_.SwitchName = POINTER_POSITION_SWITCH_NAME;
        CreatePointerObserver(pointerMode_);
        SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID).
            GetBoolValue(POINTER_POSITION_SWITCH_NAME, pointerMode_.isShow);
    }
    MMI_HILOGD("The bubbleMode_:%{public}d, pointerMode_:%{public}d", bubbleMode_.isShow, pointerMode_.isShow);
}

template <class T>
void TouchDrawingManager::CreateBubbleObserver(T &item)
{
    CALL_DEBUG_ENTER;
    SettingObserver::UpdateFunc updateFunc = [&item, this](const std::string& key) {
        auto ret = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID)
            .GetBoolValue(key, item.isShow);
        if (ret != RET_OK) {
            MMI_HILOGE("Get value from setting date fail");
            return;
        }
        CHKPV(delegateProxy_);
        delegateProxy_->OnPostSyncTask(std::bind(&TouchDrawingManager::UpdateBubbleData, this));
        MMI_HILOGI("The key:%{public}s, statusValue:%{public}d", key.c_str(), item.isShow);
    };
    sptr<SettingObserver> statusObserver = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID)
        .CreateObserver(item.SwitchName, updateFunc);
    ErrCode ret = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID).
        RegisterObserver(statusObserver);
    if (ret != ERR_OK) {
        MMI_HILOGE("Register setting observer failed, ret:%{public}d", ret);
        statusObserver = nullptr;
        return;
    }
    hasBubbleObserver_ = true;
}

template <class T>
void TouchDrawingManager::CreatePointerObserver(T &item)
{
    CALL_DEBUG_ENTER;
    SettingObserver::UpdateFunc updateFunc = [&item, this](const std::string& key) {
        auto ret = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID)
            .GetBoolValue(key, item.isShow);
        if (ret != RET_OK) {
            MMI_HILOGE("Get value from setting date fail");
            return;
        }
        CHKPV(delegateProxy_);
        delegateProxy_->OnPostSyncTask(std::bind(&TouchDrawingManager::UpdateLabels, this));
        MMI_HILOGI("The key:%{public}s, statusValue:%{public}d", key.c_str(), item.isShow);
    };
    sptr<SettingObserver> statusObserver = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID)
        .CreateObserver(item.SwitchName, updateFunc);
    ErrCode ret = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID).RegisterObserver(statusObserver);
    if (ret != ERR_OK) {
        MMI_HILOGE("Register setting observer failed, ret:%{public}d", ret);
        statusObserver = nullptr;
        return;
    }
    hasPointerObserver_ = true;
}

void TouchDrawingManager::Dump(int32_t fd, const std::vector<std::string> &args)
{
    auto touchDrawingHandler = GetTouchDrawingHandler();
    if (touchDrawingHandler == nullptr) {
        MMI_HILOGD("No touch drawing handler");
        return;
    }
    touchDrawingHandler->Dump(fd, args);
}

bool TouchDrawingManager::IsWindowRotation() const
{
    auto touchDrawingHandler = GetTouchDrawingHandler();
    if (touchDrawingHandler != nullptr) {
        return touchDrawingHandler->IsWindowRotation();
    }
    MMI_HILOGD("ROTATE_POLICY:%{public}d, FOLDABLE_DEVICE_POLICY:%{public}s",
        ROTATE_POLICY, FOLDABLE_DEVICE_POLICY.c_str());
    return (ROTATE_POLICY == WINDOW_ROTATE ||
            (ROTATE_POLICY == FOLDABLE_DEVICE &&
             ((displayInfo_.displayMode == DisplayMode::MAIN &&
               FOLDABLE_DEVICE_POLICY[0] == ROTATE_WINDOW_ROTATE) ||
              (displayInfo_.displayMode == DisplayMode::FULL &&
               (FOLDABLE_DEVICE_POLICY.size() > FOLDABLE_DEVICE) &&
               FOLDABLE_DEVICE_POLICY[FOLDABLE_DEVICE] == ROTATE_WINDOW_ROTATE))));
}

void TouchDrawingManager::SetDelegateProxy(std::shared_ptr<DelegateInterface> proxy)
{
    delegateProxy_ = proxy;
}

void TouchDrawingManager::SetMultiWindowScreenId(uint64_t screenId, uint64_t displayNodeScreenId)
{
    auto touchDrawingHandler = GetTouchDrawingHandler();
    if (touchDrawingHandler != nullptr) {
        touchDrawingHandler->SetMultiWindowScreenId(screenId, displayNodeScreenId);
    } else {
        windowScreenId_ = screenId;
        displayNodeScreenId_ = displayNodeScreenId;
    }
}

ITouchDrawingHandler* TouchDrawingManager::LoadTouchDrawingHandler()
{
    if (touchDrawingHandler_ == nullptr) {
        touchDrawingHandler_ = ComponentManager::LoadLibrary<ITouchDrawingHandler>(
            nullptr, LIB_TOUCH_DRAWING_HANDLER_PATH);
        if (touchDrawingHandler_ != nullptr) {
            touchDrawingHandler_->UpdateDisplayInfo(displayInfo_);
            touchDrawingHandler_->SetMultiWindowScreenId(windowScreenId_, displayNodeScreenId_);
        }
    }
    return touchDrawingHandler_.get();
}

ITouchDrawingHandler* TouchDrawingManager::GetTouchDrawingHandler() const
{
    return touchDrawingHandler_.get();
}

void TouchDrawingManager::UnloadTouchDrawingHandler()
{
    if (bubbleMode_.isShow || pointerMode_.isShow) {
        return;
    }
    touchDrawingHandler_ = { nullptr, ComponentManager::Component<ITouchDrawingHandler>(nullptr, nullptr) };
}
} // namespace MMI
} // namespace OHOS