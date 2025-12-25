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

#include "touch_gesture_interface.h"

#include "ffrt.h"
#include "define_multimodal.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TouchGestureInterface"

namespace OHOS {
namespace MMI {
namespace {
constexpr char LIB_TOUCH_GESTURE_MANAGER_NAME[] { "libmmi_touch_gesture_manager.z.so" };
} // namespace

std::shared_ptr<TouchGestureInterface> TouchGestureInterface::Load(IInputServiceContext *env)
{
    auto instance = std::make_shared<TouchGestureInterface>();
    ffrt::submit([instance, env]() {
        instance->LoadTouchGestureManager(env);
    });
    return instance;
}

bool TouchGestureInterface::DoesSupportGesture(TouchGestureType gestureType, int32_t nFingers) const
{
    std::shared_lock guard { mutex_ };
    if (touchGestureMgr_ == nullptr) {
        MMI_HILOGW("No touch-gesture manager");
        return false;
    }
    return touchGestureMgr_->DoesSupportGesture(gestureType, nFingers);
}

bool TouchGestureInterface::AddHandler(int32_t session, TouchGestureType gestureType, int32_t nFingers)
{
    std::unique_lock guard { mutex_ };
    if (touchGestureMgr_ == nullptr) {
        MMI_HILOGW("No touch-gesture manager");
        pendingHandlers_.emplace(Handler {
            .session_ = session,
            .gesture_ = gestureType,
            .nFingers_ = nFingers,
        });
        return true;
    }
    return touchGestureMgr_->AddHandler(session, gestureType, nFingers);
}

void TouchGestureInterface::RemoveHandler(int32_t session, TouchGestureType gestureType, int32_t nFingers)
{
    std::unique_lock guard { mutex_ };
    if (touchGestureMgr_ == nullptr) {
        MMI_HILOGW("No touch-gesture manager");
        pendingHandlers_.erase(Handler {
            .session_ = session,
            .gesture_ = gestureType,
            .nFingers_ = nFingers,
        });
        return;
    }
    touchGestureMgr_->RemoveHandler(session, gestureType, nFingers);
}

bool TouchGestureInterface::HasHandler() const
{
    std::shared_lock guard { mutex_ };
    if (!pendingHandlers_.empty()) {
        return true;
    }
    if (touchGestureMgr_ == nullptr) {
        MMI_HILOGW("No touch-gesture manager");
        return false;
    }
    return touchGestureMgr_->HasHandler();
}

void TouchGestureInterface::HandleGestureWindowEmerged(int32_t windowId, std::shared_ptr<PointerEvent> lastTouchEvent)
{
    std::shared_lock guard { mutex_ };
    if (touchGestureMgr_ == nullptr) {
        MMI_HILOGW("No touch-gesture manager");
        return;
    }
    touchGestureMgr_->HandleGestureWindowEmerged(windowId, lastTouchEvent);
}

void TouchGestureInterface::Dump(int32_t fd, const std::vector<std::string> &args)
{
    std::shared_lock guard { mutex_ };
    if (touchGestureMgr_ == nullptr) {
        MMI_HILOGW("No touch-gesture manager");
        return;
    }
    touchGestureMgr_->Dump(fd, args);
}

void TouchGestureInterface::OnSessionLost(int32_t session)
{
    std::shared_lock guard { mutex_ };
    if (touchGestureMgr_ == nullptr) {
        MMI_HILOGW("No touch-gesture manager");
        return;
    }
    touchGestureMgr_->OnSessionLost(session);
}

void TouchGestureInterface::LoadTouchGestureManager(IInputServiceContext *env)
{
    MMI_HILOGI("Start loading TouchGesture");
    TouchGestureInterface touchGestureMgr {};
    touchGestureMgr.touchGestureMgr_ = ComponentManager::LoadLibrary<ITouchGestureManager>(
        env, LIB_TOUCH_GESTURE_MANAGER_NAME);
    if (touchGestureMgr.touchGestureMgr_ == nullptr) {
        MMI_HILOGE("Failed to load TouchGesture");
        return;
    }
    MMI_HILOGI("TouchGesture loaded");
    OnTouchGestureManagerLoaded(touchGestureMgr);
}

void TouchGestureInterface::OnTouchGestureManagerLoaded(TouchGestureInterface &touchGestureMgr)
{
    std::unique_lock guard { mutex_ };
    touchGestureMgr_ = std::move(touchGestureMgr.touchGestureMgr_);
    for (const auto &handler : pendingHandlers_) {
        touchGestureMgr_->AddHandler(handler.session_, handler.gesture_, handler.nFingers_);
    }
    pendingHandlers_.clear();
}
} // namespace MMI
} // namespace OHOS