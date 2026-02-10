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
    auto touchGestureMgr = GetTouchGestureManager();
    if (touchGestureMgr == nullptr) {
        MMI_HILOGW("No touch-gesture manager");
        return false;
    }
    return touchGestureMgr->DoesSupportGesture(gestureType, nFingers);
}

bool TouchGestureInterface::AddHandler(int32_t session, TouchGestureType gestureType, int32_t nFingers)
{
    auto touchGestureMgr = GetTouchGestureManager();
    if (touchGestureMgr == nullptr) {
        MMI_HILOGW("No touch-gesture manager");
        std::lock_guard guard { mutex_ };
        pendingHandlers_.emplace(Handler {
            .session_ = session,
            .gesture_ = gestureType,
            .nFingers_ = nFingers,
        });
        return true;
    }
    return touchGestureMgr->AddHandler(session, gestureType, nFingers);
}

void TouchGestureInterface::RemoveHandler(int32_t session, TouchGestureType gestureType, int32_t nFingers)
{
    auto touchGestureMgr = GetTouchGestureManager();
    if (touchGestureMgr == nullptr) {
        MMI_HILOGW("No touch-gesture manager");
        std::lock_guard guard { mutex_ };
        pendingHandlers_.erase(Handler {
            .session_ = session,
            .gesture_ = gestureType,
            .nFingers_ = nFingers,
        });
        return;
    }
    touchGestureMgr->RemoveHandler(session, gestureType, nFingers);
}

bool TouchGestureInterface::HasHandler() const
{
    ComponentManager::Handle<ITouchGestureManager> touchGestureMgr {};
    {
        std::lock_guard guard { mutex_ };
        if (!pendingHandlers_.empty()) {
            return true;
        }
        touchGestureMgr = touchGestureMgr_;
    }
    if (touchGestureMgr == nullptr) {
        MMI_HILOGW("No touch-gesture manager");
        return false;
    }
    return touchGestureMgr->HasHandler();
}

void TouchGestureInterface::HandleGestureWindowEmerged(int32_t windowId, std::shared_ptr<PointerEvent> lastTouchEvent)
{
    auto touchGestureMgr = GetTouchGestureManager();
    if (touchGestureMgr == nullptr) {
        MMI_HILOGW("No touch-gesture manager");
        return;
    }
    touchGestureMgr->HandleGestureWindowEmerged(windowId, lastTouchEvent);
}

void TouchGestureInterface::Dump(int32_t fd, const std::vector<std::string> &args)
{
    auto touchGestureMgr = GetTouchGestureManager();
    if (touchGestureMgr == nullptr) {
        MMI_HILOGW("No touch-gesture manager");
        return;
    }
    touchGestureMgr->Dump(fd, args);
}

void TouchGestureInterface::OnSessionLost(int32_t session)
{
    auto touchGestureMgr = GetTouchGestureManager();
    if (touchGestureMgr == nullptr) {
        MMI_HILOGW("No touch-gesture manager");
        return;
    }
    touchGestureMgr->OnSessionLost(session);
}

ComponentManager::Handle<ITouchGestureManager> TouchGestureInterface::GetTouchGestureManager() const
{
    std::lock_guard guard { mutex_ };
    return touchGestureMgr_;
}

void TouchGestureInterface::LoadTouchGestureManager(IInputServiceContext *env)
{
    MMI_HILOGI("Start loading TouchGesture");
    auto touchGestureMgr = ComponentManager::LoadLibrary<ITouchGestureManager>(
        env, LIB_TOUCH_GESTURE_MANAGER_NAME);
    if (touchGestureMgr == nullptr) {
        MMI_HILOGE("Failed to load TouchGesture");
        return;
    }
    {
        std::lock_guard guard { mutex_ };
        touchGestureMgr_ = std::move(touchGestureMgr);
    }
    MMI_HILOGI("TouchGesture loaded");
    OnTouchGestureManagerLoaded();
}

void TouchGestureInterface::OnTouchGestureManagerLoaded()
{
    auto touchGestureMgr = GetTouchGestureManager();
    if (touchGestureMgr == nullptr) {
        MMI_HILOGE("TouchGestureManager not loaded");
        return;
    }
    std::set<Handler> pendingHandlers {};
    {
        std::lock_guard guard { mutex_ };
        pendingHandlers.swap(pendingHandlers_);
    }
    for (const auto &handler : pendingHandlers) {
        touchGestureMgr->AddHandler(handler.session_, handler.gesture_, handler.nFingers_);
    }
}
} // namespace MMI
} // namespace OHOS