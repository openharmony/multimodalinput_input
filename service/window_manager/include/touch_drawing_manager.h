/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef TOUCH_DRAWING_MANAGER_H
#define TOUCH_DRAWING_MANAGER_H

#include "singleton.h"

#include "i_touch_drawing_handler.h"
#include "component_manager.h"
#include "pointer_event.h"
#include "old_display_info.h"

namespace OHOS {
namespace MMI {
class DelegateInterface;
class TouchDrawingManager {
    struct DevMode {
        std::string SwitchName;
        bool isShow { false };
    };

    DECLARE_DELAYED_SINGLETON(TouchDrawingManager);

public:
    DISALLOW_COPY_AND_MOVE(TouchDrawingManager);
    void Initialize();
    void TouchDrawHandler(std::shared_ptr<PointerEvent> pointerEvent);
    void UpdateDisplayInfo(const OLD::DisplayInfo& displayInfo);
    void GetOriginalTouchScreenCoordinates(Direction direction, int32_t width, int32_t height,
        int32_t &physicalX, int32_t &physicalY);
    void RotationScreen();
    void Dump(int32_t fd, const std::vector<std::string> &args);
    bool IsWindowRotation() const;
    void SetDelegateProxy(std::shared_ptr<DelegateInterface> proxy);
    void SetMultiWindowScreenId(uint64_t screenId, uint64_t displayNodeScreenId);
    void ResetTouchWindow();

private:
    void SetupSettingObserver(int32_t nRetries);
    void CreateObserver();
    int32_t UpdateLabels();
    void RemoveUpdateLabelsTimer();
    void AddUpdateLabelsTimer();
    int32_t UpdateBubbleData();
    template <class T>
    void CreateBubbleObserver(T& item);
    template <class T>
    void CreatePointerObserver(T& item);
    ITouchDrawingHandler* LoadTouchDrawingHandler();
    ITouchDrawingHandler* GetTouchDrawingHandler() const;
    void UnloadTouchDrawingHandler();

private:
    OLD::DisplayInfo displayInfo_ {};
    DevMode bubbleMode_;
    DevMode pointerMode_;
    bool hasBubbleObserver_{ false };
    bool hasPointerObserver_{ false };
    uint64_t windowScreenId_ { 0 };
    uint64_t displayNodeScreenId_ { 0 };
    std::shared_ptr<DelegateInterface> delegateProxy_ { nullptr };
    std::unique_ptr<ITouchDrawingHandler, ComponentManager::Component<ITouchDrawingHandler>> touchDrawingHandler_ {
        nullptr, ComponentManager::Component<ITouchDrawingHandler>(nullptr, nullptr) };
    int32_t timerId_ { -1 };
};

#define TOUCH_DRAWING_MGR ::OHOS::DelayedSingleton<TouchDrawingManager>::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // TOUCH_DRAWING_MANAGER_H
