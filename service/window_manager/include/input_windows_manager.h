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
#ifndef INPUT_WINDOWS_MANAGER_H
#define INPUT_WINDOWS_MANAGER_H

#include <vector>

#include "libinput.h"
#include "nocopyable.h"
#include "singleton.h"

#include "display_info.h"
#include "input_event.h"
#include "pointer_event.h"
#include "uds_server.h"

namespace OHOS {
namespace MMI {
struct MouseLocation {
    int32_t globalX;
    int32_t globalY;
};

class InputWindowsManager : public DelayedSingleton<InputWindowsManager> {
public:
    InputWindowsManager();
    virtual ~InputWindowsManager();
    DISALLOW_COPY_AND_MOVE(InputWindowsManager);

    void Init(UDSServer& udsServer);
    void UpdateSeatsInfo();
    void UpdateScreensInfo();

    int32_t GetPidAndUpdateTarget(std::shared_ptr<InputEvent> inputEvent);
    int32_t UpdateTarget(std::shared_ptr<InputEvent> inputEvent);
    void UpdateDisplayInfo(const DisplayGroupInfo &displayGroupInfo);
    MouseLocation GetMouseInfo();
    void UpdateAndAdjustMouseLoction(int32_t& displayId, double& x, double& y);
    void AdjustGlobalCoordinate(const DisplayInfo& displayInfo, int32_t& globalX, int32_t& globalY) const;
    bool UpdataDisplayId(int32_t& displayId);
    int32_t UpdateTargetPointer(std::shared_ptr<PointerEvent> pointerEvent);
    bool TouchPointToDisplayPoint(struct libinput_event_touch* touch,
        EventTouch& touchInfo, int32_t& targetDisplayId);
    void RotateTouchScreen(DisplayInfo info, LogicalCoordinate& coord) const;
    bool TransformTipPoint(struct libinput_event_tablet_tool* tip, LogicalCoordinate& coord, int32_t& displayId) const;
    bool CalculateTipPoint(struct libinput_event_tablet_tool* tip,
        int32_t& targetDisplayId, LogicalCoordinate& coord) const;
    DisplayGroupInfo GetDisplayGroupInfo();
    
private:
    bool IsInsideWindow(int32_t x, int32_t y, const std::vector<Rect> &rects) const;
    void PrintDisplayInfo();
    int32_t UpdateMouseTarget(std::shared_ptr<PointerEvent> pointerEvent);
    int32_t UpdateTouchScreenTarget(std::shared_ptr<PointerEvent> pointerEvent);
    int32_t UpdateTouchPadTarget(std::shared_ptr<PointerEvent> pointerEvent);
    const DisplayInfo* GetPhysicalDisplay(int32_t id) const;
    const DisplayInfo* FindPhysicalDisplayInfo(const std::string& uniq) const;
    int32_t GetDisplayId(std::shared_ptr<InputEvent> inputEvent) const;
    void SelectWindowInfo(const int32_t& globalX, const int32_t& globalY,
        const std::shared_ptr<PointerEvent>& pointerEvent, WindowInfo*& touchWindow);
    void GetGlobalLogicDisplayCoord(struct libinput_event_touch* touch,
        EventTouch& touchInfo, DisplayInfo info);
    bool IsInsideDisplay(DisplayInfo displayInfo, int32_t globalX, int32_t globalY);
    void FindPhysicalDisplay(DisplayInfo displayInfo, int32_t& globalX, int32_t& globalY, int32_t& displayId);
private:
    UDSServer* udsServer_ = nullptr;
    int32_t firstBtnDownWindowId_ = -1;
    DisplayGroupInfo displayGroupInfo_;
    MouseLocation mouseLoction_ = {-1, -1}; // physical coord
};

#define WinMgr InputWindowsManager::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // INPUT_WINDOWS_MANAGER_H
