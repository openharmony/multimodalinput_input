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

    bool Init(UDSServer& udsServer);
    void UpdateSeatsInfo();
    void UpdateScreensInfo();

    int32_t GetPidAndUpdateTarget(std::shared_ptr<InputEvent> inputEvent) const;
    int32_t UpdateTarget(std::shared_ptr<InputEvent> inputEvent);
    void UpdateDisplayInfo(const std::vector<PhysicalDisplayInfo> &physicalDisplays,
        const std::vector<LogicalDisplayInfo> &logicalDisplays);
    const std::vector<LogicalDisplayInfo>& GetLogicalDisplayInfo() const;
    MouseLocation GetMouseInfo() const;
    void UpdateAndAdjustMouseLoction(double& x, double& y);
    void AdjustGlobalCoordinate(int32_t& globalX, int32_t& globalY, int32_t width, int32_t height);
    bool UpdataDisplayId(int32_t& displayId);
    LogicalDisplayInfo* GetLogicalDisplayId(int32_t displayId);
    int32_t UpdateTargetPointer(std::shared_ptr<PointerEvent> pointerEvent);
    bool TouchDownPointToDisplayPoint(struct libinput_event_touch* touch, Direction& direction,
        int32_t& logicalX, int32_t& logicalY, int32_t& logicalDisplayId);
    bool TouchMotionPointToDisplayPoint(struct libinput_event_touch* touch, Direction& direction,
        int32_t targetDisplayId, int32_t& displayX, int32_t& displayY);
    bool TransformDisplayPoint(struct libinput_event_touch* touch, Direction& direction, int32_t &globalLogicalX,
        int32_t &globalLogicalY);
    void RotateTouchScreen(PhysicalDisplayInfo* info, Direction direction,
        int32_t& logicalX, int32_t& logicalY);

private:
    bool IsInsideWindow(int32_t x, int32_t y, const WindowInfo &info) const;
    void PrintDisplayDebugInfo();
    int32_t UpdateMouseTarget(std::shared_ptr<PointerEvent> pointerEvent);
    int32_t UpdateTouchScreenTarget(std::shared_ptr<PointerEvent> pointerEvent);
    int32_t UpdateTouchPadTarget(std::shared_ptr<PointerEvent> pointerEvent);
    PhysicalDisplayInfo* GetPhysicalDisplay(int32_t id);
    PhysicalDisplayInfo* FindPhysicalDisplayInfo(const std::string seatId, const std::string seatName);
    int32_t GetDisplayId(std::shared_ptr<InputEvent> inputEvent) const;

private:
    UDSServer* udsServer_ = nullptr;
    int32_t firstBtnDownWindowId_ = -1;
    std::vector<PhysicalDisplayInfo> physicalDisplays_ = {};
    std::vector<LogicalDisplayInfo> logicalDisplays_ = {};
    std::map<int32_t, WindowInfo> windowInfos_ = {};
    MouseLocation mouseLoction_ = {};
};

#define WinMgr InputWindowsManager::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // INPUT_WINDOWS_MANAGER_H
