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

#ifndef TABLET_TOOL_TRANSFORM_PROCESSOR_H
#define TABLET_TOOL_TRANSFORM_PROCESSOR_H

#include <optional>

#include "cJSON.h"
#include "old_display_info.h"
#include "struct_multimodal.h"
#include "transform_processor.h"
#include "window_info.h"

namespace OHOS {
namespace MMI {
class TabletToolTransformProcessor final : public TransformProcessor {
private:
    struct TabletCalibration {
        double tabletMinX { 0.0 };
        double tabletMaxX { 0.0 };
        double tabletMinY { 0.0 };
        double tabletMaxY { 0.0 };

        double calibratedMinX { 0.0 };
        double calibratedMaxX { 0.0 };
        double calibratedMinY { 0.0 };
        double calibratedMaxY { 0.0 };

        int32_t displayId { -1 };
        int32_t screenWidth { 0 };
        int32_t screenHeight { 0 };
        Direction screenDirection { Direction::DIRECTION0 };
    };

public:
    explicit TabletToolTransformProcessor(int32_t deviceId);
    DISALLOW_COPY_AND_MOVE(TabletToolTransformProcessor);
    ~TabletToolTransformProcessor() = default;
    std::shared_ptr<PointerEvent> OnEvent(struct libinput_event *event) override;
    std::shared_ptr<PointerEvent> GetPointerEvent() override { return nullptr; }
    void OnDeviceRemoved() override;
    void OnDeviceEnabled() override;
    void OnDeviceDisabled() override;

private:
    int32_t GetToolType(struct libinput_event_tablet_tool* tabletEvent);
    bool OnTip(struct libinput_event* event);
    bool OnTipProximity(struct libinput_event* event);
    bool OnTipDown(struct libinput_event_tablet_tool* event);
    bool OnTipMotion(struct libinput_event* event);
    bool OnTipUp(struct libinput_event_tablet_tool* event);
    bool IsTouching(struct libinput_event_tablet_tool* tabletEvent);
    void DrawTouchGraphic();
    void DrawTouchGraphicIdle();
    void DrawTouchGraphicDrawing();
    bool OnToolButton(struct libinput_event* event);

    bool IsTabletPointer() const;
    bool InitializeCalibration(struct libinput_device* device, int32_t displayId);
    void InitializeDefaultCalibration(struct libinput_device* device,
        const OLD::DisplayInfo& displayInfo, TabletCalibration &calib);
    void CalculateCalibration(const OLD::DisplayInfo& displayInfo, TabletCalibration &calib);
    bool IsScreenChanged(int32_t currentDisplayId) const;
    bool CalculateWithCalibration(struct libinput_event_tablet_tool* tabletEvent,
        int32_t& targetDisplayId, PhysicalCoordinate& coord);
    bool CalculateScreenCoordinateWithCalibration(struct libinput_event_tablet_tool* tabletEvent,
        const OLD::DisplayInfo& displayInfo, PhysicalCoordinate& coord);
    bool CalculateCalibratedTipPoint(struct libinput_event_tablet_tool* tabletEvent,
        int32_t& targetDisplayId, PhysicalCoordinate& coord, PointerEvent::PointerItem& pointerItem);

    static bool IsCalibrationEnabled();
    static void LoadProductConfig(bool& enabled);
    static bool ReadTabletCalibrationConfig(const char* cfgPath, cJSON* jsonCfg, bool& enabled);

    void RecordActiveOperations();
    void SendProximityOutEvent();
    void SendTipUpEvent();
    void SendButtonUpEvents();
    void UpdateDeviceStateFromPointerEvent();

private:
    const int32_t deviceId_ { -1 };
    bool isProximity_ { false };
    bool isPressed_ { false };
    std::function<void()> current_;
    std::shared_ptr<PointerEvent> pointerEvent_ { nullptr };
    std::optional<TabletCalibration> calibration_ {};
};
} // namespace MMI
} // namespace OHOS
#endif // TABLET_TOOL_TRANSFORM_PROCESSOR_H
