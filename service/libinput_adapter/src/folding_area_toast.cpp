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

#include "folding_area_toast.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "want.h"
#include "parameters.h"
#include "util.h"
#include "timer_manager.h"
#include "input_device_manager.h"
#include "input_windows_manager.h"
#include "product_type_parser.h"
#include "product_name_definition.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_SERVER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "FoldingAreaToast"

namespace OHOS {
namespace MMI {
namespace {
    const std::string OHOS_PERMISSION_FOLDING_AREA_TOUCH = "ohos.permission.NOTIFICATION_CONTROLLER";
    const std::string FOLDAREA_TOUCH_STATUS = "usual.event.FOLDING_AREA_TOUCH";
    const std::string FOLDAREA_TOUCH_STATE = "foldingAreaTouchState";
    const int16_t FOLDAREA_DIM2_START = 1608;
    const int16_t FOLDAREA_DIM2_END = 1688;
    const int16_t FOLDAREA_MAX_PRESS_TIMES = 500;
    const int16_t FOLDAREA_MAX_CLK_DB_TIME = 800;
    const int16_t FOLDAREA_MAX_CLK_DB_END_TIME = 1500;
    const int16_t FOLDAREA_MAX_CLK_NUM = 5;
    const int16_t FOLDAREA_MAX_CLK_SAME_AREA = 100;
    const std::string PRODUCT_TYPE = OHOS::system::GetParameter("const.build.product", "HYM");
} // namespace

FoldingAreaToast::FoldingAreaToast()
{
    // init touch device Id.
    deviceId_ = -1;
}

FoldingAreaToast::~FoldingAreaToast() = default;

void FoldingAreaToast::NotifyFoldingAreaTouchStatus(const int8_t state)
{
    OHOS::AAFwk::Want want;
    want.SetAction(FOLDAREA_TOUCH_STATUS);
    want.SetParam(FOLDAREA_TOUCH_STATE, state);
    MMI_HILOGD("TAC detect FoldingAreaTouchStatus state: %{public}d", state);
    EventFwk::CommonEventData CommonEventData { want };
    EventFwk::CommonEventPublishInfo publishInfo;
    std::vector<std::string> permissionVec { OHOS_PERMISSION_FOLDING_AREA_TOUCH };
    publishInfo.SetSubscriberPermissions(permissionVec);
    EventFwk::CommonEventManager::PublishCommonEvent(CommonEventData, publishInfo);
}

void FoldingAreaToast::FoldingAreaClear(void)
{
    if (!touchId2FirstDownTimes_.empty()) {
        touchId2FirstDownTimes_.clear();
    }
    if (!touchId2KeepDownTimes_.empty()) {
        touchId2KeepDownTimes_.clear();
    }
    if (!touchId2KeepFrames_.empty()) {
        touchId2KeepFrames_.clear();
    }
    if (!tacTouchs_.empty()) {
        tacTouchs_.clear();
    }
    if (!touchId2clickTouchs_.empty()) {
        touchId2clickTouchs_.clear();
    }
    if (!touchId2touchNum_.empty()) {
        touchId2touchNum_.clear();
    }
    clickInFoldingAreaBeginTimeStamp_ = 0;
    touchId_ = 0;
    pointX_ = 0;
    pointY_ = 0;
}

void FoldingAreaToast::FoldingAreaLongPressProcess(void)
{
    if (pointY_ >= FOLDAREA_DIM2_START && pointY_ <= FOLDAREA_DIM2_END) {
        touchId2KeepFrames_[touchId_]++;
    } else {
        touchId2KeepFrames_[touchId_] = 0;
    }
    if (touchId2KeepFrames_[touchId_] == 1) {
        touchId2FirstDownTimes_[touchId_] = GetMillisTime();
        touchId2KeepDownTimes_[touchId_] = 0;
    }
    if (touchId2KeepFrames_[touchId_] > 1) {
        touchId2KeepDownTimes_[touchId_] = GetMillisTime() - touchId2FirstDownTimes_[touchId_];
    }
    if (touchId2KeepDownTimes_.count(touchId_) && touchId2KeepDownTimes_[touchId_] > FOLDAREA_MAX_PRESS_TIMES) {
        MMI_HILOGI(
            "TAC detect touch:%d, position = [%d,%d] long press frames %d cost times:%d, in folding area over 0.5s",
            touchId_, pointX_, pointY_, touchId2KeepFrames_[touchId_], touchId2KeepDownTimes_[touchId_]);
        NotifyFoldingAreaTouchStatus(1);
        touchId2KeepFrames_[touchId_] = 0;
        touchId2KeepDownTimes_[touchId_] = 0;
    }
}

void FoldingAreaToast::FoldingAreaGetTouchid2TouchNum(void)
{
    for (auto clickTouch : touchId2clickTouchs_) {
        uint16_t clickTouchDim1 = clickTouch.second.first;
        uint16_t clickTouchDim2 = clickTouch.second.second;
        for (auto tacTouch : tacTouchs_) {
            uint16_t tacTouchDim1 = tacTouch.first;
            uint16_t tacTouchDim2 = tacTouch.second;
            MMI_HILOGD("TAC detect clickTouch position = [%d,%d], tacTouch position = [%d,%d]",
                clickTouchDim1, clickTouchDim2, tacTouchDim1,
                tacTouchDim2);
            if ((tacTouchDim1 >= clickTouchDim1 && (tacTouchDim1 - clickTouchDim1) <= FOLDAREA_MAX_CLK_SAME_AREA) ||
                (tacTouchDim1 < clickTouchDim1 && (clickTouchDim1 - tacTouchDim1) <= FOLDAREA_MAX_CLK_SAME_AREA)) {
                    touchId2touchNum_[clickTouch.first]++;
            }
        }
    }
}

void FoldingAreaToast::FoldingAreaFastClickProcess(void)
{
    if ((pointY_ < FOLDAREA_DIM2_START) || (pointY_ > FOLDAREA_DIM2_END)) {
        return;
    }
    if (tacTouchs_.empty()) {
        clickInFoldingAreaBeginTimeStamp_ = GetMillisTime();
    }
    if (GetMillisTime() < clickInFoldingAreaBeginTimeStamp_ + FOLDAREA_MAX_CLK_DB_TIME) {
        tacTouchs_.push_back(std::make_pair(pointX_, pointY_));
        touchId2clickTouchs_[touchId_].first = pointX_;
        touchId2clickTouchs_[touchId_].second = pointY_;
    }
    if (!tacTouchs_.empty() && GetMillisTime() > clickInFoldingAreaBeginTimeStamp_ + FOLDAREA_MAX_CLK_DB_TIME &&
        GetMillisTime() < clickInFoldingAreaBeginTimeStamp_ + FOLDAREA_MAX_CLK_DB_END_TIME) {
        MMI_HILOGD("TAC detect tacTouchs_ over 1s, curTimeStamp:%ld", GetMillisTime());
        FoldingAreaGetTouchid2TouchNum();
        for (auto touchNum : touchId2touchNum_) {
            if (touchNum.second >= FOLDAREA_MAX_CLK_NUM) {
                MMI_HILOGI(
                    "TAC detect touch:%d fast click %d times position = [%d,%d] in 1s in folding area",
                    touchNum.first, touchNum.second, touchId2clickTouchs_[touchNum.first].first,
                    touchId2clickTouchs_[touchNum.first].second);
                NotifyFoldingAreaTouchStatus(1);
            }
        }
        FoldingAreaClear();
    }
    if (!tacTouchs_.empty() && GetMillisTime() > clickInFoldingAreaBeginTimeStamp_ + FOLDAREA_MAX_CLK_DB_END_TIME) {
        FoldingAreaClear();
        MMI_HILOGD("TAC detect over 1500ms tacTouchs_ clear");
    }
}

void FoldingAreaToast::FoldingAreaCheckDeviceId(struct libinput_event *event)
{
    if (deviceId_ == -1) {
        libinput_device* device = libinput_event_get_device(event);
        if (device != nullptr) {
            deviceId_ = INPUT_DEV_MGR->FindInputDeviceId(device);
        }
    }
}

void FoldingAreaToast::FoldingAreaProcess(struct libinput_event *event)
{
    if (PRODUCT_TYPE != DEVICE_TYPE_FOLD_PC) {
        return;
    }
    FoldingAreaCheckDeviceId(event);
    libinput_event_type eventType = libinput_event_get_type(event);
    libinput_event_touch* touch = nullptr;
    if (eventType == LIBINPUT_EVENT_TOUCH_DOWN || eventType == LIBINPUT_EVENT_TOUCH_UP ||
        eventType == LIBINPUT_EVENT_TOUCH_MOTION || eventType == LIBINPUT_EVENT_TOUCH_CANCEL ||
        eventType == LIBINPUT_EVENT_TOUCH_FRAME) {
        touch = libinput_event_get_touch_event(event);
        if (!touch) {
            FoldingAreaClear();
            return;
        }
        EventTouch touchInfo;
        int32_t logicalDisplayId = -1;
        if (!WIN_MGR->TouchPointToDisplayPoint(deviceId_, touch, touchInfo, logicalDisplayId)) {
            FoldingAreaClear();
            return;
        } else {
            pointX_ = static_cast<uint16_t>(touchInfo.point.x);
            pointY_ = static_cast<uint16_t>(touchInfo.point.y);
            auto displayInfo = WIN_MGR->GetPhysicalDisplay(logicalDisplayId);
            if (!displayInfo || (displayInfo != nullptr && displayInfo->direction > Direction::DIRECTION0)) {
                FoldingAreaClear();
                return;
            }
        }
        if (eventType != LIBINPUT_EVENT_TOUCH_FRAME) {
            touchId_ = libinput_event_touch_get_slot(touch);
        }
        if (eventType == LIBINPUT_EVENT_TOUCH_UP || eventType == LIBINPUT_EVENT_TOUCH_CANCEL) {
            touchId2KeepFrames_[touchId_] = 0;
            touchId2KeepDownTimes_[touchId_] = 0;
        }
        if (eventType == LIBINPUT_EVENT_TOUCH_DOWN || eventType == LIBINPUT_EVENT_TOUCH_MOTION) {
            FoldingAreaLongPressProcess();
        }
        if (eventType == LIBINPUT_EVENT_TOUCH_DOWN) {
            FoldingAreaFastClickProcess();
        }
    }
}
} // namespace MMI
} // namespace OHOS