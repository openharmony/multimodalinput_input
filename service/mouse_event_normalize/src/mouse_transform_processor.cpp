/*
 * Copyright (c) 2022-2026 Huawei Device Co., Ltd.
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

#include "mouse_transform_processor.h"
#include "cursor_drawing_component.h"
#include "dfx_hisysevent.h"
#include "event_log_helper.h"
#include "i_input_windows_manager.h"
#include "i_preference_manager.h"
#include "i_setting_manager.h"
#include "mouse_device_state.h"
#include "mouse_preference_accessor.h"
#include "pointer_device_manager.h"
#include "pointer_motion_acceleration.h"
#include "scene_board_judgement.h"
#ifdef OHOS_BUILD_ENABLE_TOUCHPAD
#include "touchpad_transform_processor.h"
#endif // OHOS_BUILD_ENABLE_TOUCHPAD
#include "product_name_definition.h"
#include "product_type_parser.h"
#include "util_ex.h"
#include "linux/input.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_DISPATCH
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "MouseTransformProcessor"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t BTN_RIGHT_MENUE_CODE { 0x118 };
constexpr int32_t RIGHT_CLICK_TYPE_MIN { 1 };
constexpr int32_t TP_RIGHT_CLICK_FINGER_CNT { 2 };
constexpr int32_t HARD_PC_PRO_DEVICE_WIDTH { 2880 };
constexpr int32_t HARD_PC_PRO_DEVICE_HEIGHT { 1920 };
constexpr int32_t SOFT_PC_PRO_DEVICE_WIDTH { 3120 };
constexpr int32_t SOFT_PC_PRO_DEVICE_HEIGHT { 2080 };
constexpr int32_t TABLET_DEVICE_WIDTH { 2880 };
constexpr int32_t TABLET_DEVICE_HEIGHT { 1920 };
const std::string SYS_PRODUCT_TYPE = OHOS::system::GetParameter("const.build.product", SYS_GET_DEVICE_TYPE_PARAM);
constexpr int32_t ANGLE_90 { 90 };
constexpr int32_t ANGLE_360 { 360 };
constexpr int32_t FINE_CALCULATE { 20 };
constexpr int32_t STEP_CALCULATE { 40 };
constexpr int32_t STOP_CALCULATE { 5000 };
constexpr int32_t CALCULATE_STEP { 5 };
constexpr float MM_TO_INCH { 25.4f };
constexpr int32_t SCREEN_DIAGONAL_0 { 0 };
constexpr int32_t SCREEN_DIAGONAL_8 { 8 };
constexpr int32_t SCREEN_DIAGONAL_18 { 18 };
constexpr int32_t SCREEN_DIAGONAL_27 { 27 };
constexpr int32_t SCREEN_DIAGONAL_55 { 55 };
constexpr float FACTOR_0 { 1.0f };
constexpr float FACTOR_8 { 0.7f };
constexpr float FACTOR_18 { 1.0f };
constexpr float FACTOR_27 { 1.2f };
constexpr float FACTOR_55 { 1.6f };
constexpr float FACTOR_MAX { 2.4f };
constexpr double CONST_HALF { 0.5 };
constexpr int32_t CONST_TWO { 2 };
constexpr double CONST_DOUBLE_ZERO { 0.0 };
constexpr double CONST_DOUBLE_ONE { 1.0 };
} // namespace

#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
std::atomic_bool MouseTransformProcessor::isVirtualDeviceEvent_ = false;
#endif // OHOS_BUILD_ENABLE_VKEYBOARD

std::atomic_int32_t MouseTransformProcessor::globalScrollSwitchPid_ = -1;

MouseTransformProcessor::MouseTransformProcessor(IInputServiceContext *env, int32_t deviceId)
    : env_(env), deviceId_(deviceId)
{
    pointerEvent_ = PointerEvent::Create();
    if (env_ == nullptr) {
        MMI_HILOGE("Env is nullptr");
        return;
    }
}

MouseTransformProcessor::~MouseTransformProcessor()
{
    CALL_INFO_TRACE;
    auto timerMgr = GetTimerManager();
    if (timerMgr == nullptr) {
        MMI_HILOGE("timerMgr is nullptr");
        return;
    }
    if (timerMgr->IsExist(timerId_)) {
        timerMgr->RemoveTimer(timerId_);
    }
}

std::shared_ptr<PointerEvent> MouseTransformProcessor::GetPointerEvent() const
{
    return pointerEvent_;
}

#ifdef OHOS_BUILD_EMULATOR
static Coordinate2D CalculateCursorPosFromOffset(Offset offset, const OLD::DisplayInfo &displayInfo)
{
    auto direction = displayInfo.displayDirection;
    auto width = displayInfo.validWidth;
    auto height = displayInfo.validHeight;
    constexpr int evenNum = 2;
    if ((displayInfo.displayDirection - displayInfo.direction) % evenNum != 0) {
        std::swap(width, height);
    }
    auto offsetX = displayInfo.offsetX;
    auto offsetY = displayInfo.offsetY;
    if (displayInfo.fixedDirection % evenNum != 0) {
        std::swap(offsetX, offsetY);
    }
    offset.dx -= offsetX;
    offset.dy -= offsetY;
    if (direction == DIRECTION90) {
        std::swap(offset.dx, offset.dy);
        offset.dx = width - offset.dx;
    } else if (direction == DIRECTION180) {
        offset.dx = width - offset.dx;
        offset.dy = height - offset.dy;
    } else if (direction == DIRECTION270) {
        std::swap(offset.dx, offset.dy);
        offset.dy = height - offset.dy;
    }
    return {offset.dx, offset.dy};
}
#endif

float ScreenFactor(const int32_t diagonalInch)
{
    if (diagonalInch <= SCREEN_DIAGONAL_0) {
        return FACTOR_0;
    } else if (diagonalInch < SCREEN_DIAGONAL_8) {
        return FACTOR_8;
    } else if (diagonalInch < SCREEN_DIAGONAL_18) {
        return FACTOR_18;
    } else if (diagonalInch < SCREEN_DIAGONAL_27) {
        return FACTOR_27;
    } else if (diagonalInch < SCREEN_DIAGONAL_55) {
        return FACTOR_55;
    } else {
        return FACTOR_MAX;
    }
}

int32_t MouseTransformProcessor::HandleMotionInner(struct libinput_event_pointer* data, struct libinput_event* event)
{
    CALL_DEBUG_ENTER;
    CHKPR(data, ERROR_NULL_POINTER);
    CHKPR(pointerEvent_, ERROR_NULL_POINTER);
#ifndef OHOS_BUILD_ENABLE_WATCH
    pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent_->SetButtonId(buttonId_);
    if (env_ == nullptr) {
        MMI_HILOGE("Env is nullptr");
        return RET_ERR;
    }
    auto winMgr = GetInputWindowsManager();
    if (winMgr == nullptr) {
        MMI_HILOGE("winMgr is nullptr");
        return RET_ERR;
    }
    CursorPosition cursorPos = winMgr->GetCursorPos();
    if (cursorPos.displayId < 0) {
        MMI_HILOGE("No display");
        return RET_ERR;
    }
    unaccelerated_.dx = libinput_event_pointer_get_dx_unaccelerated(data);
    unaccelerated_.dy = libinput_event_pointer_get_dy_unaccelerated(data);

    Offset offset { unaccelerated_.dx, unaccelerated_.dy };
    auto displayInfo = winMgr->GetPhysicalDisplay(cursorPos.displayId);
    CHKPR(displayInfo, ERROR_NULL_POINTER);
    CalculateMouseResponseTimeProbability(event);
    const int32_t type = libinput_event_get_type(event);
    int32_t ret = RET_ERR;
    DeviceType deviceType = CheckDeviceType(displayInfo->width, displayInfo->height);
    if (type == LIBINPUT_EVENT_POINTER_MOTION_TOUCHPAD) {
        pointerEvent_->AddFlag(InputEvent::EVENT_FLAG_TOUCHPAD_POINTER);
        ret = UpdateTouchpadMoveLocation(displayInfo, event, offset, cursorPos.cursorPos.x, cursorPos.cursorPos.y,
            static_cast<int32_t>(deviceType));
    } else {
        pointerEvent_->ClearFlag(InputEvent::EVENT_FLAG_TOUCHPAD_POINTER);
        pointerEvent_->ClearFlag(InputEvent::EVENT_FLAG_VIRTUAL_TOUCHPAD_POINTER);
        ret = UpdateMouseMoveLocation(displayInfo, offset, cursorPos.cursorPos.x, cursorPos.cursorPos.y,
            static_cast<int32_t>(deviceType));
    }
    if (ret != RET_OK) {
        MMI_HILOGE("Failed to handle motion correction");
        return ret;
    }
#ifdef OHOS_BUILD_EMULATOR
    cursorPos.cursorPos = CalculateCursorPosFromOffset(offset, *displayInfo);
#endif // OHOS_BUILD_EMULATOR
    winMgr->UpdateAndAdjustMouseLocation(cursorPos.displayId,
        cursorPos.cursorPos.x, cursorPos.cursorPos.y);
    pointerEvent_->SetTargetDisplayId(cursorPos.displayId);
    MMI_HILOGD("Change coordinate: x:%.2f, y:%.2f, currentDisplayId:%d",
        cursorPos.cursorPos.x, cursorPos.cursorPos.y, cursorPos.displayId);
#endif // OHOS_BUILD_ENABLE_WATCH
    return RET_OK;
}

int32_t MouseTransformProcessor::UpdateMouseMoveLocation(const OLD::DisplayInfo* displayInfo, Offset &offset,
    double &abs_x, double &abs_y, int32_t deviceType)
{
    CHKPR(displayInfo, ERROR_NULL_POINTER);
    int32_t ret = RET_ERR;
    uint64_t dalta_time = 0;
#ifdef OHOS_BUILD_MOUSE_REPORTING_RATE
    dalta_time = filterInsertionPoint_.filterDeltaTime;
    HandleFilterMouseEvent(&offset);
#endif // OHOS_BUILD_MOUSE_REPORTING_RATE
    CalculateOffset(displayInfo, offset);
    if (!enableMouseAleaccelerateBool_) {
        abs_x += offset.dx;
        abs_y += offset.dy;
        ret = RET_OK;
        MMI_HILOGD("Skip mouse acceleration motion");
        return ret;
    }
    auto winMgr = GetInputWindowsManager();
        if (winMgr == nullptr) {
            MMI_HILOGE("winMgr is nullptr");
            return RET_ERR;
        }
    if (displayInfo->ppi > static_cast<float>(CONST_DOUBLE_ZERO)) {
        double displaySize = sqrt(pow(displayInfo->width, CONST_TWO) + pow(displayInfo->height, CONST_TWO));
        double diagonalMm = sqrt(pow(displayInfo->physicalWidth, CONST_TWO)
            + pow(displayInfo->physicalHeight, CONST_TWO));
        double displayPpi = static_cast<double>(displayInfo->ppi);
        if (displayInfo->validWidth != static_cast<int32_t>(CONST_DOUBLE_ZERO) &&
            displayInfo->validHeight != static_cast<int32_t>(CONST_DOUBLE_ZERO)  &&
            (displayInfo->validWidth != displayInfo->width || displayInfo->validHeight != displayInfo->height)) {
            displaySize = sqrt(pow(displayInfo->validWidth, CONST_TWO) + pow(displayInfo->validHeight, CONST_TWO));
            diagonalMm = sqrt(pow(displayInfo->physicalWidth, CONST_TWO)
                + pow(displayInfo->physicalHeight * CONST_HALF, CONST_TWO));
        }
#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
        if (displayInfo->pointerActiveWidth > static_cast<int32_t>(CONST_DOUBLE_ZERO) &&
            displayInfo->pointerActiveHeight > static_cast<int32_t>(CONST_DOUBLE_ZERO)) {
            MMI_HILOGD("vkb is show, use half display accelerate");
            displaySize = sqrt(pow(displayInfo->pointerActiveWidth, CONST_TWO) +
                pow(displayInfo->pointerActiveHeight, CONST_TWO));
            diagonalMm = sqrt(pow(displayInfo->physicalWidth, CONST_TWO) +
                pow(displayInfo->physicalHeight * CONST_HALF, CONST_TWO));
        }
#endif // OHOS_BUILD_ENABLE_VKEYBOARD
        if (diagonalMm > CONST_DOUBLE_ZERO) {
            displayPpi = displaySize * MM_TO_INCH / diagonalMm;
        }
        int32_t diagonalInch = static_cast<int32_t>(diagonalMm / MM_TO_INCH);
        float factor = ScreenFactor(diagonalInch);
        if (env_ == nullptr) {
            MMI_HILOGE("Env is nullptr");
            return RET_ERR;
        }
        int32_t userId = WIN_MGR->FindDisplayUserId(pointerEvent_->GetTargetDisplayId());
        ret = PointerMotionAcceleration::DynamicAccelerateMouse(offset,
            winMgr->GetMouseIsCaptureMode(),
            MousePreferenceAccessor::GetPointerSpeed(*env_, userId), dalta_time, displayPpi,
                static_cast<double>(factor), abs_x, abs_y);
        return ret;
    } else {
        MMI_HILOGW("displayinfo get failed, use default acclerate. width:%{public}d height:%{public}d",
            displayInfo->width, displayInfo->height);
        int32_t userId = WIN_MGR->FindDisplayUserId(pointerEvent_->GetTargetDisplayId());
        ret = PointerMotionAcceleration::AccelerateMouse(offset,
            winMgr->GetMouseIsCaptureMode(),
            MousePreferenceAccessor::GetPointerSpeed(*env_, userId), static_cast<DeviceType>(deviceType), abs_x, abs_y);
        return ret;
    }
}

int32_t MouseTransformProcessor::UpdateTouchpadMoveLocation(const OLD::DisplayInfo* displayInfo,
    struct libinput_event* event, Offset &offset, double &abs_x, double &abs_y, int32_t deviceType)
{
    CHKPR(displayInfo, ERROR_NULL_POINTER);
    int32_t ret = RET_ERR;
    CalculateOffset(displayInfo, offset);
    struct libinput_device *device = libinput_event_get_device(event);
    CHKPR(device, ERROR_NULL_POINTER);
    if (env_ == nullptr) {
        MMI_HILOGE("Env is nullptr");
        return RET_ERR;
    }
    const std::string devName = libinput_device_get_name(device);
    auto winMgr = GetInputWindowsManager();
    if (winMgr == nullptr) {
        MMI_HILOGE("winMgr is nullptr");
        return RET_ERR;
    }
    int32_t userId = WIN_MGR->FindDisplayUserId(pointerEvent_->GetTargetDisplayId());
    if (displayInfo->width == static_cast<int32_t>(CONST_DOUBLE_ZERO) ||
        displayInfo->height == static_cast<int32_t>(CONST_DOUBLE_ZERO)) {
        MMI_HILOGW("displayinfo get failed, use default acclerate. width:%{public}d height:%{public}d",
            displayInfo->width, displayInfo->height);
        ret = PointerMotionAcceleration::AccelerateTouchpad(offset,
            winMgr->GetMouseIsCaptureMode(),
            MousePreferenceAccessor::GetTouchpadSpeed(*env_, userId),
            static_cast<DeviceType>(deviceType), abs_x, abs_y);
        return ret;
    } else if (SYS_PRODUCT_TYPE == DEVICE_TYPE_FOLD_PC && devName == "input_mt_wrapper") {
        deviceType = static_cast<int32_t>(DeviceType::DEVICE_FOLD_PC_VIRT);
        pointerEvent_->AddFlag(InputEvent::EVENT_FLAG_VIRTUAL_TOUCHPAD_POINTER);
        ret = PointerMotionAcceleration::AccelerateTouchpad(offset, winMgr->GetMouseIsCaptureMode(),
            MousePreferenceAccessor::GetTouchpadSpeed(*env_, userId), static_cast<DeviceType>(deviceType),
            abs_x, abs_y);
        return ret;
    } else {
        pointerEvent_->AddFlag(InputEvent::EVENT_FLAG_TOUCHPAD_POINTER);
        double displaySize = sqrt(pow(displayInfo->width, CONST_TWO) + pow(displayInfo->height, CONST_TWO));
        if (displayInfo->validWidth != static_cast<int32_t>(CONST_DOUBLE_ZERO) &&
            displayInfo->validHeight != static_cast<int32_t>(CONST_DOUBLE_ZERO) &&
            (displayInfo->validWidth != displayInfo->width || displayInfo->validHeight != displayInfo->height)) {
            displaySize = sqrt(pow(displayInfo->validWidth, CONST_TWO) + pow(displayInfo->validHeight, CONST_TWO));
        }
#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
        if (displayInfo->pointerActiveWidth > static_cast<int32_t>(CONST_DOUBLE_ZERO) &&
            displayInfo->pointerActiveHeight > static_cast<int32_t>(CONST_DOUBLE_ZERO)) {
            MMI_HILOGD("vkb is show, use half display accelerate");
            displaySize = sqrt(pow(displayInfo->pointerActiveWidth, CONST_TWO) +
                pow(displayInfo->pointerActiveHeight, CONST_TWO));
        }
#endif // OHOS_BUILD_ENABLE_VKEYBOARD
        double touchpadPPi = libinput_touchpad_device_get_ppi(device);
        double touchpadSize = libinput_touchpad_device_get_hypot_size(device) * touchpadPPi;
        int32_t frequency = libinput_touchpad_device_get_frequency(device);
        if (touchpadPPi < CONST_DOUBLE_ONE || touchpadSize < CONST_DOUBLE_ONE || frequency < CONST_DOUBLE_ONE) {
            return RET_ERR;
        }
        ret = PointerMotionAcceleration::DynamicAccelerateTouchpad(offset,
            winMgr->GetMouseIsCaptureMode(),
            MousePreferenceAccessor::GetTouchpadSpeed(*env_, userId), displaySize, touchpadSize, touchpadPPi, frequency,
                abs_x, abs_y);
        return ret;
    }
}

void MouseTransformProcessor::CalculateMouseResponseTimeProbability(struct libinput_event *event)
{
    CHKPV(event);
    struct libinput_device *dev = libinput_event_get_device(event);
    CHKPV(dev);
    const std::string mouseName = libinput_device_get_name(dev);
    const int32_t devType = static_cast<int32_t>(libinput_device_get_id_bustype(dev));
    MMI_HILOGD("mouseName:%{public}s, devType:%{public}d", mouseName.c_str(), devType);
    if (devType != BUS_USB && devType != BUS_BLUETOOTH) {
        return;
    }
    std::string connectType = devType == BUS_USB ? "USB" : "BLUETOOTH";
    auto curMouseTimeMap = mouseMap.find(mouseName);
    if (curMouseTimeMap == mouseMap.end()) {
        mouseMap[mouseName] = std::chrono::steady_clock::now();
        mouseResponseMap[mouseName] = {};
    } else {
        std::chrono::time_point<std::chrono::steady_clock> curTime = std::chrono::steady_clock::now();
        long long gap =
            std::chrono::duration_cast<std::chrono::milliseconds>(curTime - curMouseTimeMap->second).count();
        mouseMap[mouseName] = curTime;
        std::map<long long, int32_t> &curMap = mouseResponseMap.find(mouseName)->second;

        if (gap < FINE_CALCULATE) {
            auto curMapIt = curMap.try_emplace(gap, 1);
            if (!curMapIt.second) {
                curMapIt.first->second += 1;
            }
        } else if (gap >= FINE_CALCULATE && gap < STEP_CALCULATE) {
            long long tempNum = gap - gap % CALCULATE_STEP;
            auto curMapIt = curMap.try_emplace(tempNum, 1);
            if (!curMapIt.second) {
                curMapIt.first->second += 1;
            }
        } else if (gap >= STEP_CALCULATE && gap < STOP_CALCULATE) {
            auto curMapIt = curMap.try_emplace(STEP_CALCULATE, 1);
            if (!curMapIt.second) {
                curMapIt.first->second += 1;
            }
        } else if (gap > STOP_CALCULATE) {
            HandleReportMouseResponseTime(connectType, curMap);
            mouseResponseMap.erase(mouseName);
            mouseMap.erase(mouseName);
        }
    }
}

void MouseTransformProcessor::HandleReportMouseResponseTime(
    std::string &connectType, std::map<long long, int32_t> &curMap)
{
    long total = 0;
    for (const auto &[key, value] : curMap) {
        total += value;
    }
    if (total <= 0) {
        MMI_HILOGD("mouse not move");
        return;
    }
    int32_t ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "COLLECT_MOUSE_RESPONSE_TIME",
        OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC,
        "MOUSE_CONNECT_TYPE", connectType,
        "MOVING_TOTAL", total,
        "1ms", CalculateProportion(1, total, curMap),
        "2ms", CalculateProportion(2, total, curMap),
        "3ms", CalculateProportion(3, total, curMap),
        "4ms", CalculateProportion(4, total, curMap),
        "5ms", CalculateProportion(5, total, curMap),
        "6ms", CalculateProportion(6, total, curMap),
        "7ms", CalculateProportion(7, total, curMap),
        "8ms", CalculateProportion(8, total, curMap),
        "9ms", CalculateProportion(9, total, curMap),
        "10ms", CalculateProportion(10, total, curMap),
        "11ms", CalculateProportion(11, total, curMap),
        "12ms", CalculateProportion(12, total, curMap),
        "13ms", CalculateProportion(13, total, curMap),
        "14ms", CalculateProportion(14, total, curMap),
        "15ms", CalculateProportion(15, total, curMap),
        "16ms", CalculateProportion(16, total, curMap),
        "17ms", CalculateProportion(17, total, curMap),
        "18ms", CalculateProportion(18, total, curMap),
        "19ms", CalculateProportion(19, total, curMap),
        "20ms", CalculateProportion(FINE_CALCULATE, total, curMap),
        "25ms", CalculateProportion(25, total, curMap),
        "30ms", CalculateProportion(30, total, curMap),
        "35ms", CalculateProportion(35, total, curMap),
        "40ms", CalculateProportion(STEP_CALCULATE, total, curMap),
        "MSG", "collectiong mouse response time probability");
    if (ret != RET_OK) {
        MMI_HILOGE("Mouse write failed , ret:%{public}d", ret);
    }
}

double MouseTransformProcessor::CalculateProportion(long long key, long &total,
    std::map<long long, int32_t> &curMap)
{
    auto iter = curMap.find(key);
    bool isUsed = (iter != curMap.end()) && (total != 0);
    return isUsed ? (1.0 * iter->second / total) : 0;
}

Direction MouseTransformProcessor::GetDisplayDirection(const OLD::DisplayInfo *displayInfo)
{
    Direction displayDirection = DIRECTION0;
    CHKPR(displayInfo, DIRECTION0);
    if (Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        displayDirection = static_cast<Direction>((
            ((displayInfo->direction - displayInfo->displayDirection) * ANGLE_90 + ANGLE_360) % ANGLE_360) / ANGLE_90);
    }
    return displayDirection;
}

void MouseTransformProcessor::CalculateOffset(const OLD::DisplayInfo* displayInfo, Offset &offset)
{
#ifndef OHOS_BUILD_EMULATOR
    if (Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        Direction direction = GetDisplayDirection(displayInfo);
        std::negate<double> neg;
        if (direction == DIRECTION90) {
            double tmp = offset.dx;
            offset.dx = offset.dy;
            offset.dy = neg(tmp);
        } else if (direction == DIRECTION180) {
            offset.dx = neg(offset.dx);
            offset.dy = neg(offset.dy);
        } else if (direction == DIRECTION270) {
            double tmp = offset.dx;
            offset.dx = neg(offset.dy);
            offset.dy = tmp;
        }
    }
#endif // OHOS_BUILD_EMULATOR
}

int32_t MouseTransformProcessor::HandleButtonInner(struct libinput_event_pointer* data, struct libinput_event* event)
{
    CALL_DEBUG_ENTER;
    CHKPR(data, ERROR_NULL_POINTER);
    CHKPR(event, ERROR_NULL_POINTER);
    CHKPR(pointerEvent_, ERROR_NULL_POINTER);
    if (env_ == nullptr) {
        MMI_HILOGE("Env is nullptr");
        return RET_ERR;
    }
#ifndef OHOS_BUILD_ENABLE_WATCH
    MMI_HILOGD("Current action:%{public}d", pointerEvent_->GetPointerAction());

    uint32_t button = libinput_event_pointer_get_button(data);
    uint32_t originButton = button;
    const int32_t type = libinput_event_get_type(event);
    bool tpTapSwitch = true;
    int32_t userId = WIN_MGR->FindDisplayUserId(pointerEvent_->GetTargetDisplayId());
    MousePreferenceAccessor::GetTouchpadTapSwitch(*env_, userId, tpTapSwitch);

#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
    if (isVirtualDeviceEvent_) {
        GetVirtualTouchpadTapSwitch(tpTapSwitch);
        unaccelerated_.dx = libinput_event_vtrackpad_get_dx_unaccelerated(data);
        unaccelerated_.dy = libinput_event_vtrackpad_get_dy_unaccelerated(data);
    }
#endif // OHOS_BUILD_ENABLE_VKEYBOARD

    // touch pad tap switch is disable
    if (type == LIBINPUT_EVENT_POINTER_TAP && !tpTapSwitch) {
        MMI_HILOGD("Touch pad is disable");
        return RET_ERR;
    }
    PointerEvent::PointerItem pointerItem;
    auto isItemExist = pointerEvent_->GetPointerItem(pointerEvent_->GetPointerId(), pointerItem);
    if (isItemExist) {
        pointerItem.SetCanceled(false);
        pointerEvent_->UpdatePointerItem(pointerEvent_->GetPointerId(), pointerItem);
    }
    auto state = libinput_event_pointer_get_button_state(data);
    HandleTouchPadButton(state, type);

    TransTouchpadRightButton(data, type, button);

    if (button == MouseDeviceState::LIBINPUT_BUTTON_CODE::LIBINPUT_MIDDLE_BUTTON_CODE &&
        type == LIBINPUT_EVENT_POINTER_BUTTON_TOUCHPAD) {
        button = MouseDeviceState::LIBINPUT_BUTTON_CODE::LIBINPUT_LEFT_BUTTON_CODE;
    }

    auto ret = HandleButtonValueInner(data, button, type);
    if (ret != RET_OK) {
        MMI_HILOGE("The button value does not exist");
        return RET_ERR;
    }

    if (state == LIBINPUT_BUTTON_STATE_RELEASED) {
        SetPointerEventRightButtonSource(type, button);
        MouseState->MouseBtnStateCounts(button, BUTTON_STATE_RELEASED);
        pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_UP);
        int32_t buttonId = MouseState->LibinputChangeToPointer(button);
        pointerEvent_->DeleteReleaseButton(buttonId);
        DeletePressedButton(originButton);
        isPressed_ = false;
        buttonId_ = PointerEvent::BUTTON_NONE;
    } else if (state == LIBINPUT_BUTTON_STATE_PRESSED) {
        SetPointerEventRightButtonSource(type, button);
        MouseState->MouseBtnStateCounts(button, BUTTON_STATE_PRESSED);
        pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_DOWN);
        int32_t buttonId = MouseState->LibinputChangeToPointer(button);
        pointerEvent_->SetButtonPressed(buttonId);
        buttonMapping_[originButton] = buttonId;
        isPressed_ = true;
        buttonId_ = pointerEvent_->GetButtonId();
        auto winMgr = GetInputWindowsManager();
        if (winMgr == nullptr) {
            MMI_HILOGE("winMgr is nullptr");
            return RET_ERR;
        }
        CursorPosition cursorPos = winMgr->GetCursorPos();
        if (cursorPos.displayId < 0) {
            MMI_HILOGE("No display");
            return RET_ERR;
        }
        auto displayInfo = winMgr->GetPhysicalDisplay(cursorPos.displayId);
        CHKPR(displayInfo, ERROR_NULL_POINTER);
        if (cursorPos.direction != displayInfo->direction) {
            winMgr->UpdateAndAdjustMouseLocation(cursorPos.displayId,
                cursorPos.cursorPos.x, cursorPos.cursorPos.y);
        }
    } else {
        MMI_HILOGE("Unknown state, state:%{public}u", state);
        return RET_ERR;
    }
#endif // OHOS_BUILD_ENABLE_WATCH
    return RET_OK;
}

void MouseTransformProcessor::SetPointerEventRightButtonSource(const int32_t eventType, uint32_t button)
{
    if (button != MouseDeviceState::LIBINPUT_BUTTON_CODE::LIBINPUT_RIGHT_BUTTON_CODE) {
        pointerEvent_->SetRightButtonSource(PointerEvent::RightButtonSource::INVALID);
        return;
    }
    if (eventType == LIBINPUT_EVENT_POINTER_TAP) {
        pointerEvent_->SetRightButtonSource(PointerEvent::RightButtonSource::TOUCHPAD_TWO_FINGER_TAP);
    } else if (eventType == LIBINPUT_EVENT_POINTER_BUTTON_TOUCHPAD) {
        pointerEvent_->SetRightButtonSource(PointerEvent::RightButtonSource::TOUCHPAD_RIGHT_BUTTONS);
    } else if (eventType == LIBINPUT_EVENT_POINTER_BUTTON) {
        pointerEvent_->SetRightButtonSource(PointerEvent::RightButtonSource::MOUSE_RIGHT);
    } else {
        MMI_HILOGD("Invalid type, eventType:%{public}d", eventType);
        pointerEvent_->SetRightButtonSource(PointerEvent::RightButtonSource::OTHERS);
    }
}

void MouseTransformProcessor::HandleTouchPadButton(enum libinput_button_state state, int32_t type)
{
    if (state != LIBINPUT_BUTTON_STATE_PRESSED) {
        return;
    }
    if (type != LIBINPUT_EVENT_POINTER_TAP && type != LIBINPUT_EVENT_POINTER_BUTTON_TOUCHPAD) {
        return;
    }
    CHKPV(pointerEvent_);
    auto pressedButtons = pointerEvent_->GetPressedButtons();
    if (pressedButtons.empty()) {
        return;
    }
    MMI_HILOGW("touchpad button residue size:%{public}zu", pressedButtons.size());
    for (auto it = pressedButtons.begin(); it != pressedButtons.end(); it++) {
        MMI_HILOGW("touchpad button residue id:%{public}d", *it);
    }
    std::shared_ptr<PointerEvent> cancelPointerEvent = std::make_shared<PointerEvent>(*pointerEvent_);
    pointerEvent_->ClearButtonPressed();
    CHKPV(cancelPointerEvent);
    cancelPointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
    if (env_ == nullptr) {
        MMI_HILOGE("Env is nullptr");
        return;
    }
    auto winMgr = GetInputWindowsManager();
    if (winMgr == nullptr) {
        MMI_HILOGE("winMgr is nullptr");
        return;
    }
    winMgr->UpdateTargetPointer(cancelPointerEvent);
    auto eventDispatchHandler = GetDispatchHandler();
    CHKPV(eventDispatchHandler);
    eventDispatchHandler->HandlePointerEvent(cancelPointerEvent);
}

void MouseTransformProcessor::DeletePressedButton(uint32_t originButton)
{
    auto iter = buttonMapping_.find(originButton);
    if (iter != buttonMapping_.end()) {
        pointerEvent_->DeleteReleaseButton(iter->second);
        buttonMapping_.erase(iter);
    }
}

int32_t MouseTransformProcessor::HandleButtonValueInner(struct libinput_event_pointer *data, uint32_t& button,
    int32_t type)
{
    CALL_DEBUG_ENTER;
    CHKPR(data, ERROR_NULL_POINTER);
    CHKPR(pointerEvent_, ERROR_NULL_POINTER);
    int32_t buttonId = MouseState->LibinputChangeToPointer(button);
    if (buttonId == PointerEvent::BUTTON_NONE) {
        MMI_HILOGE("Unknown btn, btn:%{public}u", button);
        return RET_ERR;
    }

    std::string name = "primaryButton";
    if (env_ == nullptr) {
        MMI_HILOGE("Env is nullptr");
        return RET_ERR;
    }
    int32_t primaryButton = 0;
    int32_t userId = WIN_MGR->FindDisplayUserId(pointerEvent_->GetTargetDisplayId());
    INPUT_SETTING_MANAGER->GetIntValue(userId, MOUSE_KEY_SETTING, FIELD_MOUSE_PRIMARY_BUTTON, primaryButton);
#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
    if (isVirtualDeviceEvent_) {
        primaryButton = GetVirtualTouchpadPrimaryButton();
    }
#endif // OHOS_BUILD_ENABLE_VKEYBOARD
    MMI_HILOGD("Set mouse primary button:%{public}d", primaryButton);
    if (type == LIBINPUT_EVENT_POINTER_BUTTON && primaryButton == RIGHT_BUTTON) {
        if (buttonId == PointerEvent::MOUSE_BUTTON_LEFT) {
            buttonId = PointerEvent::MOUSE_BUTTON_RIGHT;
            button = MouseDeviceState::LIBINPUT_BUTTON_CODE::LIBINPUT_RIGHT_BUTTON_CODE;
        } else if (buttonId == PointerEvent::MOUSE_BUTTON_RIGHT) {
            buttonId = PointerEvent::MOUSE_BUTTON_LEFT;
            button = MouseDeviceState::LIBINPUT_BUTTON_CODE::LIBINPUT_LEFT_BUTTON_CODE;
        } else {
            MMI_HILOGD("The buttonId does not switch");
        }
    }

    pointerEvent_->SetButtonId(buttonId);
    return RET_OK;
}

void MouseTransformProcessor::HandleTouchPadAxisState(libinput_pointer_axis_source source,
    int32_t& direction, bool& tpScrollSwitch)
{
    bool scrollDirectionState = true;
    if (env_ == nullptr) {
        MMI_HILOGD("Env is nullptr");
        return;
    }
    int32_t userId = WIN_MGR->FindDisplayUserId(pointerEvent_->GetTargetDisplayId());
    MousePreferenceAccessor::GetTouchpadScrollSwitch(*env_, userId, tpScrollSwitch);
    MousePreferenceAccessor::GetTouchpadScrollDirection(*env_, userId, scrollDirectionState);
    if (scrollDirectionState == true && source == LIBINPUT_POINTER_AXIS_SOURCE_FINGER) {
        direction = -1;
    }
}

int32_t MouseTransformProcessor::HandleAxisInner(struct libinput_event_pointer* data)
{
    CALL_DEBUG_ENTER;
    CHKPR(data, ERROR_NULL_POINTER);
    CHKPR(pointerEvent_, ERROR_NULL_POINTER);
    bool tpScrollSwitch = true;
    int32_t tpScrollDirection = 1;

    libinput_pointer_axis_source source = libinput_event_pointer_get_axis_source(data);
    HandleTouchPadAxisState(source, tpScrollDirection, tpScrollSwitch);
    if (!tpScrollSwitch && source == LIBINPUT_POINTER_AXIS_SOURCE_FINGER) {
        MMI_HILOGE("TouchPad axis event is disable,pid:%{public}d Set false", globalScrollSwitchPid_.load());
        return RET_ERR;
    }

    if (buttonId_ == PointerEvent::BUTTON_NONE && pointerEvent_->GetButtonId() != PointerEvent::BUTTON_NONE) {
        pointerEvent_->SetButtonId(PointerEvent::BUTTON_NONE);
    }
    if (libinput_event_pointer_get_axis_source(data) == LIBINPUT_POINTER_AXIS_SOURCE_FINGER) {
        MMI_HILOGD("Libinput event axis source type is finger");
        MMI_HILOGD("Axis event type is update");
        pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_UPDATE);
        pointerEvent_->SetAxisEventType(PointerEvent::AXIS_EVENT_TYPE_SCROLL);
    } else {
        auto timerMgr = GetTimerManager();
        if (timerMgr == nullptr) {
            MMI_HILOGD("timerMgr is nullptr");
            return RET_ERR;
        }
        if (timerMgr->IsExist(timerId_)) {
            pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_UPDATE);
            pointerEvent_->SetAxisEventType(PointerEvent::AXIS_EVENT_TYPE_SCROLL);
            timerMgr->ResetTimer(timerId_);
            MMI_HILOGD("Axis update");
        } else {
            static constexpr int32_t timeout = 100;
            std::weak_ptr<MouseTransformProcessor> weakPtr = shared_from_this();
            timerId_ = timerMgr->AddTimer(timeout, 1, [weakPtr]() {
                CALL_DEBUG_ENTER;
                auto sharedPtr = weakPtr.lock();
                CHKPV(sharedPtr);
                MMI_HILOGD("Timer:%{public}d", sharedPtr->timerId_);
                sharedPtr->timerId_ = -1;
                auto pointerEvent = sharedPtr->GetPointerEvent();
                CHKPV(pointerEvent);
                pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_END);
                pointerEvent->SetAxisEventType(PointerEvent::AXIS_EVENT_TYPE_SCROLL);
                pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL, 0);
                pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL, 0);
                pointerEvent->UpdateId();
                LogTracer lt(pointerEvent->GetId(), pointerEvent->GetEventType(), pointerEvent->GetPointerAction());
                auto inputEventNormalizeHandler = sharedPtr->GetEventNormalizeHandler();
                CHKPV(inputEventNormalizeHandler);
                inputEventNormalizeHandler->HandlePointerEvent(pointerEvent);
            }, "MouseTransformProcessor");

            pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_BEGIN);
            pointerEvent_->SetAxisEventType(PointerEvent::AXIS_EVENT_TYPE_SCROLL);
            MMI_HILOGD("Axis begin");
            auto winMgr = GetInputWindowsManager();
            if (winMgr == nullptr) {
                MMI_HILOGE("winMgr is nullptr");
                return RET_ERR;
            }
            CursorPosition cursorPos = winMgr->GetCursorPos();
            if (cursorPos.displayId < 0) {
                MMI_HILOGE("No display");
                return RET_ERR;
            }
            auto displayInfo = winMgr->GetPhysicalDisplay(cursorPos.displayId);
            CHKPR(displayInfo, ERROR_NULL_POINTER);
            if (cursorPos.direction != displayInfo->direction) {
                winMgr->UpdateAndAdjustMouseLocation(cursorPos.displayId,
                    cursorPos.cursorPos.x, cursorPos.cursorPos.y);
            }
        }
    }
    if (env_ == nullptr) {
        return ERROR_NULL_POINTER;
    }
    int32_t userId = WIN_MGR->FindDisplayUserId(pointerEvent_->GetTargetDisplayId());
#ifndef OHOS_BUILD_ENABLE_WATCH
    if (source == LIBINPUT_POINTER_AXIS_SOURCE_FINGER) {
#ifdef OHOS_BUILD_ENABLE_TOUCHPAD
        pointerEvent_->SetScrollRows(MousePreferenceAccessor::GetTouchpadScrollRows(*env_, userId));
#endif // OHOS_BUILD_ENABLE_TOUCHPAD
    } else {
        pointerEvent_->SetScrollRows(MousePreferenceAccessor::GetMouseScrollRows(*env_, userId));
    }
#else
    pointerEvent_->SetScrollRows(MousePreferenceAccessor::GetMouseScrollRows(*env_, userId));
#endif // OHOS_BUILD_ENABLE_WATCH
    const int32_t initRows = 3;
    if (libinput_event_pointer_has_axis(data, LIBINPUT_POINTER_AXIS_SCROLL_VERTICAL)) {
        double axisValue = libinput_event_pointer_get_axis_value(data, LIBINPUT_POINTER_AXIS_SCROLL_VERTICAL);
#ifndef OHOS_BUILD_ENABLE_WATCH
        if (source == LIBINPUT_POINTER_AXIS_SOURCE_FINGER) {
#ifdef OHOS_BUILD_ENABLE_TOUCHPAD
            axisValue = MousePreferenceAccessor::GetTouchpadScrollRows(*env_, userId) * (axisValue / initRows);
            axisValue = HandleAxisAccelateTouchPad(userId, axisValue) * tpScrollDirection;
#endif // OHOS_BUILD_ENABLE_TOUCHPAD
        } else {
            axisValue = MousePreferenceAccessor::GetMouseScrollRows(*env_, userId) * axisValue * tpScrollDirection;
        }
#else
        axisValue = MousePreferenceAccessor::GetMouseScrollRows(*env_, userId) * axisValue * tpScrollDirection;
#endif // OHOS_BUILD_ENABLE_WATCH
        pointerEvent_->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL, axisValue);
    }
    if (libinput_event_pointer_has_axis(data, LIBINPUT_POINTER_AXIS_SCROLL_HORIZONTAL)) {
        double axisValue = libinput_event_pointer_get_axis_value(data, LIBINPUT_POINTER_AXIS_SCROLL_HORIZONTAL);
#ifndef OHOS_BUILD_ENABLE_WATCH
        if (source == LIBINPUT_POINTER_AXIS_SOURCE_FINGER) {
#ifdef OHOS_BUILD_ENABLE_TOUCHPAD
            axisValue = MousePreferenceAccessor::GetTouchpadScrollRows(*env_, userId) * (axisValue / initRows);
            axisValue = HandleAxisAccelateTouchPad(userId, axisValue) * tpScrollDirection;
#endif // OHOS_BUILD_ENABLE_TOUCHPAD
        } else {
            axisValue = MousePreferenceAccessor::GetMouseScrollRows(*env_, userId) * axisValue * tpScrollDirection;
        }
#else
        axisValue = MousePreferenceAccessor::GetMouseScrollRows(*env_, userId) * axisValue * tpScrollDirection;
#endif // OHOS_BUILD_ENABLE_WATCH
        pointerEvent_->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL, axisValue);
    }
    return RET_OK;
}

#ifdef OHOS_BUILD_ENABLE_TOUCHPAD
double MouseTransformProcessor::HandleAxisAccelateTouchPad(int32_t userId, double axisValue)
{
    const int32_t initRows = 3;
    DeviceType deviceType = DeviceType::DEVICE_PC;
    std::string productType = SYS_PRODUCT_TYPE;
    if (PRODUCT_TYPE_PARSER.GetProductType(productType, deviceType) != RET_OK) {
        MMI_HILOGW("GetProductType failed, productType:%{public}s", productType.c_str());
    }
#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
    if (isVirtualDeviceEvent_) {
        deviceType = DeviceType::DEVICE_FOLD_PC_VIRT;
        double speedAdjustCoef = 1.0;
        axisValue = axisValue * speedAdjustCoef;
    }
#endif // OHOS_BUILD_ENABLE_VKEYBOARD
    auto winMgr = GetInputWindowsManager();
    if (winMgr == nullptr) {
        MMI_HILOGE("winMgr is nullptr");
        return RET_ERR;
    }
    if (HandleAxisAccelerateTouchpad(winMgr->GetMouseIsCaptureMode(),
        &axisValue, static_cast<int32_t>(deviceType))
        != RET_OK) {
        MMI_HILOGW("Fail accelerate axis");
        if (env_ == nullptr) {
            MMI_HILOGE("Env is nullptr");
            return axisValue;
        }
        axisValue = MousePreferenceAccessor::GetTouchpadScrollRows(*env_, userId) * (axisValue / initRows);
    }
    return axisValue;
}
#endif // OHOS_BUILD_ENABLE_TOUCHPAD

int32_t MouseTransformProcessor::HandleAxisBeginEndInner(struct libinput_event *event)
{
    CALL_DEBUG_ENTER;
    CHKPR(event, ERROR_NULL_POINTER);
    CHKPR(pointerEvent_, ERROR_NULL_POINTER);
    if (buttonId_ == PointerEvent::BUTTON_NONE && pointerEvent_->GetButtonId() != PointerEvent::BUTTON_NONE) {
        pointerEvent_->SetButtonId(PointerEvent::BUTTON_NONE);
    }
    if (!isAxisBegin_ && isPressed_) {
        MMI_HILOGE("Axis is invalid");
        return RET_ERR;
    }
    if (isAxisBegin_ && isPressed_) {
        pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_END);
        pointerEvent_->SetAxisEventType(PointerEvent::AXIS_EVENT_TYPE_SCROLL);
        isAxisBegin_ = false;
        MMI_HILOGD("Axis end due to a pressed event");
        return RET_OK;
    }
    if (libinput_event_get_type(event) == LIBINPUT_EVENT_TOUCHPAD_DOWN && !isPressed_) {
        pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_BEGIN);
        pointerEvent_->SetAxisEventType(PointerEvent::AXIS_EVENT_TYPE_SCROLL);
        isAxisBegin_ = true;
        MMI_HILOGD("Axis begin");
        return RET_OK;
    }
    if (libinput_event_get_type(event) == LIBINPUT_EVENT_TOUCHPAD_UP && !isPressed_) {
        pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_END);
        pointerEvent_->SetAxisEventType(PointerEvent::AXIS_EVENT_TYPE_SCROLL);
        isAxisBegin_ = false;
        MMI_HILOGD("Axis end");
        return RET_OK;
    }
    MMI_HILOGE("Axis is invalid");
    return RET_ERR;
}

int32_t MouseTransformProcessor::HandleScrollFingerInner(struct libinput_event *event)
{
    CALL_DEBUG_ENTER;
    CHKPR(event, ERROR_NULL_POINTER);
    CHKPR(pointerEvent_, ERROR_NULL_POINTER);
    if (buttonId_ == PointerEvent::BUTTON_NONE && pointerEvent_->GetButtonId() != PointerEvent::BUTTON_NONE) {
        pointerEvent_->SetButtonId(PointerEvent::BUTTON_NONE);
    }
    if (libinput_event_get_type(event) == LIBINPUT_EVENT_POINTER_SCROLL_FINGER_BEGIN) {
        pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_BEGIN);
        pointerEvent_->SetAxisEventType(PointerEvent::AXIS_EVENT_TYPE_SCROLL);
        MMI_HILOGD("Axis begin");
    } else if (libinput_event_get_type(event) == LIBINPUT_EVENT_POINTER_SCROLL_FINGER_END) {
        pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_END);
        pointerEvent_->SetAxisEventType(PointerEvent::AXIS_EVENT_TYPE_SCROLL);
        MMI_HILOGD("Axis end");
    } else {
        MMI_HILOGE("Axis is invalid");
        return RET_ERR;
    }
    return RET_OK;
}

void MouseTransformProcessor::HandleAxisPostInner(PointerEvent::PointerItem &pointerItem)
{
    CALL_DEBUG_ENTER;
    CHKPV(pointerEvent_);
    auto winMgr = GetInputWindowsManager();
    if (winMgr == nullptr) {
        MMI_HILOGE("winMgr is nullptr");
        return;
    }
    auto mouseInfo = winMgr->GetMouseInfo();
    MouseState->SetMouseCoords(mouseInfo.physicalX, mouseInfo.physicalY);
    pointerItem.SetDisplayX(mouseInfo.physicalX);
    pointerItem.SetDisplayY(mouseInfo.physicalY);
    pointerItem.SetDisplayXPos(mouseInfo.physicalX);
    pointerItem.SetDisplayYPos(mouseInfo.physicalY);
    pointerItem.SetWindowX(0);
    pointerItem.SetWindowY(0);
    pointerItem.SetWindowXPos(0.0);
    pointerItem.SetWindowYPos(0.0);
    pointerItem.SetPointerId(0);
    pointerItem.SetPressed(isPressed_);
    int64_t time = GetSysClockTime();
    pointerItem.SetDownTime(time);
    pointerItem.SetWidth(0);
    pointerItem.SetHeight(0);
    pointerItem.SetPressure(0);
    pointerItem.SetToolType(PointerEvent::TOOL_TYPE_TOUCHPAD);
    pointerItem.SetDeviceId(deviceId_);
    pointerItem.SetRawDx(0);
    pointerItem.SetRawDy(0);
    pointerEvent_->UpdateId();
    StartLogTraceId(pointerEvent_->GetId(), pointerEvent_->GetEventType(), pointerEvent_->GetPointerAction());
    pointerEvent_->UpdatePointerItem(pointerEvent_->GetPointerId(), pointerItem);
    pointerEvent_->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent_->SetActionTime(time);
    pointerEvent_->SetActionStartTime(time);
    pointerEvent_->SetPointerId(0);
    pointerEvent_->SetDeviceId(deviceId_);
    pointerEvent_->SetTargetDisplayId(mouseInfo.displayId);
    pointerEvent_->SetTargetWindowId(-1);
    pointerEvent_->SetAgentWindowId(-1);
}

bool MouseTransformProcessor::HandlePostInner(struct libinput_event_pointer* data,
    PointerEvent::PointerItem &pointerItem)
{
    CALL_DEBUG_ENTER;
    CHKPF(pointerEvent_);
    auto winMgr = GetInputWindowsManager();
    if (winMgr == nullptr) {
        MMI_HILOGE("winMgr is nullptr");
        return false;
    }
    auto mouseInfo = winMgr->GetMouseInfo();
    MouseState->SetMouseCoords(mouseInfo.physicalX, mouseInfo.physicalY);
    pointerItem.SetDisplayX(mouseInfo.physicalX);
    pointerItem.SetDisplayY(mouseInfo.physicalY);
    pointerItem.SetDisplayXPos(mouseInfo.physicalX);
    pointerItem.SetDisplayYPos(mouseInfo.physicalY);
    pointerItem.SetWindowX(0);
    pointerItem.SetWindowY(0);
    pointerItem.SetWindowXPos(0.0);
    pointerItem.SetWindowYPos(0.0);
    pointerItem.SetPointerId(0);
    pointerItem.SetPressed(isPressed_);

    int64_t time = GetSysClockTime();
    pointerItem.SetDownTime(time);
    pointerItem.SetWidth(0);
    pointerItem.SetHeight(0);
    pointerItem.SetPressure(0);
    pointerItem.SetDeviceId(deviceId_);
    if (pointerEvent_->GetPointerAction() == PointerEvent::POINTER_ACTION_BUTTON_UP) {
        pointerItem.SetRawDx(0);
        pointerItem.SetRawDy(0);
    } else {
        pointerItem.SetRawDx(static_cast<int32_t>(unaccelerated_.dx));
        pointerItem.SetRawDy(static_cast<int32_t>(unaccelerated_.dy));
    }

    pointerEvent_->UpdateId();
    StartLogTraceId(pointerEvent_->GetId(), pointerEvent_->GetEventType(), pointerEvent_->GetPointerAction());
    pointerEvent_->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent_->SetActionTime(time);
    pointerEvent_->SetActionStartTime(time);
    pointerEvent_->SetDeviceId(deviceId_);
    pointerEvent_->SetPointerId(0);
    pointerEvent_->SetTargetDisplayId(mouseInfo.displayId);
    pointerEvent_->SetTargetWindowId(-1);
    pointerEvent_->SetAgentWindowId(-1);
    if (data == nullptr) {
        pointerEvent_->UpdatePointerItem(pointerEvent_->GetPointerId(), pointerItem);
        return false;
    }
    if (libinput_event_pointer_get_axis_source(data) == LIBINPUT_POINTER_AXIS_SOURCE_FINGER) {
        pointerItem.SetToolType(PointerEvent::TOOL_TYPE_TOUCHPAD);
        MMI_HILOGD("ToolType is touchpad");
    } else {
        pointerItem.SetToolType(PointerEvent::TOOL_TYPE_MOUSE);
    }
    pointerEvent_->UpdatePointerItem(pointerEvent_->GetPointerId(), pointerItem);
    return true;
}

bool MouseTransformProcessor::CheckAndPackageAxisEvent()
{
    CALL_INFO_TRACE;
    if (!isAxisBegin_) {
        return false;
    }
    pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_END);
    isAxisBegin_ = false;
    PointerEvent::PointerItem item;
    HandleAxisPostInner(item);
    auto winMgr = GetInputWindowsManager();
    if (winMgr == nullptr) {
        MMI_HILOGE("winMgr is nullptr");
        return false;
    }
    winMgr->UpdateTargetPointer(pointerEvent_);
    return true;
}

int32_t MouseTransformProcessor::Normalize(struct libinput_event *event)
{
    CALL_DEBUG_ENTER;
    CHKPR(event, ERROR_NULL_POINTER);
    CHKPR(pointerEvent_, ERROR_NULL_POINTER);
    const int32_t type = libinput_event_get_type(event);
    auto data = libinput_event_get_pointer_event(event);
    if (type != LIBINPUT_EVENT_TOUCHPAD_DOWN && type != LIBINPUT_EVENT_TOUCHPAD_UP) {
        CHKPR(data, ERROR_NULL_POINTER);
    }
    if (pointerEvent_->HasFlag(InputEvent::EVENT_FLAG_ACCESSIBILITY)) {
        pointerEvent_->ClearFlag(InputEvent::EVENT_FLAG_ACCESSIBILITY);
    }
    pointerEvent_->ClearAxisValue();
#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
    isVirtualDeviceEvent_ = IsEventFromVirtualSource(event);
#endif // OHOS_BUILD_ENABLE_VKEYBOARD
    int32_t result;
    switch (type) {
        case LIBINPUT_EVENT_POINTER_MOTION:
        case LIBINPUT_EVENT_POINTER_MOTION_ABSOLUTE:
        case LIBINPUT_EVENT_POINTER_MOTION_TOUCHPAD:
            result = HandleMotionInner(data, event);
            break;
        case LIBINPUT_EVENT_POINTER_TAP:
        case LIBINPUT_EVENT_POINTER_BUTTON:
        case LIBINPUT_EVENT_POINTER_BUTTON_TOUCHPAD:
            result = HandleButtonInner(data, event);
            break;
        case LIBINPUT_EVENT_POINTER_AXIS:
            result = HandleAxisInner(data);
            break;
        case LIBINPUT_EVENT_POINTER_SCROLL_FINGER_BEGIN:
        case LIBINPUT_EVENT_POINTER_SCROLL_FINGER_END:
            result = HandleScrollFingerInner(event);
            break;
        default:
            MMI_HILOGE("Unknown type:%{public}d", type);
            return RET_ERR;
    }
    if (result == RET_ERR) {
        MMI_HILOGE("Handle LIBINPUT_MOUSE_EVENT failed, type:%{public}d", type);
        return result;
    }
    PointerEvent::PointerItem pointerItem;
    pointerEvent_->GetPointerItem(pointerEvent_->GetPointerId(), pointerItem);
    if (type == LIBINPUT_EVENT_POINTER_SCROLL_FINGER_BEGIN || type == LIBINPUT_EVENT_POINTER_SCROLL_FINGER_END) {
        HandleAxisPostInner(pointerItem);
    } else if (!HandlePostInner(data, pointerItem)) {
        CHKPL(pointerEvent_);
        return RET_ERR;
    }
    auto winMgr = GetInputWindowsManager();
    if (winMgr == nullptr) {
        MMI_HILOGE("winMgr is nullptr");
        return RET_ERR;
    }
    winMgr->UpdateTargetPointer(pointerEvent_);
    DumpInner();
    return result;
}

int32_t MouseTransformProcessor::NormalizeRotateEvent(struct libinput_event *event, int32_t type, double angle)
{
    CALL_DEBUG_ENTER;
    CHKPR(event, ERROR_NULL_POINTER);
    CHKPR(pointerEvent_, ERROR_NULL_POINTER);
    auto data = libinput_event_get_pointer_event(event);
    pointerEvent_->SetPointerAction(type);
    pointerEvent_->ClearAxisValue();
    pointerEvent_->SetAxisValue(PointerEvent::AXIS_TYPE_ROTATE, angle);
    PointerEvent::PointerItem pointerItem;
    pointerItem.SetToolType(PointerEvent::TOOL_TYPE_TOUCHPAD);
    auto winMgr = GetInputWindowsManager();
    if (winMgr == nullptr) {
        MMI_HILOGE("winMgr is nullptr");
        return RET_ERR;
    }
    if (!HandlePostInner(data, pointerItem)) {
        winMgr->UpdateTargetPointer(pointerEvent_);
        DumpInner();
        return ERROR_NULL_POINTER;
    }
    winMgr->UpdateTargetPointer(pointerEvent_);
    DumpInner();
    return RET_OK;
}

#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
void MouseTransformProcessor::HandleMotionMoveMouse(int32_t offsetX, int32_t offsetY)
{
    CALL_DEBUG_ENTER;
    CHKPV(pointerEvent_);
    auto winMgr = GetInputWindowsManager();
    if (winMgr == nullptr) {
        MMI_HILOGE("winMgr is nullptr");
        return;
    }
    pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    CursorPosition cursorPos = winMgr->GetCursorPos();
    cursorPos.cursorPos.x += offsetX;
    cursorPos.cursorPos.y += offsetY;
    winMgr->UpdateAndAdjustMouseLocation(cursorPos.displayId, cursorPos.cursorPos.x,
        cursorPos.cursorPos.y);
}

void MouseTransformProcessor::OnDisplayLost(IInputServiceContext &env, int32_t displayId)
{
    CursorPosition cursorPos = env.GetInputWindowsManager()->GetCursorPos();
    if (cursorPos.displayId != displayId) {
        cursorPos = env.GetInputWindowsManager()->ResetCursorPos();
        env.GetInputWindowsManager()->UpdateAndAdjustMouseLocation(cursorPos.displayId, cursorPos.cursorPos.x,
            cursorPos.cursorPos.y);
    }
}

int32_t MouseTransformProcessor::GetDisplayId(IInputServiceContext &env)
{
    return env.GetInputWindowsManager()->GetCursorPos().displayId;
}

void MouseTransformProcessor::HandlePostMoveMouse(PointerEvent::PointerItem& pointerItem)
{
    CALL_DEBUG_ENTER;
    auto winMgr = GetInputWindowsManager();
    if (winMgr == nullptr) {
        MMI_HILOGE("winMgr is nullptr");
        return;
    }
    auto mouseInfo = winMgr->GetMouseInfo();
    CHKPV(pointerEvent_);
    MouseState->SetMouseCoords(mouseInfo.physicalX, mouseInfo.physicalY);
    pointerItem.SetDisplayX(mouseInfo.physicalX);
    pointerItem.SetDisplayY(mouseInfo.physicalY);
    pointerItem.SetDisplayXPos(mouseInfo.physicalX);
    pointerItem.SetDisplayYPos(mouseInfo.physicalY);
    pointerItem.SetWindowX(0);
    pointerItem.SetWindowY(0);
    pointerItem.SetWindowXPos(0.0);
    pointerItem.SetWindowYPos(0.0);
    pointerItem.SetPointerId(0);
    pointerItem.SetPressed(isPressed_);

    int64_t time = GetSysClockTime();
    pointerItem.SetDownTime(time);
    pointerItem.SetWidth(0);
    pointerItem.SetHeight(0);
    pointerItem.SetPressure(0);

    pointerEvent_->UpdateId();
    StartLogTraceId(pointerEvent_->GetId(), pointerEvent_->GetEventType(), pointerEvent_->GetPointerAction());
    pointerEvent_->UpdatePointerItem(pointerEvent_->GetPointerId(), pointerItem);
    pointerEvent_->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent_->SetActionTime(time);
    pointerEvent_->SetActionStartTime(time);

    pointerEvent_->SetPointerId(0);
    pointerEvent_->SetTargetDisplayId(-1);
    pointerEvent_->SetTargetWindowId(-1);
    pointerEvent_->SetAgentWindowId(-1);
}

bool MouseTransformProcessor::NormalizeMoveMouse(int32_t offsetX, int32_t offsetY)
{
    CALL_DEBUG_ENTER;
    CHKPF(pointerEvent_);
    auto devMgr = GetDeviceManager();
    if (devMgr == nullptr) {
        MMI_HILOGE("devMgr is nullptr");
        return RET_ERR;
    }
    bool bHasPointerDevice = devMgr->HasPointerDevice();
    if (!bHasPointerDevice) {
        MMI_HILOGE("There hasn't any pointer device");
        return false;
    }

    PointerEvent::PointerItem pointerItem;
    HandleMotionMoveMouse(offsetX, offsetY);
    HandlePostMoveMouse(pointerItem);
    DumpInner();
    return bHasPointerDevice;
}
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING

void MouseTransformProcessor::DumpInner()
{
    static int32_t lastDeviceId = -1;
    static std::string lastDeviceName("default");
    auto nowId = pointerEvent_->GetDeviceId();
    if (lastDeviceId != nowId) {
        auto devMgr = GetDeviceManager();
        if (devMgr == nullptr) {
            MMI_HILOGE("devMgr is nullptr");
            return;
        }
        auto device = devMgr->GetInputDevice(nowId);
        CHKPV(device);
        lastDeviceId = nowId;
        lastDeviceName = device->GetName();
    }
    EventLogHelper::PrintEventData(pointerEvent_, MMI_LOG_FREEZE);
    aggregator_.Record(MMI_LOG_FREEZE, lastDeviceName + ", TW: " +
        std::to_string(pointerEvent_->GetTargetWindowId()), std::to_string(pointerEvent_->GetId()));
}

DeviceType MouseTransformProcessor::CheckDeviceType(int32_t width, int32_t height)
{
    CALL_DEBUG_ENTER;
    DeviceType ret = DeviceType::DEVICE_PC;
    if (SYS_PRODUCT_TYPE == DEVICE_TYPE_PC_PRO) {
        if (width == HARD_PC_PRO_DEVICE_WIDTH && height == HARD_PC_PRO_DEVICE_HEIGHT) {
            ret = DeviceType::DEVICE_HARD_PC_PRO;
        } else if (width == SOFT_PC_PRO_DEVICE_WIDTH && height == SOFT_PC_PRO_DEVICE_HEIGHT) {
            ret = DeviceType::DEVICE_SOFT_PC_PRO;
        } else if (EventLogHelper::IsBetaVersion()) {
            MMI_HILOGD("Undefined width:%{private}d, height:%{private}d", width, height);
        }
        MMI_HILOGD("Device width:%{private}d, height:%{private}d", width, height);
    }
    if (SYS_PRODUCT_TYPE == DEVICE_TYPE_TABLET || SYS_PRODUCT_TYPE == DEVICE_TYPE_TABLET_P) {
        if (width == TABLET_DEVICE_WIDTH && height == TABLET_DEVICE_HEIGHT) {
            ret = DeviceType::DEVICE_TABLET;
        }
    }
    if (SYS_PRODUCT_TYPE == DEVICE_TYPE_FOLD_PC) {
        ret = DeviceType::DEVICE_FOLD_PC;
    }
    return ret;
}

void MouseTransformProcessor::Dump(int32_t fd, const std::vector<std::string> &args)
{
    CALL_DEBUG_ENTER;
    PointerEvent::PointerItem item;
    CHKPV(pointerEvent_);
    pointerEvent_->GetPointerItem(pointerEvent_->GetPointerId(), item);
    mprintf(fd, "Mouse device state information:\t");
    mprintf(fd,
            "PointerId:%d | SourceType:%s | PointerAction:%s | WindowX:%d | WindowY:%d | ButtonId:%d "
            "| AgentWindowId:%d | TargetWindowId:%d | DownTime:%" PRId64 " | IsPressed:%s \t",
            pointerEvent_->GetPointerId(), pointerEvent_->DumpSourceType(), pointerEvent_->DumpPointerAction(),
            item.GetWindowX(), item.GetWindowY(), pointerEvent_->GetButtonId(), pointerEvent_->GetAgentWindowId(),
            pointerEvent_->GetTargetWindowId(), item.GetDownTime(), item.IsPressed() ? "true" : "false");
    PointerMotionAcceleration::Dump(fd, args);
}

int32_t MouseTransformProcessor::SetPointerLocation(IInputServiceContext &env, int32_t x, int32_t y, int32_t displayId)
{
    MMI_HILOGI("SetPointerLocation x:%d, y:%d, displayId:%d", x, y, displayId);
    CursorPosition cursorPos = env.GetInputWindowsManager()->GetCursorPos();
    if (cursorPos.displayId < 0) {
        MMI_HILOGE("No display");
        return RET_ERR;
    }
    cursorPos.cursorPos.x = x;
    cursorPos.cursorPos.y = y;
    if (displayId >= 0) {
        cursorPos.displayId = displayId;
    }
    env.GetInputWindowsManager()->UpdateAndAdjustMouseLocation(cursorPos.displayId, cursorPos.cursorPos.x,
        cursorPos.cursorPos.y, false);
    cursorPos = env.GetInputWindowsManager()->GetCursorPos();
    env.GetCursorDrawingComponent().SetPointerLocation(cursorPos.cursorPos.x, cursorPos.cursorPos.y,
        cursorPos.displayId);

    MMI_HILOGI("CursorPosX:%f, cursorPosY:%f", cursorPos.cursorPos.x, cursorPos.cursorPos.y);
    return RET_OK;
}

int32_t MouseTransformProcessor::GetPointerLocation(IInputServiceContext &env, int32_t &displayId,
    double &displayX, double &displayY)
{
    auto mouseInfo = env.GetInputWindowsManager()->GetMouseInfo();
    displayId = mouseInfo.displayId;
    displayX = mouseInfo.physicalX;
    displayY = mouseInfo.physicalY;
    MMI_HILOGD("Cursor {%{public}d,%{private}f,%{private}f}", displayId, displayX, displayY);
    return RET_OK;
}

void MouseTransformProcessor::SetScrollSwitchSetterPid(int32_t pid)
{
    globalScrollSwitchPid_.store(pid);
}

std::shared_ptr<IInputEventHandler> MouseTransformProcessor::GetEventNormalizeHandler() const
{
    if (env_ == nullptr) {
        MMI_HILOGE("Env is nullptr");
        return nullptr;
    }
    return env_->GetEventNormalizeHandler();
}

std::shared_ptr<IInputEventHandler> MouseTransformProcessor::GetDispatchHandler() const
{
    if (env_ == nullptr) {
        MMI_HILOGE("Env is nullptr");
        return nullptr;
    }
    return env_->GetDispatchHandler();
}

std::shared_ptr<ITimerManager> MouseTransformProcessor::GetTimerManager() const
{
    if (env_ == nullptr) {
        MMI_HILOGE("Env is nullptr");
        return nullptr;
    }
    return env_->GetTimerManager();
}

std::shared_ptr<IInputWindowsManager> MouseTransformProcessor::GetInputWindowsManager() const
{
    if (env_ == nullptr) {
        MMI_HILOGE("Env is nullptr");
        return nullptr;
    }
    return env_->GetInputWindowsManager();
}

std::shared_ptr<IInputDeviceManager> MouseTransformProcessor::GetDeviceManager() const
{
    if (env_ == nullptr) {
        MMI_HILOGE("Env is nullptr");
        return nullptr;
    }
    return env_->GetDeviceManager();
}

std::shared_ptr<IPreferenceManager> MouseTransformProcessor::GetPreferenceManager() const
{
    if (env_ == nullptr) {
        MMI_HILOGE("Env is nullptr");
        return nullptr;
    }
    return env_->GetPreferenceManager();
}

std::shared_ptr<ISettingManager> MouseTransformProcessor::GetSettingManager() const
{
    if (env_ == nullptr) {
        MMI_HILOGE("Env is nullptr");
        return nullptr;
    }
    return env_->GetSettingManager();
}

#ifndef OHOS_BUILD_ENABLE_WATCH
void MouseTransformProcessor::HandleTouchpadRightButton(struct libinput_event_pointer *data, const int32_t eventType,
    uint32_t &button)
{
    // touchpad left click 280 -> 272
    if (button == BTN_RIGHT_MENUE_CODE) {
        button = MouseDeviceState::LIBINPUT_BUTTON_CODE::LIBINPUT_LEFT_BUTTON_CODE;
        return;
    }

    // touchpad two finger tap 273 -> 0
    if (button == MouseDeviceState::LIBINPUT_BUTTON_CODE::LIBINPUT_RIGHT_BUTTON_CODE &&
        eventType == LIBINPUT_EVENT_POINTER_TAP) {
        button = 0;
        return;
    }

    // touchpad two finger button 272 -> 0
    uint32_t buttonArea = libinput_event_pointer_get_button_area(data);
    if (buttonArea == BTN_RIGHT) {
        button = MouseDeviceState::LIBINPUT_BUTTON_CODE::LIBINPUT_RIGHT_BUTTON_CODE;
    } else {
        button = MouseDeviceState::LIBINPUT_BUTTON_CODE::LIBINPUT_LEFT_BUTTON_CODE;
    }
}

void MouseTransformProcessor::HandleTouchpadLeftButton(struct libinput_event_pointer *data, const int32_t eventType,
    uint32_t &button)
{
    // touchpad left click 280 -> 273
    if (button == BTN_RIGHT_MENUE_CODE) {
        button = MouseDeviceState::LIBINPUT_BUTTON_CODE::LIBINPUT_RIGHT_BUTTON_CODE;
        return;
    }

    // touchpad right click 273 -> 272
    uint32_t fingerCount = libinput_event_pointer_get_finger_count(data);
    if (button == MouseDeviceState::LIBINPUT_BUTTON_CODE::LIBINPUT_RIGHT_BUTTON_CODE &&
        eventType != LIBINPUT_EVENT_POINTER_TAP && fingerCount != TP_RIGHT_CLICK_FINGER_CNT) {
        button = MouseDeviceState::LIBINPUT_BUTTON_CODE::LIBINPUT_LEFT_BUTTON_CODE;
        return;
    }

    // touchpad two finger tap 273 -> 0
    if (button == MouseDeviceState::LIBINPUT_BUTTON_CODE::LIBINPUT_RIGHT_BUTTON_CODE &&
        eventType == LIBINPUT_EVENT_POINTER_TAP) {
        button = 0;
        return;
    }

    uint32_t buttonArea = libinput_event_pointer_get_button_area(data);
    if (buttonArea == BTN_RIGHT_MENUE_CODE) {
        button = MouseDeviceState::LIBINPUT_BUTTON_CODE::LIBINPUT_RIGHT_BUTTON_CODE;
    } else {
        button = MouseDeviceState::LIBINPUT_BUTTON_CODE::LIBINPUT_LEFT_BUTTON_CODE;
    }
}

void MouseTransformProcessor::HandleTouchpadTwoFingerButton(struct libinput_event_pointer *data,
    const int32_t eventType, uint32_t &button)
{
#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
    // skip button remapping for virtual trackpad
    if (isVirtualDeviceEvent_) {
        return;
    }
#endif // OHOS_BUILD_ENABLE_VKEYBOARD

    // touchpad two finger button -> 273
    uint32_t fingerCount = libinput_event_pointer_get_finger_count(data);
    if (fingerCount == TP_RIGHT_CLICK_FINGER_CNT) {
        if (button == BTN_RIGHT_MENUE_CODE) {
            button = MouseDeviceState::LIBINPUT_BUTTON_CODE::LIBINPUT_LEFT_BUTTON_CODE;
        }
        return;
    }

    // touchpad right click 273 -> 272
    if (button == MouseDeviceState::LIBINPUT_BUTTON_CODE::LIBINPUT_RIGHT_BUTTON_CODE &&
        eventType == LIBINPUT_EVENT_POINTER_BUTTON_TOUCHPAD) {
        button = MouseDeviceState::LIBINPUT_BUTTON_CODE::LIBINPUT_LEFT_BUTTON_CODE;
        return;
    }

    // touchpad left click 280 -> 272
    if (button == BTN_RIGHT_MENUE_CODE) {
        button = MouseDeviceState::LIBINPUT_BUTTON_CODE::LIBINPUT_LEFT_BUTTON_CODE;
        return;
    }
}

void MouseTransformProcessor::HandleTouchpadTwoFingerButtonOrRightButton(struct libinput_event_pointer *data,
    const int32_t eventType, uint32_t &button)
{
    uint32_t buttonTemp = button;
    HandleTouchpadTwoFingerButton(data, eventType, buttonTemp);
    if (buttonTemp == MouseDeviceState::LIBINPUT_BUTTON_CODE::LIBINPUT_RIGHT_BUTTON_CODE) {
        button = buttonTemp;
        return;
    }
    HandleTouchpadRightButton(data, eventType, button);
}

void MouseTransformProcessor::HandleTouchpadTwoFingerButtonOrLeftButton(struct libinput_event_pointer *data,
    const int32_t eventType, uint32_t &button)
{
    uint32_t buttonTemp = button;
    HandleTouchpadTwoFingerButton(data, eventType, buttonTemp);
    if (buttonTemp == MouseDeviceState::LIBINPUT_BUTTON_CODE::LIBINPUT_RIGHT_BUTTON_CODE) {
        button = buttonTemp;
        return;
    }
    HandleTouchpadLeftButton(data, eventType, button);
}

void MouseTransformProcessor::TransTouchpadRightButton(struct libinput_event_pointer *data, const int32_t evenType,
    uint32_t &button)
{
    CHKPV(pointerEvent_);
    int32_t userId = WIN_MGR->FindDisplayUserId(pointerEvent_->GetTargetDisplayId());
    int32_t switchTypeData = RIGHT_CLICK_TYPE_MIN;
    if (env_ == nullptr) {
        MMI_HILOGE("Env is nullptr");
        return;
    }
    MousePreferenceAccessor::GetTouchpadRightClickType(*env_, userId, switchTypeData);
#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
    if (isVirtualDeviceEvent_) {
        GetVirtualTouchpadRightClickType(switchTypeData);
    }
#endif // OHOS_BUILD_ENABLE_VKEYBOARD

    RightClickType switchType = RightClickType(switchTypeData);
    if (evenType != LIBINPUT_EVENT_POINTER_TAP && evenType != LIBINPUT_EVENT_POINTER_BUTTON_TOUCHPAD) {
        MMI_HILOGD("Event not from touchpad");
        return;
    }
    MMI_HILOGD("Transform right button event, evenType:%d, switchType:%d, button:%d", evenType, switchType, button);
    uint32_t btn = button;
    auto state = libinput_event_pointer_get_button_state(data);
    if (state == LIBINPUT_BUTTON_STATE_RELEASED) {
        button = pressedButton_;
        if (button < MouseDeviceState::LIBINPUT_BUTTON_CODE::LIBINPUT_LEFT_BUTTON_CODE) {
            MMI_HILOGE("button release from:%{public}d to :%{public}d, evenType:%{public}d, switchType:%{public}d",
                button, btn, evenType, switchType);
        }
        return;
    }
    switch (switchType) {
        case RightClickType::TP_RIGHT_BUTTON:
            HandleTouchpadRightButton(data, evenType, button);
            break;
        case RightClickType::TP_LEFT_BUTTON:
            HandleTouchpadLeftButton(data, evenType, button);
            break;
        case RightClickType::TP_TWO_FINGER_TAP:
            HandleTouchpadTwoFingerButton(data, evenType, button);
            break;
        case RightClickType::TP_TWO_FINGER_TAP_OR_RIGHT_BUTTON:
            HandleTouchpadTwoFingerButtonOrRightButton(data, evenType, button);
            break;
        case RightClickType::TP_TWO_FINGER_TAP_OR_LEFT_BUTTON:
            HandleTouchpadTwoFingerButtonOrLeftButton(data, evenType, button);
            break;
        default:
            MMI_HILOGD("Invalid type, switchType:%{public}d", switchType);
            break;
    }
    if (state == LIBINPUT_BUTTON_STATE_PRESSED) {
        pressedButton_ = button;
        if (button < MouseDeviceState::LIBINPUT_BUTTON_CODE::LIBINPUT_LEFT_BUTTON_CODE) {
            MMI_HILOGE("button press from:%{public}d to :%{public}d, evenType:%{public}d, switchType:%{public}d",
                button, btn, evenType, switchType);
        }
    }
}
#endif // OHOS_BUILD_ENABLE_WATCH

int32_t MouseTransformProcessor::SetMouseAccelerateMotionSwitch(bool enable)
{
    enableMouseAleaccelerateBool_ = enable;
    MMI_HILOGI("Set accelerate motion switch is %{public}d", enableMouseAleaccelerateBool_);
    return RET_OK;
}

void MouseTransformProcessor::OnDeviceRemoved()
{}

#ifdef OHOS_BUILD_MOUSE_REPORTING_RATE
void MouseTransformProcessor::HandleFilterMouseEvent(Offset* offset)
{
    if (filterInsertionPoint_.filterFlag) {
        offset->dx = filterInsertionPoint_.filterX;
        offset->dy = filterInsertionPoint_.filterY;
        filterInsertionPoint_.filterDeltaTime = 0;
        filterInsertionPoint_.filterX = 0.0;
        filterInsertionPoint_.filterY = 0.0;
        filterInsertionPoint_.filterFlag = false;
        MMI_HILOGD("x:%.2f, y:%.2f", offset->dx, offset->dy);
    }
}

bool MouseTransformProcessor::CheckFilterMouseEvent(struct libinput_event *event)
{
    CHKPF(event);

    if (libinput_event_get_type(event) != LIBINPUT_EVENT_POINTER_MOTION) {
        return false;
    }

    auto data = libinput_event_get_pointer_event(event);
    CHKPF(data);
    uint64_t currentTime = libinput_event_pointer_get_time_usec(data);
    if ((!filterInsertionPoint_.filterPrePointTime) ||
        (currentTime < filterInsertionPoint_.filterPrePointTime)) {
        filterInsertionPoint_.filterPrePointTime = currentTime;
    }

    double dx = libinput_event_pointer_get_dx_unaccelerated(data);
    double dy = libinput_event_pointer_get_dy_unaccelerated(data);

    filterInsertionPoint_.filterDeltaTime += currentTime - filterInsertionPoint_.filterPrePointTime;
    filterInsertionPoint_.filterX += dx;
    filterInsertionPoint_.filterY += dy;

    filterInsertionPoint_.filterPrePointTime = currentTime;
    struct libinput_device *device = libinput_event_get_device(event);
    CHKPF(device);
    if (filterInsertionPoint_.filterDeltaTime < FilterInsertionPoint::FILTER_THRESHOLD_US &&
        libinput_device_get_id_bustype(device) == BUS_USB) {
        MMI_HILOGD("Mouse motion event delta time is too short");
        return true;
    }

    filterInsertionPoint_.filterFlag = true;
    return false;
}
#endif // OHOS_BUILD_MOUSE_REPORTING_RATE

#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
bool MouseTransformProcessor::IsEventFromVirtualSource(struct libinput_event* event)
{
    CHKPF(event);
    struct libinput_device *device = libinput_event_get_device(event);
    CHKPF(device);
    const std::string devName = libinput_device_get_name(device);
    // virtual touchpad's event is generated from the touchscreen on a foldable PC.
    return (SYS_PRODUCT_TYPE == DEVICE_TYPE_FOLD_PC && devName == "input_mt_wrapper");
}

void MouseTransformProcessor::GetVirtualTouchpadTapSwitch(bool &switchFlag)
{
    // always allow touchpad tap for virtual trackpad regardless of the settings.
    MMI_HILOGI("VTrackpad always allows touchpad tap.");
    switchFlag = true;
}

void MouseTransformProcessor::GetVirtualTouchpadRightClickType(int32_t &type)
{
    const int32_t twoFingerSwitchType = static_cast<int32_t>(RightClickType::TP_TWO_FINGER_TAP);
    // always allow two finger tap to open menu for virtual trackpad regardless of the settings.
    MMI_HILOGI("VTrackpad always uses right-click type=%{public}d", twoFingerSwitchType);
    type = twoFingerSwitchType;
}

int32_t MouseTransformProcessor::GetVirtualTouchpadPrimaryButton()
{
    MMI_HILOGI("VTrackpad always sets left button as primary button.");
    return LEFT_BUTTON;
}
#endif // OHOS_BUILD_ENABLE_VKEYBOARD
} // namespace MMI
} // namespace OHOS