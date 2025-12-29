/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "touch_gesture_adapter.h"

#include <regex>
#include "config_policy_utils.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TouchGestureAdapter"

namespace OHOS {
namespace MMI {
namespace {
constexpr std::uintmax_t MAX_SIZE_OF_INPUT_PRODUCT_CONFIG { 4096 };
} // namespace

const TouchGestureParameter& TouchGestureParameter::Load()
{
    static TouchGestureParameter param {};
    static std::once_flag flag;

    std::call_once(flag, []() {
        param.LoadTouchGestureParameter();
    });
    return param;
}

bool TouchGestureParameter::IsInteger(const char *target)
{
    if (target == nullptr) {
        return false;
    }
    std::regex pattern("^\\s*-?(0|([1-9]\\d*))\\s*$");
    return std::regex_match(target, pattern);
}

bool TouchGestureParameter::DoesSupportGesture(TouchGestureType gestureType, int32_t nFingers) const
{
    if ((gestureType & TOUCH_GESTURE_TYPE_ALL) == TOUCH_GESTURE_TYPE_NONE) {
        return false;
    }
    if (nFingers == ALL_FINGER_COUNT) {
        return true;
    }
    const auto &param = TouchGestureParameter::Load();
    if (((gestureType & TOUCH_GESTURE_TYPE_SWIPE) == TOUCH_GESTURE_TYPE_SWIPE) &&
        ((nFingers < param.GetMinFingerCountForSwipe()) || (nFingers > param.GetMaxFingerCountForSwipe()))) {
        return false;
    }
    if (((gestureType & TOUCH_GESTURE_TYPE_PINCH) == TOUCH_GESTURE_TYPE_PINCH) &&
        ((nFingers < param.GetMinFingerCountForPinch()) || (nFingers > param.GetMaxFingerCountForPinch()))) {
        return false;
    }
    return true;
}

int32_t TouchGestureParameter::GetMaxFingerCountForPinch() const
{
    return maxFingerCountForPinch_;
}

float TouchGestureParameter::GetMaxFingerSpacing() const
{
    return maxFingerSpacing_;
}

int64_t TouchGestureParameter::GetMaxDownInterval() const
{
    return maxDownInterval_;
}

float TouchGestureParameter::GetFingerMovementThreshold() const
{
    return fingerMovementThreshold_;
}

int32_t TouchGestureParameter::GetMinFingerCountForPinch() const
{
    return minFingerCountForPinch_;
}

int32_t TouchGestureParameter::GetFingerCountOffsetForPinch() const
{
    return fingerCountOffsetForPinch_;
}

int32_t TouchGestureParameter::GetContinuousPinchesForNotification() const
{
    return continuousPinchesForNotification_;
}

float TouchGestureParameter::GetMinGravityOffsetForPinch() const
{
    return minGravityOffsetForPinch_;
}

int32_t TouchGestureParameter::GetMaxFingerCountForSwipe() const
{
    return maxFingerCountForSwipe_;
}

int32_t TouchGestureParameter::GetMinFingerCountForSwipe() const
{
    return minFingerCountForSwipe_;
}

int32_t TouchGestureParameter::GetMinKeepTimeForSwipe() const
{
    return minKeepTimeForSwipe_;
}

void TouchGestureParameter::LoadTouchGestureParameter()
{
    char cfgName[] { "etc/input/input_product_config.json" };
    auto cfgNames = std::unique_ptr<CfgFiles, std::function<void(CfgFiles*)>>(
        ::GetCfgFiles(cfgName),
        [](CfgFiles *names) {
            if (names != nullptr) {
                ::FreeCfgFiles(names);
            }
        });
    if (cfgNames == nullptr) {
        MMI_HILOGW("Can not find InputProductConfig");
        return;
    }
    for (int32_t index = 0; index < MAX_CFG_POLICY_DIRS_CNT; ++index) {
        if (cfgNames->paths[index] == nullptr) {
            continue;
        }
        MMI_HILOGD("Try loading TouchGestureParameter from '%{private}s'", cfgNames->paths[index]);
        TouchGestureParameter param {};
        if (param.LoadTouchGestureParameter(cfgNames->paths[index])) {
            MMI_HILOGI("Load TouchGestureParameter from '%{private}s'", cfgNames->paths[index]);
            *this = param;
            break;
        }
    }
}

bool TouchGestureParameter::LoadTouchGestureParameter(const char *cfgPath)
{
    std::error_code ec {};
    auto realPath = std::filesystem::canonical(cfgPath, ec);
    if (ec || !std::filesystem::exists(realPath, ec)) {
        MMI_HILOGE("'%{private}s' is not real", cfgPath);
        return false;
    }
    auto fsize = std::filesystem::file_size(realPath, ec);
    if (ec || (fsize > MAX_SIZE_OF_INPUT_PRODUCT_CONFIG)) {
        MMI_HILOGE("Unexpected size of InputProductConfig");
        return false;
    }
    std::ifstream ifs(cfgPath);
    if (!ifs.is_open()) {
        MMI_HILOGE("Can not open config");
        return false;
    }
    return ReadTouchGestureParameter(ifs);
}

bool TouchGestureParameter::ReadTouchGestureParameter(std::ifstream &ifs)
{
    std::string cfg { std::istream_iterator<char>(ifs), std::istream_iterator<char>() };
    auto jsonProductCfg = std::unique_ptr<cJSON, std::function<void(cJSON *)>>(
        cJSON_Parse(cfg.c_str()),
        [](cJSON *productCfg) {
            if (productCfg != nullptr) {
                cJSON_Delete(productCfg);
            }
        });
    if (jsonProductCfg == nullptr) {
        MMI_HILOGE("Not json");
        return false;
    }
    return ReadTouchGestureParameter(jsonProductCfg.get());
}

bool TouchGestureParameter::ReadTouchGestureParameter(cJSON *jsonProductCfg)
{
    if (!cJSON_IsObject(jsonProductCfg)) {
        MMI_HILOGE("Not json format");
        return false;
    }
    cJSON *jsonTouchGesture = cJSON_GetObjectItemCaseSensitive(jsonProductCfg, "TouchGesture");
    if (!cJSON_IsObject(jsonTouchGesture)) {
        MMI_HILOGE("The TouchGesture is not object");
        return false;
    }
    return (
        ReadMaxFingerSpacing(jsonTouchGesture) &&
        ReadMaxDownInterval(jsonTouchGesture) &&
        ReadFingerMovementThreshold(jsonTouchGesture) &&
        ReadFingerCountOffsetForPinch(jsonTouchGesture) &&
        ReadContinuousPinchesForNotification(jsonTouchGesture) &&
        ReadMinGravityOffsetForPinch(jsonTouchGesture) &&
        ReadMinKeepTimeForSwipe(jsonTouchGesture)
    );
}

bool TouchGestureParameter::ReadMaxFingerSpacing(cJSON *jsonTouchGesture)
{
    cJSON *jsonParam = cJSON_GetObjectItemCaseSensitive(jsonTouchGesture, "MaxFingerSpacing");
    if (jsonParam == nullptr) {
        return true;
    }
    if (!cJSON_IsNumber(jsonParam)) {
        MMI_HILOGE("The MaxFingerSpacing is not number");
        return false;
    }
    maxFingerSpacing_ = static_cast<float>(cJSON_GetNumberValue(jsonParam));
    if (maxFingerSpacing_ < 0.0F) {
        MMI_HILOGE("The MaxFingerSpacing is invalid");
        return false;
    }
    return true;
}

bool TouchGestureParameter::ReadMaxDownInterval(cJSON *jsonTouchGesture)
{
    cJSON *jsonParam = cJSON_GetObjectItemCaseSensitive(jsonTouchGesture, "MaxDownInterval");
    if (jsonParam == nullptr) {
        return true;
    }
    if (!cJSON_IsNumber(jsonParam)) {
        MMI_HILOGE("The MaxDownInterval is not number");
        return false;
    }
    auto sMaxDownInterval = std::unique_ptr<char, std::function<void(char *)>>(
        cJSON_Print(jsonParam),
        [](char *sParam) {
            if (sParam != nullptr) {
                cJSON_free(sParam);
            }
        });
    if ((sMaxDownInterval != nullptr) && !IsInteger(sMaxDownInterval.get())) {
        MMI_HILOGE("Config of TouchGesture.MaxDownInterval is not integer");
        return false;
    }
    maxDownInterval_ = static_cast<int64_t>(cJSON_GetNumberValue(jsonParam));
    if (maxDownInterval_ < 0) {
        MMI_HILOGE("The MaxDownInterval is invalid");
        return false;
    }
    return true;
}

bool TouchGestureParameter::ReadFingerMovementThreshold(cJSON *jsonTouchGesture)
{
    cJSON *jsonParam = cJSON_GetObjectItemCaseSensitive(jsonTouchGesture, "FingerMovementThreshold");
    if (jsonParam == nullptr) {
        return true;
    }
    if (!cJSON_IsNumber(jsonParam)) {
        MMI_HILOGE("The FingerMovementThreshold is not number");
        return false;
    }
    fingerMovementThreshold_ = static_cast<float>(cJSON_GetNumberValue(jsonParam));
    if (fingerMovementThreshold_ < 0.0F) {
        MMI_HILOGE("The FingerMovementThreshold is invalid");
        return false;
    }
    return true;
}

bool TouchGestureParameter::ReadFingerCountOffsetForPinch(cJSON *jsonTouchGesture)
{
    cJSON *jsonParam = cJSON_GetObjectItemCaseSensitive(jsonTouchGesture, "FingerCountOffsetForPinch");
    if (jsonParam == nullptr) {
        return true;
    }
    if (!cJSON_IsNumber(jsonParam)) {
        MMI_HILOGE("The FingerCountOffsetForPinch is not number");
        return false;
    }
    auto sFingerCountOffsetForPinch = std::unique_ptr<char, std::function<void(char *)>>(
        cJSON_Print(jsonParam),
        [](char *sParam) {
            if (sParam != nullptr) {
                cJSON_free(sParam);
            }
        });
    if ((sFingerCountOffsetForPinch != nullptr) && !IsInteger(sFingerCountOffsetForPinch.get())) {
        MMI_HILOGE("Config of TouchGesture.FingerCountOffsetForPinch is not integer");
        return false;
    }
    fingerCountOffsetForPinch_ = static_cast<int32_t>(cJSON_GetNumberValue(jsonParam));
    if (fingerCountOffsetForPinch_ < 0) {
        MMI_HILOGE("The FingerCountOffsetForPinch is invalid");
        return false;
    }
    return true;
}

bool TouchGestureParameter::ReadContinuousPinchesForNotification(cJSON *jsonTouchGesture)
{
    cJSON *jsonParam = cJSON_GetObjectItemCaseSensitive(jsonTouchGesture, "ContinuousPinchesForNotification");
    if (jsonParam == nullptr) {
        return true;
    }
    if (!cJSON_IsNumber(jsonParam)) {
        MMI_HILOGE("The ContinuousPinchesForNotification is not number");
        return false;
    }
    auto sContinuousPinchesForNotification = std::unique_ptr<char, std::function<void(char *)>>(
        cJSON_Print(jsonParam),
        [](char *sParam) {
            if (sParam != nullptr) {
                cJSON_free(sParam);
            }
        });
    if ((sContinuousPinchesForNotification != nullptr) && !IsInteger(sContinuousPinchesForNotification.get())) {
        MMI_HILOGE("Config of TouchGesture.ContinuousPinchesForNotification is not integer");
        return false;
    }
    continuousPinchesForNotification_ = static_cast<int32_t>(cJSON_GetNumberValue(jsonParam));
    if (continuousPinchesForNotification_ < 0) {
        MMI_HILOGE("The ContinuousPinchesForNotification is invalid");
        return false;
    }
    return true;
}

bool TouchGestureParameter::ReadMinGravityOffsetForPinch(cJSON *jsonTouchGesture)
{
    cJSON *jsonParam = cJSON_GetObjectItemCaseSensitive(jsonTouchGesture, "MinGravityOffsetForPinch");
    if (jsonParam == nullptr) {
        return true;
    }
    if (!cJSON_IsNumber(jsonParam)) {
        MMI_HILOGE("The MinGravityOffsetForPinch is not number");
        return false;
    }
    minGravityOffsetForPinch_ = static_cast<float>(cJSON_GetNumberValue(jsonParam));
    if (minGravityOffsetForPinch_ < 0.0F) {
        MMI_HILOGE("The MinGravityOffsetForPinch is invalid");
        return false;
    }
    return true;
}

bool TouchGestureParameter::ReadMinKeepTimeForSwipe(cJSON *jsonTouchGesture)
{
    cJSON *jsonParam = cJSON_GetObjectItemCaseSensitive(jsonTouchGesture, "MinKeepTimeForSwipe");
    if (jsonParam == nullptr) {
        return true;
    }
    if (!cJSON_IsNumber(jsonParam)) {
        MMI_HILOGE("The MinKeepTimeForSwipe is not number");
        return false;
    }
    auto sMinKeepTimeForSwipe = std::unique_ptr<char, std::function<void(char *)>>(
        cJSON_Print(jsonParam),
        [](char *sParam) {
            if (sParam != nullptr) {
                cJSON_free(sParam);
            }
        });
    if ((sMinKeepTimeForSwipe != nullptr) && !IsInteger(sMinKeepTimeForSwipe.get())) {
        MMI_HILOGE("Config of TouchGesture.MinKeepTimeForSwipe is not integer");
        return false;
    }
    minKeepTimeForSwipe_ = static_cast<int32_t>(cJSON_GetNumberValue(jsonParam));
    if (minKeepTimeForSwipe_ < 0) {
        MMI_HILOGE("The MinKeepTimeForSwipe is invalid");
        return false;
    }
    return true;
}

std::shared_ptr<IDelegateInterface> TouchGestureAdapter::GetDelegateInterface(IInputServiceContext *env)
{
    if (env == nullptr) {
        MMI_HILOGE("Env is null");
        return nullptr;
    }
    return env->GetDelegateInterface();
}

IUdsServer* TouchGestureAdapter::GetUDSServer(IInputServiceContext *env)
{
    if (env == nullptr) {
        MMI_HILOGE("Env is null");
        return nullptr;
    }
    return env->GetUDSServer();
}

std::shared_ptr<IInputEventHandler> TouchGestureAdapter::GetEventNormalizeHandler(IInputServiceContext *env)
{
    if (env == nullptr) {
        MMI_HILOGE("Env is null");
        return nullptr;
    }
    return env->GetEventNormalizeHandler();
}

std::shared_ptr<IInputEventHandler> TouchGestureAdapter::GetMonitorHandler(IInputServiceContext *env)
{
    if (env == nullptr) {
        MMI_HILOGE("Env is null");
        return nullptr;
    }
    return env->GetMonitorHandler();
}

std::shared_ptr<ITimerManager> TouchGestureAdapter::GetTimerManager(IInputServiceContext *env)
{
    if (env == nullptr) {
        MMI_HILOGE("Env is null");
        return nullptr;
    }
    return env->GetTimerManager();
}

std::shared_ptr<IInputWindowsManager> TouchGestureAdapter::GetInputWindowsManager(IInputServiceContext *env)
{
    if (env == nullptr) {
        MMI_HILOGE("Env is null");
        return nullptr;
    }
    return env->GetInputWindowsManager();
}

TouchGestureAdapter::TouchGestureAdapter(
    IInputServiceContext *env, TouchGestureType type, std::shared_ptr<TouchGestureAdapter> next)
    : env_(env), gestureType_(type), nextAdapter_(next)
{}

void TouchGestureAdapter::SetGestureCondition(bool flag, TouchGestureType type, int32_t fingers)
{
    if ((gestureDetector_ != nullptr) && ((type & gestureType_) == gestureType_)) {
        if (flag) {
            gestureDetector_->AddGestureFingers(fingers);
        } else {
            gestureDetector_->RemoveGestureFingers(fingers);
        }
    }
    if (nextAdapter_ != nullptr) {
        nextAdapter_->SetGestureCondition(flag, type, fingers);
    }
}

void TouchGestureAdapter::process(std::shared_ptr<PointerEvent> event)
{
    LogTouchEvent(event);
    OnTouchEvent(event);
    if (ShouldDeliverToNext() && nextAdapter_ != nullptr) {
        nextAdapter_->process(event);
    }
}

void TouchGestureAdapter::HandleGestureWindowEmerged(int32_t windowId, std::shared_ptr<PointerEvent> lastTouchEvent)
{
    if (gestureDetector_ != nullptr) {
        gestureDetector_->HandleGestureWindowEmerged(windowId, lastTouchEvent);
    }
    if (nextAdapter_ != nullptr) {
        nextAdapter_->HandleGestureWindowEmerged(windowId, lastTouchEvent);
    }
}

void TouchGestureAdapter::Init()
{
    if (gestureDetector_ == nullptr) {
        gestureDetector_ = std::make_shared<TouchGestureDetector>(env_, gestureType_, shared_from_this());
    }
    if (nextAdapter_ != nullptr) {
        nextAdapter_->Init();
    }
}

void TouchGestureAdapter::LogTouchEvent(std::shared_ptr<PointerEvent> event) const
{
    CHKPV(event);
    if (event->GetSourceType() != PointerEvent::SOURCE_TYPE_TOUCHSCREEN) {
        return;
    }
    switch (event->GetPointerAction()) {
        case PointerEvent::POINTER_ACTION_DOWN:
        case PointerEvent::POINTER_ACTION_UP:
        case PointerEvent::POINTER_ACTION_CANCEL:
        case PointerEvent::POINTER_ACTION_PULL_UP: {
            break;
        }
        default: {
            return;
        }
    }
    auto pointers = event->GetPointerIds();
    std::ostringstream sTouches;
    sTouches << "(";

    if (auto iter = pointers.cbegin(); iter != pointers.cend()) {
        sTouches << *iter;
        for (++iter; iter != pointers.cend(); ++iter) {
            sTouches << "," << *iter;
        }
    }
    sTouches << ")";
    MMI_HILOGI("GestureType:%{public}u,No:%{public}d,PA:%{public}s,PI:%{public}d,Touches:%{public}s",
        gestureType_, event->GetId(), event->DumpPointerAction(), event->GetPointerId(),
        std::move(sTouches).str().c_str());
}

std::shared_ptr<TouchGestureAdapter> TouchGestureAdapter::GetGestureFactory(IInputServiceContext *env)
{
    std::shared_ptr<TouchGestureAdapter> pinch =
        std::make_shared<TouchGestureAdapter>(env, TOUCH_GESTURE_TYPE_PINCH, nullptr);
    std::shared_ptr<TouchGestureAdapter> swipe =
        std::make_shared<TouchGestureAdapter>(env, TOUCH_GESTURE_TYPE_SWIPE, pinch);
    swipe->Init();
    return swipe;
}

void TouchGestureAdapter::OnTouchEvent(std::shared_ptr<PointerEvent> event)
{
    CHKPV(event);
    CHKPV(gestureDetector_);
    if (event->GetSourceType() != PointerEvent::SOURCE_TYPE_TOUCHSCREEN) {
        return;
    }
    shouldDeliverToNext_ = true;

    if (gestureType_ == TOUCH_GESTURE_TYPE_SWIPE) {
        OnSwipeGesture(event);
    } else if (gestureType_ == TOUCH_GESTURE_TYPE_PINCH) {
        OnPinchGesture(event);
    }
    if (gestureStarted_ && (event->GetPointerAction() == PointerEvent::POINTER_ACTION_MOVE)) {
        shouldDeliverToNext_ = false;
    }
}

void TouchGestureAdapter::OnSwipeGesture(std::shared_ptr<PointerEvent> event)
{
    CHKPV(gestureDetector_);
    if ((state_ == GestureState::PINCH) && (event->GetPointerAction() == PointerEvent::POINTER_ACTION_MOVE)) {
        return;
    }
    gestureStarted_ = gestureDetector_->OnTouchEvent(event);
    state_ = gestureStarted_ ? GestureState::SWIPE : GestureState::IDLE;
}

void TouchGestureAdapter::OnPinchGesture(std::shared_ptr<PointerEvent> event)
{
    CHKPV(gestureDetector_);
    if ((state_ == GestureState::SWIPE) && (event->GetPointerAction() == PointerEvent::POINTER_ACTION_MOVE)) {
        return;
    }
    gestureStarted_ = gestureDetector_->OnTouchEvent(event);
    state_ = gestureStarted_ ? GestureState::PINCH : GestureState::IDLE;
}

bool TouchGestureAdapter::OnGestureEvent(std::shared_ptr<PointerEvent> event, GestureMode mode)
{
#ifdef OHOS_BUILD_ENABLE_MONITOR
    auto pointEvent = std::make_shared<PointerEvent>(*event);
    pointEvent->SetHandlerEventType(HANDLE_EVENT_TYPE_TOUCH_GESTURE);
    switch (mode) {
        case GestureMode::ACTION_SWIPE_DOWN:
            pointEvent->SetPointerAction(PointerEvent::TOUCH_ACTION_SWIPE_DOWN);
            break;
        case GestureMode::ACTION_SWIPE_UP:
            pointEvent->SetPointerAction(PointerEvent::TOUCH_ACTION_SWIPE_UP);
            break;
        case GestureMode::ACTION_SWIPE_LEFT:
            pointEvent->SetPointerAction(PointerEvent::TOUCH_ACTION_SWIPE_LEFT);
            break;
        case GestureMode::ACTION_SWIPE_RIGHT:
            pointEvent->SetPointerAction(PointerEvent::TOUCH_ACTION_SWIPE_RIGHT);
            break;
        case GestureMode::ACTION_PINCH_CLOSED:
            pointEvent->SetPointerAction(PointerEvent::TOUCH_ACTION_PINCH_CLOSEED);
            break;
        case GestureMode::ACTION_PINCH_OPENED:
            pointEvent->SetPointerAction(PointerEvent::TOUCH_ACTION_PINCH_OPENED);
            break;
        case GestureMode::ACTION_GESTURE_END:
            pointEvent->SetPointerAction(PointerEvent::TOUCH_ACTION_GESTURE_END);
            break;
        default:
            MMI_HILOGW("unknow mode:%{public}d", mode);
            return false;
    }
    auto monitor = TouchGestureAdapter::GetMonitorHandler(env_);
    CHKPF(monitor);
    monitor->HandlePointerEvent(pointEvent);
#endif // OHOS_BUILD_ENABLE_MONITOR
    return true;
}

void TouchGestureAdapter::OnGestureTrend(std::shared_ptr<PointerEvent> event)
{
    auto winMgr = TouchGestureAdapter::GetInputWindowsManager(env_);
    if (winMgr != nullptr) {
        winMgr->CancelAllTouches(event);
    }
}
} // namespace MMI
} // namespace OHOS