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

#include "touch_gesture_handler.h"

#include <config_policy_utils.h>

#include "key_command_handler_util.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TouchGestureHandler"

namespace OHOS {
namespace MMI {
namespace {
const std::string TOUCH_GESTURE_HANDLER_NAME { "TouchGestureHandler" };
constexpr int32_t TOUCH_GESTURE_HANDLER_SESSION { -100 };
}

TouchGestureHandler::TouchGestureHandler(
    std::shared_ptr<DelegateInterface> delegate, std::shared_ptr<TouchGestureManager> touchGestureMgr)
    : delegate_(delegate), touchGestureMgr_(touchGestureMgr)
{
    LoadGestureHandlerConfig();
    StartMonitor();
}

TouchGestureHandler::~TouchGestureHandler()
{
    StopMonitor();
    UnregisterGestureHandlers();
}

void TouchGestureHandler::LoadGestureHandlerConfig()
{
    char cfgName[] { "etc/multimodalinput/ability_launch_config.json" };
    char buf[MAX_PATH_LEN] {};

    char *cfgPath = ::GetOneCfgFile(cfgName, buf, sizeof(buf));
    if (cfgPath == nullptr) {
        MMI_HILOGE("No '%{public}s' was found", cfgName);
        return;
    }
    MMI_HILOGI("Config of gesture handlers: %{public}s", cfgPath);
    ReadGestureHandlerConfig(std::string(cfgPath));
}

void TouchGestureHandler::ReadGestureHandlerConfig(const std::string &cfgPath)
{
    std::string cfg = ReadJsonFile(cfgPath);
    JsonParser parser;
    parser.json_ = cJSON_Parse(cfg.c_str());
    if (!cJSON_IsObject(parser.json_)) {
        MMI_HILOGE("Not json format");
        return;
    }
    cJSON *jsonHandlers = cJSON_GetObjectItemCaseSensitive(parser.json_, "TouchGestureHandlers");
    if (!cJSON_IsArray(jsonHandlers)) {
        MMI_HILOGE("jsonHandlers is not array");
        return;
    }
    int32_t nHandlers = cJSON_GetArraySize(jsonHandlers);
    for (int32_t index = 0; index < nHandlers; ++index) {
        cJSON *jsonHandler = cJSON_GetArrayItem(jsonHandlers, index);
        ReadGestureHandlerConfig(jsonHandler);
    }
}

void TouchGestureHandler::ReadGestureHandlerConfig(cJSON *jsonHandler)
{
    if (!cJSON_IsObject(jsonHandler)) {
        MMI_HILOGE("Not json object");
        return;
    }
    Handler handler {};

    cJSON *jsonGestureModes = cJSON_GetObjectItem(jsonHandler, "GestureModes");
    if (!cJSON_IsString(jsonGestureModes)) {
        MMI_HILOGE("Expect string for GestureMode");
        return;
    }
    char *strGestureModes = cJSON_GetStringValue(jsonGestureModes);
    CHKPV(strGestureModes);
    handler.modes_ = ConvertGestureModes(std::string(strGestureModes));

    cJSON *jsonFingerNum = cJSON_GetObjectItem(jsonHandler, "FingerNum");
    if (!cJSON_IsNumber(jsonFingerNum)) {
        MMI_HILOGE("Expect number for FingerNum");
        return;
    }
    handler.nFingers_ = static_cast<int32_t>(cJSON_GetNumberValue(jsonFingerNum));

    cJSON *jsonAbility = cJSON_GetObjectItem(jsonHandler, "Ability");
    if (!PackageAbility(jsonAbility, handler.ability_)) {
        MMI_HILOGE("Incomplete ability config");
        return;
    }
    RegisterGestureHandler(handler);
    handlers_.emplace_back(handler);
}

std::set<GestureMode> TouchGestureHandler::ConvertGestureModes(const std::string &sGestureModes) const
{
    std::set<GestureMode> gestureModes;
    std::string::size_type sPos { 0 };

    while (sPos != std::string::npos) {
        GestureMode gestureMode { GestureMode::ACTION_UNKNOWN };
        auto tPos = sGestureModes.find(',', sPos);
        if (tPos != std::string::npos) {
            gestureMode = ConvertGestureMode(sGestureModes.substr(sPos, tPos - sPos));
            sPos = tPos + 1;
        } else {
            gestureMode = ConvertGestureMode(sGestureModes.substr(sPos));
            sPos = tPos;
        }
        if (gestureMode != GestureMode::ACTION_UNKNOWN) {
            gestureModes.emplace(gestureMode);
        }
    }
    return gestureModes;
}

GestureMode TouchGestureHandler::ConvertGestureMode(const std::string &sGestureMode) const
{
    static std::map<std::string, GestureMode> gestureModeMap {
        { "SwipeDown", GestureMode::ACTION_SWIPE_DOWN },
        { "SwipeUp", GestureMode::ACTION_SWIPE_UP },
        { "SwipeLeft", GestureMode::ACTION_SWIPE_LEFT },
        { "SwipeRight", GestureMode::ACTION_SWIPE_RIGHT },
        { "PinchClose", GestureMode::ACTION_PINCH_CLOSED },
        { "PinchOpen", GestureMode::ACTION_PINCH_OPENED },
        { "GestureEnd", GestureMode::ACTION_GESTURE_END },
    };
    if (auto iter = gestureModeMap.find(sGestureMode); iter != gestureModeMap.cend()) {
        return iter->second;
    }
    return GestureMode::ACTION_UNKNOWN;
}

void TouchGestureHandler::RegisterGestureHandler(const Handler &handler) const
{
    auto touchGestureMgr = touchGestureMgr_.lock();
    CHKPV(touchGestureMgr);

    for (const auto &gestureMode : handler.modes_) {
        auto gestureType = GestureMode2GestureType(gestureMode);
        touchGestureMgr->AddHandler(TOUCH_GESTURE_HANDLER_SESSION, gestureType, handler.nFingers_);
    }
}

TouchGestureType TouchGestureHandler::GestureMode2GestureType(GestureMode gestureMode) const
{
    switch (gestureMode) {
        case GestureMode::ACTION_SWIPE_DOWN:
        case GestureMode::ACTION_SWIPE_UP:
        case GestureMode::ACTION_SWIPE_LEFT:
        case GestureMode::ACTION_SWIPE_RIGHT: {
            return TOUCH_GESTURE_TYPE_SWIPE;
        }
        case GestureMode::ACTION_PINCH_CLOSED:
        case GestureMode::ACTION_PINCH_OPENED: {
            return TOUCH_GESTURE_TYPE_PINCH;
        }
        default: {
            return TOUCH_GESTURE_TYPE_NONE;
        }
    }
}

void TouchGestureHandler::UnregisterGestureHandlers()
{
    for (const auto &handler : handlers_) {
        UnregisterGestureHandler(handler);
    }
    handlers_.clear();
}

void TouchGestureHandler::UnregisterGestureHandler(const Handler &handler)
{
    auto touchGestureMgr = touchGestureMgr_.lock();
    CHKPV(touchGestureMgr);

    for (const auto &gestureMode : handler.modes_) {
        auto gestureType = GestureMode2GestureType(gestureMode);
        touchGestureMgr->RemoveHandler(TOUCH_GESTURE_HANDLER_SESSION, gestureType, handler.nFingers_);
    }
}

void TouchGestureHandler::StartMonitor()
{
    if (handlers_.empty()) {
        MMI_HILOGI("No touch gesture handler");
        return;
    }
    auto delegate = delegate_.lock();
    CHKPV(delegate);
    if (delegate->HasHandler(TOUCH_GESTURE_HANDLER_NAME)) {
        return;
    }
    MMI_HILOGI("Start touch gesture monitor");
    auto ret = delegate->AddHandler(
        InputHandlerType::MONITOR,
        DelegateInterface::HandlerSummary {
            .handlerName = TOUCH_GESTURE_HANDLER_NAME,
            .eventType = HANDLE_EVENT_TYPE_TOUCH_GESTURE,
            .mode = HandlerMode::SYNC,
            .gestureType = TOUCH_GESTURE_TYPE_ALL,
            .fingers = ALL_FINGER_COUNT,
            .cb = [this](std::shared_ptr<PointerEvent> event) {
                ProcessGestureEvent(event);
                return RET_OK;
            }
        });
    if (ret != RET_OK) {
        MMI_HILOGE("Failed to add gesture monitor, error:%{public}d", ret);
    }
}

void TouchGestureHandler::StopMonitor()
{
    auto delegate = delegate_.lock();
    CHKPV(delegate);
    MMI_HILOGI("Stop touch gesture monitor");
    delegate->RemoveHandler(InputHandlerType::MONITOR, TOUCH_GESTURE_HANDLER_NAME);
}

void TouchGestureHandler::ProcessGestureEvent(std::shared_ptr<PointerEvent> event)
{
    auto gestureMode = GetGestureMode(event);
    if (gestureMode == GestureMode::ACTION_UNKNOWN) {
        return;
    }
    for (const auto &handler : handlers_) {
        if ((handler.modes_.find(gestureMode) != handler.modes_.cend()) &&
            (handler.nFingers_ == event->GetPointerCount())) {
            LaunchAbility(handler.ability_);
        }
    }
}

GestureMode TouchGestureHandler::GetGestureMode(std::shared_ptr<PointerEvent> event) const
{
    static std::map<int32_t, GestureMode> gestureModeMap {
        { PointerEvent::TOUCH_ACTION_SWIPE_DOWN, GestureMode::ACTION_SWIPE_DOWN },
        { PointerEvent::TOUCH_ACTION_SWIPE_UP, GestureMode::ACTION_SWIPE_UP },
        { PointerEvent::TOUCH_ACTION_SWIPE_RIGHT, GestureMode::ACTION_SWIPE_RIGHT },
        { PointerEvent::TOUCH_ACTION_SWIPE_LEFT, GestureMode::ACTION_SWIPE_LEFT },
        { PointerEvent::TOUCH_ACTION_PINCH_OPENED, GestureMode::ACTION_PINCH_OPENED },
        { PointerEvent::TOUCH_ACTION_PINCH_CLOSEED, GestureMode::ACTION_PINCH_CLOSED },
        { PointerEvent::TOUCH_ACTION_GESTURE_END, GestureMode::ACTION_GESTURE_END },
    };
    CHKPR(event, GestureMode::ACTION_UNKNOWN);

    if (auto iter = gestureModeMap.find(event->GetPointerAction()); iter != gestureModeMap.cend()) {
        return iter->second;
    }
    return GestureMode::ACTION_UNKNOWN;
}

void TouchGestureHandler::LaunchAbility(const Ability &ability)
{
    AAFwk::Want want {};
    want.SetElementName(ability.deviceId, ability.bundleName, ability.abilityName);
    want.SetAction(ability.action);
    want.SetUri(ability.uri);
    want.SetType(ability.uri);
    for (const auto &entity : ability.entities) {
        want.AddEntity(entity);
    }
    for (const auto &item : ability.params) {
        want.SetParam(item.first, item.second);
    }
    MMI_HILOGW("Launch ability(%{public}s)", ability.bundleName.c_str());
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want);
    if (err != ERR_OK) {
        MMI_HILOGE("LaunchAbility(%{public}s) fail, error:%{public}d", ability.bundleName.c_str(), err);
    }
}
} // namespace MMI
} // namespace OHOS