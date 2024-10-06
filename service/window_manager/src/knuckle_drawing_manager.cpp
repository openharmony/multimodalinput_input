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

#include "knuckle_drawing_manager.h"

#ifdef OHOS_BUILD_ENABLE_NEW_KNUCKLE_DYNAMIC
#include "animation/rs_particle_params.h"
#endif // OHOS_BUILD_ENABLE_NEW_KNUCKLE_DYNAMIC
#include "image/bitmap.h"
#include "image_source.h"
#include "image_type.h"
#include "image_utils.h"
#ifndef USE_ROSEN_DRAWING
#include "pipeline/rs_recording_canvas.h"
#else
#include "ui/rs_canvas_drawing_node.h"
#endif // USE_ROSEN_DRAWING

#include "define_multimodal.h"
#include "i_multimodal_input_connect.h"
#include "mmi_log.h"
#include "parameters.h"
#include "setting_datashare.h"
#ifdef OHOS_BUILD_ENABLE_NEW_KNUCKLE_DYNAMIC
#include "timer_manager.h"
#endif // OHOS_BUILD_ENABLE_NEW_KNUCKLE_DYNAMIC
#include "touch_drawing_manager.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KnuckleDrawingManager"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t DEFAULT_VALUE { -1 };
constexpr int32_t MAX_POINTER_NUM { 5 };
constexpr int32_t MID_POINT { 2 };
constexpr int32_t POINT_INDEX0 { 0 };
constexpr int32_t POINT_INDEX1 { 1 };
constexpr int32_t POINT_INDEX2 { 2 };
constexpr int32_t POINT_INDEX3 { 3 };
constexpr int32_t POINT_INDEX4 { 4 };
constexpr int32_t PAINT_STROKE_WIDTH { 10 };
constexpr int32_t PAINT_PATH_RADIUS { 10 };
constexpr int64_t DOUBLE_CLICK_INTERVAL_TIME_SLOW { 450000 };
[[ maybe_unused ]] constexpr int64_t WAIT_DOUBLE_CLICK_INTERVAL_TIME { 100000 };
constexpr float DOUBLE_CLICK_DISTANCE_LONG_CONFIG { 96.0f };
[[ maybe_unused ]] constexpr float VPR_CONFIG { 3.25f };
constexpr int32_t POW_SQUARE { 2 };
constexpr int32_t ROTATION_ANGLE_0 { 0 };
constexpr int32_t ROTATION_ANGLE_90 { 90 };
constexpr int32_t ROTATION_ANGLE_180 { 180 };
constexpr int32_t ROTATION_ANGLE_270 { 270 };
constexpr uint64_t FOLD_SCREEN_MAIN_ID { 5 };
const int32_t ROTATE_POLICY = system::GetIntParameter("const.window.device.rotate_policy", 0);
const std::string FOLDABLE = system::GetParameter("const.window.foldabledevice.rotate_policy", "");
constexpr int32_t WINDOW_ROTATE { 0 };
constexpr int32_t SCREEN_ROTATE { 1 };
constexpr int32_t FOLDABLE_DEVICE { 2 };
constexpr char FOLDABLE_ROTATE { '0' };
constexpr int32_t SUBSCRIPT_TWO { 2 };
constexpr int32_t SUBSCRIPT_ZERO { 0 };
constexpr std::string_view SCREEN_READING { "accessibility_screenreader_enabled" };
constexpr std::string_view SCREEN_READ_ENABLE { "1" };
constexpr int32_t POINTER_NUMBER_TO_DRAW { 10 };

void KnuckleDrawingManager::CreateObserver()
{
    CALL_DEBUG_ENTER;
    if (!hasScreenReadObserver_) {
        screenReadState_.switchName = SCREEN_READING;
        CreateScreenReadObserver(screenReadState_);
        hasScreenReadObserver_ = true;
    }
    MMI_HILOGD("screenReadState_.state: %{public}s", screenReadState_.state.c_str());
}

template <class T>
void KnuckleDrawingManager::CreateScreenReadObserver(T &item)
{
    CALL_DEBUG_ENTER;
    SettingObserver::UpdateFunc updateFunc = [&item](const std::string& key) {
        auto ret = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID)
            .GetStringValue(key, item.state);
        if (ret != RET_OK) {
            MMI_HILOGE("Get value from setting date fail");
            return;
        }
        MMI_HILOGI("key: %{public}s, state: %{public}s", key.c_str(), item.state.c_str());
    };
    sptr<SettingObserver> statusObserver = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID)
        .CreateObserver(item.switchName, updateFunc);
    ErrCode ret = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID).
        RegisterObserver(statusObserver);
    if (ret != ERR_OK) {
        MMI_HILOGE("register setting observer failed, ret=%{public}d", ret);
        statusObserver = nullptr;
    }
}

std::string KnuckleDrawingManager::GetScreenReadState()
{
    return screenReadState_.state;
}
} // namespace MMI
} // namespace OHOS