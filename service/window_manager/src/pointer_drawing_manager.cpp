/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "pointer_drawing_manager.h"

#include <parameters.h>
#include <regex>
#include <utility>

#include "image/bitmap.h"
#include "image_source.h"
#include "image_type.h"
#include "image_utils.h"
#include "table_dump.h"
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
#include "magic_pointer_drawing_manager.h"
#include "magic_pointer_velocity_tracker.h"
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR

#include "bytrace_adapter.h"
#include "define_multimodal.h"
#include "i_multimodal_input_connect.h"
#include "input_device_manager.h"
#include "i_input_windows_manager.h"
#include "ipc_skeleton.h"
#include "mmi_log.h"
#include "i_preference_manager.h"
#include "parameters.h"
#include "pipeline/rs_recording_canvas.h"
#include "preferences.h"
#include "preferences_errno.h"
#include "preferences_helper.h"
#include "render/rs_pixel_map_util.h"
#include "scene_board_judgement.h"
#include "setting_datashare.h"
#include "util.h"
#include "dfx_hisysevent.h"
#include "timer_manager.h"
#include "surface.h"
#include "common_event_data.h"
#include "common_event_manager.h"
#include "common_event_support.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_CURSOR
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "PointerDrawingManager"
#define FOCUS_COORDINATES(FOCUS_COORDINATES_, CHANGE) float FOCUS_COORDINATES_##CHANGE
#define CALCULATE_CANVAS_SIZE(CALCULATE_CANVAS_SIZE_, CHANGE) float CALCULATE_CANVAS_SIZE_##CHANGE

namespace OHOS {
namespace MMI {
namespace {
const std::string FOLD_SCREEN_FLAG = system::GetParameter("const.window.foldscreen.type", "");
const std::string IMAGE_POINTER_DEFAULT_PATH = "/system/etc/multimodalinput/mouse_icon/";
const std::string DefaultIconPath = IMAGE_POINTER_DEFAULT_PATH + "Default.svg";
const std::string CursorIconPath = IMAGE_POINTER_DEFAULT_PATH + "Cursor_Circle.png";
const std::string CustomCursorIconPath = IMAGE_POINTER_DEFAULT_PATH + "Custom_Cursor_Circle.svg";
const std::string LoadingIconPath = IMAGE_POINTER_DEFAULT_PATH + "Loading.svg";
const std::string LoadingRightIconPath = IMAGE_POINTER_DEFAULT_PATH + "Loading_Right.svg";
const char* POINTER_COLOR { "pointerColor" };
const char* POINTER_SIZE { "pointerSize" };
const char* MAGIC_POINTER_COLOR { "magicPointerColor" };
const char* MAGIC_POINTER_SIZE { "magicPointerSize"};
const char* POINTER_CURSOR_RENDER_RECEIVER_NAME { "PointerCursorReceiver" };
const std::vector<std::string> DEVICE_TYPES = {};
constexpr int32_t BASELINE_DENSITY { 160 };
constexpr int32_t CALCULATE_MIDDLE { 2 };
[[ maybe_unused ]] constexpr int32_t MAGIC_INDEPENDENT_PIXELS { 30 };
constexpr int32_t DEVICE_INDEPENDENT_PIXELS { 40 };
constexpr int32_t POINTER_WINDOW_INIT_SIZE { 64 };
constexpr int32_t DEFAULT_POINTER_SIZE { 1 };
constexpr int32_t MIN_POINTER_SIZE { 1 };
constexpr int32_t MAX_POINTER_SIZE { 7 };
constexpr int32_t DEFAULT_VALUE { -1 };
constexpr int32_t ANIMATION_DURATION { 500 };
constexpr int32_t DEFAULT_POINTER_STYLE { 0 };
constexpr int32_t CURSOR_CIRCLE_STYLE { 41 };
constexpr int32_t AECH_DEVELOPER_DEFINED_STYLE { 47 };
constexpr float MOUSE_ICON_BIAS_RATIO { 5 / 33.0f };
constexpr int32_t VISIBLE_LIST_MAX_SIZE { 100 };
[[ maybe_unused ]] constexpr int32_t WAIT_TIME_FOR_MAGIC_CURSOR { 6000 };
constexpr float ROTATION_ANGLE { 360.f };
constexpr float LOADING_CENTER_RATIO { 0.5f };
constexpr float RUNNING_X_RATIO { 0.3f };
constexpr float RUNNING_Y_RATIO { 0.675f };
constexpr float INCREASE_RATIO { 1.22f };
constexpr float ROTATION_ANGLE90 { 90.f };
constexpr int32_t MIN_POINTER_COLOR { 0x000000 };
constexpr int32_t MAX_POINTER_COLOR { 0x00ffffff };
constexpr int32_t MIN_CURSOR_SIZE { 64 };
constexpr uint32_t RGB_CHANNEL_BITS_LENGTH { 24 };
constexpr float MAX_ALPHA_VALUE { 255.f };
constexpr int32_t MOUSE_STYLE_OPT { 0 };
constexpr int32_t MAGIC_STYLE_OPT { 1 };
constexpr size_t RETRY_TIMES { 3 };
const std::string MOUSE_FILE_NAME { "mouse_settings.xml" };
bool g_isRsRemoteDied { false };
bool g_isHdiRemoteDied { false };
bool g_isReStartVsync { false };
constexpr uint64_t FOLD_SCREEN_ID_FULL { 0 };
constexpr uint64_t FOLD_SCREEN_ID_MAIN { 5 };
constexpr float IMAGE_PIXEL { 0.0f };
constexpr float CALCULATE_IMAGE_MIDDLE { 2.0f };
constexpr int32_t QUEUE_SIZE { 5 };
constexpr int32_t DYNAMIC_ROTATION_ANGLE { 12 };
constexpr float CALCULATE_MOUSE_ICON_BAIS { 5.0f };
constexpr int32_t SYNC_FENCE_WAIT_TIME { 3000 };
float g_hardwareCanvasSize = { 512.0f };
float g_focalPoint = { 256.0f };
constexpr int32_t REPEAT_COOLING_TIME { 1000 };
constexpr int32_t REPEAT_ONCE { 1 };
constexpr int32_t ANGLE_90 { 90 };
constexpr int32_t ANGLE_360 { 360 };
constexpr int32_t MAX_CUSTOM_CURSOR_SIZE { 256 };
constexpr float MAX_CUSTOM_CURSOR_DIMENSION { 256.0f };
constexpr uint32_t CURSOR_STRIDE { 4 };
constexpr int32_t MAX_FAIL_COUNT { 1000 };
constexpr int32_t CHECK_SLEEP_TIME { 10 };
std::atomic<bool> g_isRsRestart { false };
} // namespace
} // namespace MMI
} // namespace OHOS

namespace OHOS {
namespace MMI {
#ifdef OHOS_BUILD_ENABLE_HARDWARE_CURSOR
class DisplyStatusReceiver : public EventFwk::CommonEventSubscriber {
public:
    explicit DisplyStatusReceiver(const OHOS::EventFwk::CommonEventSubscribeInfo& subscribeInfo)
        : OHOS::EventFwk::CommonEventSubscriber(subscribeInfo)
    {
        MMI_HILOGI("DisplyStatusReceiver register");
    }
 
    virtual ~DisplyStatusReceiver() = default;
 
    void OnReceiveEvent(const EventFwk::CommonEventData &eventData)
    {
        std::string action = eventData.GetWant().GetAction();
        if (action.empty()) {
            MMI_HILOGE("action is empty");
            return;
        }
        MMI_HILOGI("Received screen status:%{public}s", action.c_str());
        if (action == EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF) {
            IPointerDrawingManager::GetInstance()->DetachAllSurfaceNode();
        } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON) {
            int32_t ret = IPointerDrawingManager::GetInstance()->CheckHwcReady();
            if (ret != RET_OK) {
                MMI_HILOGE("CheckHwcReady failed");
            }
            std::shared_ptr<DelegateInterface> delegateProxy =
                IPointerDrawingManager::GetInstance()->GetDelegateProxy();
            CHKPV(delegateProxy);
            delegateProxy->OnPostSyncTask([] {
                PointerStyle curPointerStyle = IPointerDrawingManager::GetInstance()->GetLastMouseStyle();
                MMI_HILOGI("curPointerStyle:%{public}d", curPointerStyle.id);
                curPointerStyle.id = MOUSE_ICON::DEFAULT;
                IPointerDrawingManager::GetInstance()->DrawPointerStyle(curPointerStyle);
                IPointerDrawingManager::GetInstance()->AttachAllSurfaceNode();
                return RET_OK;
            });
        }
    }
};
#endif // OHOS_BUILD_ENABLE_HARDWARE_CURSOR

static bool IsSingleDisplayFoldDevice()
{
    return (!FOLD_SCREEN_FLAG.empty() && (FOLD_SCREEN_FLAG[0] == '1' || FOLD_SCREEN_FLAG[0] == '4'));
}

void RsRemoteDiedCallback()
{
    CALL_INFO_TRACE;
    g_isRsRemoteDied = true;
    g_isHdiRemoteDied = true;
    g_isReStartVsync = true;
    g_isRsRestart = false;
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
    MAGIC_CURSOR->RsRemoteDiedCallbackForMagicCursor();
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
    IPointerDrawingManager::GetInstance()->DestroyPointerWindow();
}

void PointerDrawingManager::InitPointerCallback()
{
    MMI_HILOGI("Init RS Callback start");
    g_isRsRemoteDied = false;
    g_isRsRestart = false;
    Rosen::OnRemoteDiedCallback callback = RsRemoteDiedCallback;
    auto begin = std::chrono::high_resolution_clock::now();
    Rosen::RSInterfaces::GetInstance().SetOnRemoteDiedCallback(callback);
    auto durationMS = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::high_resolution_clock::now() - begin).count();
#ifdef OHOS_BUILD_ENABLE_DFX_RADAR
    DfxHisysevent::ReportApiCallTimes(ApiDurationStatistics::Api::SET_ON_REMOTE_DIED_CALLBACK, durationMS);
#endif // OHOS_BUILD_ENABLE_DFX_RADAR
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
    if (HasMagicCursor() && surfaceNode_ != nullptr) {
        surfaceNode_ = nullptr;
        MAGIC_CURSOR->RsRemoteInitCallbackForMagicCursor();
    }
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
#ifdef OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    if (!initEventhandlerFlag_.load()) {
        std::string productType = OHOS::system::GetParameter("const.build.product", "HYM");
        if (std::find(DEVICE_TYPES.begin(), DEVICE_TYPES.end(), productType) != DEVICE_TYPES.end()) {
            renderThread_ = std::make_unique<std::thread>([this] { this->RenderThreadLoop(); });
            softCursorRenderThread_ =
                std::make_unique<std::thread>([this] { this->SoftCursorRenderThreadLoop(); });
        }
        initEventhandlerFlag_.store(true);
    }
#endif // OHOS_BUILD_ENABLE_HARDWARE_CURSOR
}

void PointerDrawingManager::DestroyPointerWindow()
{
    CALL_INFO_TRACE;
    CHKPV(delegateProxy_);
    delegateProxy_->OnPostSyncTask([this] {
        if (surfaceNode_ != nullptr) {
            MMI_HILOGI("Pointer window destroy start screenId_ %{public}" PRIu64, screenId_);
            g_isRsRemoteDied = false;
            surfaceNode_->DetachToDisplay(screenId_);
            surfaceNode_ = nullptr;
            Rosen::RSTransaction::FlushImplicitTransaction();
            MMI_HILOGI("Pointer window destroy success");
        }
        return RET_OK;
    });
}

static inline bool IsNum(const std::string &str)
{
    std::istringstream sin(str);
    double num;
    return (sin >> num) && sin.eof();
}

static float GetCanvasSize()
{
    auto ret = system::GetParameter("rosen.multimodalinput.pc.setcanvassize", "512.0");
    if (IsNum(ret)) {
        return g_hardwareCanvasSize;
    }
    return std::stoi(ret.c_str());
}

static float GetFocusCoordinates()
{
    auto ret = system::GetParameter("rosen.multimodalinput.pc.setfocuscoordinates", "256.0");
    if (IsNum(ret)) {
        return g_focalPoint;
    }
    return std::stoi(ret.c_str());
}

PointerDrawingManager::PointerDrawingManager()
{
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
    MMI_HILOGI("The magiccurosr InitStyle");
    hasMagicCursor_.name = "isMagicCursor";
    MAGIC_CURSOR->InitStyle();
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
    InitStyle();
#ifdef OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    hardwareCursorPointerManager_ = std::make_shared<HardwareCursorPointerManager>();
    g_hardwareCanvasSize = GetCanvasSize();
    g_focalPoint = GetFocusCoordinates();
#endif // OHOS_BUILD_ENABLE_HARDWARE_CURSOR
}

PointerDrawingManager::~PointerDrawingManager()
{
    MMI_HILOGI("~PointerDrawingManager enter");
#ifdef OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    if (runner_ != nullptr) {
        runner_->Stop();
    }
    if ((renderThread_ != nullptr) && renderThread_->joinable()) {
        renderThread_->join();
    }

    if (softCursorRunner_ != nullptr) {
        softCursorRunner_->Stop();
    }
    if ((softCursorRenderThread_ != nullptr) && softCursorRenderThread_->joinable()) {
        softCursorRenderThread_->join();
    }
#endif // OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    MMI_HILOGI("~PointerDrawingManager complete");
}

PointerStyle PointerDrawingManager::GetLastMouseStyle()
{
    CALL_DEBUG_ENTER;
    return lastMouseStyle_;
}

ICON_TYPE PointerDrawingManager::MouseIcon2IconType(MOUSE_ICON m)
{
    return ICON_TYPE(mouseIcons_[m].alignmentWay);
}

bool PointerDrawingManager::SetCursorLocation(int32_t displayId, int32_t physicalX,
    int32_t physicalY, ICON_TYPE iconType)
{
    bool magicCursorSetBounds = false;
    if (UpdateSurfaceNodeBounds(physicalX, physicalY) == RET_OK) {
        magicCursorSetBounds = true;
        Rosen::RSTransaction::FlushImplicitTransaction();
    }
#ifdef OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    CHKPF(hardwareCursorPointerManager_);
    CHKPF(surfaceNode_);
    if (g_isHdiRemoteDied) {
        hardwareCursorPointerManager_->SetHdiServiceState(false);
    }
    if (!magicCursorSetBounds) {
        if (hardwareCursorPointerManager_->IsSupported()) {
            if (lastMouseStyle_.id != MOUSE_ICON::LOADING &&
                lastMouseStyle_.id != MOUSE_ICON::RUNNING) {
                // Change the coordinates issued by RS to asynchronous,
                // without blocking the issuance of HardwareCursor coordinates.
                SoftwareCursorMoveAsync(physicalX, physicalY, iconType);
            }
        } else {
            surfaceNode_->SetBounds(physicalX, physicalY, surfaceNode_->GetStagingProperties().GetBounds().z_,
                surfaceNode_->GetStagingProperties().GetBounds().w_);
            Rosen::RSTransaction::FlushImplicitTransaction();
        }
    }
    CHKPF(hardwareCursorPointerManager_);
    if (hardwareCursorPointerManager_->IsSupported() &&
        lastMouseStyle_.id != MOUSE_ICON::LOADING &&
        lastMouseStyle_.id != MOUSE_ICON::RUNNING) {
        HardwareCursorMove(physicalX, physicalY, iconType);
    }
#else
    if (!magicCursorSetBounds) {
        surfaceNode_->SetBounds(physicalX, physicalY,
            surfaceNode_->GetStagingProperties().GetBounds().z_, surfaceNode_->GetStagingProperties().GetBounds().w_);
        Rosen::RSTransaction::FlushImplicitTransaction();
    }
#endif // OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    return true;
}

void PointerDrawingManager::ForceClearPointerVisiableStatus()
{
    MMI_HILOGI("Force clear all pointer visiable status");
    pidInfos_.clear();
    UpdatePointerVisible();
}

int32_t PointerDrawingManager::UpdateMouseLayer(const PointerStyle& pointerStyle,
    int32_t displayId, int32_t physicalX, int32_t physicalY)
{
    if (InitLayer(MOUSE_ICON(lastMouseStyle_.id)) != RET_OK) {
        mouseIconUpdate_ = false;
        MMI_HILOGE("Init layer failed");
        return RET_ERR;
    }
    if (!SetCursorLocation(displayId, physicalX, physicalY, MouseIcon2IconType(MOUSE_ICON(lastMouseStyle_.id)))) {
        return RET_ERR;
    }
    return RET_OK;
}

int32_t PointerDrawingManager::DrawMovePointer(int32_t displayId, int32_t physicalX, int32_t physicalY,
    PointerStyle pointerStyle, Direction direction)
{
    CHKPR(surfaceNode_, RET_ERR);
    MMI_HILOGD("Pointer window move success, pointerStyle id:%{public}d", pointerStyle.id);
    displayId_ = displayId;
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
    bool cursorEnlarged = MAGIC_POINTER_VELOCITY_TRACKER->GetCursorEnlargedStatus();
    if (cursorEnlarged) {
        MAGIC_POINTER_VELOCITY_TRACKER->SetLastPointerStyle(pointerStyle);
        MAGIC_POINTER_VELOCITY_TRACKER->SetDirection(direction);
        if (pointerStyle.id != MOUSE_ICON::DEFAULT && pointerStyle.id != MOUSE_ICON::CROSS) {
            pointerStyle.id = MOUSE_ICON::DEFAULT;
        }
    }
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
#ifdef OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    UpdateBindDisplayId(displayId);
#endif // OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    if (lastMouseStyle_ == pointerStyle && !mouseIconUpdate_ && lastDirection_ == direction) {
        if (!SetCursorLocation(displayId, physicalX, physicalY, MouseIcon2IconType(MOUSE_ICON(lastMouseStyle_.id)))) {
            return RET_ERR;
        }
        MMI_HILOGD("The lastpointerStyle is equal with pointerStyle, id:%{public}d, size:%{public}d",
            pointerStyle.id, pointerStyle.size);
        return RET_OK;
    }
    if (lastDirection_ != direction) {
        RotateDegree(direction);
        lastDirection_ = direction;
    }
    lastMouseStyle_ = pointerStyle;
#ifdef OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    CHKPR(hardwareCursorPointerManager_, RET_ERR);
    if (hardwareCursorPointerManager_->IsSupported()) {
        UpdatePointerVisible();
    } else {
        int32_t UpdateLayerRes = UpdateMouseLayer(pointerStyle, displayId, physicalX, physicalY);
        if (UpdateLayerRes != RET_OK) {
            MMI_HILOGE("Update Mouse Layer failed.");
        }
        UpdatePointerVisible();
    }
#else
    int32_t UpdateLayerRes = UpdateMouseLayer(pointerStyle, displayId, physicalX, physicalY);
    if (UpdateLayerRes != RET_OK) {
        MMI_HILOGE("Update Mouse Layer failed.");
    }
    UpdatePointerVisible();
#endif // OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    mouseIconUpdate_ = false;
    MMI_HILOGD("Leave, display:%{public}d, physicalX:%{public}d, physicalY:%{public}d",
        displayId, physicalX, physicalY);
    return RET_OK;
}

int32_t PointerDrawingManager::UpdateSurfaceNodeBounds(int32_t physicalX, int32_t physicalY)
{
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
    if (HasMagicCursor()) {
        if (currentMouseStyle_.id == DEVELOPER_DEFINED_ICON) {
            surfaceNode_->SetBounds(physicalX, physicalY,
                canvasWidth_, canvasHeight_);
        } else {
            CHKPR(surfaceNode_, RET_ERR);
            surfaceNode_->SetBounds(physicalX, physicalY,
                imageWidth_, imageHeight_);
        }
        return RET_OK;
    }
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
    return RET_ERR;
}

void PointerDrawingManager::DrawMovePointer(int32_t displayId, int32_t physicalX, int32_t physicalY)
{
    CALL_DEBUG_ENTER;
    if (surfaceNode_ != nullptr) {
        if (!SetCursorLocation(displayId, physicalX, physicalY, MouseIcon2IconType(MOUSE_ICON(lastMouseStyle_.id)))) {
            return;
        }
        MMI_HILOGD("Move pointer, physicalX:%d, physicalY:%d", physicalX, physicalY);
    }
}

void PointerDrawingManager::SetHardwareCursorPosition(int32_t displayId, int32_t physicalX, int32_t physicalY,
    PointerStyle pointerStyle)
{
#ifdef OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    CHKPV(hardwareCursorPointerManager_);
    if (g_isHdiRemoteDied) {
        hardwareCursorPointerManager_->SetHdiServiceState(false);
    }
    if (hardwareCursorPointerManager_->IsSupported() && lastMouseStyle_.id != MOUSE_ICON::LOADING &&
            lastMouseStyle_.id != MOUSE_ICON::RUNNING) {
        auto align = MouseIcon2IconType(MOUSE_ICON(lastMouseStyle_.id));
        HardwareCursorMove(physicalX, physicalY, align);
    }
#endif // OHOS_BUILD_ENABLE_HARDWARE_CURSOR
}

void PointerDrawingManager::DrawPointer(int32_t displayId, int32_t physicalX, int32_t physicalY,
    const PointerStyle pointerStyle, Direction direction)
{
    CALL_DEBUG_ENTER;
    MMI_HILOGD("Display:%{public}d, physicalX:%{public}d, physicalY:%{public}d, pointerStyle:%{public}d",
        displayId, physicalX, physicalY, pointerStyle.id);
    FixCursorPosition(physicalX, physicalY);
    lastPhysicalX_ = physicalX;
    lastPhysicalY_ = physicalY;
    currentMouseStyle_ = pointerStyle;
    currentDirection_ = direction;
    if (pointerStyle.id == MOUSE_ICON::DEFAULT && mouseIcons_[MOUSE_ICON(pointerStyle.id)].iconPath == CursorIconPath) {
        AdjustMouseFocus(direction, ICON_TYPE(mouseIcons_[MOUSE_ICON(MOUSE_ICON::CURSOR_CIRCLE)].alignmentWay),
            physicalX, physicalY);
    } else if (pointerStyle.id == MOUSE_ICON::DEFAULT &&
        mouseIcons_[MOUSE_ICON(pointerStyle.id)].iconPath == CustomCursorIconPath) {
            AdjustMouseFocus(direction,
                ICON_TYPE(mouseIcons_[MOUSE_ICON(MOUSE_ICON::AECH_DEVELOPER_DEFINED_ICON)].alignmentWay),
                    physicalX, physicalY);
    } else {
        AdjustMouseFocus(direction, ICON_TYPE(mouseIcons_[MOUSE_ICON(pointerStyle.id)].alignmentWay),
            physicalX, physicalY);
    }
    // Log printing only occurs when the mouse style changes
    if (currentMouseStyle_.id != lastMouseStyle_.id) {
        MMI_HILOGD("MagicCursor AdjustMouseFocus:%{public}d",
            ICON_TYPE(mouseIcons_[MOUSE_ICON(pointerStyle.id)].alignmentWay));
    }
    if (DrawMovePointer(displayId, physicalX, physicalY, pointerStyle, direction) == RET_OK) {
        return;
    }
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
    if (HasMagicCursor() && currentMouseStyle_.id != DEVELOPER_DEFINED_ICON) {
        MMI_HILOGD("magicCursor DrawPointer enter CreatePointerWindow");
        MAGIC_CURSOR->CreatePointerWindow(displayId, physicalX, physicalY, direction, surfaceNode_);
    } else {
        CreatePointerWindow(displayId, physicalX, physicalY, direction);
    }
#else
    CreatePointerWindow(displayId, physicalX, physicalY, direction);
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
    CHKPV(surfaceNode_);
    UpdateMouseStyle();
    if (InitLayer(MOUSE_ICON(lastMouseStyle_.id)) != RET_OK) {
        MMI_HILOGE("Init layer failed");
        return;
    }
    UpdatePointerVisible();
    SetHardwareCursorPosition(displayId, physicalX, physicalY, lastMouseStyle_);
    MMI_HILOGI("Leave, display:%{public}d, physicalX:%d, physicalY:%d", displayId, physicalX, physicalY);
}

void PointerDrawingManager::UpdateMouseStyle()
{
    CALL_DEBUG_ENTER;
    PointerStyle curPointerStyle;
    GetPointerStyle(pid_, GLOBAL_WINDOW_ID, curPointerStyle);
    if (curPointerStyle.id == CURSOR_CIRCLE_STYLE || curPointerStyle.id == AECH_DEVELOPER_DEFINED_STYLE) {
        lastMouseStyle_.id = curPointerStyle.id;
        return;
    }
}

int32_t PointerDrawingManager::SwitchPointerStyle()
{
    CALL_DEBUG_ENTER;
    int32_t size = GetPointerSize();
    if (size < MIN_POINTER_SIZE) {
        size = MIN_POINTER_SIZE;
    } else if (size > MAX_POINTER_SIZE) {
        size = MAX_POINTER_SIZE;
    }
    imageWidth_ = pow(INCREASE_RATIO, size - 1) * displayInfo_.dpi * GetIndependentPixels() / BASELINE_DENSITY;
    imageHeight_ = pow(INCREASE_RATIO, size - 1) * displayInfo_.dpi * GetIndependentPixels() / BASELINE_DENSITY;
    canvasWidth_ = (imageWidth_ / POINTER_WINDOW_INIT_SIZE + 1) * POINTER_WINDOW_INIT_SIZE;
    canvasHeight_ = (imageHeight_ / POINTER_WINDOW_INIT_SIZE + 1) * POINTER_WINDOW_INIT_SIZE;
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
    MAGIC_CURSOR->SetPointerSize(imageWidth_, imageHeight_);
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
    Direction direction = DIRECTION0;
    int32_t physicalX = lastPhysicalX_;
    int32_t physicalY = lastPhysicalY_;
    AdjustMouseFocus(
        direction, ICON_TYPE(GetIconStyle(MOUSE_ICON(lastMouseStyle_.id)).alignmentWay), physicalX, physicalY);
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
    if (HasMagicCursor()) {
        MAGIC_CURSOR->EnableCursorInversion();
        MAGIC_CURSOR->CreatePointerWindow(displayInfo_.uniqueId, physicalX, physicalY, direction, surfaceNode_);
    } else {
        MAGIC_CURSOR->DisableCursorInversion();
        CreatePointerWindow(displayInfo_.uniqueId, physicalX, physicalY, direction);
    }
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
    int32_t ret = InitLayer(MOUSE_ICON(lastMouseStyle_.id));
    if (ret != RET_OK) {
        MMI_HILOGE("Init layer failed");
        return ret;
    }
    UpdatePointerVisible();
    SetHardwareCursorPosition(displayInfo_.uniqueId, physicalX, physicalY, lastMouseStyle_);
    return RET_OK;
}

void PointerDrawingManager::CreateMagicCursorChangeObserver()
{
    // Listening enabling cursor deformation and color inversion
    SettingObserver::UpdateFunc func = [](const std::string& key) {
        bool statusValue = false;
        auto ret = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID).GetBoolValue(key, statusValue);
        if (ret != RET_OK) {
            MMI_HILOGE("Get value from setting date fail");
            return;
        }
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
        MAGIC_CURSOR->UpdateMagicCursorChangeState(statusValue);
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
    };
    std::string dynamicallyKey = "smartChange";
    sptr<SettingObserver> magicCursorChangeObserver = SettingDataShare::GetInstance(
        MULTIMODAL_INPUT_SERVICE_ID).CreateObserver(dynamicallyKey, func);
    ErrCode ret =
        SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID).RegisterObserver(magicCursorChangeObserver);
    if (ret != ERR_OK) {
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
        DfxHisysevent::ReportMagicCursorFault(dynamicallyKey, "Register setting observer failed");
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
        MMI_HILOGE("Register magic cursor change observer failed, ret:%{public}d", ret);
        magicCursorChangeObserver = nullptr;
    }
}

void PointerDrawingManager::UpdateStyleOptions()
{
    CALL_DEBUG_ENTER;
    PointerStyle curPointerStyle;
    WIN_MGR->GetPointerStyle(pid_, GLOBAL_WINDOW_ID, curPointerStyle);
    curPointerStyle.options = HasMagicCursor() ? MAGIC_STYLE_OPT : MOUSE_STYLE_OPT;
    int ret = WIN_MGR->SetPointerStyle(pid_, GLOBAL_WINDOW_ID, curPointerStyle);
    if (ret != RET_OK) {
        MMI_HILOGE("Set pointer style failed");
    }
}

void PointerDrawingManager::InitPointerObserver()
{
    CALL_INFO_TRACE;
    if (hasInitObserver_) {
        MMI_HILOGI("Settingdata observer has init");
        return;
    }
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
    int32_t ret = CreatePointerSwitchObserver(hasMagicCursor_);
    if (ret == RET_OK) {
        hasInitObserver_ = true;
        MMI_HILOGD("Create pointer switch observer success");
    }
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
}

int32_t PointerDrawingManager::CreatePointerSwitchObserver(isMagicCursor& item)
{
    CALL_DEBUG_ENTER;
    SettingObserver::UpdateFunc updateFunc = [this, &item](const std::string& key) {
        bool statusValue = false;
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
        statusValue = true;
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
        auto ret = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID).GetBoolValue(key, statusValue);
        if (ret != RET_OK) {
            MMI_HILOGE("Get value from setting date fail");
            return;
        }
        bool tmp = item.isShow;
        item.isShow = statusValue;
        this->UpdateStyleOptions();
        if (item.isShow != tmp) {
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
            MAGIC_CURSOR->InitRenderThread([]() { IPointerDrawingManager::GetInstance()->SwitchPointerStyle(); });
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
            CHKPV(surfaceNode_);
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
            MMI_HILOGD("Switch pointer style");
            int64_t nodeId = static_cast<int64_t>(this->surfaceNode_->GetId());
            if (nodeId != MAGIC_CURSOR->GetSurfaceNodeId(nodeId)) {
                MMI_HILOGI("DetachToDisplay start screenId_:%{public}" PRIu64, screenId_);
                surfaceNode_->DetachToDisplay(screenId_);
                surfaceNode_ = nullptr;
                Rosen::RSTransaction::FlushImplicitTransaction();
            }
            MAGIC_CURSOR->DetachDisplayNode();
            this->SwitchPointerStyle();
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
        }
    };
    sptr<SettingObserver> statusObserver =
        SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID).CreateObserver(item.name, updateFunc);
    ErrCode ret = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID).RegisterObserver(statusObserver);
    if (ret != ERR_OK) {
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
        DfxHisysevent::ReportMagicCursorFault(item.name, "Register setting observer failed");
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
        MMI_HILOGE("Register setting observer failed, ret:%{public}d", ret);
        statusObserver = nullptr;
        return RET_ERR;
    }
    CreateMagicCursorChangeObserver();
    return RET_OK;
}

bool PointerDrawingManager::HasMagicCursor()
{
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
    if (!MAGIC_CURSOR->isExistDefaultStyle) {
        MMI_HILOGE("MagicCursor default icon file is not exist");
        return false;
    }
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
    return hasMagicCursor_.isShow;
}
 
#ifdef OHOS_BUILD_ENABLE_HARDWARE_CURSOR
int32_t PointerDrawingManager::InitVsync(MOUSE_ICON mouseStyle)
{
    if (g_isReStartVsync) {
        isRenderRuning_.store(true);
        auto rsClient = std::static_pointer_cast<Rosen::RSRenderServiceClient>(
            Rosen::RSIRenderClient::CreateRenderServiceClient());
        CHKPR(rsClient, RET_ERR);
        receiver_ = rsClient->CreateVSyncReceiver(POINTER_CURSOR_RENDER_RECEIVER_NAME, handler_);
        if (receiver_ == nullptr || receiver_->Init() != VSYNC_ERROR_OK) {
            MMI_HILOGE("Receiver init failed");
            return RET_ERR;
        }
        g_isReStartVsync = false;
    }
    return RequestNextVSync();
}

sptr<OHOS::SurfaceBuffer> PointerDrawingManager::RetryGetSurfaceBuffer(sptr<OHOS::Surface> layer)
{
    sptr<OHOS::SurfaceBuffer> buffer;
    if (hardwareCursorPointerManager_->IsSupported()) {
        for (size_t i = 0; i < RETRY_TIMES; i++) {
            buffer = GetSurfaceBuffer(layer);
            if (buffer != nullptr && buffer->GetVirAddr() != nullptr) {
                return buffer;
            }
        }
    }
    return buffer;
}

int32_t PointerDrawingManager::GetMainScreenDisplayInfo(const DisplayGroupInfo &displayGroupInfo,
    DisplayInfo &mainScreenDisplayInfo) const
{
    if (displayGroupInfo.displaysInfo.empty()) {
        MMI_HILOGE("displayGroupInfo doesn't contain displayInfo");
        return RET_ERR;
    }
    for (const DisplayInfo& display : displayGroupInfo.displaysInfo) {
        if (display.screenCombination == OHOS::MMI::ScreenCombination::SCREEN_MAIN) {
            mainScreenDisplayInfo = display;
            return RET_OK;
        }
    }
    mainScreenDisplayInfo = displayGroupInfo.displaysInfo[0];
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_HARDWARE_CURSOR

int32_t PointerDrawingManager::InitLayer(const MOUSE_ICON mouseStyle)
{
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
    if (HasMagicCursor() && mouseStyle != MOUSE_ICON::DEVELOPER_DEFINED_ICON) {
        MMI_HILOGD("magiccursor enter MAGIC_CURSOR->Initlayer");
        return MAGIC_CURSOR->InitLayer(mouseStyle);
    }
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
#ifdef OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    CHKPR(hardwareCursorPointerManager_, RET_ERR);
    if (hardwareCursorPointerManager_->IsSupported()) {
        if ((mouseStyle == MOUSE_ICON::LOADING) || (mouseStyle == MOUSE_ICON::RUNNING)) {
            return InitVsync(mouseStyle);
        } else {
            GetCanvasSize();
            GetFocusCoordinates();
            hardwareCanvasSize_ = g_hardwareCanvasSize;
            // Change the drawing to asynchronous, and when obtaining the surfaceBuffer fails,
            // repeatedly obtain the surfaceBuffer.
            PostSoftCursorTask([this, mouseStyle]() {
                SoftwareCursorRender(mouseStyle);
            });
            HardwareCursorRender(mouseStyle);
            return RET_OK;
        }
    }
#endif // OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    return DrawCursor(mouseStyle);
}

int32_t PointerDrawingManager::DrawCursor(const MOUSE_ICON mouseStyle)
{
    CALL_DEBUG_ENTER;
    CHKPR(surfaceNode_, RET_ERR);
    DrawLoadingPointerStyle(mouseStyle);
    DrawRunningPointerAnimate(mouseStyle);
    sptr<OHOS::Surface> layer = GetLayer();
    if (layer == nullptr) {
        MMI_HILOGE("Init layer is failed, Layer is nullptr");
        surfaceNode_->DetachToDisplay(screenId_);
        surfaceNode_ = nullptr;
        Rosen::RSTransaction::FlushImplicitTransaction();
        MMI_HILOGE("Pointer window destroy success");
        return RET_ERR;
    }
    sptr<OHOS::SurfaceBuffer> buffer = GetSurfaceBuffer(layer);
    if (buffer == nullptr || buffer->GetVirAddr() == nullptr) {
        MMI_HILOGI("DetachToDisplay start screenId_:%{public}" PRIu64, screenId_);
        surfaceNode_->DetachToDisplay(screenId_);
        surfaceNode_ = nullptr;
        Rosen::RSTransaction::FlushImplicitTransaction();
        MMI_HILOGE("Pointer window destroy success");
        return RET_ERR;
    }

    CHKPR(buffer, RET_ERR);
    auto addr = static_cast<uint8_t *>(buffer->GetVirAddr());
    CHKPR(addr, RET_ERR);
    DoDraw(addr, buffer->GetWidth(), buffer->GetHeight(), mouseStyle);
    OHOS::BufferFlushConfig flushConfig = {
        .damage = {
            .w = buffer->GetWidth(),
            .h = buffer->GetHeight(),
        },
    };
    OHOS::SurfaceError ret = layer->FlushBuffer(buffer, DEFAULT_VALUE, flushConfig);
    if (ret != OHOS::SURFACE_ERROR_OK) {
        MMI_HILOGE("Init layer failed, FlushBuffer return ret:%{public}s", SurfaceErrorStr(ret).c_str());
        layer->CancelBuffer(buffer);
        return RET_ERR;
    }
    MMI_HILOGD("Init layer success");
    return RET_OK;
}

void PointerDrawingManager::DrawLoadingPointerStyle(const MOUSE_ICON mouseStyle)
{
    CALL_DEBUG_ENTER;
    CHKPV(surfaceNode_);
    Rosen::RSAnimationTimingProtocol protocol;
    if (mouseStyle != MOUSE_ICON::LOADING &&
        (mouseStyle != MOUSE_ICON::DEFAULT ||
            mouseIcons_[mouseStyle].iconPath != (IMAGE_POINTER_DEFAULT_PATH + "Loading.svg"))) {
        protocol.SetDuration(0);
        Rosen::RSNode::Animate(
            protocol,
            Rosen::RSAnimationTimingCurve::LINEAR,
            [this]() {
                if (!Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
                    RotateDegree(DIRECTION0);
                    return;
                }
                RotateDegree(currentDirection_);
            });
        MMI_HILOGE("Current pointer is not loading");
        Rosen::RSTransaction::FlushImplicitTransaction();
        return;
    }
    float ratio = imageWidth_ * 1.0 / canvasWidth_;
    surfaceNode_->SetPivot({LOADING_CENTER_RATIO * ratio, LOADING_CENTER_RATIO * ratio});
    protocol.SetDuration(ANIMATION_DURATION);
    protocol.SetRepeatCount(DEFAULT_VALUE);

    // create property animation
    Rosen::RSNode::Animate(
        protocol,
        Rosen::RSAnimationTimingCurve::LINEAR,
        [this]() { surfaceNode_->SetRotation(ROTATION_ANGLE); });

    Rosen::RSTransaction::FlushImplicitTransaction();
}

std::shared_ptr<Rosen::Drawing::ColorSpace> PointerDrawingManager::ConvertToColorSpace(
    Media::ColorSpace colorSpace)
{
    switch (colorSpace) {
        case Media::ColorSpace::DISPLAY_P3:
            return Rosen::Drawing::ColorSpace::CreateRGB(
                Rosen::Drawing::CMSTransferFuncType::SRGB, Rosen::Drawing::CMSMatrixType::DCIP3);
        case Media::ColorSpace::LINEAR_SRGB:
            return Rosen::Drawing::ColorSpace::CreateSRGBLinear();
        case Media::ColorSpace::SRGB:
            return Rosen::Drawing::ColorSpace::CreateSRGB();
        default:
            return Rosen::Drawing::ColorSpace::CreateSRGB();
    }
}

Rosen::Drawing::ColorType PointerDrawingManager::PixelFormatToColorType(Media::PixelFormat pixelFormat)
{
    switch (pixelFormat) {
        case Media::PixelFormat::RGB_565:
            return Rosen::Drawing::ColorType::COLORTYPE_RGB_565;
        case Media::PixelFormat::RGBA_8888:
            return Rosen::Drawing::ColorType::COLORTYPE_RGBA_8888;
        case Media::PixelFormat::BGRA_8888:
            return Rosen::Drawing::ColorType::COLORTYPE_BGRA_8888;
        case Media::PixelFormat::ALPHA_8:
            return Rosen::Drawing::ColorType::COLORTYPE_ALPHA_8;
        case Media::PixelFormat::RGBA_F16:
            return Rosen::Drawing::ColorType::COLORTYPE_RGBA_F16;
        case Media::PixelFormat::UNKNOWN:
        case Media::PixelFormat::ARGB_8888:
        case Media::PixelFormat::RGB_888:
        case Media::PixelFormat::NV21:
        case Media::PixelFormat::NV12:
        case Media::PixelFormat::CMYK:
        default:
            return Rosen::Drawing::ColorType::COLORTYPE_UNKNOWN;
    }
}

Rosen::Drawing::AlphaType PointerDrawingManager::AlphaTypeToAlphaType(Media::AlphaType alphaType)
{
    switch (alphaType) {
        case Media::AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN:
            return Rosen::Drawing::AlphaType::ALPHATYPE_UNKNOWN;
        case Media::AlphaType::IMAGE_ALPHA_TYPE_OPAQUE:
            return Rosen::Drawing::AlphaType::ALPHATYPE_OPAQUE;
        case Media::AlphaType::IMAGE_ALPHA_TYPE_PREMUL:
            return Rosen::Drawing::AlphaType::ALPHATYPE_PREMUL;
        case Media::AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL:
            return Rosen::Drawing::AlphaType::ALPHATYPE_UNPREMUL;
        default:
            return Rosen::Drawing::AlphaType::ALPHATYPE_UNKNOWN;
    }
}

static void PixelMapReleaseProc(const void* /* pixels */, void* context)
{
    PixelMapReleaseContext* ctx = static_cast<PixelMapReleaseContext*>(context);
    if (ctx != nullptr) {
        delete ctx;
    }
}

std::shared_ptr<Rosen::Drawing::Image> PointerDrawingManager::ExtractDrawingImage(
    std::shared_ptr<Media::PixelMap> pixelMap)
{
    CHKPP(pixelMap);
    Media::ImageInfo imageInfo;
    pixelMap->GetImageInfo(imageInfo);
    Rosen::Drawing::ImageInfo drawingImageInfo { imageInfo.size.width, imageInfo.size.height,
        PixelFormatToColorType(imageInfo.pixelFormat),
        AlphaTypeToAlphaType(imageInfo.alphaType),
        ConvertToColorSpace(imageInfo.colorSpace) };
    Rosen::Drawing::Pixmap imagePixmap(drawingImageInfo,
        reinterpret_cast<const void*>(pixelMap->GetPixels()), pixelMap->GetRowBytes());
    PixelMapReleaseContext* releaseContext = new (std::nothrow) PixelMapReleaseContext(pixelMap);
    CHKPP(releaseContext);
    auto image = Rosen::Drawing::Image::MakeFromRaster(imagePixmap, PixelMapReleaseProc, releaseContext);
    if (image == nullptr) {
        MMI_HILOGE("ExtractDrawingImage image fail");
        delete releaseContext;
    }
    return image;
}

#ifdef OHOS_BUILD_ENABLE_HARDWARE_CURSOR
void PointerDrawingManager::PostTask(std::function<void()> task)
{
    CHKPV(hardwareCursorPointerManager_);
    if (g_isHdiRemoteDied) {
        hardwareCursorPointerManager_->SetHdiServiceState(false);
    }
    if (handler_ != nullptr) {
        handler_->PostTask(task);
    }
}

void PointerDrawingManager::PostSoftCursorTask(std::function<void()> task)
{
    CHKPV(hardwareCursorPointerManager_);
    if (g_isHdiRemoteDied) {
        hardwareCursorPointerManager_->SetHdiServiceState(false);
    }
    if (softCursorHander_ != nullptr) {
        softCursorHander_->PostTask(task);
    }
}

void PointerDrawingManager::DrawDynamicHardwareCursor(std::shared_ptr<OHOS::Rosen::Drawing::Bitmap> bitmap,
    int32_t px, int32_t py, ICON_TYPE align)
{
    auto sp = GetScreenPointer(screenId_);
    CHKPV(sp);
    auto buffer = sp->RequestBuffer();
    CHKPV(buffer);
    auto addr = static_cast<uint8_t*>(buffer->GetVirAddr());
    CHKPV(addr);

    uint32_t addrSize = static_cast<uint32_t>(buffer->GetWidth()) *
        static_cast<uint32_t>(buffer->GetHeight()) * CURSOR_STRIDE;
    auto ret = memcpy_s(addr, addrSize, bitmap->GetPixels(), addrSize);
    if (ret != EOK) {
        MMI_HILOGE("memcpy_s failed, ret:%{public}d", ret);
        return;
    }
    for (auto &sp : GetMirrorScreenPointers()) {
        auto buf = sp->RequestBuffer();
        CHKPC(buf);
        auto addr = static_cast<uint8_t*>(buf->GetVirAddr());
        CHKPC(addr);
        ret = memcpy_s(addr, addrSize, bitmap->GetPixels(), addrSize);
        if (ret != EOK) {
            MMI_HILOGE("memcpy_s failed, ret:%{public}d", ret);
            return;
        }
    }
}

int32_t PointerDrawingManager::DrawDynamicHardwareCursor(std::shared_ptr<ScreenPointer> sp,
    const RenderConfig &cfg)
{
    CHKPR(sp, RET_ERR);
    auto buffer = sp->RequestBuffer();
    CHKPR(buffer, RET_ERR);
    auto addr = static_cast<uint8_t*>(buffer->GetVirAddr());
    CHKPR(addr, RET_ERR);
    pointerRenderer_.DynamicRender(addr, buffer->GetWidth(), buffer->GetHeight(), cfg);
    MMI_HILOGD("DrawDynamicHardwareCursor success, screenId_:%{public}" PRIu64, screenId_);
    return RET_OK;
}

void PointerDrawingManager::HardwareCursorDynamicRender(MOUSE_ICON mouseStyle)
{
    std::unordered_map<uint32_t, std::shared_ptr<ScreenPointer>> screenPointers;
    {
        std::lock_guard<std::mutex> lock(mtx_);
        screenPointers = screenPointers_;
    }
    RenderConfig cfg {
        .style = mouseStyle,
        .align = MouseIcon2IconType(mouseStyle),
        .path = mouseIcons_[mouseStyle].iconPath,
        .color = GetPointerColor(),
        .size = GetPointerSize(),
        .direction = displayInfo_.direction,
        .isHard = true,
        .rotationAngle = currentFrame_ * DYNAMIC_ROTATION_ANGLE,
        .userIconPixelMap = DecodeImageToPixelMap(mouseStyle),
    };
    for (auto it : screenPointers) {
        CHKPV(it.second);
        cfg.dpi = it.second->GetDPI() * it.second->GetScale();
        cfg.direction = it.second->IsMirror() ? DIRECTION0 : displayInfo_.direction;
        MMI_HILOGD("HardwareCursorRender, screen = %{public}u, dpi = %{public}f",
            it.first, cfg.dpi);
        if (it.second->IsMirror() || it.first == screenId_) {
            if (mouseStyle == MOUSE_ICON::LOADING) {
                cfg.rotationFocusX = GetFocusCoordinates();
                cfg.rotationFocusY = GetFocusCoordinates();
            } else {
                cfg.rotationFocusX = GetFocusCoordinates() + cfg.GetImageSize() * RUNNING_X_RATIO;
                cfg.rotationFocusY = GetFocusCoordinates() + cfg.GetImageSize() * RUNNING_Y_RATIO;
            }
            cfg.direction = it.second->IsMirror() ? DIRECTION0 : displayInfo_.direction;
            DrawDynamicHardwareCursor(it.second, cfg);
        } else {
            it.second->SetInvisible();
        }
    }
    MMI_HILOGD("HardwareCursorDynamicRender success");
}

int32_t PointerDrawingManager::DrawDynamicSoftCursor(std::shared_ptr<Rosen::RSSurfaceNode> sn,
    const RenderConfig &cfg)
{
    CHKPR(sn, RET_ERR);
    auto layer = sn->GetSurface();
    CHKPR(layer, RET_ERR);
    auto buffer = GetSurfaceBuffer(layer);
    CHKPR(buffer, RET_ERR);
    auto addr = static_cast<uint8_t*>(buffer->GetVirAddr());
    CHKPR(addr, RET_ERR);
    pointerRenderer_.DynamicRender(addr, buffer->GetWidth(), buffer->GetHeight(), cfg);

    OHOS::BufferFlushConfig flushConfig = {
        .damage = {
            .w = buffer->GetWidth(),
            .h = buffer->GetHeight(),
        }
    };
    OHOS::SurfaceError ret = layer->FlushBuffer(buffer, -1, flushConfig);
    if (ret != OHOS::SURFACE_ERROR_OK) {
        MMI_HILOGE("FlushBuffer failed, return: %{public}s", SurfaceErrorStr(ret).data());
        layer->CancelBuffer(buffer);
        return RET_ERR;
    }
    MMI_HILOGD("DrawDynamicSoftCursor on sn success");
    return RET_OK;
}

void PointerDrawingManager::SoftwareCursorDynamicRender(MOUSE_ICON mouseStyle)
{
    std::unordered_map<uint32_t, std::shared_ptr<ScreenPointer>> screenPointers;
    {
        std::lock_guard<std::mutex> lock(mtx_);
        screenPointers = screenPointers_;
    }
    for (auto it : screenPointers) {
        RenderConfig cfg {
            .style = mouseStyle,
            .align = MouseIcon2IconType(mouseStyle),
            .path = mouseIcons_[mouseStyle].iconPath,
            .color = GetPointerColor(),
            .size = GetPointerSize(),
            .direction = displayInfo_.direction,
            .isHard = false,
            .rotationAngle = currentFrame_ * DYNAMIC_ROTATION_ANGLE,
        };
        CHKPV(it.second);
        auto sn = it.second->GetSurfaceNode();
        cfg.dpi = it.second->GetDPI();
        MMI_HILOGD("SoftwareCursorDynamicRender, screen = %{public}u, dpi = %{public}f",
            it.first, cfg.dpi);
        if (it.second->IsMirror() || it.first == screenId_) {
            if (mouseStyle == MOUSE_ICON::LOADING) {
                cfg.rotationFocusX = GetFocusCoordinates();
                cfg.rotationFocusY = GetFocusCoordinates();
            } else {
                cfg.rotationFocusX = GetFocusCoordinates() + cfg.GetImageSize() * RUNNING_X_RATIO;
                cfg.rotationFocusY = GetFocusCoordinates() + cfg.GetImageSize() * RUNNING_Y_RATIO;
            }
            DrawDynamicSoftCursor(sn, cfg);
        } else {
            cfg.style = MOUSE_ICON::TRANSPARENT_ICON;
            cfg.align = MouseIcon2IconType(cfg.style);
            cfg.path = mouseIcons_[cfg.style].iconPath;
            DrawDynamicSoftCursor(it.second->GetSurfaceNode(), cfg);
        }
    }
}

void PointerDrawingManager::OnVsync(uint64_t timestamp)
{
    if (currentMouseStyle_.id != MOUSE_ICON::RUNNING && currentMouseStyle_.id != MOUSE_ICON::LOADING) {
        MMI_HILOGE("Current mouse style is not equal to last mouse style");
        return;
    }
    PostTask([this]() -> void {
        if (currentMouseStyle_.id != MOUSE_ICON::RUNNING && currentMouseStyle_.id != MOUSE_ICON::LOADING) {
            MMI_HILOGE("Current post task mouse style is not equal to last mouse style");
            return;
        }

        HardwareCursorDynamicRender(MOUSE_ICON(currentMouseStyle_.id));
        HardwareCursorMove(lastPhysicalX_, lastPhysicalY_, MouseIcon2IconType(MOUSE_ICON(currentMouseStyle_.id)));
        PostSoftCursorTask([this]() {
            SoftwareCursorDynamicRender(MOUSE_ICON(currentMouseStyle_.id));
            SoftwareCursorMove(lastPhysicalX_, lastPhysicalY_, MouseIcon2IconType(MOUSE_ICON(currentMouseStyle_.id)));
        });
        currentFrame_++;
        if (currentFrame_ == frameCount_) {
            currentFrame_ = 0;
        }
        mouseIconUpdate_ = false;
    });
    RequestNextVSync();
}

int32_t PointerDrawingManager::RequestNextVSync()
{
    if (handler_ != nullptr) {
        Rosen::VSyncReceiver::FrameCallback fcb = {
            .userData_ = this,
            .callback_ = [this] (uint64_t timestamp, void*) {
                return this->OnVsync(timestamp);
            },
        };
        if (receiver_ != nullptr) {
            receiver_->RequestNextVSync(fcb);
            return RET_OK;
        }
    }
    return RET_ERR;
}

void PointerDrawingManager::RenderThreadLoop()
{
    isRenderRuning_.store(true);
    runner_ = AppExecFwk::EventRunner::Create(false);
    CHKPV(runner_);
    handler_ = std::make_shared<AppExecFwk::EventHandler>(runner_);
    CHKPV(handler_);
    auto rsClient = std::static_pointer_cast<Rosen::RSRenderServiceClient>(
        Rosen::RSIRenderClient::CreateRenderServiceClient());
    CHKPV(rsClient);
    receiver_ = rsClient->CreateVSyncReceiver(POINTER_CURSOR_RENDER_RECEIVER_NAME, handler_);
    if (receiver_ == nullptr || receiver_->Init() != VSYNC_ERROR_OK) {
        MMI_HILOGE("Receiver init failed");
        return;
    }
    if (runner_ != nullptr) {
        MMI_HILOGI("Runner is run");
        runner_->Run();
    }
}

void PointerDrawingManager::SoftCursorRenderThreadLoop()
{
    softCursorRunner_ = AppExecFwk::EventRunner::Create(false);
    CHKPV(softCursorRunner_);
    softCursorHander_ = std::make_shared<AppExecFwk::EventHandler>(softCursorRunner_);
    CHKPV(softCursorHander_);
    if (softCursorRunner_ != nullptr) {
        MMI_HILOGI("Runner is run");
        softCursorRunner_->Run();
    }
}
#endif // OHOS_BUILD_ENABLE_HARDWARE_CURSOR

void PointerDrawingManager::DrawRunningPointerAnimate(const MOUSE_ICON mouseStyle)
{
    CALL_DEBUG_ENTER;
    CHKPV(surfaceNode_);
    CHKPV(canvasNode_);
    if (mouseStyle != MOUSE_ICON::RUNNING && (mouseStyle != MOUSE_ICON::DEFAULT ||
            mouseIcons_[mouseStyle].iconPath != (IMAGE_POINTER_DEFAULT_PATH + "Loading_Left.svg"))) {
        if (canvasNode_ != nullptr) {
            Rosen::RSAnimationTimingProtocol protocol;
            protocol.SetDuration(0);
            Rosen::RSNode::Animate(
                protocol,
                Rosen::RSAnimationTimingCurve::LINEAR,
                [this]() { canvasNode_->SetRotation(0); });
            Rosen::RSTransaction::FlushImplicitTransaction();
            canvasNode_->SetVisible(false);
        }
        MMI_HILOGE("current pointer is not running");
        return;
    }
    canvasNode_->SetVisible(true);
    float ratio = imageWidth_ * 1.0 / canvasWidth_;
    canvasNode_->SetPivot({RUNNING_X_RATIO * ratio, RUNNING_Y_RATIO * ratio});
    std::shared_ptr<OHOS::Media::PixelMap> pixelmap =
        DecodeImageToPixelMap(MOUSE_ICON::RUNNING_RIGHT);
    CHKPV(pixelmap);
    MMI_HILOGD("Set mouseicon to OHOS system");

#ifndef USE_ROSEN_DRAWING
    auto canvas = static_cast<Rosen::RSRecordingCanvas *>(canvasNode_->BeginRecording(imageWidth_, imageHeight_));
    canvas->DrawPixelMap(pixelmap, 0, 0, SkSamplingOptions(), nullptr);
#else
    Rosen::Drawing::Brush brush;
    Rosen::Drawing::Rect src = Rosen::Drawing::Rect(0, 0, pixelmap->GetWidth(), pixelmap->GetHeight());
    Rosen::Drawing::Rect dst = Rosen::Drawing::Rect(src);
    auto canvas =
        static_cast<Rosen::ExtendRecordingCanvas *>(canvasNode_->BeginRecording(imageWidth_, imageHeight_));
    canvas->AttachBrush(brush);
    canvas->DrawPixelMapRect(pixelmap, src, dst, Rosen::Drawing::SamplingOptions());
    canvas->DetachBrush();
#endif // USE_ROSEN_DRAWING

    canvasNode_->FinishRecording();

    Rosen::RSAnimationTimingProtocol protocol;
    protocol.SetDuration(ANIMATION_DURATION);
    protocol.SetRepeatCount(DEFAULT_VALUE);

    // create property animation
    Rosen::RSNode::Animate(
        protocol,
        Rosen::RSAnimationTimingCurve::LINEAR,
        [this]() { canvasNode_->SetRotation(ROTATION_ANGLE); });

    Rosen::RSTransaction::FlushImplicitTransaction();
}

void PointerDrawingManager::AdjustMouseFocus(Direction direction, ICON_TYPE iconType,
    int32_t &physicalX, int32_t &physicalY)
{
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    CHKPV(hardwareCursorPointerManager_);
    if (hardwareCursorPointerManager_->IsSupported()) {
        return;
    }
#endif // OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    switch (direction) {
        case DIRECTION0: {
            AdjustMouseFocusByDirection0(iconType, physicalX, physicalY);
            break;
        }
        case DIRECTION90: {
            AdjustMouseFocusByDirection90(iconType, physicalX, physicalY);
            break;
        }
        case DIRECTION180: {
            AdjustMouseFocusByDirection180(iconType, physicalX, physicalY);
            break;
        }
        case DIRECTION270: {
            AdjustMouseFocusByDirection270(iconType, physicalX, physicalY);
            break;
        }
        default: {
            MMI_HILOGW("direction is invalid,direction:%{public}d", direction);
            break;
        }
    }
}

void PointerDrawingManager::AdjustMouseFocusByDirection0(ICON_TYPE iconType, int32_t &physicalX, int32_t &physicalY)
{
    CALL_DEBUG_ENTER;
    int32_t height = imageHeight_;
    int32_t width = imageWidth_;
#ifdef OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    CHKPV(hardwareCursorPointerManager_);
    if (hardwareCursorPointerManager_->IsSupported() &&
        currentMouseStyle_.id == MOUSE_ICON::DEVELOPER_DEFINED_ICON) {
        height = cursorHeight_;
        width = cursorWidth_;
    }
#endif // OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    switch (iconType) {
        case ANGLE_SW: {
            physicalY -= height;
            break;
        }
        case ANGLE_CENTER: {
            physicalX -= width / CALCULATE_MIDDLE;
            physicalY -= height / CALCULATE_MIDDLE;
            break;
        }
        case ANGLE_NW_RIGHT: {
            physicalX -= width * MOUSE_ICON_BIAS_RATIO;
            [[fallthrough]];
        }
        case ANGLE_NW: {
            if (currentMouseStyle_.id == MOUSE_ICON::DEVELOPER_DEFINED_ICON) {
                if (GetUserIconCopy() != nullptr) {
                    physicalX -= userIconHotSpotX_;
                    physicalY -= userIconHotSpotY_;
                }
            }
            break;
        }
        default: {
            MMI_HILOGW("No need adjust mouse focus,iconType:%{public}d", iconType);
            break;
        }
    }
}

void PointerDrawingManager::AdjustMouseFocusByDirection90(ICON_TYPE iconType, int32_t &physicalX, int32_t &physicalY)
{
    CALL_DEBUG_ENTER;
    int32_t height = imageHeight_;
    int32_t width = imageWidth_;
#ifdef OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    CHKPV(hardwareCursorPointerManager_);
    if (hardwareCursorPointerManager_->IsSupported() &&
        currentMouseStyle_.id == MOUSE_ICON::DEVELOPER_DEFINED_ICON) {
        height = cursorHeight_;
        width = cursorWidth_;
    }
#endif // OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    switch (iconType) {
        case ANGLE_SW: {
            physicalY += height;
            break;
        }
        case ANGLE_CENTER: {
            physicalX -= width / CALCULATE_MIDDLE;
            physicalY += height / CALCULATE_MIDDLE;
            break;
        }
        case ANGLE_NW_RIGHT: {
            physicalX -= width * MOUSE_ICON_BIAS_RATIO;
            [[fallthrough]];
        }
        case ANGLE_NW: {
            if (currentMouseStyle_.id == MOUSE_ICON::DEVELOPER_DEFINED_ICON) {
                if (GetUserIconCopy() != nullptr) {
                    physicalX -= userIconHotSpotX_;
                    physicalY += userIconHotSpotY_;
                }
            }
            break;
        }
        default: {
            MMI_HILOGW("No need adjust mouse focus,iconType:%{public}d", iconType);
            break;
        }
    }
}

void PointerDrawingManager::AdjustMouseFocusByDirection180(ICON_TYPE iconType, int32_t &physicalX, int32_t &physicalY)
{
    CALL_DEBUG_ENTER;
    int32_t height = imageHeight_;
    int32_t width = imageWidth_;
#ifdef OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    CHKPV(hardwareCursorPointerManager_);
    if (hardwareCursorPointerManager_->IsSupported() &&
        currentMouseStyle_.id == MOUSE_ICON::DEVELOPER_DEFINED_ICON) {
        height = cursorHeight_;
        width = cursorWidth_;
    }
#endif // OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    switch (iconType) {
        case ANGLE_SW: {
            physicalY += height;
            break;
        }
        case ANGLE_CENTER: {
            physicalX += width / CALCULATE_MIDDLE;
            physicalY += height / CALCULATE_MIDDLE;
            break;
        }
        case ANGLE_NW_RIGHT: {
            physicalX += width * MOUSE_ICON_BIAS_RATIO;
            [[fallthrough]];
        }
        case ANGLE_NW: {
            if (currentMouseStyle_.id == MOUSE_ICON::DEVELOPER_DEFINED_ICON) {
                if (GetUserIconCopy() != nullptr) {
                    physicalX += userIconHotSpotX_;
                    physicalY += userIconHotSpotY_;
                }
            }
            break;
        }
        default: {
            MMI_HILOGW("No need adjust mouse focus,iconType:%{public}d", iconType);
            break;
        }
    }
}

void PointerDrawingManager::AdjustMouseFocusByDirection270(ICON_TYPE iconType, int32_t &physicalX, int32_t &physicalY)
{
    CALL_DEBUG_ENTER;
    int32_t height = imageHeight_;
    int32_t width = imageWidth_;
#ifdef OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    CHKPV(hardwareCursorPointerManager_);
    if (hardwareCursorPointerManager_->IsSupported() &&
        currentMouseStyle_.id == MOUSE_ICON::DEVELOPER_DEFINED_ICON) {
        height = cursorHeight_;
        width = cursorWidth_;
    }
#endif // OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    switch (iconType) {
        case ANGLE_SW: {
            physicalY -= height;
            break;
        }
        case ANGLE_CENTER: {
            physicalX += width / CALCULATE_MIDDLE;
            physicalY -= height / CALCULATE_MIDDLE;
            break;
        }
        case ANGLE_NW_RIGHT: {
            physicalX += width * MOUSE_ICON_BIAS_RATIO;
            [[fallthrough]];
        }
        case ANGLE_NW: {
            if (currentMouseStyle_.id == MOUSE_ICON::DEVELOPER_DEFINED_ICON) {
                if (GetUserIconCopy() != nullptr) {
                    physicalX += userIconHotSpotX_;
                    physicalY -= userIconHotSpotY_;
                }
            }
            break;
        }
        default: {
            MMI_HILOGW("No need adjust mouse focus,iconType:%{public}d", iconType);
            break;
        }
    }
}

void PointerDrawingManager::SetMouseDisplayState(bool state)
{
    CALL_DEBUG_ENTER;
    if (mouseDisplayState_ != state) {
        mouseDisplayState_ = state;
        if (mouseDisplayState_) {
#ifdef OHOS_BUILD_ENABLE_HARDWARE_CURSOR
            CHKPV(hardwareCursorPointerManager_);
            if (!hardwareCursorPointerManager_->IsSupported()) {
                InitLayer(MOUSE_ICON(lastMouseStyle_.id));
            }
#else
            InitLayer(MOUSE_ICON(lastMouseStyle_.id));
#endif // OHOS_BUILD_ENABLE_HARDWARE_CURSOR
        }
        MMI_HILOGI("The state:%{public}s", state ? "true" : "false");
        UpdatePointerVisible();
    }
}

bool PointerDrawingManager::GetMouseDisplayState() const
{
    return mouseDisplayState_;
}

void PointerDrawingManager::FixCursorPosition(int32_t &physicalX, int32_t &physicalY)
{
    if (physicalX < 0) {
        physicalX = 0;
    }

    if (physicalY < 0) {
        physicalY = 0;
    }
    const int32_t cursorUnit = 16;
    Direction direction = static_cast<Direction>((
        ((displayInfo_.direction - displayInfo_.displayDirection) * ANGLE_90 + ANGLE_360) % ANGLE_360) / ANGLE_90);
#ifdef OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    CHKPV(hardwareCursorPointerManager_);
    if (g_isHdiRemoteDied) {
        hardwareCursorPointerManager_->SetHdiServiceState(false);
    }
    if (hardwareCursorPointerManager_->IsSupported()) {
        direction = displayInfo_.direction;
    }
#endif // OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    if (!Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        direction = displayInfo_.direction;
    }
#ifdef OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    if (!hardwareCursorPointerManager_->IsSupported()) {
        return;
    }
    if (direction == DIRECTION0) {
        if (physicalX > (displayInfo_.validWidth - imageWidth_ / cursorUnit)) {
            physicalX = displayInfo_.validWidth - imageWidth_ / cursorUnit;
        }
        if (physicalY > (displayInfo_.validHeight - imageHeight_ / cursorUnit)) {
            physicalY = displayInfo_.validHeight - imageHeight_ / cursorUnit;
        }
    } else if (direction == DIRECTION90) {
        if (physicalX > (displayInfo_.validHeight - imageHeight_ / cursorUnit)) {
            physicalX = displayInfo_.validHeight - imageHeight_ / cursorUnit;
        }
        if (physicalY < imageWidth_ / cursorUnit) {
            physicalY = imageWidth_ / cursorUnit;
        }
    } else if (direction == DIRECTION180) {
        if (physicalX < imageHeight_ / cursorUnit) {
            physicalX = imageHeight_ / cursorUnit;
        }
        if (physicalY < imageWidth_ / cursorUnit) {
            physicalY = imageWidth_ / cursorUnit;
        }
    } else if (direction == DIRECTION270) {
        if (physicalX < imageHeight_ / cursorUnit) {
            physicalX = imageHeight_ / cursorUnit;
        }
        if (physicalY > (displayInfo_.validWidth - imageWidth_ / cursorUnit)) {
            physicalY = displayInfo_.validWidth - imageWidth_ / cursorUnit;
        }
    }
#else
    if (direction == DIRECTION0 || direction == DIRECTION180) {
        if (physicalX > (displayInfo_.validWidth - imageWidth_ / cursorUnit)) {
            physicalX = displayInfo_.validWidth - imageWidth_ / cursorUnit;
        }
        if (physicalY > (displayInfo_.validHeight - imageHeight_ / cursorUnit)) {
            physicalY = displayInfo_.validHeight - imageHeight_ / cursorUnit;
        }
    } else {
        if (physicalX > (displayInfo_.validHeight - imageHeight_ / cursorUnit)) {
            physicalX = displayInfo_.validHeight - imageHeight_ / cursorUnit;
        }
        if (physicalY > (displayInfo_.validWidth - imageWidth_ / cursorUnit)) {
            physicalY = displayInfo_.validWidth - imageWidth_ / cursorUnit;
        }
    }
#endif // OHOS_BUILD_ENABLE_HARDWARE_CURSOR
}

void PointerDrawingManager::AttachToDisplay()
{
    CALL_DEBUG_ENTER;
    CHKPV(surfaceNode_);
    if (IsSingleDisplayFoldDevice() && (WIN_MGR->GetDisplayMode() == DisplayMode::MAIN)
        && (screenId_ == FOLD_SCREEN_ID_FULL)) {
        screenId_ = FOLD_SCREEN_ID_MAIN;
    }
    MMI_HILOGI("The screenId_:%{public}" PRIu64"", screenId_);

#ifdef OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    CHKPV(hardwareCursorPointerManager_);
    if (g_isHdiRemoteDied) {
        hardwareCursorPointerManager_->SetHdiServiceState(false);
    }
    if (hardwareCursorPointerManager_->IsSupported()) {
        auto sp = GetScreenPointer(screenId_);
        CHKPV(sp);
        surfaceNode_ = sp->GetSurfaceNode();
        if (originSetColor_ != -1 && surfaceNode_ != nullptr) {
            float alphaRatio = (static_cast<uint32_t>(originSetColor_) >> RGB_CHANNEL_BITS_LENGTH) / MAX_ALPHA_VALUE;
            if (alphaRatio > 1) {
                MMI_HILOGW("Invalid alphaRatio:%{public}f", alphaRatio);
            } else {
                surfaceNode_->SetAlpha(1 - alphaRatio);
            }
        }
    }
#endif // OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    surfaceNode_->AttachToDisplay(screenId_);
}

void PointerDrawingManager::CreateCanvasNode()
{
#ifdef OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    CHKPV(hardwareCursorPointerManager_);
    if (g_isHdiRemoteDied) {
        hardwareCursorPointerManager_->SetHdiServiceState(false);
    }
    if (hardwareCursorPointerManager_->IsSupported()) {
        return;
    }
#endif // OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    CHKPV(surfaceNode_);
    canvasNode_ = Rosen::RSCanvasNode::Create();
    CHKPV(canvasNode_);
    canvasNode_->SetBounds(0, 0, canvasWidth_, canvasHeight_);
    canvasNode_->SetFrame(0, 0, canvasWidth_, canvasHeight_);
#ifndef USE_ROSEN_DRAWING
    canvasNode_->SetBackgroundColor(SK_ColorTRANSPARENT);
#else
    canvasNode_->SetBackgroundColor(Rosen::Drawing::Color::COLOR_TRANSPARENT);
#endif // USE_ROSEN_DRAWING
    canvasNode_->SetCornerRadius(1);
    canvasNode_->SetPositionZ(Rosen::RSSurfaceNode::POINTER_WINDOW_POSITION_Z);
    canvasNode_->SetRotation(0);
    surfaceNode_->AddChild(canvasNode_, DEFAULT_VALUE);
}

#ifdef OHOS_BUILD_ENABLE_HARDWARE_CURSOR
int32_t PointerDrawingManager::CreatePointerWindowForScreenPointer(int32_t displayId,
    int32_t physicalX, int32_t physicalY)
{
    CALL_DEBUG_ENTER;
    // suface node init
    std::shared_ptr<ScreenPointer> sp = nullptr;
    {
        if (screenPointers_.count(displayId)) {
            sp = screenPointers_[displayId];
            if (!g_isRsRestart) {
                for (auto it : screenPointers_) {
                    CHKPR(it.second, RET_ERR);
                    it.second->Init();
                }
                if (displayId == displayInfo_.uniqueId) {
                    surfaceNode_ = sp->GetSurfaceNode();
                }
                Rosen::RSTransaction::FlushImplicitTransaction();
                g_isRsRestart = true;
            }
        } else {
            g_isRsRestart = true;
            sp = std::make_shared<ScreenPointer>(hardwareCursorPointerManager_, handler_, displayInfo_);
            screenPointers_[displayInfo_.uniqueId] = sp;
            CHKPR(sp, RET_ERR);
            if (!sp->Init()) {
                MMI_HILOGE("ScreenPointer %{public}d init failed", displayInfo_.uniqueId);
                return RET_ERR;
            }
            if (displayId == displayInfo_.uniqueId) {
                surfaceNode_ = sp->GetSurfaceNode();
            }
            MMI_HILOGI("ScreenPointer displayId %{public}d displayInfo_.uniqueId %{public}d",
                displayId, displayInfo_.uniqueId);
            Rosen::RSTransaction::FlushImplicitTransaction();
        }
    }
    CHKPR(sp, RET_ERR);
    surfaceNode_ = sp->GetSurfaceNode(); // use SurfaceNode from current display
    CHKPR(surfaceNode_, RET_ERR);
    sp->MoveSoft(physicalX, physicalY, MouseIcon2IconType(MOUSE_ICON(lastMouseStyle_.id)));
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_HARDWARE_CURSOR
 
int32_t PointerDrawingManager::CreatePointerWindowForNoScreenPointer(int32_t displayId,
    int32_t physicalX, int32_t physicalY)
{
    CALL_DEBUG_ENTER;
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    CHKPR(surfaceNode_, RET_ERR);
    surfaceNode_->SetPositionZ(Rosen::RSSurfaceNode::POINTER_WINDOW_POSITION_Z);
    surfaceNode_->SetFrameGravity(Rosen::Gravity::RESIZE_ASPECT_FILL);
    surfaceNode_->SetBounds(physicalX, physicalY, canvasWidth_, canvasHeight_);
#ifndef USE_ROSEN_DRAWING
    surfaceNode_->SetBackgroundColor(SK_ColorTRANSPARENT);
#else
    surfaceNode_->SetBackgroundColor(Rosen::Drawing::Color::COLOR_TRANSPARENT);
#endif
    return RET_OK;
}

void PointerDrawingManager::CreatePointerWindow(int32_t displayId, int32_t physicalX, int32_t physicalY,
    Direction direction)
{
    CALL_DEBUG_ENTER;
    CALL_INFO_TRACE;
    BytraceAdapter::StartRsSurfaceNode(displayId);

#ifdef OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    CHKPV(hardwareCursorPointerManager_);
    if (g_isHdiRemoteDied) {
        hardwareCursorPointerManager_->SetHdiServiceState(false);
    }
    if (hardwareCursorPointerManager_->IsSupported()) {
        g_isHdiRemoteDied = false;
        if (CreatePointerWindowForScreenPointer(displayId, physicalX, physicalY) != RET_OK) {
            return;
        }
    } else {
        if (CreatePointerWindowForNoScreenPointer(displayId, physicalX, physicalY) != RET_OK) {
            return;
        }
    }
#else
    if (CreatePointerWindowForNoScreenPointer(displayId, physicalX, physicalY) != RET_OK) {
        return;
    }
#endif // OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    MMI_HILOGI("CreatePointerWindow The screenId_:%{public}" PRIu64, screenId_);
    screenId_ = static_cast<uint64_t>(displayId);
    AttachToDisplay();
    lastDisplayId_ = displayId;
    RotateDegree(direction);
    lastDirection_ = direction;
    CreateCanvasNode();
    Rosen::RSTransaction::FlushImplicitTransaction();
    BytraceAdapter::StopRsSurfaceNode();
}

sptr<OHOS::Surface> PointerDrawingManager::GetLayer()
{
    CALL_DEBUG_ENTER;
    CHKPP(surfaceNode_);
    return surfaceNode_->GetSurface();
}

sptr<OHOS::SurfaceBuffer> PointerDrawingManager::GetSurfaceBuffer(sptr<OHOS::Surface> layer)
{
    CALL_DEBUG_ENTER;
    sptr<OHOS::SurfaceBuffer> buffer;
    int32_t releaseFence = -1;
    int32_t width = 0;
    int32_t height = 0;
#ifdef OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    CHKPP(hardwareCursorPointerManager_);
    if (g_isHdiRemoteDied) {
        hardwareCursorPointerManager_->SetHdiServiceState(false);
    }
    if (hardwareCursorPointerManager_->IsSupported()) {
        CALCULATE_CANVAS_SIZE(CALCULATE_CANVAS_SIZE_, CHANGE) = GetCanvasSize();
        auto canvasSize = static_cast<int32_t>(CALCULATE_CANVAS_SIZE_CHANGE);
        width = canvasSize;
        height = canvasSize;
    } else {
        width = canvasWidth_;
        height = canvasHeight_;
    }
#else
    width = canvasWidth_;
    height = canvasHeight_;
#endif // OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    OHOS::BufferRequestConfig config = {
        .width = width,
        .height = height,
        .strideAlignment = 0x8,
        .format = GRAPHIC_PIXEL_FMT_RGBA_8888,
        .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA,
        .timeout = 150,
    };

    OHOS::SurfaceError ret = layer->RequestBuffer(buffer, releaseFence, config);
    if (ret != OHOS::SURFACE_ERROR_OK) {
        MMI_HILOGE("Request buffer ret:%{public}s", SurfaceErrorStr(ret).c_str());
        return nullptr;
    }
    sptr<OHOS::SyncFence> tempFence = new OHOS::SyncFence(releaseFence);
    if (tempFence != nullptr && (tempFence->Wait(SYNC_FENCE_WAIT_TIME) < 0)) {
        MMI_HILOGE("Failed to create surface, this buffer is not available");
    }
    return buffer;
}

void PointerDrawingManager::DrawImage(OHOS::Rosen::Drawing::Canvas &canvas, MOUSE_ICON mouseStyle)
{
    MMI_HILOGI("Draw mouse icon of style(%{public}d)", static_cast<int32_t>(mouseStyle));
    OHOS::Rosen::Drawing::Pen pen;
    pen.SetAntiAlias(true);
    pen.SetColor(OHOS::Rosen::Drawing::Color::COLOR_BLUE);
    OHOS::Rosen::Drawing::scalar penWidth = 1;
    pen.SetWidth(penWidth);
    canvas.AttachPen(pen);
    std::shared_ptr<Rosen::Drawing::Image> image = nullptr;
    std::shared_ptr<OHOS::Media::PixelMap> pixelmap = nullptr;
    if (mouseStyle == MOUSE_ICON::DEVELOPER_DEFINED_ICON) {
        MMI_HILOGD("Set mouseicon by userIcon_");
        auto userIconCopy = GetUserIconCopy();
        image = ExtractDrawingImage(userIconCopy);
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
        SetPixelMap(userIconCopy);
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
    } else {
        surfaceNode_->SetBounds(lastPhysicalX_, lastPhysicalY_, canvasWidth_, canvasHeight_);
        if (mouseStyle == MOUSE_ICON::RUNNING) {
            pixelmap = DecodeImageToPixelMap(MOUSE_ICON::RUNNING_LEFT);
        } else {
            pixelmap = DecodeImageToPixelMap(mouseStyle);
        }
        CHKPV(pixelmap);
        image = ExtractDrawingImage(pixelmap);
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
        if ((mouseStyle == MOUSE_ICON::DEFAULT) || (mouseStyle == MOUSE_ICON::CURSOR_CIRCLE) ||
             (mouseStyle == MOUSE_ICON::AECH_DEVELOPER_DEFINED_ICON)) {
            SetPixelMap(pixelmap);
        }
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
    }
    CHKPV(image);
    OHOS::Rosen::Drawing::Brush brush;
    brush.SetColor(Rosen::Drawing::Color::COLOR_TRANSPARENT);
    canvas.DrawBackground(brush);
    canvas.DrawImage(*image, IMAGE_PIXEL, IMAGE_PIXEL, Rosen::Drawing::SamplingOptions());
    MMI_HILOGD("Canvas draw image, success");
}

#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
void PointerDrawingManager::SetPixelMap(std::shared_ptr<OHOS::Media::PixelMap> pixelMap)
{
    MMI_HILOGI("Set pointer snapshot");
    pixelMap_ = pixelMap;
}

int32_t PointerDrawingManager::GetPointerSnapshot(void *pixelMapPtr)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<Media::PixelMap> *newPixelMapPtr = static_cast<std::shared_ptr<Media::PixelMap> *>(pixelMapPtr);
    MMI_HILOGI("Get pointer snapshot");
    *newPixelMapPtr = pixelMap_;
    if (HasMagicCursor()) {
        MMI_HILOGE("magic pixelmap");
        *newPixelMapPtr = MAGIC_CURSOR->GetPixelMap();
    }
    CHKPR(*newPixelMapPtr, ERROR_NULL_POINTER);
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR

void PointerDrawingManager::DoDraw(uint8_t *addr, uint32_t width, uint32_t height, const MOUSE_ICON mouseStyle)
{
    CALL_DEBUG_ENTER;
    CHKPV(addr);

    const uint32_t addrSize = width * height * CURSOR_STRIDE;

    currentFrame_ = 0;
    OHOS::Rosen::Drawing::Bitmap bitmap;
    OHOS::Rosen::Drawing::BitmapFormat format { OHOS::Rosen::Drawing::COLORTYPE_RGBA_8888,
        OHOS::Rosen::Drawing::ALPHATYPE_OPAQUE };
    bitmap.Build(width, height, format);
    OHOS::Rosen::Drawing::Canvas canvas;
    canvas.Bind(bitmap);
    canvas.Clear(OHOS::Rosen::Drawing::Color::COLOR_TRANSPARENT);
    DrawImage(canvas, mouseStyle);
    errno_t ret = memcpy_s(addr, addrSize, bitmap.GetPixels(), addrSize);
    if (ret != EOK) {
        MMI_HILOGE("Memcpy data is error, ret:%{public}d", ret);
        return;
    }
}

void PointerDrawingManager::DrawPixelmap(OHOS::Rosen::Drawing::Canvas &canvas, const MOUSE_ICON mouseStyle)
{
    CALL_DEBUG_ENTER;
    OHOS::Rosen::Drawing::Pen pen;
    pen.SetAntiAlias(true);
    pen.SetColor(OHOS::Rosen::Drawing::Color::COLOR_BLUE);
    OHOS::Rosen::Drawing::scalar penWidth = 1;
    pen.SetWidth(penWidth);
    canvas.AttachPen(pen);
    if (mouseStyle == MOUSE_ICON::DEVELOPER_DEFINED_ICON) {
        MMI_HILOGD("Set mouseicon by userIcon_");
        auto userIconCopy = GetUserIconCopy();
        CHKPV(userIconCopy);
        OHOS::Rosen::RSPixelMapUtil::DrawPixelMap(canvas, *userIconCopy, 0, 0);
    } else {
        std::shared_ptr<OHOS::Media::PixelMap> pixelmap;
        if (mouseStyle == MOUSE_ICON::RUNNING) {
            pixelmap = DecodeImageToPixelMap(MOUSE_ICON::RUNNING_LEFT);
        } else {
            pixelmap = DecodeImageToPixelMap(mouseStyle);
        }
        CHKPV(pixelmap);
        MMI_HILOGD("Set mouseicon to OHOS system");
        OHOS::Rosen::RSPixelMapUtil::DrawPixelMap(canvas, *pixelmap, 0, 0);
    }
}

int32_t PointerDrawingManager::SetCustomCursor(void* pixelMap, int32_t pid, int32_t windowId, int32_t focusX,
    int32_t focusY)
{
    CALL_DEBUG_ENTER;
    followSystem_ = false;
#ifdef OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    userIconFollowSystem_ = true;
#endif // OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    CHKPR(pixelMap, RET_ERR);
    if (pid == -1) {
        MMI_HILOGE("The pid is invalid");
        return RET_ERR;
    }
    if (windowId < 0) {
        int32_t ret = UpdateCursorProperty(pixelMap, focusX, focusY);
        if (ret != RET_OK) {
            MMI_HILOGE("UpdateCursorProperty is failed");
            return ret;
        }
        // Constructing a PointerStyle indicates that the SA is being passed in
        MMI_HILOGE("This indicates that the message transmitted is SA, windowId:%{public}d", windowId);
        mouseIconUpdate_ = true;
        PointerStyle style;
        style.id = MOUSE_ICON::AECH_DEVELOPER_DEFINED_ICON;
        lastMouseStyle_ = style;
        ret = SetPointerStyle(pid, windowId, style);
        if (ret != RET_OK) {
            MMI_HILOGE("SetPointerStyle is failed");
        }
        return ret;
    }
    if (WIN_MGR->CheckWindowIdPermissionByPid(windowId, pid) != RET_OK) {
        MMI_HILOGE("The windowId not in right pid");
        return RET_ERR;
    }
    int32_t ret = UpdateCursorProperty(pixelMap, focusX, focusY);
    if (ret != RET_OK) {
        MMI_HILOGE("UpdateCursorProperty is failed");
        return ret;
    }
    mouseIconUpdate_ = true;
    PointerStyle style;
    style.id = MOUSE_ICON::DEVELOPER_DEFINED_ICON;
    lastMouseStyle_ = style;

    ret = SetPointerStyle(pid, windowId, style);
    if (ret == RET_ERR) {
        MMI_HILOGE("SetPointerStyle is failed");
    }
    MMI_HILOGD("style.id:%{public}d, userIconHotSpotX_:%{public}d, userIconHotSpotY_:%{public}d",
        style.id, userIconHotSpotX_, userIconHotSpotY_);
    return ret;
}


int32_t PointerDrawingManager::UpdateCursorProperty(void* pixelMap, const int32_t &focusX, const int32_t &focusY)
{
    CHKPR(pixelMap, RET_ERR);
    Media::PixelMap* newPixelMap = static_cast<Media::PixelMap*>(pixelMap);
    CHKPR(newPixelMap, RET_ERR);
    Media::ImageInfo imageInfo;
    newPixelMap->GetImageInfo(imageInfo);
    int32_t cursorSize = GetPointerSize();
    cursorWidth_ =
        pow(INCREASE_RATIO, cursorSize - 1) * displayInfo_.dpi * GetIndependentPixels() / BASELINE_DENSITY;
    cursorHeight_ =
        pow(INCREASE_RATIO, cursorSize - 1) * displayInfo_.dpi * GetIndependentPixels() / BASELINE_DENSITY;
    cursorWidth_ = cursorWidth_ < MIN_CURSOR_SIZE ? MIN_CURSOR_SIZE : cursorWidth_;
    cursorHeight_ = cursorHeight_ < MIN_CURSOR_SIZE ? MIN_CURSOR_SIZE : cursorHeight_;
    float xAxis = (float)cursorWidth_ / (float)imageInfo.size.width;
    float yAxis = (float)cursorHeight_ / (float)imageInfo.size.height;
    newPixelMap->scale(xAxis, yAxis, Media::AntiAliasingOption::LOW);
    {
        std::lock_guard<std::mutex> guard(mtx_);
        userIcon_.reset(newPixelMap);
    }
    userIconHotSpotX_ = static_cast<int32_t>((float)focusX * xAxis);
    userIconHotSpotY_ = static_cast<int32_t>((float)focusY * yAxis);
    MMI_HILOGI("cursorWidth:%{public}d, cursorHeight:%{public}d, imageWidth:%{public}d, imageHeight:%{public}d,"
        "focusX:%{public}d, focuxY:%{public}d, xAxis:%{public}f, yAxis:%{public}f, userIconHotSpotX_:%{public}d,"
        "userIconHotSpotY_:%{public}d", cursorWidth_, cursorHeight_, imageInfo.size.width, imageInfo.size.height,
        focusX, focusY, xAxis, yAxis, userIconHotSpotX_, userIconHotSpotY_);
    return RET_OK;
}

int32_t PointerDrawingManager::SetMouseIcon(int32_t pid, int32_t windowId, void* pixelMap)
    __attribute__((no_sanitize("cfi")))
{
    CALL_DEBUG_ENTER;
    if (pid == -1) {
        MMI_HILOGE("pid is invalid return -1");
        return RET_ERR;
    }
    CHKPR(pixelMap, RET_ERR);
    if (windowId < 0) {
        MMI_HILOGE("Get invalid windowId, %{public}d", windowId);
        return RET_ERR;
    }
    if (WIN_MGR->CheckWindowIdPermissionByPid(windowId, pid) != RET_OK) {
        MMI_HILOGE("windowId not in right pid");
        return RET_ERR;
    }
    OHOS::Media::PixelMap* pixelMapPtr = static_cast<OHOS::Media::PixelMap*>(pixelMap);
    {
        std::lock_guard<std::mutex> guard(mtx_);
        userIcon_.reset(pixelMapPtr);
    }

    mouseIconUpdate_ = true;
    PointerStyle style;
    style.id = MOUSE_ICON::DEVELOPER_DEFINED_ICON;
    int32_t ret = SetPointerStyle(pid, windowId, style);
    if (ret == RET_ERR) {
        MMI_HILOGE("SetPointerStyle return RET_ERR here");
    }
    return ret;
}

int32_t PointerDrawingManager::SetMouseHotSpot(int32_t pid, int32_t windowId, int32_t hotSpotX, int32_t hotSpotY)
{
    CALL_DEBUG_ENTER;
    if (pid == -1) {
        MMI_HILOGE("Pid is invalid return -1");
        return RET_ERR;
    }
    if (windowId < 0) {
        MMI_HILOGE("Invalid windowId, %{public}d", windowId);
        return RET_ERR;
    }
    if (WIN_MGR->CheckWindowIdPermissionByPid(windowId, pid) != RET_OK) {
        MMI_HILOGE("WindowId not in right pid");
        return RET_ERR;
    }
    auto userIconCopy = GetUserIconCopy();
    if (hotSpotX < 0 || hotSpotY < 0 || userIconCopy == nullptr) {
        MMI_HILOGE("Invalid value");
        return RET_ERR;
    }
    PointerStyle pointerStyle;
    WIN_MGR->GetPointerStyle(pid, windowId, pointerStyle);
    if (pointerStyle.id != MOUSE_ICON::DEVELOPER_DEFINED_ICON) {
        MMI_HILOGE("Get pointer style failed, pid %{public}d, pointerStyle %{public}d", pid, pointerStyle.id);
        return RET_ERR;
    }
    userIconHotSpotX_ = hotSpotX;
    userIconHotSpotY_ = hotSpotY;
    return RET_OK;
}

static void ChangeSvgCursorColor(std::string& str, int32_t color)
{
    std::string targetColor = IntToHexRGB(color);
    StringReplace(str, "#000000", targetColor);
    if (color == MAX_POINTER_COLOR) {
        // stroke=\"#FFFFFF" fill="#000000" stroke-linejoin="round" transform="xxx"
        std::regex re("(<path.*)(stroke=\"#[a-fA-F0-9]{6}\")(.*path>)");
        str = std::regex_replace(str, re, "$1stroke=\"#000000\"$3");
    }
}

std::shared_ptr<OHOS::Media::PixelMap> PointerDrawingManager::LoadCursorSvgWithColor(MOUSE_ICON type, int32_t color)
{
    CALL_DEBUG_ENTER;
    std::string svgContent;
    std::string imagePath = mouseIcons_[type].iconPath;
    if (!ReadFile(imagePath, svgContent)) {
        MMI_HILOGE("read file failed");
        return nullptr;
    }
    OHOS::Media::SourceOptions opts;
    uint32_t ret = 0;
    std::unique_ptr<std::istream> isp(std::make_unique<std::istringstream>(svgContent));
    auto imageSource = OHOS::Media::ImageSource::CreateImageSource(std::move(isp), opts, ret);
    if (!imageSource || ret != ERR_OK) {
        MMI_HILOGE("Get image source failed, ret:%{public}d", ret);
    }
    CHKPP(imageSource);
    OHOS::Media::DecodeOptions decodeOpts;
    decodeOpts.desiredSize = {
        .width = imageWidth_,
        .height = imageHeight_
    };
    int32_t pointerColor = GetPointerColor();
    if (tempPointerColor_ != DEFAULT_VALUE && type != AECH_DEVELOPER_DEFINED_STYLE) {
        decodeOpts.SVGOpts.fillColor = {.isValidColor = true, .color = pointerColor};
        if (color == MAX_POINTER_COLOR) {
            decodeOpts.SVGOpts.strokeColor = {.isValidColor = true, .color = MIN_POINTER_COLOR};
        } else {
            decodeOpts.SVGOpts.strokeColor = {.isValidColor = true, .color = MAX_POINTER_COLOR};
        }
    }

    std::shared_ptr<OHOS::Media::PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, ret);
    CHKPL(pixelMap);
    return pixelMap;
}
std::shared_ptr<OHOS::Media::PixelMap> PointerDrawingManager::DecodeImageToPixelMap(MOUSE_ICON type)
{
    CALL_DEBUG_ENTER;
    auto pointerColor = GetPointerColor();
    std::lock_guard<std::mutex> guard(mousePixelMapMutex_);
    auto pixelInfo = mousePixelMap_.find(type);
    // 目前只缓存了两个光标
    if (pixelInfo == mousePixelMap_.end()) {
        return LoadCursorSvgWithColor(type, pointerColor);
    }
    if (pixelInfo->second.imageWidth != imageWidth_ || pixelInfo->second.imageHeight != imageHeight_ ||
        pixelInfo->second.pointerColor != pointerColor) {
        ReloadPixelMaps(mousePixelMap_, pointerColor);
        return mousePixelMap_[type].pixelMap;
    } else {
        return pixelInfo->second.pixelMap;
    }
}

void PointerDrawingManager::GetPreferenceKey(std::string &name)
{
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
    if (HasMagicCursor()) {
        if (name == POINTER_COLOR) {
            name = MAGIC_POINTER_COLOR;
        } else if (name == POINTER_SIZE) {
            name = MAGIC_POINTER_SIZE;
        }
    }
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
}

int32_t PointerDrawingManager::ReloadPixelMaps(
    std::map<MOUSE_ICON, PixelMapInfo>& mousePixelMap, int32_t pointerColor)
{
    for (auto iter = mousePixelMap.begin(); iter != mousePixelMap.end(); ++iter) {
        std::shared_ptr<OHOS::Media::PixelMap> pixelMap = LoadCursorSvgWithColor(iter->first, pointerColor);
        CHKPR(pixelMap, RET_ERR);
        iter->second.pixelMap = pixelMap;
        iter->second.imageWidth = imageWidth_;
        iter->second.imageHeight = imageHeight_;
        iter->second.pointerColor = pointerColor;
        int32_t width = pixelMap->GetWidth();
        int32_t height = pixelMap->GetHeight();
        MMI_HILOGI("Pixelmap width:%{public}d, height:%{public}d, %{public}d update success",
            width, height, iter->first);
    }
    return RET_OK;
}

int32_t PointerDrawingManager::SetPointerColor(int32_t color)
{
    CALL_DEBUG_ENTER;
    MMI_HILOGI("PointerColor:%{public}x", color);
    originSetColor_ = color;
    // ARGB从表面看比RGB多了个A，也是一种色彩模式，是在RGB的基础上添加了Alpha（透明度）通道。
    // 透明度也是以0到255表示的，所以也是总共有256级，透明是0，不透明是255。
    // 这个color每8位代表一个通道值，分别是alpha和rgb，总共32位。
    color = static_cast<int32_t>(static_cast<uint32_t>(color) & static_cast<uint32_t>(MAX_POINTER_COLOR));
    std::string name = POINTER_COLOR;
    GetPreferenceKey(name);
    int32_t ret = PREFERENCES_MGR->SetIntValue(name, MOUSE_FILE_NAME, color);
    if (ret != RET_OK) {
        MMI_HILOGE("Set pointer color failed, color:%{public}d", color);
        return ret;
    }
    MMI_HILOGD("Set pointer color successfully, color:%{public}d", color);
    if (!WIN_MGR->GetExtraData().drawCursor) {
        if (surfaceNode_ != nullptr) {
            float alphaRatio = (static_cast<uint32_t>(color) >> RGB_CHANNEL_BITS_LENGTH) / MAX_ALPHA_VALUE;
            if (alphaRatio > 1) {
                MMI_HILOGW("Invalid alphaRatio:%{public}f", alphaRatio);
            } else {
                surfaceNode_->SetAlpha(1 - alphaRatio);
            }
        }
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
        if (HasMagicCursor()) {
            ret = MAGIC_CURSOR->SetPointerColor(color);
        } else {
            ret = InitLayer(MOUSE_ICON(lastMouseStyle_.id));
        }
#else
        ret = InitLayer(MOUSE_ICON(lastMouseStyle_.id));
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
        if (ret != RET_OK) {
            MMI_HILOGE("Init layer failed");
            return RET_ERR;
        }
    }
    UpdatePointerVisible();
    SetHardwareCursorPosition(displayInfo_.uniqueId, lastPhysicalX_, lastPhysicalY_, lastMouseStyle_);
    return RET_OK;
}

int32_t PointerDrawingManager::GetPointerColor()
{
    CALL_DEBUG_ENTER;
    std::string name = POINTER_COLOR;
    GetPreferenceKey(name);
    int32_t pointerColor = PREFERENCES_MGR->GetIntValue(name, DEFAULT_VALUE);
    tempPointerColor_ = pointerColor;
    if (pointerColor == DEFAULT_VALUE) {
        pointerColor = MIN_POINTER_COLOR;
    }
    MMI_HILOGD("Get pointer color successfully, pointerColor:%{public}d", pointerColor);
    return pointerColor;
}

void PointerDrawingManager::UpdateDisplayInfo(const DisplayInfo &displayInfo)
{
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    CHKPV(hardwareCursorPointerManager_);
    if (g_isHdiRemoteDied) {
        hardwareCursorPointerManager_->SetHdiServiceState(false);
    }
    if (hardwareCursorPointerManager_->IsSupported()) {
        if (screenPointers_.count(displayInfo.uniqueId)) {
            auto sp = screenPointers_[displayInfo.uniqueId];
            CHKPV(sp);
            if (sp->IsMain()) {
                UpdateMirrorScreens(sp, displayInfo);
            }
            sp->OnDisplayInfo(displayInfo);
        }
    }
#endif // OHOS_BUILD_ENABLE_HARDWARE_CURSOR

    hasDisplay_ = true;
    displayInfo_ = displayInfo;
    int32_t size = GetPointerSize();
    imageWidth_ = pow(INCREASE_RATIO, size - 1) * displayInfo.dpi * GetIndependentPixels() / BASELINE_DENSITY;
    imageHeight_ = pow(INCREASE_RATIO, size - 1) * displayInfo.dpi * GetIndependentPixels() / BASELINE_DENSITY;
    canvasWidth_ = (imageWidth_ / POINTER_WINDOW_INIT_SIZE + 1) * POINTER_WINDOW_INIT_SIZE;
    canvasHeight_ = (imageHeight_ / POINTER_WINDOW_INIT_SIZE + 1) * POINTER_WINDOW_INIT_SIZE;
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
    MAGIC_CURSOR->SetDisplayInfo(displayInfo);
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
}

int32_t PointerDrawingManager::GetIndependentPixels()
{
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
    if (HasMagicCursor()) {
        return MAGIC_INDEPENDENT_PIXELS;
    } else {
        return DEVICE_INDEPENDENT_PIXELS;
    }
#else
    return DEVICE_INDEPENDENT_PIXELS;
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
}

int32_t PointerDrawingManager::SetPointerSize(int32_t size)
{
    CALL_DEBUG_ENTER;
    if (size < MIN_POINTER_SIZE) {
        size = MIN_POINTER_SIZE;
    } else if (size > MAX_POINTER_SIZE) {
        size = MAX_POINTER_SIZE;
    }
    std::string name = POINTER_SIZE;
    GetPreferenceKey(name);
    int32_t ret = PREFERENCES_MGR->SetIntValue(name, MOUSE_FILE_NAME, size);
    if (ret != RET_OK) {
        MMI_HILOGE("Set pointer size failed, code:%{public}d", ret);
        return ret;
    }

    CHKPR(surfaceNode_, RET_OK);
    imageWidth_ = pow(INCREASE_RATIO, size - 1) * displayInfo_.dpi * GetIndependentPixels() / BASELINE_DENSITY;
    imageHeight_ = pow(INCREASE_RATIO, size - 1) * displayInfo_.dpi * GetIndependentPixels() / BASELINE_DENSITY;
    canvasWidth_ = (imageWidth_ / POINTER_WINDOW_INIT_SIZE + 1) * POINTER_WINDOW_INIT_SIZE;
    canvasHeight_ = (imageHeight_ / POINTER_WINDOW_INIT_SIZE + 1) * POINTER_WINDOW_INIT_SIZE;
    int32_t physicalX = lastPhysicalX_;
    int32_t physicalY = lastPhysicalY_;
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
    MAGIC_CURSOR->SetPointerSize(imageWidth_, imageHeight_);
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
    Direction direction = static_cast<Direction>((
        ((displayInfo_.direction - displayInfo_.displayDirection) * ANGLE_90 + ANGLE_360) % ANGLE_360) / ANGLE_90);
    auto& iconPath = GetMouseIconPath();
    AdjustMouseFocus(direction, ICON_TYPE(iconPath.at(MOUSE_ICON(lastMouseStyle_.id)).alignmentWay),
        physicalX, physicalY);
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
    if (HasMagicCursor()) {
        MAGIC_CURSOR->CreatePointerWindow(displayInfo_.uniqueId, physicalX, physicalY, direction, surfaceNode_);
    } else {
        CreatePointerWindow(displayInfo_.uniqueId, physicalX, physicalY, direction);
    }
#else
    CreatePointerWindow(displayInfo_.uniqueId, physicalX, physicalY, direction);
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
    if (lastMouseStyle_.id == MOUSE_ICON::CURSOR_CIRCLE) {
        MMI_HILOGE("Cursor circle does not need to draw size");
    }
    if (InitLayer(MOUSE_ICON(lastMouseStyle_.id)) != RET_OK) {
        MMI_HILOGE("Init layer failed");
        return RET_ERR;
    }
    UpdatePointerVisible();
    SetHardwareCursorPosition(displayInfo_.uniqueId, physicalX, physicalY, lastMouseStyle_);
    return RET_OK;
}

int32_t PointerDrawingManager::GetPointerSize()
{
    CALL_DEBUG_ENTER;
    std::string name = POINTER_SIZE;
    GetPreferenceKey(name);
    int32_t pointerSize = PREFERENCES_MGR->GetIntValue(name, DEFAULT_POINTER_SIZE);
    MMI_HILOGD("Get pointer size successfully, pointerSize:%{public}d", pointerSize);
    return pointerSize;
}

void PointerDrawingManager::GetPointerImageSize(int32_t &width, int32_t &height)
{
    width = imageWidth_;
    height = imageHeight_;
}

int32_t PointerDrawingManager::GetCursorSurfaceId(uint64_t &surfaceId)
{
    surfaceId = (surfaceNode_ != nullptr ? surfaceNode_->GetId() : Rosen::INVALID_NODEID);
    MMI_HILOGI("CursorSurfaceId:%{public}" PRIu64, surfaceId);
    return RET_OK;
}

void PointerDrawingManager::OnDisplayInfo(const DisplayGroupInfo &displayGroupInfo)
{
    CALL_DEBUG_ENTER;
    for (const auto& item : displayGroupInfo.displaysInfo) {
        if (item.uniqueId == displayInfo_.uniqueId &&
            item.screenCombination == displayInfo_.screenCombination) {
            UpdateDisplayInfo(item);
            DrawManager();
            return;
        }
    }
    DisplayInfo displayInfo = displayGroupInfo.displaysInfo[0];
#ifdef OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    (void)GetMainScreenDisplayInfo(displayGroupInfo, displayInfo);
#endif // OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    UpdateDisplayInfo(displayInfo);
    lastPhysicalX_ = displayInfo.validWidth / CALCULATE_MIDDLE;
    lastPhysicalY_ = displayInfo.validHeight / CALCULATE_MIDDLE;
    MouseEventHdr->OnDisplayLost(displayInfo_.uniqueId);
    if (surfaceNode_ != nullptr) {
#ifndef OHOS_BUILD_ENABLE_HARDWARE_CURSOR
        MMI_HILOGI("Pointer window DetachToDisplay start screenId_:%{public}" PRIu64, screenId_);
        surfaceNode_->DetachToDisplay(screenId_);
        surfaceNode_ = nullptr;
#endif // OHOS_BUILD_ENABLE_HARDWARE_CURSOR
        Rosen::RSTransaction::FlushImplicitTransaction();
        MMI_HILOGD("Pointer window destroy success");
    }
    MMI_HILOGD("displayId_:%{public}d, displayWidth_:%{public}d, displayHeight_:%{public}d",
        displayInfo_.uniqueId, displayInfo_.validWidth, displayInfo_.validHeight);
}

void PointerDrawingManager::OnWindowInfo(const WinInfo &info)
{
    CALL_DEBUG_ENTER;
    if (pid_ != info.windowPid) {
        windowId_ = info.windowId;
        pid_ = info.windowPid;
        UpdatePointerVisible();
    }
}

void PointerDrawingManager::UpdatePointerDevice(bool hasPointerDevice, bool isPointerVisible,
    bool isHotPlug)
{
    CALL_DEBUG_ENTER;
    MMI_HILOGD("The hasPointerDevice:%{public}s, isPointerVisible:%{public}s",
        hasPointerDevice ? "true" : "false", isPointerVisible? "true" : "false");
    hasPointerDevice_ = hasPointerDevice;
    if (hasPointerDevice_) {
        bool pointerVisible = isPointerVisible;
        if (!isHotPlug) {
            pointerVisible = (pointerVisible && IsPointerVisible());
        }
        SetPointerVisible(getpid(), pointerVisible, 0, false);
    } else {
        DeletePointerVisible(getpid());
    }
    DrawManager();
    if (!hasPointerDevice_ && surfaceNode_ != nullptr) {
#ifdef OHOS_BUILD_ENABLE_HARDWARE_CURSOR
        {
            std::lock_guard<std::mutex> lock(mtx_);
            for (auto sp : screenPointers_) {
                if (sp.second != nullptr && sp.second->IsMirror()) {
                    sp.second->SetInvisible();
                }
            }
        }
#endif // OHOS_BUILD_ENABLE_HARDWARE_CURSOR
        MMI_HILOGD("Pointer window destroy start");
        surfaceNode_->DetachToDisplay(screenId_);
        surfaceNode_ = nullptr;
        Rosen::RSTransaction::FlushImplicitTransaction();
        MMI_HILOGD("Pointer window destroy success");
    }
}

#ifdef OHOS_BUILD_ENABLE_HARDWARE_CURSOR
void PointerDrawingManager::AttachAllSurfaceNode()
{
    std::lock_guard<std::mutex> lock(mtx_);
    for (auto sp : screenPointers_) {
        if (sp.second == nullptr) {
            continue;
        }
        auto surfaceNode = sp.second->GetSurfaceNode();
        if (surfaceNode == nullptr) {
            continue;
        }
        auto screenId = sp.second->GetScreenId();
        if (screenId == screenId_ && surfaceNode_ == nullptr) {
            MMI_HILOGI("surfaceNode_ is nullptr skip screenId:%{public}u", screenId);
            continue;
        }
        MMI_HILOGI("Attach screenId:%{public}u", screenId);
        surfaceNode->AttachToDisplay(screenId);
    }
    if (surfaceNode_ == nullptr) {
        for (auto sp : screenPointers_) {
            if (sp.second != nullptr && sp.second->IsMirror()) {
                sp.second->SetInvisible();
                MMI_HILOGI("surfaceNode_ is nullptr, hide mirror pointer screenId:%{public}u",
                    sp.second->GetScreenId());
            }
        }
    }
    Rosen::RSTransaction::FlushImplicitTransaction();
}
 
void PointerDrawingManager::DetachAllSurfaceNode()
{
    std::lock_guard<std::mutex> lock(mtx_);
    for (auto sp : screenPointers_) {
        if (sp.second != nullptr) {
            auto surfaceNode = sp.second->GetSurfaceNode();
            if (surfaceNode != nullptr) {
                auto screenId = sp.second->GetScreenId();
                MMI_HILOGI("Detach screenId:%{public}u", screenId);
                surfaceNode->DetachToDisplay(screenId);
            }
        }
    }
    Rosen::RSTransaction::FlushImplicitTransaction();
}
#endif // OHOS_BUILD_ENABLE_HARDWARE_CURSOR

void PointerDrawingManager::DrawManager()
{
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
    if (HasMagicCursor() && lastDrawPointerStyle_.id != currentMouseStyle_.id
        && (lastDrawPointerStyle_.id == DEVELOPER_DEFINED_ICON
        || currentMouseStyle_.id == DEVELOPER_DEFINED_ICON)) {
        if (surfaceNode_ != nullptr) {
            MMI_HILOGI("Pointer window DetachToDisplay start screenId_:%{public}" PRIu64, screenId_);
            surfaceNode_->DetachToDisplay(screenId_);
            surfaceNode_ = nullptr;
            Rosen::RSTransaction::FlushImplicitTransaction();
        }
    }
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
    if (hasDisplay_ && hasPointerDevice_ && surfaceNode_ == nullptr) {
        MMI_HILOGD("Draw pointer begin");
        PointerStyle pointerStyle;
        WIN_MGR->GetPointerStyle(pid_, windowId_, pointerStyle);
        MMI_HILOGD("Get pid %{public}d with pointerStyle %{public}d", pid_, pointerStyle.id);
        Direction direction = static_cast<Direction>((
            ((displayInfo_.direction - displayInfo_.displayDirection) * ANGLE_90 + ANGLE_360) % ANGLE_360) / ANGLE_90);
        lastDrawPointerStyle_ = pointerStyle;
        if (lastPhysicalX_ == -1 || lastPhysicalY_ == -1) {
            DrawPointer(displayInfo_.uniqueId, displayInfo_.validWidth / CALCULATE_MIDDLE,
                displayInfo_.validHeight / CALCULATE_MIDDLE, pointerStyle, direction);
            MMI_HILOGD("Draw manager, mouseStyle:%{public}d, last physical is initial value", pointerStyle.id);
            return;
        }
        DrawPointer(displayInfo_.uniqueId, lastPhysicalX_, lastPhysicalY_, pointerStyle, direction);
        MMI_HILOGD("Draw manager, mouseStyle:%{public}d", pointerStyle.id);
        return;
    }
}

void PointerDrawingManager::InitPixelMaps()
{
    auto pointerColor = GetPointerColor();
    std::lock_guard<std::mutex> guard(mousePixelMapMutex_);
    mousePixelMap_[MOUSE_ICON::LOADING];
    mousePixelMap_[MOUSE_ICON::RUNNING];
    ReloadPixelMaps(mousePixelMap_, pointerColor);
}

bool PointerDrawingManager::Init()
{
    CALL_DEBUG_ENTER;
    auto self = std::shared_ptr<PointerDrawingManager>(this, [](PointerDrawingManager*) {});
    INPUT_DEV_MGR->Attach(self);
    pidInfos_.clear();
    hapPidInfos_.clear();
    {
        std::lock_guard<std::mutex> guard(mousePixelMapMutex_);
        mousePixelMap_.clear();
    }
    InitPixelMaps();
    return true;
}

IPointerDrawingManager* IPointerDrawingManager::GetInstance()
{
    static PointerDrawingManager instance;
    return &instance;
}

void PointerDrawingManager::UpdatePointerVisible()
{
    CALL_DEBUG_ENTER;
    CHKPV(surfaceNode_);
    if (IsPointerVisible() && mouseDisplayState_) {
        surfaceNode_->SetVisible(true);
#ifdef OHOS_BUILD_ENABLE_HARDWARE_CURSOR
        CHKPV(hardwareCursorPointerManager_);
        if (g_isHdiRemoteDied) {
            hardwareCursorPointerManager_->SetHdiServiceState(false);
        }
        if (hardwareCursorPointerManager_->IsSupported()) {
            if (InitLayer(MOUSE_ICON(lastMouseStyle_.id)) != RET_OK) {
                MMI_HILOGE("Init Layer failed");
                return;
            }
            auto align = MouseIcon2IconType(MOUSE_ICON(lastMouseStyle_.id));
            if (!SetCursorLocation(displayId_, lastPhysicalX_, lastPhysicalY_, align)) {
                MMI_HILOGE("SetCursorLocation fail");
            }
        }
#endif // OHOS_BUILD_ENABLE_HARDWARE_CURSOR
        MMI_HILOGI("Pointer window show success, mouseDisplayState_:%{public}s, displayId_:%{public}d",
            mouseDisplayState_ ? "true" : "false", displayId_);
    } else {
#ifdef OHOS_BUILD_ENABLE_HARDWARE_CURSOR
        CHKPV(hardwareCursorPointerManager_);
        if (g_isHdiRemoteDied) {
            hardwareCursorPointerManager_->SetHdiServiceState(false);
        }
        if (hardwareCursorPointerManager_->IsSupported()) {
            PostSoftCursorTask([this]() {
                SoftwareCursorRender(MOUSE_ICON::TRANSPARENT_ICON);
            });
            HideHardwareCursors();
        }
#endif // OHOS_BUILD_ENABLE_HARDWARE_CURSOR
        surfaceNode_->SetVisible(false);
        MMI_HILOGI("Pointer window hide success, mouseDisplayState_:%{public}s",
            mouseDisplayState_ ? "true" : "false");
    }
    Rosen::RSTransaction::FlushImplicitTransaction();
}

bool PointerDrawingManager::IsPointerVisible()
{
    CALL_DEBUG_ENTER;
    if (!pidInfos_.empty()) {
        auto info = pidInfos_.back();
        if (!info.visible) {
            MMI_HILOGI("High priority visible property:%{public}zu.%{public}d-visible:%{public}s",
                pidInfos_.size(), info.pid, info.visible?"true":"false");
            return info.visible;
        }
    }
    if (!hapPidInfos_.empty()) {
        for (auto& item : hapPidInfos_) {
            if (item.pid == pid_) {
                MMI_HILOGI("Visible pid:%{public}d-visible:%{public}s",
                    item.pid, item.visible ? "true" : "false");
                return item.visible;
            }
        }
        if (!(INPUT_DEV_MGR->HasPointerDevice() || WIN_MGR->IsMouseSimulate()) || pid_ == 0) {
            auto info = hapPidInfos_.back();
            MMI_HILOGI("Only hap visible pid:%{public}d-visible:%{public}s",
                info.pid, info.visible ? "true" : "false");
            return info.visible;
        }
    }
    if (pidInfos_.empty()) {
        MMI_HILOGD("Visible property is true");
        return true;
    }
    auto info = pidInfos_.back();
    MMI_HILOGI("Visible property:%{public}zu.%{public}d-visible:%{public}s",
        pidInfos_.size(), info.pid, info.visible ? "true" : "false");
    return info.visible;
}

void PointerDrawingManager::DeletePointerVisible(int32_t pid)
{
    CALL_DEBUG_ENTER;
    MMI_HILOGI("The g_isRsRemoteDied:%{public}d", g_isRsRemoteDied ? 1 : 0);
    if (g_isRsRemoteDied && surfaceNode_ != nullptr) {
        g_isRsRemoteDied = false;
        MMI_HILOGI("Pointer window DetachToDisplay start screenId_:%{public}" PRIu64, screenId_);
        surfaceNode_->DetachToDisplay(screenId_);
        surfaceNode_ = nullptr;
        Rosen::RSTransaction::FlushImplicitTransaction();
    }
    if (pidInfos_.empty()) {
        return;
    }
    auto it = pidInfos_.begin();
    for (; it != pidInfos_.end(); ++it) {
        if (it->pid == pid) {
            pidInfos_.erase(it);
            break;
        }
    }
    if (it != pidInfos_.end()) {
        if (IsPointerVisible()) {
            InitLayer(MOUSE_ICON(lastMouseStyle_.id));
        }
        UpdatePointerVisible();
    }
}

bool PointerDrawingManager::GetPointerVisible(int32_t pid)
{
    bool ret = true;
    int32_t count = 0;
    for (auto it = pidInfos_.begin(); it != pidInfos_.end(); ++it) {
        if (it->pid == pid) {
            count++;
            ret = it->visible;
            break;
        }
    }
    if (count == 0 && !hapPidInfos_.empty()) {
        for (auto& item : hapPidInfos_) {
            if (item.pid == pid_) {
                MMI_HILOGI("Visible pid:%{public}d-visible:%{public}s",
                    item.pid, item.visible ? "true" : "false");
                count++;
                ret = item.visible;
                break;
            }
        }
    }
    return ret;
}

void PointerDrawingManager::OnSessionLost(int32_t pid)
{
    for (auto it = hapPidInfos_.begin(); it != hapPidInfos_.end(); ++it) {
        if (it->pid == pid) {
            hapPidInfos_.erase(it);
            break;
        }
    }
}

int32_t PointerDrawingManager::SetPointerVisible(int32_t pid, bool visible, int32_t priority, bool isHap)
{
    MMI_HILOGI("The pid:%{public}d,visible:%{public}s,priority:%{public}d,isHap:%{public}s", pid,
        visible ? "true" : "false", priority, isHap ? "true" : "false");
    if (isHap) {
        for (auto it = hapPidInfos_.begin(); it != hapPidInfos_.end(); ++it) {
            if (it->pid == pid) {
                hapPidInfos_.erase(it);
                break;
            }
        }
        PidInfo info = { .pid = pid, .visible = visible };
        hapPidInfos_.push_back(info);
        if (hapPidInfos_.size() > VISIBLE_LIST_MAX_SIZE) {
            hapPidInfos_.pop_front();
        }
        UpdatePointerVisible();
        return RET_OK;
    }
    if (WIN_MGR->GetExtraData().appended && visible && priority == 0) {
        MMI_HILOGE("current is drag state, can not set pointer visible");
        return RET_ERR;
    }
    for (auto it = pidInfos_.begin(); it != pidInfos_.end(); ++it) {
        if (it->pid == pid) {
            pidInfos_.erase(it);
            break;
        }
    }
    PidInfo info = { .pid = pid, .visible = visible };
    pidInfos_.push_back(info);
    if (pidInfos_.size() > VISIBLE_LIST_MAX_SIZE) {
        pidInfos_.pop_front();
    }
    if (!WIN_MGR->HasMouseHideFlag() || INPUT_DEV_MGR->HasPointerDevice() || INPUT_DEV_MGR->HasVirtualPointerDevice()) {
        UpdatePointerVisible();
    }
    return RET_OK;
}

void PointerDrawingManager::SetPointerLocation(int32_t x, int32_t y, int32_t displayId)
{
    CALL_DEBUG_ENTER;
    FixCursorPosition(x, y);
    lastPhysicalX_ = x;
    lastPhysicalY_ = y;
    MMI_HILOGD("Pointer window move, x:%{public}d, y:%{public}d", lastPhysicalX_, lastPhysicalY_);
    CHKPV(surfaceNode_);
    displayId_ = displayId;
#ifdef OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    CHKPV(hardwareCursorPointerManager_);
    if (g_isHdiRemoteDied) {
        hardwareCursorPointerManager_->SetHdiServiceState(false);
    }
    if (hardwareCursorPointerManager_->IsSupported()) {
        if (!SetCursorLocation(displayId_, x, y, MouseIcon2IconType(MOUSE_ICON(lastMouseStyle_.id)))) {
            MMI_HILOGE("SetCursorLocation fail");
            return;
        }
    }
#endif // OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    MMI_HILOGD("Pointer window move success");
}

int32_t PointerDrawingManager::UpdateDefaultPointerStyle(int32_t pid, int32_t windowId, PointerStyle pointerStyle,
    bool isUiExtension)
{
    if (windowId != GLOBAL_WINDOW_ID) {
        MMI_HILOGD("No need to change the default icon style");
        return RET_OK;
    }
    PointerStyle style;
    WIN_MGR->GetPointerStyle(pid, GLOBAL_WINDOW_ID, style, isUiExtension);
    if (pointerStyle.id != style.id) {
        auto iconPath = GetMouseIconPath();
        auto it = iconPath.find(MOUSE_ICON(MOUSE_ICON::DEFAULT));
        if (it == iconPath.end()) {
            MMI_HILOGE("Cannot find the default style");
            return RET_ERR;
        }
        std::string newIconPath;
        if (pointerStyle.id == MOUSE_ICON::DEFAULT) {
            newIconPath = DefaultIconPath;
        } else {
            newIconPath = iconPath.at(MOUSE_ICON(pointerStyle.id)).iconPath;
        }
        MMI_HILOGD("Default path has changed from %{public}s to %{public}s",
            it->second.iconPath.c_str(), newIconPath.c_str());
        UpdateIconPath(MOUSE_ICON(MOUSE_ICON::DEFAULT), newIconPath);
    }
    lastMouseStyle_ = style;
    return RET_OK;
}

const std::map<MOUSE_ICON, IconStyle>& PointerDrawingManager::GetMouseIconPath()
{
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
    if (HasMagicCursor()) {
        MMI_HILOGD("Magiccurosr get magic mouse map");
        return MAGIC_CURSOR->magicMouseIcons_;
    } else {
        MMI_HILOGD("Magiccurosr get mouse icon, HasMagicCursor is false");
        return mouseIcons_;
    }
#else
    return mouseIcons_;
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
}

IconStyle PointerDrawingManager::GetIconStyle(const MOUSE_ICON mouseStyle)
{
    std::map<MOUSE_ICON, IconStyle> mouseIcons = GetMouseIcons();
    auto iter = mouseIcons.find(mouseStyle);
    if (iter == mouseIcons.end()) {
        MMI_HILOGE("Cannot find the mouseStyle:%{public}d", static_cast<int32_t>(mouseStyle));
        return IconStyle();
    }
    return iter->second;
}

std::map<MOUSE_ICON, IconStyle>& PointerDrawingManager::GetMouseIcons()
{
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
    if (HasMagicCursor()) {
        MMI_HILOGD("Magiccurosr get magic mouse map");
        return MAGIC_CURSOR->magicMouseIcons_;
    } else {
        MMI_HILOGD("Magiccurosr get mouse icon, HasMagicCursor is false");
        return mouseIcons_;
    }
#else
    return mouseIcons_;
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
}

void PointerDrawingManager::UpdateIconPath(const MOUSE_ICON mouseStyle, std::string iconPath)
{
    auto iter = mouseIcons_.find(mouseStyle);
    if (iter == mouseIcons_.end()) {
        MMI_HILOGE("Cannot find the mouseStyle:%{public}d", static_cast<int32_t>(mouseStyle));
        return;
    }
    iter->second.iconPath = iconPath;
}

int32_t PointerDrawingManager::SetPointerStylePreference(PointerStyle pointerStyle)
{
    CALL_DEBUG_ENTER;
    std::string name = "pointerStyle";
    int32_t ret = PREFERENCES_MGR->SetIntValue(name, MOUSE_FILE_NAME, pointerStyle.id);
    if (ret == RET_OK) {
        MMI_HILOGE("Set pointer style successfully, style:%{public}d", pointerStyle.id);
    }
    return RET_OK;
}

bool PointerDrawingManager::CheckPointerStyleParam(int32_t windowId, PointerStyle pointerStyle)
{
    CALL_DEBUG_ENTER;
    if (windowId < -1) {
        return false;
    }
    if ((pointerStyle.id < MOUSE_ICON::DEFAULT && pointerStyle.id != MOUSE_ICON::DEVELOPER_DEFINED_ICON) ||
        pointerStyle.id > MOUSE_ICON::AECH_DEVELOPER_DEFINED_ICON) {
        return false;
    }
    return true;
}

int32_t PointerDrawingManager::SetPointerStyle(int32_t pid, int32_t windowId, PointerStyle pointerStyle,
    bool isUiExtension)
{
    CALL_DEBUG_ENTER;
    if (!CheckPointerStyleParam(windowId, pointerStyle)) {
        MMI_HILOGE("PointerStyle param is invalid");
        return RET_ERR;
    }
    if (windowId == GLOBAL_WINDOW_ID) {
        int32_t ret = SetPointerStylePreference(pointerStyle);
        if (ret != RET_OK) {
            MMI_HILOGE("Set style preference is failed, ret:%{public}d", ret);
            return RET_ERR;
        }
    }
    auto& iconPath = GetMouseIconPath();
    if (iconPath.find(MOUSE_ICON(pointerStyle.id)) == iconPath.end()) {
        MMI_HILOGE("The param pointerStyle is invalid");
        return RET_ERR;
    }
    if (UpdateDefaultPointerStyle(pid, windowId, pointerStyle) != RET_OK) {
        MMI_HILOGE("Update default pointer iconPath failed");
        return RET_ERR;
    }
    if (WIN_MGR->SetPointerStyle(pid, windowId, pointerStyle, isUiExtension) != RET_OK) {
        MMI_HILOGE("Set pointer style failed");
        return RET_ERR;
    }
    if (!INPUT_DEV_MGR->HasPointerDevice() && !INPUT_DEV_MGR->HasVirtualPointerDevice()) {
        MMI_HILOGD("The pointer device is not exist");
        return RET_OK;
    }
    if (!WIN_MGR->IsNeedRefreshLayer(windowId)) {
        MMI_HILOGD("Not need refresh layer, window type:%{public}d, pointer style:%{public}d",
            windowId, pointerStyle.id);
        return RET_OK;
    }
    if (windowId != GLOBAL_WINDOW_ID && (pointerStyle.id == MOUSE_ICON::DEFAULT &&
        iconPath.at(MOUSE_ICON(pointerStyle.id)).iconPath != DefaultIconPath)) {
        PointerStyle style;
        WIN_MGR->GetPointerStyle(pid, GLOBAL_WINDOW_ID, style);
        pointerStyle = style;
    }
    if (windowId == windowId_ || windowId == GLOBAL_WINDOW_ID) {
        // Draw mouse style only when the current window is the top-level window
        if (!WIN_MGR->SelectPointerChangeArea(windowId, lastPhysicalX_ + displayInfo_.x,
            lastPhysicalY_ + displayInfo_.y)) {
            if (!WIN_MGR->GetExtraData().drawCursor) {
                DrawPointerStyle(pointerStyle);
            }
        } else {
            MMI_HILOGW("skip the pointerstyle");
        }
    } else {
        MMI_HILOGW("set windowid:%{public}d, top windowid:%{public}d, dont draw pointer", windowId, windowId_);
    }
    MMI_HILOGI("Window id:%{public}d set pointer style:%{public}d success", windowId, pointerStyle.id);
    return RET_OK;
}

int32_t PointerDrawingManager::GetPointerStyle(int32_t pid, int32_t windowId, PointerStyle &pointerStyle,
    bool isUiExtension)
{
    CALL_DEBUG_ENTER;
    if (windowId == GLOBAL_WINDOW_ID) {
        std::string name = POINTER_COLOR;
        pointerStyle.color = PREFERENCES_MGR->GetIntValue(name, DEFAULT_VALUE);
        name = POINTER_SIZE;
        pointerStyle.size = PREFERENCES_MGR->GetIntValue(name, DEFAULT_POINTER_SIZE);
        name = "pointerStyle";
        int32_t style = PREFERENCES_MGR->GetIntValue(name, DEFAULT_POINTER_STYLE);
        MMI_HILOGD("Get pointer style successfully, pointerStyle:%{public}d", style);
        if (style == CURSOR_CIRCLE_STYLE || style == AECH_DEVELOPER_DEFINED_STYLE) {
            pointerStyle.id = style;
            return RET_OK;
        }
    }
    WIN_MGR->GetPointerStyle(pid, windowId, pointerStyle, isUiExtension);
    MMI_HILOGD("Window id:%{public}d get pointer style:%{public}d success", windowId, pointerStyle.id);
    return RET_OK;
}

int32_t PointerDrawingManager::ClearWindowPointerStyle(int32_t pid, int32_t windowId)
{
    CALL_DEBUG_ENTER;
    return WIN_MGR->ClearWindowPointerStyle(pid, windowId);
}

void PointerDrawingManager::DrawPointerStyle(const PointerStyle& pointerStyle)
{
    CALL_DEBUG_ENTER;
    bool simulate = WIN_MGR->IsMouseSimulate();
    if (hasDisplay_ && (hasPointerDevice_ || simulate)) {
        if (surfaceNode_ != nullptr) {
            AttachToDisplay();
#ifdef OHOS_BUILD_ENABLE_HARDWARE_CURSOR
            PostTask([]() {
                Rosen::RSTransaction::FlushImplicitTransaction();
            });
#else
            Rosen::RSTransaction::FlushImplicitTransaction();
#endif // OHOS_BUILD_ENABLE_HARDWARE_CURSOR
        }
        Direction direction = static_cast<Direction>((
            ((displayInfo_.direction - displayInfo_.displayDirection) * ANGLE_90 + ANGLE_360) % ANGLE_360) / ANGLE_90);
#ifdef OHOS_BUILD_ENABLE_HARDWARE_CURSOR
        CHKPV(hardwareCursorPointerManager_);
        if (g_isHdiRemoteDied) {
            hardwareCursorPointerManager_->SetHdiServiceState(false);
        }
        if (hardwareCursorPointerManager_->IsSupported()) {
            direction = static_cast<Direction>((
                (displayInfo_.direction * ANGLE_90 + ANGLE_360) % ANGLE_360) / ANGLE_90);
        }
#endif // OHOS_BUILD_ENABLE_HARDWARE_CURSOR
        if (lastPhysicalX_ == -1 || lastPhysicalY_ == -1) {
            DrawPointer(displayInfo_.uniqueId, displayInfo_.validWidth / CALCULATE_MIDDLE,
                displayInfo_.validHeight / CALCULATE_MIDDLE, pointerStyle, direction);
            MMI_HILOGD("Draw pointer style, mouseStyle:%{public}d", pointerStyle.id);
            return;
        }

        DrawPointer(displayInfo_.uniqueId, lastPhysicalX_, lastPhysicalY_, pointerStyle, direction);
        MMI_HILOGD("Draw pointer style, mouseStyle:%{public}d", pointerStyle.id);
    }
}

void PointerDrawingManager::CheckMouseIconPath()
{
    for (auto iter = mouseIcons_.begin(); iter != mouseIcons_.end();) {
        if ((ReadCursorStyleFile(iter->second.iconPath)) != RET_OK) {
            iter = mouseIcons_.erase(iter);
            continue;
        }
        ++iter;
    }
}

int32_t PointerDrawingManager::EnableHardwareCursorStats(int32_t pid, bool enable)
{
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    CHKPR(hardwareCursorPointerManager_, ERROR_NULL_POINTER);
    if (g_isHdiRemoteDied) {
        hardwareCursorPointerManager_->SetHdiServiceState(false);
    }
    if (hardwareCursorPointerManager_->IsSupported()) {
        if ((hardwareCursorPointerManager_->EnableStats(enable)) != RET_OK) {
            MMI_HILOGE("Enable stats failed");
            return RET_ERR;
        }
    }
#endif // OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    MMI_HILOGI("EnableHardwareCursorStats, enable:%{private}d", enable);
    return RET_OK;
}

int32_t PointerDrawingManager::GetHardwareCursorStats(int32_t pid, uint32_t &frameCount, uint32_t &vsyncCount)
{
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    CHKPR(hardwareCursorPointerManager_, ERROR_NULL_POINTER);
    if (g_isHdiRemoteDied) {
        hardwareCursorPointerManager_->SetHdiServiceState(false);
    }
    if (hardwareCursorPointerManager_->IsSupported()) {
        if ((hardwareCursorPointerManager_->GetCursorStats(frameCount, vsyncCount)) != RET_OK) {
            MMI_HILOGE("Query stats failed");
            return RET_ERR;
        }
    }
#endif // OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    MMI_HILOGI("GetHardwareCursorStats, frameCount:%{private}d, vsyncCount:%{private}d", frameCount, vsyncCount);
    return RET_OK;
}

void PointerDrawingManager::SubscribeScreenModeChange()
{
#ifdef OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    std::vector<sptr<OHOS::Rosen::ScreenInfo>> screenInfos;
    OHOS::Rosen::ScreenManagerLite::GetInstance().GetPhysicalScreenInfos(screenInfos);
    if (!screenInfos.empty()) {
        OnScreenModeChange(screenInfos);
    }

    auto callback = [this](const std::vector<sptr<OHOS::Rosen::ScreenInfo>> &screens) {
        CHKPV(hardwareCursorPointerManager_);
        if (g_isHdiRemoteDied) {
            hardwareCursorPointerManager_->SetHdiServiceState(false);
        }
        if (hardwareCursorPointerManager_->IsSupported()) {
            this->OnScreenModeChange(screens);
        }
    };
    screenModeChangeListener_ = new ScreenModeChangeListener(callback);
    auto begin = std::chrono::high_resolution_clock::now();
    auto ret = OHOS::Rosen::ScreenManagerLite::GetInstance().RegisterScreenModeChangeListener(
        screenModeChangeListener_);
    auto durationMS = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::high_resolution_clock::now() - begin).count();
#ifdef OHOS_BUILD_ENABLE_DFX_RADAR
    DfxHisysevent::ReportApiCallTimes(ApiDurationStatistics::Api::RE_SCREEN_MODE_CHANGE_LISTENER, durationMS);
#endif // OHOS_BUILD_ENABLE_DFX_RADAR
    if (ret != OHOS::Rosen::DMError::DM_OK) {
        MMI_HILOGE("RegisterScreenModeChangeListener failed, ret=%{public}d", ret);
        return;
    }
    MMI_HILOGI("SubscribeScreenModeChange success");

    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF);
    EventFwk::CommonEventSubscribeInfo commonEventSubscribeInfo(matchingSkills);
    OHOS::EventFwk::CommonEventManager::SubscribeCommonEvent(
        std::make_shared<DisplyStatusReceiver>(commonEventSubscribeInfo));
#endif // OHOS_BUILD_ENABLE_HARDWARE_CURSOR
}

void PointerDrawingManager::InitStyle()
{
    CALL_DEBUG_ENTER;
    mouseIcons_ = {
        {DEFAULT, {ANGLE_NW, IMAGE_POINTER_DEFAULT_PATH + "Default.svg"}},
        {EAST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "East.svg"}},
        {WEST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "West.svg"}},
        {SOUTH, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "South.svg"}},
        {NORTH, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "North.svg"}},
        {WEST_EAST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "West_East.svg"}},
        {NORTH_SOUTH, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "North_South.svg"}},
        {NORTH_EAST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "North_East.svg"}},
        {NORTH_WEST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "North_West.svg"}},
        {SOUTH_EAST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "South_East.svg"}},
        {SOUTH_WEST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "South_West.svg"}},
        {NORTH_EAST_SOUTH_WEST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "North_East_South_West.svg"}},
        {NORTH_WEST_SOUTH_EAST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "North_West_South_East.svg"}},
        {CROSS, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "Cross.svg"}},
        {CURSOR_COPY, {ANGLE_NW, IMAGE_POINTER_DEFAULT_PATH + "Copy.svg"}},
        {CURSOR_FORBID, {ANGLE_NW, IMAGE_POINTER_DEFAULT_PATH + "Forbid.svg"}},
        {COLOR_SUCKER, {ANGLE_SW, IMAGE_POINTER_DEFAULT_PATH + "Colorsucker.svg"}},
        {HAND_GRABBING, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "Hand_Grabbing.svg"}},
        {HAND_OPEN, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "Hand_Open.svg"}},
        {HAND_POINTING, {ANGLE_NW_RIGHT, IMAGE_POINTER_DEFAULT_PATH + "Hand_Pointing.svg"}},
        {HELP, {ANGLE_NW, IMAGE_POINTER_DEFAULT_PATH + "Help.svg"}},
        {CURSOR_MOVE, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "Move.svg"}},
        {RESIZE_LEFT_RIGHT, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "Resize_Left_Right.svg"}},
        {RESIZE_UP_DOWN, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "Resize_Up_Down.svg"}},
        {SCREENSHOT_CHOOSE, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "Screenshot_Cross.svg"}},
        {SCREENSHOT_CURSOR, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "Screenshot_Cursor.svg"}},
        {TEXT_CURSOR, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "Text_Cursor.svg"}},
        {ZOOM_IN, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "Zoom_In.svg"}},
        {ZOOM_OUT, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "Zoom_Out.svg"}},
        {MIDDLE_BTN_EAST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "MID_Btn_East.svg"}},
        {MIDDLE_BTN_WEST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "MID_Btn_West.svg"}},
        {MIDDLE_BTN_SOUTH, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "MID_Btn_South.svg"}},
        {MIDDLE_BTN_NORTH, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "MID_Btn_North.svg"}},
        {MIDDLE_BTN_NORTH_SOUTH, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "MID_Btn_North_South.svg"}},
        {MIDDLE_BTN_EAST_WEST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "MIDDLE_BTN_EAST_WEST.svg"}},
        {MIDDLE_BTN_NORTH_EAST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "MID_Btn_North_East.svg"}},
        {MIDDLE_BTN_NORTH_WEST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "MID_Btn_North_West.svg"}},
        {MIDDLE_BTN_SOUTH_EAST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "MID_Btn_South_East.svg"}},
        {MIDDLE_BTN_SOUTH_WEST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "MID_Btn_South_West.svg"}},
        {MIDDLE_BTN_NORTH_SOUTH_WEST_EAST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH +
            "MID_Btn_North_South_West_East.svg"}},
        {HORIZONTAL_TEXT_CURSOR, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "Horizontal_Text_Cursor.svg"}},
        {CURSOR_CROSS, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "Cursor_Cross.svg"}},
        {CURSOR_CIRCLE, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "Cursor_Circle.png"}},
        {LOADING, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "Loading.svg"}},
        {RUNNING, {ANGLE_NW, IMAGE_POINTER_DEFAULT_PATH + "Loading_Left.svg"}},
        {RUNNING_LEFT, {ANGLE_NW, IMAGE_POINTER_DEFAULT_PATH + "Loading_Left.svg"}},
        {RUNNING_RIGHT, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "Loading_Right.svg"}},
        {AECH_DEVELOPER_DEFINED_ICON, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "Custom_Cursor_Circle.svg"}},
        {DEVELOPER_DEFINED_ICON, {ANGLE_NW, IMAGE_POINTER_DEFAULT_PATH + "Default.svg"}},
        {TRANSPARENT_ICON, {ANGLE_NW, IMAGE_POINTER_DEFAULT_PATH + "Default.svg"}},
    };
    CheckMouseIconPath();
}

void PointerDrawingManager::RotateDegree(Direction direction)
{
#ifdef OHOS_BUILD_ENABLE_HARDWARE_CURSOR
        CHKPV(hardwareCursorPointerManager_);
        if (g_isHdiRemoteDied) {
            hardwareCursorPointerManager_->SetHdiServiceState(false);
        }
        if (hardwareCursorPointerManager_->IsSupported()) {
            return;
        }
#endif // OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    CHKPV(surfaceNode_);
    surfaceNode_->SetPivot(0, 0);
    float degree = (static_cast<int>(DIRECTION0) - static_cast<int>(direction)) * ROTATION_ANGLE90;
    surfaceNode_->SetRotation(degree);
}

int32_t PointerDrawingManager::SkipPointerLayer(bool isSkip)
{
    CALL_INFO_TRACE;
    if (surfaceNode_ != nullptr) {
        surfaceNode_->SetSkipLayer(isSkip);
    }
    return RET_OK;
}

std::vector<std::vector<std::string>> PointerDrawingManager::GetDisplayInfo(DisplayInfo &di)
{
    std::vector<std::vector<std::string>> displayInfo = {
        {std::to_string(di.id), std::to_string(di.x), std::to_string(di.y), std::to_string(di.width),
         std::to_string(di.height), std::to_string(di.dpi), di.name, di.uniq,
         std::to_string(static_cast<int32_t>(di.direction)), std::to_string(static_cast<int32_t>(di.displayDirection)),
         std::to_string(static_cast<int32_t>(di.displayMode)), std::to_string(di.isCurrentOffScreenRendering),
         std::to_string(di.screenRealWidth), std::to_string(di.screenRealHeight), std::to_string(di.screenRealPPI),
         std::to_string(di.screenRealDPI), std::to_string(static_cast<int32_t>(di.screenCombination))}};
    return displayInfo;
}

void PointerDrawingManager::Dump(int32_t fd, const std::vector<std::string> &args)
{
    CALL_DEBUG_ENTER;
    std::ostringstream oss;
    oss << std::endl;

    std::vector<std::string> displayTitles = {"ID", "X", "Y", "Width", "Height", "DPI", "Name", "Uniq",
                                              "Direction", "Display Direction", "Display Mode",
                                              "Is Current Off Screen Rendering", "Screen Real Width",
                                              "Screen Real Height", "Screen Real PPI", "Screen Real DPI",
                                              "Screen Combination"};
    std::vector<std::vector<std::string>> displayInfo = GetDisplayInfo(displayInfo_);

    DumpFullTable(oss, "Display Info", displayTitles, displayInfo);
    oss << std::endl;

    std::vector<std::string> titles1 = {"hasDisplay", "hasPointerDevice", "lastPhysicalX", "lastPhysicalY",
                                        "pid", "windowId", "imageWidth", "imageHeight", "canvasWidth", "canvasHeight"};
    std::vector<std::vector<std::string>> data1 = {
        {std::to_string(hasDisplay_), std::to_string(hasPointerDevice_), std::to_string(lastPhysicalX_),
         std::to_string(lastPhysicalY_), std::to_string(pid_), std::to_string(windowId_),
         std::to_string(imageWidth_), std::to_string(imageHeight_), std::to_string(canvasWidth_),
         std::to_string(canvasHeight_)}};

    DumpFullTable(oss, "Cursor Info", titles1, data1);
    oss << std::endl;

    std::vector<std::string> titles2 = {"mouseDisplayState", "mouseIconUpdate", "screenId", "userIconHotSpotX",
                                        "userIconHotSpotY", "tempPointerColor", "lastDirection", "currentDirection"};
    std::vector<std::vector<std::string>> data2 = {
        {std::to_string(mouseDisplayState_), std::to_string(mouseIconUpdate_), std::to_string(screenId_),
         std::to_string(userIconHotSpotX_), std::to_string(userIconHotSpotY_), std::to_string(tempPointerColor_),
         std::to_string(lastDirection_), std::to_string(currentDirection_)}};

    DumpFullTable(oss, "Cursor Info", titles2, data2);
    oss << std::endl;

    std::vector<std::string> styleTitles = {"name", "Size", "Color", "ID"};
    std::vector<std::vector<std::string>> styleData = {
        {"lastMouseStyle", std::to_string(lastMouseStyle_.size), std::to_string(lastMouseStyle_.color),
         std::to_string(lastMouseStyle_.id)},
        {"currentMouseStyle", std::to_string(currentMouseStyle_.size), std::to_string(currentMouseStyle_.color),
         std::to_string(currentMouseStyle_.id)}};

    DumpFullTable(oss, "Cursor Style Info", styleTitles, styleData);
    oss << std::endl;

    std::vector<std::string> pidTitles = {"pid", "visible"};
    std::vector<std::vector<std::string>> pidInfos;
    for (const auto &pidInfo : pidInfos_) {
        pidInfos.push_back({std::to_string(pidInfo.pid), pidInfo.visible ? "true" : "false"});
    }
    DumpFullTable(oss, "Visible Info", pidTitles, pidInfos);
    oss << std::endl;

    std::string dumpInfo = oss.str();
    dprintf(fd, dumpInfo.c_str());
}

#ifdef OHOS_BUILD_ENABLE_HARDWARE_CURSOR
void PointerDrawingManager::UpdateBindDisplayId(int32_t displayId)
{
    if (lastDisplayId_ == displayId) {
        return;
    }
    MMI_HILOGI("Mouse traversal occurs, lastDisplayId_:%{public}d, displayId:%{public}d",
        lastDisplayId_, displayId);

    CHKPV(hardwareCursorPointerManager_);
    if (g_isHdiRemoteDied) {
        hardwareCursorPointerManager_->SetHdiServiceState(false);
    }
    if (hardwareCursorPointerManager_->IsSupported()) {
        // 隐藏上一个屏幕的软、硬光标
        PostSoftCursorTask([this]() {
            SoftwareCursorRender(MOUSE_ICON::TRANSPARENT_ICON);
        });
        HideHardwareCursors();
        Rosen::RSTransaction::FlushImplicitTransaction();

        // 绑定新屏幕 SurfaceNode 到全局 surfaceNode_
        screenId_ = static_cast<uint64_t>(displayId);
        MMI_HILOGI("The screenId_:%{public}" PRIu64, screenId_);
        AttachToDisplay();
 
        // 新屏幕上重新绘制软硬光标
        UpdatePointerVisible();
    }

    // 绑定新屏幕 SurfaceNode 到全局 surfaceNode_
    MMI_HILOGI("UpdateBindDisplayId The screenId_:%{public}" PRIu64, screenId_);
    screenId_ = static_cast<uint64_t>(displayId);
    MMI_HILOGI("The screenId_:%{public}" PRIu64, screenId_);
    AttachToDisplay();

    // 新屏幕上软硬光标位置更新
    auto align = MouseIcon2IconType(MOUSE_ICON(lastMouseStyle_.id));
    if (!SetCursorLocation(displayId, lastPhysicalX_, lastPhysicalY_, align)) {
        MMI_HILOGE("SetCursorLocation fail");
    }

    lastDisplayId_ = displayId;
}

bool PointerDrawingManager::IsSupported()
{
    return hardwareCursorPointerManager_->IsSupported();
}

void PointerDrawingManager::OnScreenModeChange(const std::vector<sptr<OHOS::Rosen::ScreenInfo>> &screens)
{
    MMI_HILOGI("OnScreenModeChange enter, screen size:%{public}lu", screens.size());
    std::set<uint32_t> sids;
    uint32_t mainWidth = 0;
    uint32_t mainHeight = 0;
    rotation_t mainRotation = static_cast<rotation_t>(DIRECTION0);
    {
        std::lock_guard<std::mutex> lock(mtx_);
        // construct ScreenPointers for new screens
        for (auto si : screens) {
            MMI_HILOGI("Got screen, id:%{public}lu, shape=(%{public}u,%{public}u), rotation=%{public}u, "
                "dpi=%{public}f", si->GetRsId(), GetScreenInfoWidth(si), GetScreenInfoHeight(si),
                si->GetRotation(), si->GetVirtualPixelRatio());
            if (si->GetType() != OHOS::Rosen::ScreenType::REAL) {
                continue;
            }

            uint32_t sid = si->GetRsId();
            sids.insert(sid);

            if (si->GetSourceMode() == OHOS::Rosen::ScreenSourceMode::SCREEN_MAIN) {
                mainWidth = GetScreenInfoWidth(si);
                mainHeight = GetScreenInfoHeight(si);
                mainRotation = static_cast<rotation_t>(si->GetRotation());
            }

            auto it = screenPointers_.find(sid);
            if (it != screenPointers_.end()) {
                // ScreenPointer already exist
                MMI_HILOGI("OnScreenModeChange screen %{public}u info update", sid);
                it->second->UpdateScreenInfo(si);
            } else {
                // Create & Init ScreenPointer
                MMI_HILOGI("OnScreenModeChange got new screen %{public}u", sid);
                auto sp = std::make_shared<ScreenPointer>(hardwareCursorPointerManager_, handler_, si);
                screenPointers_[sid] = sp;
                if (!sp->Init()) {
                    MMI_HILOGE("ScreenPointer::Init failed, screenId=%{public}u", sid);
                }
            }
        }

        // delete ScreenPointers that disappeared
        for (auto it = screenPointers_.begin(); it != screenPointers_.end();) {
            if (!sids.count(it->first)) {
                MMI_HILOGI("OnScreenModeChange, delete screen %{public}u", it->first);
                it = screenPointers_.erase(it);
            } else {
                it++;
            }
        }

        // update screen scale and padding
        for (auto sp : screenPointers_) {
            if (sp.second->IsMirror()) {
                sp.second->SetRotation(mainRotation);
                sp.second->UpdatePadding(mainWidth, mainHeight);
            }
        }
    }
    UpdatePointerVisible();
}

void PointerDrawingManager::CreateRenderConfig(RenderConfig& cfg, std::shared_ptr<ScreenPointer> sp,
    MOUSE_ICON mouseStyle, bool isHard)
{
    CHKPV(sp);
    cfg.style = mouseStyle;
    cfg.align = MouseIcon2IconType(mouseStyle);
    cfg.path = mouseIcons_[mouseStyle].iconPath;
    cfg.color = static_cast<uint32_t>(GetPointerColor());
    cfg.size = static_cast<uint32_t>(GetPointerSize());
    cfg.isHard = isHard;
    float scale = isHard ? sp->GetScale() : 1.0f;
    cfg.dpi = sp->GetDPI() * scale;
    cfg.direction = sp->IsMirror() ? DIRECTION0 : displayInfo_.direction;
    if (mouseStyle == MOUSE_ICON::DEVELOPER_DEFINED_ICON) {
        MMI_HILOGD("Set mouseIcon by userIcon_");
        cfg.userIconPixelMap = GetUserIconCopy();
        CHKPV(cfg.userIconPixelMap);
        cfg.userIconHotSpotX = userIconHotSpotX_ * scale;
        cfg.userIconHotSpotY = userIconHotSpotY_ * scale;
        cfg.userIconFollowSystem = userIconFollowSystem_;
        cfg.userIconPixelMap->scale(scale, scale, Media::AntiAliasingOption::LOW);
    }
}

void PointerDrawingManager::HardwareCursorRender(MOUSE_ICON mouseStyle)
{
    std::unordered_map<uint32_t, std::shared_ptr<ScreenPointer>> screenPointers;
    {
        std::lock_guard<std::mutex> lock(mtx_);
        screenPointers = screenPointers_;
    }

    for (auto it : screenPointers) {
        CHKPV(it.second);
        RenderConfig cfg;
        CreateRenderConfig(cfg, it.second, mouseStyle, true);
        MMI_HILOGI("HardwareCursorRender, screen:%{public}u, dpi:%{public}f, screenId_:%{public}" PRIu64,
            it.first, cfg.dpi, screenId_);
        if (it.second->IsMirror() || it.first == screenId_) {
            DrawHardCursor(it.second, cfg);
        } else {
            it.second->SetInvisible();
        }
    }
    MMI_HILOGD("HardwareCursorRender success");
}

void PointerDrawingManager::SoftwareCursorRender(MOUSE_ICON mouseStyle)
{
    std::unordered_map<uint32_t, std::shared_ptr<ScreenPointer>> screenPointers;
    {
        std::lock_guard<std::mutex> lock(mtx_);
        screenPointers = screenPointers_;
    }

    for (auto it : screenPointers) {
        CHKPV(it.second);
        RenderConfig cfg;
        CreateRenderConfig(cfg, it.second, mouseStyle, false);
        MMI_HILOGI("SoftwareCursorRender, screen:%{public}u, dpi:%{public}f, direction:%{public}d,"
            "screenId_:%{public}" PRIu64, it.first, cfg.dpi, cfg.direction, screenId_);
        if (!it.second->IsMirror() && it.first != screenId_) {
            cfg.style = MOUSE_ICON::TRANSPARENT_ICON;
            cfg.align = MouseIcon2IconType(cfg.style);
            cfg.path = mouseIcons_[cfg.style].iconPath;
        }
        DrawSoftCursor(it.second->GetSurfaceNode(), cfg);
    }
    MMI_HILOGD("SoftwareCursorRender success");
}

int32_t PointerDrawingManager::DrawSoftCursor(std::shared_ptr<Rosen::RSSurfaceNode> surfaceNode,
    const RenderConfig &cfg)
{
    CHKPR(surfaceNode, RET_ERR);

    auto layer = surfaceNode->GetSurface();
    CHKPR(layer, RET_ERR);
    auto buffer = GetSurfaceBuffer(layer);
    if (buffer == nullptr || buffer->GetVirAddr() == nullptr) {
        buffer = RetryGetSurfaceBuffer(layer);
    }
    CHKPR(buffer, RET_ERR);
    CHKPR(buffer->GetVirAddr(), RET_ERR);
    auto addr = static_cast<uint8_t*>(buffer->GetVirAddr());
    CHKPR(addr, RET_ERR);
    pointerRenderer_.Render(addr, buffer->GetWidth(), buffer->GetHeight(), cfg);

    OHOS::BufferFlushConfig flushConfig = {
        .damage = {
            .w = buffer->GetWidth(),
            .h = buffer->GetHeight(),
        }
    };
    OHOS::SurfaceError ret = layer->FlushBuffer(buffer, -1, flushConfig);
    if (ret != OHOS::SURFACE_ERROR_OK) {
        MMI_HILOGE("FlushBuffer failed, return: %{public}s", SurfaceErrorStr(ret).data());
        layer->CancelBuffer(buffer);
        return RET_ERR;
    }
    MMI_HILOGD("DrawSoftCursor on SurfaceNode success");
    return RET_OK;
}

int32_t PointerDrawingManager::DrawCursor(std::shared_ptr<ScreenPointer> sp, const RenderConfig &cfg)
{
    CHKPR(sp, RET_ERR);

    auto buffer = sp->RequestBuffer();
    CHKPR(buffer, RET_ERR);

    auto addr = static_cast<uint8_t *>(buffer->GetVirAddr());
    CHKPR(addr, RET_ERR);
    pointerRenderer_.Render(addr, buffer->GetWidth(), buffer->GetHeight(), cfg);

    MMI_HILOGI("DrawHardCursor on ScreenPointer success, screenId_:%{public}" PRIu64, screenId_);
    return RET_OK;
}

void PointerDrawingManager::UpdateMirrorScreens(std::shared_ptr<ScreenPointer> sp, DisplayInfo displayInfo)
{
    if (sp->GetRotation() != static_cast<rotation_t>(displayInfo.direction)) {
        uint32_t mainWidth = sp->GetScreenWidth();
        uint32_t mainHeight = sp->GetScreenHeight();
        auto mirrorScreens = GetMirrorScreenPointers();
        for (auto mirrorScreen : mirrorScreens) {
            if (mirrorScreen != nullptr) {
                mirrorScreen->SetRotation(static_cast<rotation_t>(displayInfo.direction));
                mirrorScreen->UpdatePadding(mainWidth, mainHeight);
            }
        }
    }
}

std::vector<std::shared_ptr<ScreenPointer>> PointerDrawingManager::GetMirrorScreenPointers()
{
    std::vector<std::shared_ptr<ScreenPointer>> mirrors;
    std::lock_guard<std::mutex> lock(mtx_);
    for (auto it : screenPointers_) {
        if (it.second->IsMirror()) {
            mirrors.push_back(it.second);
        }
    }
    return mirrors;
}

std::shared_ptr<ScreenPointer> PointerDrawingManager::GetScreenPointer(uint32_t sid)
{
    std::lock_guard<std::mutex> lock(mtx_);
    if (screenPointers_.count(sid)) {
        return screenPointers_[sid];
    }
    return nullptr;
}

void PointerDrawingManager::HardwareCursorMove(int32_t x, int32_t y, ICON_TYPE align)
{
    MMI_HILOGD("HardwareCursorMove loc: (%{public}d, %{public}d), align type: %{public}d", x, y, align);
    auto sp = GetScreenPointer(displayId_);
    CHKPV(sp);
    if (!sp->Move(x, y, align)) {
        MMI_HILOGE("ScreenPointer::Move failed, screenId: %{public}u", displayId_);
    }
    std::unordered_map<uint32_t, std::shared_ptr<ScreenPointer>> screenPointers;
    {
        std::lock_guard<std::mutex> lock(mtx_);
        screenPointers = screenPointers_;
    }
    for (auto it : screenPointers) {
        if (it.second->IsMirror()) {
            if (!it.second->Move(x, y, align)) {
                MMI_HILOGE("ScreenPointer::Move failed, screenId: %{public}u", it.first);
            }
        } else if (it.first != displayId_) {
            if (!it.second->Move(0, 0, align)) {
                MMI_HILOGE("ScreenPointer::Move failed, screenId: %{public}u", it.first);
            }
        }
    }
}

int32_t PointerDrawingManager::CheckHwcReady()
{
    auto sp = GetScreenPointer(displayId_);
    CHKPR(sp, RET_ERR);
    int32_t failCount = 0;
    while (sp != nullptr && !sp->Move(lastPhysicalX_, lastPhysicalY_, ICON_TYPE::ANGLE_NW)) {
        failCount++;
        if (failCount > MAX_FAIL_COUNT) {
            MMI_HILOGE("CheckHwcReady failed, screenId: %{public}u", displayId_);
            return RET_ERR;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(CHECK_SLEEP_TIME));
    }
    MMI_HILOGI("CheckHwcReady success, screenId: %{public}u, check counts: %{public}d", displayId_, failCount);
    return RET_OK;
}

void PointerDrawingManager::SoftwareCursorMove(int32_t x, int32_t y, ICON_TYPE align)
{
    auto sp = GetScreenPointer(displayId_);
    CHKPV(sp);
    sp->MoveSoft(x, y, align);

    for (auto msp : GetMirrorScreenPointers()) {
        msp->MoveSoft(x, y, align);
    }
    Rosen::RSTransaction::FlushImplicitTransaction();
}

void PointerDrawingManager::SoftwareCursorMoveAsync(int32_t x, int32_t y, ICON_TYPE align)
{
    PostSoftCursorTask([this, x, y, align]() {
        SoftwareCursorMove(x, y, align);
    });
}

void PointerDrawingManager::HideHardwareCursors()
{
    auto curSp = GetScreenPointer(screenId_);
    CHKPV(curSp);
    if (!curSp->SetInvisible()) {
        MMI_HILOGE("Hide cursor of current screen failed, screenId_: %{public}" PRIu64, screenId_);
    }

    for (auto msp : GetMirrorScreenPointers()) {
        if (!msp->SetInvisible()) {
            MMI_HILOGE("Hide cursor of mirror screen failed, screenId_: %{public}" PRIu64, screenId_);
        }
    }
}

#endif // OHOS_BUILD_ENABLE_HARDWARE_CURSOR

void PointerDrawingManager::DrawScreenCenterPointer(const PointerStyle& pointerStyle)
{
    CALL_DEBUG_ENTER;
    if (hasDisplay_ && hasPointerDevice_) {
        if (surfaceNode_ != nullptr) {
            AttachToDisplay();
            Rosen::RSTransaction::FlushImplicitTransaction();
        }
        Direction direction = static_cast<Direction>((
            ((displayInfo_.direction - displayInfo_.displayDirection) * ANGLE_90 + ANGLE_360) % ANGLE_360) / ANGLE_90);
#ifdef OHOS_BUILD_ENABLE_HARDWARE_CURSOR
        if (IsSupported()) {
            direction = displayInfo_.direction;
            int32_t x = displayInfo_.width / CALCULATE_MIDDLE;
            int32_t y = displayInfo_.height / CALCULATE_MIDDLE;
            if (direction == DIRECTION90 || direction == DIRECTION270) {
                std::swap(x, y);
            }
            MMI_HILOGD("DrawScreenCenterPointer, x=%{public}d, y=%{public}d", x, y);
            DrawPointer(displayInfo_.uniqueId, x, y, pointerStyle, direction);
        }
#else
        DrawPointer(displayInfo_.id, displayInfo_.validWidth / CALCULATE_MIDDLE,
            displayInfo_.validHeight / CALCULATE_MIDDLE, pointerStyle, direction);
#endif // OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    }
}

std::shared_ptr<OHOS::Media::PixelMap> PointerDrawingManager::GetUserIconCopy()
{
    std::lock_guard<std::mutex> guard(mtx_);
    if (userIcon_ == nullptr) {
        MMI_HILOGI("userIcon_ is nullptr");
        return nullptr;
    }
    MessageParcel data;
    userIcon_->Marshalling(data);
    std::shared_ptr<OHOS::Media::PixelMap> pixelMapPtr(OHOS::Media::PixelMap::Unmarshalling(data));
    if (pixelMapPtr == nullptr) {
        MMI_HILOGE("pixelMapPtr is nullptr");
        return nullptr;
    }
    if (followSystem_) {
        Media::ImageInfo imageInfo;
        pixelMapPtr->GetImageInfo(imageInfo);
        int32_t cursorSize = GetPointerSize();
        float axis = 1.0f;
        cursorWidth_ = pow(INCREASE_RATIO, cursorSize - 1) * imageInfo.size.width;
        cursorHeight_ = pow(INCREASE_RATIO, cursorSize - 1) * imageInfo.size.height;
        int32_t maxValue = imageInfo.size.width > imageInfo.size.height ? cursorWidth_ : cursorHeight_;
        if (maxValue > MAX_CUSTOM_CURSOR_DIMENSION) {
            axis = (float)MAX_CUSTOM_CURSOR_DIMENSION / (float)std::max(imageInfo.size.width, imageInfo.size.height);
        } else {
            axis = (float)std::max(cursorWidth_, cursorHeight_) /
                (float)std::max(imageInfo.size.width, imageInfo.size.height);
        }
        pixelMapPtr->scale(axis, axis, Media::AntiAliasingOption::LOW);
        cursorWidth_ = static_cast<int32_t>((float)imageInfo.size.width * axis);
        cursorHeight_ = static_cast<int32_t>((float)imageInfo.size.height * axis);
        userIconHotSpotX_ = static_cast<int32_t>((float)focusX_ * axis);
        userIconHotSpotY_ = static_cast<int32_t>((float)focusY_ * axis);
        MMI_HILOGI("cursorWidth:%{public}d, cursorHeight:%{public}d, imageWidth:%{public}d,"
            "imageHeight:%{public}d, focusX:%{public}d, focusY:%{public}d, axis:%{public}f,"
            "userIconHotSpotX_:%{public}d, userIconHotSpotY_:%{public}d",
            cursorWidth_, cursorHeight_, imageInfo.size.width, imageInfo.size.height,
            focusX_, focusY_, axis, userIconHotSpotX_, userIconHotSpotY_);
    }
    SetSurfaceNodeBounds();
    return pixelMapPtr;
}

void PointerDrawingManager::SetSurfaceNodeBounds()
{
#ifdef OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    CHKPV(hardwareCursorPointerManager_);
    if (hardwareCursorPointerManager_->IsSupported()) {
        return;
    }
#endif // OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    if (canvasWidth_ < cursorWidth_ && canvasHeight_ < cursorHeight_) {
        canvasWidth_ = cursorWidth_;
        canvasHeight_ = cursorHeight_;
    }
    CHKPV(surfaceNode_);
    surfaceNode_->SetBounds(lastPhysicalX_, lastPhysicalY_, canvasWidth_, canvasHeight_);
}

int32_t PointerDrawingManager::SetCustomCursor(int32_t pid, int32_t windowId, CustomCursor cursor,
    CursorOptions options)
{
    CALL_DEBUG_ENTER;
    followSystem_ = options.followSystem;
#ifdef OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    userIconFollowSystem_ = false;
#endif // OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    int32_t ret = UpdateCursorProperty(cursor);
    if (ret != RET_OK) {
        MMI_HILOGE("UpdateCursorProperty is failed");
        return ret;
    }
    mouseIconUpdate_ = true;
    PointerStyle style;
    style.id = MOUSE_ICON::DEVELOPER_DEFINED_ICON;
    lastMouseStyle_ = style;
    ret = SetPointerStyle(pid, windowId, style);
    if (ret == RET_ERR) {
        MMI_HILOGE("SetPointerStyle is failed");
    }
    MMI_HILOGD("style.id:%{public}d, userIconHotSpotX_:%{public}d, userIconHotSpotY_:%{public}d",
        style.id, userIconHotSpotX_, userIconHotSpotY_);
    return ret;
}

int32_t PointerDrawingManager::UpdateCursorProperty(CustomCursor cursor)
{
    CHKPR(cursor.pixelMap, RET_ERR);
    Media::PixelMap* newPixelMap = static_cast<Media::PixelMap*>(cursor.pixelMap);
    CHKPR(newPixelMap, RET_ERR);
    Media::ImageInfo imageInfo;
    newPixelMap->GetImageInfo(imageInfo);
    if (imageInfo.size.width < cursor.focusX || imageInfo.size.width < cursor.focusY) {
        MMI_HILOGE("The focus is invalid");
        return RET_ERR;
    }
    if (imageInfo.size.width > MAX_CUSTOM_CURSOR_SIZE || imageInfo.size.height > MAX_CUSTOM_CURSOR_SIZE ||
        imageInfo.size.width <= 0 || imageInfo.size.height <= 0) {
        MMI_HILOGE("PixelMap is invalid");
        return RET_ERR;
    }
    cursorWidth_ = imageInfo.size.width;
    cursorHeight_ = imageInfo.size.height;
    {
        std::lock_guard<std::mutex> guard(mtx_);
        userIcon_.reset(newPixelMap);
    }
    focusX_ = cursor.focusX;
    focusY_ = cursor.focusY;
    userIconHotSpotX_ = cursor.focusX;
    userIconHotSpotY_ = cursor.focusY;
    MMI_HILOGI("imageWidth:%{public}d, imageHeight:%{public}d, focusX:%{public}d, focusY:%{public}d",
        imageInfo.size.width, imageInfo.size.height, cursor.focusX, cursor.focusY);
    return RET_OK;
}

int32_t PointerDrawingManager::DrawNewDpiPointer()
{
    mouseIconUpdate_ = true;
    int32_t updateRes = DrawMovePointer(lastDisplayId_, lastPhysicalX_, lastPhysicalY_,
        lastMouseStyle_, currentDirection_);
    if (updateRes != RET_OK) {
        MMI_HILOGE("Forced refresh DPI drawing failed.");
        return RET_ERR;
    }
    return RET_OK;
}
} // namespace MMI
} // namespace OHOS
