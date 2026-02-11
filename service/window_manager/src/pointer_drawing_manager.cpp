/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "account_manager.h"
#include "bytrace_adapter.h"
#include "cursor_drawing_component.h"
#include "define_multimodal.h"
#include "input_device_manager.h"
#include "i_input_windows_manager.h"
#include "ipc_skeleton.h"
#include "mmi_log.h"
#include "i_preference_manager.h"
#include "parameters.h"
#include "pipeline/rs_recording_canvas.h"
#include "pointer_device_manager.h"
#include "preferences.h"
#include "preferences_errno.h"
#include "preferences_helper.h"
#include "render/rs_pixel_map_util.h"
#include "scene_board_judgement.h"
#include "setting_datashare.h"
#include "i_setting_manager.h"
#include "util.h"
#include "dfx_hisysevent.h"
#include "timer_manager.h"
#include "surface.h"
#include "common_event_data.h"
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
const std::string CursorIconPath = IMAGE_POINTER_DEFAULT_PATH + "Cursor_Circle.png";
const std::string CustomCursorIconPath = IMAGE_POINTER_DEFAULT_PATH + "Custom_Cursor_Circle.svg";
const std::string LoadingIconPath = IMAGE_POINTER_DEFAULT_PATH + "Loading.svg";
const std::string LoadingRightIconPath = IMAGE_POINTER_DEFAULT_PATH + "Loading_Right.svg";
const char* POINTER_COLOR { "pointerColor" };
const char* POINTER_SIZE { "pointerSize" };
const char* MAGIC_POINTER_COLOR { "magicPointerColor" };
const char* MAGIC_POINTER_SIZE { "magicPointerSize"};
const char* POINTER_CURSOR_RENDER_RECEIVER_NAME { "PointerCursorReceiver" };
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
constexpr uint64_t FOLD_SCREEN_ID_FULL { 0 };
constexpr uint64_t FOLD_SCREEN_ID_MAIN { 5 };
constexpr float IMAGE_PIXEL { 0.0f };
constexpr float CALCULATE_IMAGE_MIDDLE { 2.0f };
constexpr int32_t QUEUE_SIZE { 5 };
constexpr int32_t DYNAMIC_ROTATION_ANGLE { 12 };
constexpr float CALCULATE_MOUSE_ICON_BAIS { 5.0f };
constexpr int32_t SYNC_FENCE_WAIT_TIME { 3000 };
constexpr int32_t REPEAT_COOLING_TIME { 1000 };
constexpr int32_t REPEAT_ONCE { 1 };
constexpr int32_t MOVE_RETRY_TIME { 50 };
constexpr int32_t MAX_MOVE_RETRY_COUNT { 5 };
constexpr int32_t ANGLE_90 { 90 };
constexpr int32_t ANGLE_360 { 360 };
constexpr int32_t MAX_CUSTOM_CURSOR_SIZE { 256 };
constexpr float MAX_CUSTOM_CURSOR_DIMENSION { 256.0f };
constexpr uint32_t CURSOR_STRIDE { 4 };
constexpr int32_t MAX_FAIL_COUNT { 1000 };
constexpr int32_t CHECK_SLEEP_TIME { 10 };
#ifdef OHOS_BUILD_PC_PRIORITY
constexpr int32_t PC_PRIORITY { 2 };
#endif // OHOS_BUILD_PC_PRIORITY
const int32_t MULTIMODAL_INPUT_SERVICE_ID = 3101;
bool g_isRsRemoteDied { false };
bool g_isHdiRemoteDied { false };
bool g_isReStartVsync { false };
float g_hardwareCanvasSize = { 512.0f };
float g_focalPoint = { 256.0f };
std::atomic<bool> g_isRsRestart { false };
constexpr int32_t INVALID_USER { -1 };
} // namespace
} // namespace MMI
} // namespace OHOS

namespace OHOS {
namespace MMI {
class DisplayStatusReceiver : public EventFwk::CommonEventSubscriber {
public:
    explicit DisplayStatusReceiver(const OHOS::EventFwk::CommonEventSubscribeInfo& subscribeInfo)
        : OHOS::EventFwk::CommonEventSubscriber(subscribeInfo)
    {
        MMI_HILOGI("DisplayStatusReceiver register");
    }

    virtual ~DisplayStatusReceiver() = default;

    void OnReceiveEvent(const EventFwk::CommonEventData &eventData)
    {
        if (!IPointerDrawingManager::GetInstance()->GetHardCursorEnabled()) {
            return;
        }
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

static bool IsSingleDisplayFoldDevice()
{
    return (!FOLD_SCREEN_FLAG.empty() &&
        (FOLD_SCREEN_FLAG[0] == '1' || FOLD_SCREEN_FLAG[0] == '4' || FOLD_SCREEN_FLAG[0] == '7'));
}

void PointerDrawingManager::RsRemoteDiedCallback()
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
    OnRemoteDiedCallback_ = [this]() -> void { this->RsRemoteDiedCallback(); };
    auto begin = std::chrono::high_resolution_clock::now();
    Rosen::RSInterfaces::GetInstance().SetOnRemoteDiedCallback(OnRemoteDiedCallback_);
    auto durationMS = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::high_resolution_clock::now() - begin).count();
#ifdef OHOS_BUILD_ENABLE_DFX_RADAR
    DfxHisysevent::ReportApiCallTimes(ApiDurationStatistics::Api::SET_ON_REMOTE_DIED_CALLBACK, durationMS);
#endif // OHOS_BUILD_ENABLE_DFX_RADAR
    if (GetSurfaceNode() != nullptr) {
        SetSurfaceNode(nullptr);
    }
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
    if (HasMagicCursor()) {
        MAGIC_CURSOR->RsRemoteInitCallbackForMagicCursor();
    }
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
    if (GetHardCursorEnabled() && !initEventHandlerFlag_.load()) {
        renderThread_ = std::make_unique<std::thread>([this] { this->RenderThreadLoop(); });
        softCursorRenderThread_ =
            std::make_unique<std::thread>([this] { this->SoftCursorRenderThreadLoop(); });
        moveRetryThread_ = std::make_unique<std::thread>([this] { this->MoveRetryThreadLoop(); });
        initEventHandlerFlag_.store(true);
    }
}

void PointerDrawingManager::DestroyPointerWindow()
{
    CALL_INFO_TRACE;
    CHKPV(delegateProxy_);
    delegateProxy_->OnPostSyncTask([this] {
        {
            auto surfaceNodePtr = GetSurfaceNode();
            if (surfaceNodePtr == nullptr) {
                MMI_HILOGW("SurfaceNode pointer is nullptr.");
                return RET_OK;
            }
            MMI_HILOGI("Pointer window destroy start screenId_ %{public}" PRIu64, screenId_);
            g_isRsRemoteDied = false;
            surfaceNodePtr->DetachToDisplay(screenId_);
            SetSurfaceNode(nullptr);
            MMI_HILOGI("Detach screenId:%{public}" PRIu64, screenId_);
        }
        Rosen::RSTransaction::FlushImplicitTransaction();
        MMI_HILOGI("Pointer window destroy success");
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
    return std::atoi(ret.c_str());
}

static float GetFocusCoordinates()
{
    auto ret = system::GetParameter("rosen.multimodalinput.pc.setfocuscoordinates", "256.0");
    if (IsNum(ret)) {
        return g_focalPoint;
    }
    return std::atoi(ret.c_str());
}

PointerDrawingManager::PointerDrawingManager()
{
    hardwareCursorPointerManager_ = std::make_shared<HardwareCursorPointerManager>();
    if (g_isHdiRemoteDied) {
        hardwareCursorPointerManager_->SetHdiServiceState(false);
    }
    if (hardwareCursorPointerManager_->IsSupported()) {
        g_hardwareCanvasSize = GetCanvasSize();
        g_focalPoint = GetFocusCoordinates();
    }
}

PointerDrawingManager::~PointerDrawingManager()
{
    ClearResources();
    MMI_HILOGI("~PointerDrawingManager");
}

void PointerDrawingManager::ClearResources()
{
    std::lock_guard<std::mutex> lock(isClearedMtx_);
    if (isCleared_) {
        return;
    }
    if (GetHardCursorEnabled()) {
        ClearRunnerAndHandler();
        if (commonEventSubscriber_ != nullptr) {
            if (!OHOS::EventFwk::CommonEventManager::NewUnSubscribeCommonEventSync(commonEventSubscriber_)) {
                MMI_HILOGW("UnSubscribeCommonEvent failed");
            }
            commonEventSubscriber_ = nullptr;
        }
        initDisplayStatusReceiverFlag_ = false;
        UnsubscribeScreenModeChange();
    } else {
        auto surfaceNodePtr = GetSurfaceNode();
        if (surfaceNodePtr != nullptr) {
            surfaceNodePtr->DetachToDisplay(screenId_);
            SetSurfaceNode(nullptr);
            MMI_HILOGI("Detach screenId:%{public}" PRIu64, screenId_);
            Rosen::RSTransaction::FlushImplicitTransaction();
        }
    }
    INPUT_DEV_MGR->Detach(self_);
    Rosen::RSInterfaces::GetInstance().SetOnRemoteDiedCallback(nullptr);
    ResetMoveRetryTimer();
    if (initLoadingAndLoadingRightPixelTimerId_ != DEFAULT_VALUE) {
        TimerMgr->RemoveTimer(initLoadingAndLoadingRightPixelTimerId_);
        initLoadingAndLoadingRightPixelTimerId_ = DEFAULT_VALUE;
    }
    isCleared_ = true;
    MMI_HILOGI("resources of PointerDrawingManager is cleared");
}

void PointerDrawingManager::ClearRunnerAndHandler()
{
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
    if (moveRetryRunner_ != nullptr) {
        moveRetryRunner_->Stop();
    }
    if ((moveRetryThread_ != nullptr) && moveRetryThread_->joinable()) {
        moveRetryThread_->join();
    }
}

void PointerDrawingManager::SetLastMouseStyle(PointerStyle style)
{
    CALL_DEBUG_ENTER;
    lastMouseStyle_ = style;
}

PointerStyle PointerDrawingManager::GetLastMouseStyle()
{
    CALL_DEBUG_ENTER;
    return lastMouseStyle_;
}

bool PointerDrawingManager::SetCursorLocation(int32_t physicalX, int32_t physicalY)
{
    bool magicCursorSetBounds = false;
    if (UpdateSurfaceNodeBounds(physicalX, physicalY) == RET_OK) {
        magicCursorSetBounds = true;
        Rosen::RSTransaction::FlushImplicitTransaction();
    }
    auto surfaceNodePtr = GetSurfaceNode();
    CHKPF(surfaceNodePtr);
    if (GetHardCursorEnabled()) {
        if (!magicCursorSetBounds) {
            if (lastMouseStyle_.id != MOUSE_ICON::LOADING && lastMouseStyle_.id != MOUSE_ICON::RUNNING) {
                // Change the coordinates issued by RS to asynchronous,
                // without blocking the issuance of HardwareCursor coordinates.
                SoftwareCursorMoveAsync(displayId_, physicalX, physicalY);
            }
        }
        if (lastMouseStyle_.id != MOUSE_ICON::LOADING && lastMouseStyle_.id != MOUSE_ICON::RUNNING) {
            ResetMoveRetryTimer();
            if (HardwareCursorMove(physicalX, physicalY) != RET_OK) {
                MoveRetryAsync(physicalX, physicalY);
            }
        }
    } else {
        if (!magicCursorSetBounds) {
            surfaceNodePtr->SetBounds(physicalX, physicalY, surfaceNodePtr->GetStagingProperties().GetBounds().z_,
                surfaceNodePtr->GetStagingProperties().GetBounds().w_);
            Rosen::RSTransaction::FlushImplicitTransaction();
        }
    }
    return true;
}

void PointerDrawingManager::ForceClearPointerVisibleStatus()
{
    MMI_HILOGI("Force clear all pointer visiable status");
    CursorDrawingInformation::GetInstance().ClearPidInfos();
    UpdatePointerVisible();
}

int32_t PointerDrawingManager::UpdateMouseLayer(int32_t physicalX, int32_t physicalY)
{
    if (InitLayer(MOUSE_ICON(lastMouseStyle_.id)) != RET_OK) {
        CursorDrawingInformation::GetInstance().SetMouseIconUpdate(false);
        MMI_HILOGE("Init layer failed");
        return RET_ERR;
    }
    if (!SetCursorLocation(physicalX, physicalY)) {
        return RET_ERR;
    }
    return RET_OK;
}

int32_t PointerDrawingManager::DrawMovePointer(uint64_t rsId, int32_t physicalX, int32_t physicalY,
    PointerStyle pointerStyle, Direction direction)
{
    CHKPR(GetSurfaceNode(), RET_ERR);
    MMI_HILOGD("Pointer window move success, pointerStyle id:%{public}d", pointerStyle.id);
    displayId_ = rsId;
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
#ifdef OHOS_BUILD_ENABLE_EXTERNAL_SCREEN
    UpdateBindDisplayId(rsId);
#endif // OHOS_BUILD_ENABLE_EXTERNAL_SCREEN
    bool mouseIconUpdate = CursorDrawingInformation::GetInstance().GetMouseIconUpdate();
    if (lastMouseStyle_ == pointerStyle && !mouseIconUpdate &&
        lastDirection_ == direction && !offRenderScaleUpdate_ && !mouseDirectionUpdate_) {
        if (!SetCursorLocation(physicalX, physicalY)) {
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
    if (GetHardCursorEnabled()) {
        UpdatePointerVisible();
    } else {
        int32_t UpdateLayerRes = UpdateMouseLayer(physicalX, physicalY);
        if (UpdateLayerRes != RET_OK) {
            MMI_HILOGE("Update Mouse Layer failed.");
        }
        UpdatePointerVisible();
    }
    CursorDrawingInformation::GetInstance().SetMouseIconUpdate(false);
    offRenderScaleUpdate_ = false;
    mouseDirectionUpdate_ = false;
    MMI_HILOGD("Leave, rsId:%{public}" PRIu64 ", physicalX:%{private}d, physicalY:%{private}d",
        rsId, physicalX, physicalY);
    return RET_OK;
}

int32_t PointerDrawingManager::UpdateSurfaceNodeBounds(int32_t physicalX, int32_t physicalY)
{
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
    if (HasMagicCursor()) {
        auto surfaceNodePtr = GetSurfaceNode();
        CHKPR(surfaceNodePtr, RET_ERR);
        if (currentMouseStyle_.id == DEVELOPER_DEFINED_ICON) {
            surfaceNodePtr->SetBounds(physicalX, physicalY, canvasWidth_, canvasHeight_);
        } else {
            surfaceNodePtr->SetBounds(physicalX, physicalY, imageWidth_, imageHeight_);
        }
        return RET_OK;
    }
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
    return RET_ERR;
}

void PointerDrawingManager::DrawMovePointer(uint64_t rsId, int32_t physicalX, int32_t physicalY)
{
    CALL_DEBUG_ENTER;
    displayId_ = rsId;
#ifdef OHOS_BUILD_ENABLE_EXTERNAL_SCREEN
    UpdateBindDisplayId(rsId);
#endif // OHOS_BUILD_ENABLE_EXTERNAL_SCREEN
    Direction direction = static_cast<Direction>((
        ((displayInfo_.direction - displayInfo_.displayDirection) * ANGLE_90 + ANGLE_360) % ANGLE_360) / ANGLE_90);
    AdjustMouseFocusToSoftRenderOrigin(direction, MOUSE_ICON(lastMouseStyle_.id), physicalX, physicalY);
    if (GetSurfaceNode() != nullptr) {
        if (!SetCursorLocation(physicalX, physicalY)) {
            MMI_HILOGE("SetCursorLocation failed");
            return;
        }
        MMI_HILOGD("Move pointer, physicalX:%d, physicalY:%d", physicalX, physicalY);
    }
}

void PointerDrawingManager::DrawPointer(uint64_t rsId, int32_t physicalX, int32_t physicalY,
    const PointerStyle pointerStyle, Direction direction)
{
    CALL_DEBUG_ENTER;
    MMI_HILOGD("rsId:%{public}" PRIu64 ", physicalX:%{private}d, physicalY:%{private}d, pointerStyle:%{public}d",
        rsId, physicalX, physicalY, pointerStyle.id);
    FixCursorPosition(physicalX, physicalY);
    lastPhysicalX_ = physicalX;
    lastPhysicalY_ = physicalY;
    currentMouseStyle_ = pointerStyle;
    currentDirection_ = direction;
    AdjustMouseFocusToSoftRenderOrigin(direction, MOUSE_ICON(pointerStyle.id), physicalX, physicalY);
    // Log printing only occurs when the mouse style changes
    if (currentMouseStyle_.id != lastMouseStyle_.id) {
        MMI_HILOGD("MagicCursor AdjustMouseFocus:%{public}d",
            CursorDrawingInformation::GetInstance().MouseIcon2IconType(MOUSE_ICON(pointerStyle.id)));
    }
    if (DrawMovePointer(rsId, physicalX, physicalY, pointerStyle, direction) == RET_OK) {
        return;
    }
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
    if (HasMagicCursor() && currentMouseStyle_.id != DEVELOPER_DEFINED_ICON) {
        MMI_HILOGD("magicCursor DrawPointer enter CreatePointerWindow");
        MAGIC_CURSOR->CreatePointerWindow(rsId, physicalX, physicalY, direction, surfaceNode_);
    } else {
        CreatePointerWindow(rsId, physicalX, physicalY, direction);
    }
#else
    CreatePointerWindow(rsId, physicalX, physicalY, direction);
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
    CHKPV(GetSurfaceNode());
    UpdateMouseStyle();
    if (InitLayer(MOUSE_ICON(lastMouseStyle_.id)) != RET_OK) {
        MMI_HILOGE("Init layer failed");
        return;
    }
    UpdatePointerVisible();
    MMI_HILOGI("Leave, rsId:%{private}" PRIu64 ", physicalX:%{private}d, physicalY:%{private}d",
        rsId, physicalX, physicalY);
}

void PointerDrawingManager::UpdateMouseStyle()
{
    CALL_DEBUG_ENTER;
    PointerStyle curPointerStyle;
    CursorDrawingInformation::GetInstance().GetPointerStyle(GetCurrentUser(), pid_, GLOBAL_WINDOW_ID, curPointerStyle);
    if (curPointerStyle.id == CURSOR_CIRCLE_STYLE || curPointerStyle.id == AECH_DEVELOPER_DEFINED_STYLE) {
        lastMouseStyle_.id = curPointerStyle.id;
        if (WIN_MGR->SetPointerStyle(pid_, GLOBAL_WINDOW_ID, lastMouseStyle_) != RET_OK) {
            MMI_HILOGE("Set pointer style failed");
        }
    }
    MMI_HILOGI("LastMouseStyle_.id:%{public}d, curPointerStyle.id:%{public}d", lastMouseStyle_.id, curPointerStyle.id);
}

int32_t PointerDrawingManager::SwitchPointerStyle()
{
    CALL_DEBUG_ENTER;
    int32_t size = GetPointerSize(GetCurrentUser());
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
    AdjustMouseFocusToSoftRenderOrigin(direction, MOUSE_ICON(lastMouseStyle_.id), physicalX, physicalY);
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
    if (HasMagicCursor()) {
        MAGIC_CURSOR->EnableCursorInversion();
        MAGIC_CURSOR->CreatePointerWindow(displayInfo_.rsId, physicalX, physicalY, direction, surfaceNode_);
    } else {
        MAGIC_CURSOR->DisableCursorInversion();
        CreatePointerWindow(displayInfo_.rsId, physicalX, physicalY, direction);
    }
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
    int32_t ret = InitLayer(MOUSE_ICON(lastMouseStyle_.id));
    if (ret != RET_OK) {
        MMI_HILOGE("Init layer failed");
        return ret;
    }
    UpdatePointerVisible();
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
    isMagicCursor hasMagicCursor = CursorDrawingInformation::GetInstance().GetHasMagicCursor();
    int32_t ret = CreatePointerSwitchObserver(hasMagicCursor);
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
            auto surfaceNodePtr = GetSurfaceNode();
            CHKPV(surfaceNodePtr);
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
            MMI_HILOGD("Switch pointer style");
            int64_t nodeId = static_cast<int64_t>(surfaceNodePtr->GetId());
            if (nodeId != MAGIC_CURSOR->GetSurfaceNodeId(nodeId)) {
                MMI_HILOGI("DetachToDisplay start screenId_:%{public}" PRIu64, screenId_);
                surfaceNodePtr->DetachToDisplay(screenId_);
                SetSurfaceNode(nullptr);
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
    isMagicCursor hasMagicCursor = CursorDrawingInformation::GetInstance().GetHasMagicCursor();
    return hasMagicCursor.isShow;
}

int32_t PointerDrawingManager::InitVsync(MOUSE_ICON mouseStyle)
{
    if (g_isReStartVsync) {
        isRenderRunning_.store(true);
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
    if (GetHardCursorEnabled()) {
        for (size_t i = 0; i < RETRY_TIMES; i++) {
            buffer = GetSurfaceBuffer(layer);
            if (buffer != nullptr && buffer->GetVirAddr() != nullptr) {
                return buffer;
            }
        }
    }
    return buffer;
}

int32_t PointerDrawingManager::GetMainScreenDisplayInfo(const OLD::DisplayGroupInfo &displayGroupInfo,
    OLD::DisplayInfo &mainScreenDisplayInfo) const
{
    if (displayGroupInfo.displaysInfo.empty()) {
        MMI_HILOGE("displayGroupInfo doesn't contain displayInfo");
        return RET_ERR;
    }
    for (const OLD::DisplayInfo& display : displayGroupInfo.displaysInfo) {
        if (display.displaySourceMode == OHOS::MMI::DisplaySourceMode::SCREEN_MAIN) {
            mainScreenDisplayInfo = display;
            return RET_OK;
        }
    }
    mainScreenDisplayInfo = displayGroupInfo.displaysInfo[0];
    return RET_OK;
}

int32_t PointerDrawingManager::InitLayer(const MOUSE_ICON mouseStyle)
{
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
    if (HasMagicCursor() && mouseStyle != MOUSE_ICON::DEVELOPER_DEFINED_ICON) {
        MMI_HILOGD("magiccursor enter MAGIC_CURSOR->Initlayer");
        return MAGIC_CURSOR->InitLayer(mouseStyle);
    }
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
    if (GetHardCursorEnabled()) {
        MMI_HILOGI("mouseStyle:%{public}u", static_cast<uint32_t>(mouseStyle));
        if ((mouseStyle == MOUSE_ICON::LOADING) || (mouseStyle == MOUSE_ICON::RUNNING)) {
            return InitVsync(mouseStyle);
        }
        std::lock_guard<std::recursive_mutex> lg(recursiveMtx_);
        hardwareCanvasSize_ = g_hardwareCanvasSize;
        // Change the drawing to asynchronous, and when obtaining the surfaceBuffer fails,
        // repeatedly obtain the surfaceBuffer.
        PostSoftCursorTask([this, mouseStyle]() {
            SoftwareCursorRender(mouseStyle);
        });
        HardwareCursorRender(mouseStyle);
        return RET_OK;
    }
    return DrawCursor(mouseStyle);
}

int32_t PointerDrawingManager::DrawCursor(const MOUSE_ICON mouseStyle)
{
    CALL_DEBUG_ENTER;
    auto surfaceNodePtr = GetSurfaceNode();
    CHKPR(surfaceNodePtr, RET_ERR);
    DrawLoadingPointer(mouseStyle);
    DrawRunningPointerAnimate(mouseStyle);
    sptr<OHOS::Surface> layer = GetLayer();
    if (layer == nullptr) {
        MMI_HILOGE("Init layer is failed, Layer is nullptr");
        surfaceNodePtr->DetachToDisplay(screenId_);
        SetSurfaceNode(nullptr);
        MMI_HILOGI("Detach screenId:%{public}" PRIu64, screenId_);
        Rosen::RSTransaction::FlushImplicitTransaction();
        MMI_HILOGE("Pointer window destroy success");
        return RET_ERR;
    }
    sptr<OHOS::SurfaceBuffer> buffer = GetSurfaceBuffer(layer);
    if (buffer == nullptr || buffer->GetVirAddr() == nullptr) {
        MMI_HILOGI("DetachToDisplay start screenId_:%{public}" PRIu64, screenId_);
        surfaceNodePtr->DetachToDisplay(screenId_);
        SetSurfaceNode(nullptr);
        MMI_HILOGI("Detach screenId:%{public}" PRIu64, screenId_);
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

void PointerDrawingManager::DrawLoadingPointer(const MOUSE_ICON mouseStyle)
{
    CALL_DEBUG_ENTER;
    auto surfaceNodePtr = GetSurfaceNode();
    CHKPV(surfaceNodePtr);
    Rosen::RSAnimationTimingProtocol protocol;
    auto mouseIcons = CursorDrawingInformation::GetInstance().GetMouseIconsMap();
    if (mouseStyle != MOUSE_ICON::LOADING &&
        (mouseStyle != MOUSE_ICON::DEFAULT ||
            mouseIcons[mouseStyle].iconPath != (IMAGE_POINTER_DEFAULT_PATH + "Loading.svg"))) {
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
    if (canvasWidth_ == 0) {
        MMI_HILOGE("The divisor cannot be 0");
        return;
    }
    float ratio = imageWidth_ * 1.0 / canvasWidth_;
    surfaceNodePtr->SetPivot({LOADING_CENTER_RATIO * ratio, LOADING_CENTER_RATIO * ratio});
    protocol.SetDuration(ANIMATION_DURATION);
    protocol.SetRepeatCount(DEFAULT_VALUE);

    // create property animation
    Rosen::RSNode::Animate(
        protocol,
        Rosen::RSAnimationTimingCurve::LINEAR,
        [this]() {
            auto ptr = GetSurfaceNode();
            CHKPV(ptr);
            ptr->SetRotation(ROTATION_ANGLE);
        });
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
        releaseContext = nullptr;
    }
    return image;
}

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
    if (softCursorHandler_ != nullptr) {
        softCursorHandler_->PostTask(task);
    }
}

void PointerDrawingManager::PostMoveRetryTask(std::function<void()> task)
{
    CHKPV(hardwareCursorPointerManager_);
    if (g_isHdiRemoteDied) {
        hardwareCursorPointerManager_->SetHdiServiceState(false);
    }
    if (moveRetryHandler_ != nullptr) {
        moveRetryHandler_->PostTask(task);
    }
}

int32_t PointerDrawingManager::DrawDynamicHardwareCursor(std::shared_ptr<ScreenPointer> sp,
    const RenderConfig &cfg)
{
    CHKPR(sp, RET_ERR);
    bool isCommonBuffer;
    auto buffer = sp->RequestBuffer(cfg, isCommonBuffer);
    CHKPR(buffer, RET_ERR);
    if (isCommonBuffer) {
        auto addr = static_cast<uint8_t*>(buffer->GetVirAddr());
        CHKPR(addr, RET_ERR);
        if (pointerRenderer_.DynamicRender(addr, buffer->GetWidth(), buffer->GetHeight(), cfg) != RET_OK) {
            MMI_HILOGE("DynamicRender failed");
        };
    }

    MMI_HILOGI("DrawDynamicHardwareCursor on ScreenPointer success, screenId = %{public}" PRIu64 ", style = %{public}d",
        sp->GetScreenId(), cfg.style_);
    auto sret = buffer->FlushCache();
    if (sret != RET_OK) {
        MMI_HILOGE("FlushCache ret: %{public}d", sret);
        return sret;
    }
    return RET_OK;
}

void PointerDrawingManager::HardwareCursorDynamicRender(MOUSE_ICON mouseStyle)
{
    auto screenPointers = CopyScreenPointers();
    auto mouseIcons = CursorDrawingInformation::GetInstance().GetMouseIconsMap();
    RenderConfig cfg {
        .style_ = mouseStyle,
        .align_ = CursorDrawingInformation::GetInstance().MouseIcon2IconType(mouseStyle),
        .path_ = mouseIcons[mouseStyle].iconPath,
        .color = GetPointerColor(GetCurrentUser()),
        .size = GetPointerSize(GetCurrentUser()),
        .direction = displayInfo_.direction,
        .isHard = true,
        .rotationAngle = currentFrame_ * DYNAMIC_ROTATION_ANGLE,
        .userIconPixelMap = DecodeImageToPixelMap(mouseStyle),
    };
    for (auto it : screenPointers) {
        CHKPV(it.second);
        cfg.dpi = it.second->GetDPI() * it.second->GetScale();
        cfg.direction = it.second->IsMirror() ? DIRECTION0 : displayInfo_.direction;
        MMI_HILOGD("HardwareCursorRender, screen = %{public}" PRIu64 ", dpi = %{public}f",
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
    if (pointerRenderer_.DynamicRender(addr, buffer->GetWidth(), buffer->GetHeight(), cfg) != RET_OK) {
        MMI_HILOGE("DynamicRender failed");
    }
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
    MMI_HILOGI("DrawDynamicSoftCursor on sn success, styel = %{public}d", cfg.style_);
    return RET_OK;
}

void PointerDrawingManager::SoftwareCursorDynamicRender(MOUSE_ICON mouseStyle)
{
    auto screenPointers = CopyScreenPointers();
    auto mouseIcons = CursorDrawingInformation::GetInstance().GetMouseIconsMap();
    for (auto it : screenPointers) {
        RenderConfig cfg {
            .style_ = mouseStyle,
            .align_ = CursorDrawingInformation::GetInstance().MouseIcon2IconType(mouseStyle),
            .path_ = mouseIcons[mouseStyle].iconPath,
            .color = GetPointerColor(GetCurrentUser()),
            .size = GetPointerSize(GetCurrentUser()),
            .isHard = false,
            .rotationAngle = currentFrame_ * DYNAMIC_ROTATION_ANGLE,
        };
        CHKPV(it.second);
        Direction direction = CalculateRenderDirection(false);
        cfg.direction = it.second->IsMirror() ? DIRECTION0 : direction;
        auto sn = it.second->GetSurfaceNode();
        cfg.dpi = it.second->GetDPI();
        MMI_HILOGD("SoftwareCursorDynamicRender, screen = %{public}" PRIu64 ", dpi = %{public}f", it.first, cfg.dpi);
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
            cfg.style_ = MOUSE_ICON::TRANSPARENT_ICON;
            cfg.align_ = CursorDrawingInformation::GetInstance().MouseIcon2IconType(cfg.style_);
            cfg.path_ = mouseIcons[cfg.style_].iconPath;
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
    if (!CursorDrawingInformation::GetInstance().IsPointerVisible() || !mouseDisplayState_) {
        MMI_HILOGE("Mouse is hide, stop request vsync");
        return;
    }
    PostTask([this]() -> void {
        std::lock_guard<std::recursive_mutex> lg(recursiveMtx_);
        if (currentMouseStyle_.id != MOUSE_ICON::RUNNING && currentMouseStyle_.id != MOUSE_ICON::LOADING) {
            MMI_HILOGE("Current post task mouse style is not equal to last mouse style");
            return;
        }

        HardwareCursorDynamicRender(MOUSE_ICON(currentMouseStyle_.id));
        ResetMoveRetryTimer();
        if (HardwareCursorMove(lastPhysicalX_, lastPhysicalY_) != RET_OK) {
            MoveRetryAsync(lastPhysicalX_, lastPhysicalY_);
        }
        PostSoftCursorTask([this]() {
            SoftwareCursorDynamicRender(MOUSE_ICON(currentMouseStyle_.id));
            SoftwareCursorMove(displayId_, lastPhysicalX_, lastPhysicalY_);
        });
        currentFrame_++;
        if (currentFrame_ == frameCount_) {
            currentFrame_ = 0;
        }
        CursorDrawingInformation::GetInstance().SetMouseIconUpdate(false);
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
    isRenderRunning_.store(true);
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
    SetThreadName(std::string("SoftCurRender"));
#ifdef OHOS_BUILD_PC_PRIORITY
    struct sched_param param = { 0 };
    param.sched_priority = PC_PRIORITY;
    int32_t schRet = sched_setscheduler(0, SCHED_FIFO, &param);
    if (schRet != 0) {
        MMI_HILOGE("SoftCursorRenderThreadLoop set SCHED_FIFO failed, schRet:%{public}d, errno:%{public}d",
            schRet, errno);
    }
#endif // OHOS_BUILD_PC_PRIORITY
    softCursorRunner_ = AppExecFwk::EventRunner::Create(false);
    CHKPV(softCursorRunner_);
    softCursorHandler_ = std::make_shared<AppExecFwk::EventHandler>(softCursorRunner_);
    CHKPV(softCursorHandler_);
    if (softCursorRunner_ != nullptr) {
        MMI_HILOGI("Runner is run");
        softCursorRunner_->Run();
    }
}

void PointerDrawingManager::MoveRetryThreadLoop()
{
    moveRetryRunner_ = AppExecFwk::EventRunner::Create(false);
    CHKPV(moveRetryRunner_);
    moveRetryHandler_ = std::make_shared<AppExecFwk::EventHandler>(moveRetryRunner_);
    CHKPV(moveRetryHandler_);
    if (moveRetryRunner_ != nullptr) {
        MMI_HILOGI("Runner is run");
        moveRetryRunner_->Run();
    }
}

void PointerDrawingManager::DrawRunningPointerAnimate(const MOUSE_ICON mouseStyle)
{
    CALL_DEBUG_ENTER;
    CHKPV(GetSurfaceNode());
    CHKPV(canvasNode_);
    auto mouseIcons = CursorDrawingInformation::GetInstance().GetMouseIconsMap();
    if (mouseStyle != MOUSE_ICON::RUNNING && (mouseStyle != MOUSE_ICON::DEFAULT ||
            mouseIcons[mouseStyle].iconPath != (IMAGE_POINTER_DEFAULT_PATH + "Loading_Left.svg"))) {
        if (canvasNode_ != nullptr) {
            Rosen::RSAnimationTimingProtocol protocol;
            protocol.SetDuration(0);
            Rosen::RSNode::Animate(
                protocol,
                Rosen::RSAnimationTimingCurve::LINEAR,
                [this]() { canvasNode_->SetRotation(0); });
            canvasNode_->SetVisible(false);
        }
        MMI_HILOGE("current pointer is not running");
        return;
    }
    canvasNode_->SetVisible(true);
    canvasWidth_ = (imageWidth_ / POINTER_WINDOW_INIT_SIZE + 1) * POINTER_WINDOW_INIT_SIZE;
    canvasHeight_ = (imageHeight_ / POINTER_WINDOW_INIT_SIZE + 1) * POINTER_WINDOW_INIT_SIZE;
    cursorWidth_ = imageWidth_;
    cursorHeight_ = imageHeight_;
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
    if (GetHardCursorEnabled()) {
        return;
    }
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
    if (GetHardCursorEnabled() && currentMouseStyle_.id == MOUSE_ICON::DEVELOPER_DEFINED_ICON) {
        height = cursorHeight_;
        width = cursorWidth_;
    }
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
    if (GetHardCursorEnabled() && currentMouseStyle_.id == MOUSE_ICON::DEVELOPER_DEFINED_ICON) {
        height = cursorHeight_;
        width = cursorWidth_;
    }
    switch (iconType) {
        case ANGLE_SW: {
            physicalX -= height;
            break;
        }
        case ANGLE_CENTER: {
            physicalX -= width / CALCULATE_MIDDLE;
            physicalY += height / CALCULATE_MIDDLE;
            break;
        }
        case ANGLE_NW_RIGHT: {
            physicalY -= width * MOUSE_ICON_BIAS_RATIO;
            [[fallthrough]];
        }
        case ANGLE_NW: {
            if (currentMouseStyle_.id == MOUSE_ICON::DEVELOPER_DEFINED_ICON) {
                if (GetUserIconCopy() != nullptr) {
                    physicalX -= userIconHotSpotY_;
                    physicalY += userIconHotSpotX_;
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
    if (GetHardCursorEnabled() && currentMouseStyle_.id == MOUSE_ICON::DEVELOPER_DEFINED_ICON) {
        height = cursorHeight_;
        width = cursorWidth_;
    }
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
    if (GetHardCursorEnabled() && currentMouseStyle_.id == MOUSE_ICON::DEVELOPER_DEFINED_ICON) {
        height = cursorHeight_;
        width = cursorWidth_;
    }
    switch (iconType) {
        case ANGLE_SW: {
            physicalX += height;
            break;
        }
        case ANGLE_CENTER: {
            physicalX += width / CALCULATE_MIDDLE;
            physicalY -= height / CALCULATE_MIDDLE;
            break;
        }
        case ANGLE_NW_RIGHT: {
            physicalY -= width * MOUSE_ICON_BIAS_RATIO;
            [[fallthrough]];
        }
        case ANGLE_NW: {
            if (currentMouseStyle_.id == MOUSE_ICON::DEVELOPER_DEFINED_ICON) {
                if (GetUserIconCopy() != nullptr) {
                    physicalX += userIconHotSpotY_;
                    physicalY -= userIconHotSpotX_;
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
        if (mouseDisplayState_ && !GetHardCursorEnabled()) {
            InitLayer(MOUSE_ICON(lastMouseStyle_.id));
        }
        MMI_HILOGI("The state:%{public}s", state ? "true" : "false");
        UpdatePointerVisible();
    }
    POINTER_DEV_MGR.mouseDisplayState = mouseDisplayState_;
}

bool PointerDrawingManager::GetMouseDisplayState() const
{
    return mouseDisplayState_;
}

Direction PointerDrawingManager::GetDisplayDirection(const OLD::DisplayInfo *displayInfo)
{
    CHKPR(displayInfo, DIRECTION0);
    Direction direction = static_cast<Direction>((
        ((displayInfo->direction - displayInfo->displayDirection) * ANGLE_90 + ANGLE_360) % ANGLE_360) / ANGLE_90);
    if (!Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        direction = displayInfo->direction;
    }
    return direction;
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
    Direction direction = GetDisplayDirection(&displayInfo_);
    if (!Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        direction = displayInfo_.direction;
    }
    if (GetHardCursorEnabled()) {
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
    } else {
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
    }
}

void PointerDrawingManager::AttachToDisplay()
{
    CALL_DEBUG_ENTER;
    CHKPV(GetSurfaceNode());
    if (IsSingleDisplayFoldDevice() && (WIN_MGR->GetDisplayMode() == DisplayMode::MAIN)
        && (screenId_ == FOLD_SCREEN_ID_FULL)) {
        screenId_ = FOLD_SCREEN_ID_MAIN;
    }
    MMI_HILOGI("The screenId_:%{public}" PRIu64"", screenId_);

    if (GetHardCursorEnabled()) {
        auto sp = GetScreenPointer(screenId_);
        CHKPV(sp);
        SetSurfaceNode(sp->GetSurfaceNode());
        auto ptr = GetSurfaceNode();
        if ((originSetColor_ != -1) && (ptr != nullptr)) {
            float alphaRatio = (static_cast<uint32_t>(originSetColor_) >> RGB_CHANNEL_BITS_LENGTH) / MAX_ALPHA_VALUE;
            if (alphaRatio > 1) {
                MMI_HILOGW("Invalid alphaRatio:%{public}f", alphaRatio);
            } else {
                ptr->SetAlpha(1 - alphaRatio);
            }
        }
    }
    auto surfaceNodePtr = GetSurfaceNode();
    CHKPV(surfaceNodePtr);
    MMI_HILOGI("AttachToDisplay screenId_:%{public}" PRIu64"", screenId_);
    surfaceNodePtr->AttachToDisplay(screenId_);
}

void PointerDrawingManager::CreateCanvasNode()
{
    if (GetHardCursorEnabled()) {
        return;
    }
    auto surfaceNodePtr = GetSurfaceNode();
    CHKPV(surfaceNodePtr);
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
    surfaceNodePtr->AddChild(canvasNode_, DEFAULT_VALUE);
}

int32_t PointerDrawingManager::CreatePointerWindowForScreenPointer(uint64_t rsId,
    int32_t physicalX, int32_t physicalY)
{
    CALL_DEBUG_ENTER;
    // suface node init
    auto sp = GetScreenPointer(rsId);
    if (sp != nullptr && !g_isRsRestart) {
        auto screenPointers = CopyScreenPointers();
        for (auto it : screenPointers) {
            CHKPR(it.second, RET_ERR);
            if (it.second == nullptr) {
                return RET_ERR;
            }
            it.second->Init(pointerRenderer_);
        }
        if (rsId == displayInfo_.rsId) {
            SetSurfaceNode(sp->GetSurfaceNode());
        }
        Rosen::RSTransaction::FlushImplicitTransaction();
        g_isRsRestart = true;
    } else if (sp == nullptr) {
        g_isRsRestart = true;
        sp = std::make_shared<ScreenPointer>(hardwareCursorPointerManager_, handler_, displayInfo_);
        CHKPR(sp, RET_ERR);
        InsertScreenPointer(displayInfo_.rsId, sp);
        if (!sp->Init(pointerRenderer_)) {
            MMI_HILOGE("ScreenPointer %{public}" PRIu64 " init failed", displayInfo_.rsId);
            return RET_ERR;
        }
        if (rsId == displayInfo_.rsId) {
            SetSurfaceNode(sp->GetSurfaceNode());
        }
        MMI_HILOGI("ScreenPointer rsId %{public}" PRIu64 " displayInfo_.rsId %{public}" PRIu64,
            rsId, displayInfo_.rsId);
        Rosen::RSTransaction::FlushImplicitTransaction();
    }
    CHKPR(sp, RET_ERR);
    SetSurfaceNode(sp->GetSurfaceNode()); // use SurfaceNode from current display
    CHKPR(GetSurfaceNode(), RET_ERR);
    sp->MoveSoft(physicalX, physicalY);
    return RET_OK;
}

int32_t PointerDrawingManager::CreatePointerWindowForNoScreenPointer(int32_t physicalX, int32_t physicalY)
{
    CALL_DEBUG_ENTER;
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::CURSOR_NODE;
    SetSurfaceNode(Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType));
    auto surfaceNodePtr = GetSurfaceNode();
    CHKPR(surfaceNodePtr, RET_ERR);
    surfaceNodePtr->SetPositionZ(Rosen::RSSurfaceNode::POINTER_WINDOW_POSITION_Z);
    surfaceNodePtr->SetFrameGravity(Rosen::Gravity::RESIZE_ASPECT_FILL);
    surfaceNodePtr->SetBounds(physicalX, physicalY, canvasWidth_, canvasHeight_);
#ifndef USE_ROSEN_DRAWING
    surfaceNodePtr->SetBackgroundColor(SK_ColorTRANSPARENT);
#else
    surfaceNodePtr->SetBackgroundColor(Rosen::Drawing::Color::COLOR_TRANSPARENT);
#endif
    surfaceNodePtr->SetVisible(false);
    return RET_OK;
}

void PointerDrawingManager::CreatePointerWindow(uint64_t rsId, int32_t physicalX, int32_t physicalY,
    Direction direction)
{
    CALL_INFO_TRACE;
    BytraceAdapter::StartRsSurfaceNode(rsId);

    if (GetHardCursorEnabled()) {
        g_isHdiRemoteDied = false;
        if (CreatePointerWindowForScreenPointer(rsId, physicalX, physicalY) != RET_OK) {
            return;
        }
    } else {
        if (CreatePointerWindowForNoScreenPointer(physicalX, physicalY) != RET_OK) {
            return;
        }
    }
    screenId_ = rsId;
    AttachToDisplay();
    lastDisplayId_ = rsId;
    MMI_HILOGI("CreatePointerWindow The screenId_:%{public}" PRIu64, screenId_);
    RotateDegree(direction);
    lastDirection_ = direction;
    CreateCanvasNode();
    Rosen::RSTransaction::FlushImplicitTransaction();
    BytraceAdapter::StopRsSurfaceNode();
}

sptr<OHOS::Surface> PointerDrawingManager::GetLayer()
{
    CALL_DEBUG_ENTER;
    auto surfaceNodePtr = GetSurfaceNode();
    CHKPP(surfaceNodePtr);
    return surfaceNodePtr->GetSurface();
}

sptr<OHOS::SurfaceBuffer> PointerDrawingManager::GetSurfaceBuffer(sptr<OHOS::Surface> layer)
{
    CALL_DEBUG_ENTER;
    sptr<OHOS::SurfaceBuffer> buffer;
    int32_t releaseFence = -1;
    int32_t width = 0;
    int32_t height = 0;
    if (GetHardCursorEnabled()) {
        CALCULATE_CANVAS_SIZE(CALCULATE_CANVAS_SIZE_, CHANGE) = GetCanvasSize();
        auto canvasSize = static_cast<int32_t>(CALCULATE_CANVAS_SIZE_CHANGE);
        width = canvasSize;
        height = canvasSize;
    } else {
        width = canvasWidth_;
        height = canvasHeight_;
    }
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
    pen.SetWidth(OHOS::Rosen::Drawing::scalar(1));
    canvas.AttachPen(pen);
    std::shared_ptr<Rosen::Drawing::Image> image = nullptr;
    if (mouseStyle == MOUSE_ICON::DEVELOPER_DEFINED_ICON) {
        MMI_HILOGD("Set mouseicon by userIcon_");
        auto userIconCopy = GetUserIconCopy();
        image = ExtractDrawingImage(userIconCopy);
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
        SetPixelMap(userIconCopy);
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
    } else {
        auto surfaceNodePtr = GetSurfaceNode();
        CHKPV(surfaceNodePtr);
        int32_t physicalX = lastPhysicalX_;
        int32_t physicalY = lastPhysicalY_;
        Direction direction = static_cast<Direction>((
            ((displayInfo_.direction - displayInfo_.displayDirection) * ANGLE_90 + ANGLE_360) % ANGLE_360) / ANGLE_90);
        AdjustMouseFocusToSoftRenderOrigin(direction, mouseStyle, physicalX, physicalY);
        surfaceNodePtr->SetBounds(physicalX, physicalY, canvasWidth_, canvasHeight_);
        std::shared_ptr<OHOS::Media::PixelMap> pixelmap = nullptr;
        if (mouseStyle == MOUSE_ICON::RUNNING) {
            mouseStyle = MOUSE_ICON::RUNNING_LEFT;
        }
        pixelmap = DecodeImageToPixelMap(mouseStyle);
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

int32_t PointerDrawingManager::GetCurrentCursorInfo(bool& visible, PointerStyle& pointerStyle)
{
    CALL_DEBUG_ENTER;
    visible = POINTER_DEV_MGR.isPointerVisible;
    if (!visible) {
        MMI_HILOGD("current pointer is not visible");
        return RET_OK;
    }
    pointerStyle.id = lastMouseStyle_.id;
    pointerStyle.size = GetPointerSize(GetCurrentUser());
    pointerStyle.color = GetPointerColor(GetCurrentUser());
    return RET_OK;
}

int32_t PointerDrawingManager::GetUserDefinedCursorPixelMap(void *pixelMapPtr)
{
    CHKPR(pixelMapPtr, RET_ERR);
    std::shared_ptr<Media::PixelMap> *newPixelMapPtr = static_cast<std::shared_ptr<Media::PixelMap> *>(pixelMapPtr);
    auto userIconPixelMap = GetUserIconCopy(false);
    CHKPR(userIconPixelMap, RET_ERR);
    *newPixelMapPtr = userIconPixelMap;
    return RET_OK;
}

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
    errno_t ret = memcpy_s(addr, addrSize, bitmap.GetPixels(), bitmap.ComputeByteSize());
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
    pen.SetWidth(OHOS::Rosen::Drawing::scalar(1));
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

int32_t PointerDrawingManager::SetCustomCursor(CursorPixelMap curPixelMap,
    int32_t pid, int32_t windowId, int32_t focusX, int32_t focusY)
{
    CALL_DEBUG_ENTER;
    followSystem_ = false;
    if (GetHardCursorEnabled()) {
        userIconFollowSystem_ = true;
    }
    CHKPR(curPixelMap.pixelMap, RET_ERR);
    if (pid == -1) {
        MMI_HILOGE("The pid is invalid");
        return RET_ERR;
    }
    if (windowId < 0) {
        int32_t ret = UpdateCursorProperty(curPixelMap, focusX, focusY);
        if (ret != RET_OK) {
            MMI_HILOGE("UpdateCursorProperty is failed");
            return ret;
        }
        // Constructing a PointerStyle indicates that the SA is being passed in
        MMI_HILOGE("This indicates that the message transmitted is SA, windowId:%{public}d", windowId);
        CursorDrawingInformation::GetInstance().SetMouseIconUpdate(true);
        PointerStyle style;
        style.id = MOUSE_ICON::AECH_DEVELOPER_DEFINED_ICON;
        lastMouseStyle_ = style;
        ret = CursorDrawingInformation::GetInstance().SetPointerStyle(GetCurrentUser(), pid, windowId, style);
        if (ret != RET_OK) {
            MMI_HILOGE("SetPointerStyle is failed");
        }
        return ret;
    }
    if (WIN_MGR->CheckWindowIdPermissionByPid(windowId, pid) != RET_OK) {
        MMI_HILOGE("The windowId not in right pid");
        return RET_ERR;
    }
    int32_t ret = UpdateCursorProperty(curPixelMap, focusX, focusY);
    if (ret != RET_OK) {
        MMI_HILOGE("UpdateCursorProperty is failed");
        return ret;
    }
    CursorDrawingInformation::GetInstance().SetMouseIconUpdate(true);
    PointerStyle style;
    style.id = MOUSE_ICON::DEVELOPER_DEFINED_ICON;
    lastMouseStyle_ = style;

    ret = CursorDrawingInformation::GetInstance().SetPointerStyle(GetCurrentUser(), pid, windowId, style);
    if (ret == RET_ERR) {
        MMI_HILOGE("SetPointerStyle is failed");
    }
    MMI_HILOGD("style.id:%{public}d, userIconHotSpotX_:%{private}d, userIconHotSpotY_:%{private}d",
        style.id, userIconHotSpotX_, userIconHotSpotY_);
    return ret;
}


int32_t PointerDrawingManager::UpdateCursorProperty(CursorPixelMap curPixelMap,
    const int32_t &focusX, const int32_t &focusY)
{
    CHKPR(curPixelMap.pixelMap, RET_ERR);
    Media::PixelMap* newPixelMap = static_cast<Media::PixelMap*>(curPixelMap.pixelMap);
    CHKPR(newPixelMap, RET_ERR);
    Media::ImageInfo imageInfo;
    newPixelMap->GetImageInfo(imageInfo);
    int32_t newFocusX = 0;
    int32_t newFocusY = 0;
    newFocusX = focusX < 0 ? 0 : focusX;
    newFocusY = focusY < 0 ? 0 : focusY;
    newFocusX = newFocusX > newPixelMap->GetWidth() ? newPixelMap->GetWidth() : newFocusX;
    newFocusY = newFocusY > newPixelMap->GetHeight() ? newPixelMap->GetHeight() : newFocusY;
    int32_t cursorSize = GetPointerSize(GetCurrentUser());
    cursorWidth_ =
        pow(INCREASE_RATIO, cursorSize - 1) * displayInfo_.dpi * GetIndependentPixels() / BASELINE_DENSITY;
    cursorHeight_ =
        pow(INCREASE_RATIO, cursorSize - 1) * displayInfo_.dpi * GetIndependentPixels() / BASELINE_DENSITY;
    cursorWidth_ = cursorWidth_ < MIN_CURSOR_SIZE ? MIN_CURSOR_SIZE : cursorWidth_;
    cursorHeight_ = cursorHeight_ < MIN_CURSOR_SIZE ? MIN_CURSOR_SIZE : cursorHeight_;
    float xAxis = (float)cursorWidth_ / (float)imageInfo.size.width;
    float yAxis = (float)cursorHeight_ / (float)imageInfo.size.height;
    newPixelMap->scale(xAxis, yAxis, Media::AntiAliasingOption::LOW);
    CursorDrawingInformation::GetInstance().SetUserIconPixelMap(newPixelMap);
    userIconHotSpotX_ = static_cast<int32_t>((float)newFocusX * xAxis);
    userIconHotSpotY_ = static_cast<int32_t>((float)newFocusY * yAxis);
    MMI_HILOGI("cursorWidth:%{public}d, cursorHeight:%{public}d, imageWidth:%{public}d, imageHeight:%{public}d,"
        "focusX:%{private}d, focuxY:%{private}d, xAxis:%{public}f, yAxis:%{public}f, userIconHotSpotX_:%{private}d,"
        "userIconHotSpotY_:%{private}d", cursorWidth_, cursorHeight_, imageInfo.size.width, imageInfo.size.height,
        newFocusX, newFocusY, xAxis, yAxis, userIconHotSpotX_, userIconHotSpotY_);
    return RET_OK;
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
    auto mouseIcons = CursorDrawingInformation::GetInstance().GetMouseIconsMap();
    std::string svgContent;
    std::string imagePath = mouseIcons[type].iconPath;
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
    int32_t pointerColor = GetPointerColor(GetCurrentUser());
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
    auto pointerColor = GetPointerColor(GetCurrentUser());
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

int32_t PointerDrawingManager::SetPointerColor(int32_t userId, int32_t color)
{
    CALL_DEBUG_ENTER;
    MMI_HILOGI("PointerColor:%{public}x, userId:%{private}d", color, userId);
    originSetColor_ = color;
    // ARGB从表面看比RGB多了个A，也是一种色彩模式，是在RGB的基础上添加了Alpha（透明度）通道。
    // 透明度也是以0到255表示的，所以也是总共有256级，透明是0，不透明是255。
    // 这个color每8位代表一个通道值，分别是alpha和rgb，总共32位。
    color = static_cast<int32_t>(static_cast<uint32_t>(color) & static_cast<uint32_t>(MAX_POINTER_COLOR));
    std::string name = POINTER_COLOR;
    GetPreferenceKey(name);
    bool isSuccess = INPUT_SETTING_MANAGER->SetIntValue(userId, MOUSE_KEY_SETTING, name, color);
    if (!isSuccess) {
        MMI_HILOGE("Set pointer color failed, color:%{public}d", color);
        return RET_ERR;
    }
    MMI_HILOGD("Set pointer color successfully, color:%{public}d", color);
    int32_t ret = -1;
    if (!WIN_MGR->GetExtraData().drawCursor) {
        auto surfaceNodePtr = GetSurfaceNode();
        if (surfaceNodePtr != nullptr) {
            float alphaRatio = (static_cast<uint32_t>(color) >> RGB_CHANNEL_BITS_LENGTH) / MAX_ALPHA_VALUE;
            if (alphaRatio > 1) {
                MMI_HILOGW("Invalid alphaRatio:%{public}f", alphaRatio);
            } else {
                surfaceNodePtr->SetAlpha(1 - alphaRatio);
            }
        }
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
        if (HasMagicCursor()) {
            ret = MAGIC_CURSOR->SetPointerColor(color);
        } else {
            CHKPR(surfaceNodePtr, RET_OK);
            ret = InitLayer(MOUSE_ICON(lastMouseStyle_.id));
        }
#else
        CHKPR(surfaceNodePtr, RET_OK);
        ret = InitLayer(MOUSE_ICON(lastMouseStyle_.id));
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
        if (ret != RET_OK) {
            MMI_HILOGE("Init layer failed");
            return RET_ERR;
        }
    }
    UpdatePointerVisible();
    return RET_OK;
}

int32_t PointerDrawingManager::GetPointerColor(int32_t userId)
{
    CALL_DEBUG_ENTER;
    std::string name = POINTER_COLOR;
    GetPreferenceKey(name);
    int32_t pointerColor = DEFAULT_VALUE;
    INPUT_SETTING_MANAGER->GetIntValue(userId, MOUSE_KEY_SETTING, name, pointerColor);
    tempPointerColor_ = pointerColor;
    if (pointerColor == DEFAULT_VALUE) {
        pointerColor = MIN_POINTER_COLOR;
    }
    MMI_HILOGD("Get pointer color successfully, pointerColor:%{public}d", pointerColor);
    return pointerColor;
}

void PointerDrawingManager::UpdateDisplayInfo(const OLD::DisplayInfo &displayInfo)
{
    CALL_DEBUG_ENTER;
    auto sp = GetScreenPointer(displayInfo.rsId);
    if (GetHardCursorEnabled() && sp != nullptr) {
        sp->OnDisplayInfo(displayInfo);
        if (sp->IsMain()) {
            UpdateMirrorScreens(sp, displayInfo);
        }
    }

    hasDisplay_ = true;
    if ((displayInfo.width != 0) && (displayInfo_.width != 0) &&
        ((float(displayInfo_.screenRealWidth) / displayInfo_.width) !=
        (float(displayInfo.screenRealWidth) / displayInfo.width))) {
        offRenderScaleUpdate_ = true;
    }
    if (displayInfo_.direction != displayInfo.direction) {
        mouseDirectionUpdate_ = true;
    }
    displayInfo_ = displayInfo;
    int32_t size = GetPointerSize(GetCurrentUser());
    if (lastMouseStyle_.id == MOUSE_ICON::DEVELOPER_DEFINED_ICON) {
        imageWidth_ = pow(INCREASE_RATIO, size - 1) * displayInfo.dpi * GetIndependentPixels() / BASELINE_DENSITY;
        imageHeight_ = pow(INCREASE_RATIO, size - 1) * displayInfo.dpi * GetIndependentPixels() / BASELINE_DENSITY;
    } else {
        imageWidth_ = pow(INCREASE_RATIO, size - 1) * displayInfo.dpi * GetIndependentPixels() / BASELINE_DENSITY;
        imageHeight_ = pow(INCREASE_RATIO, size - 1) * displayInfo.dpi * GetIndependentPixels() / BASELINE_DENSITY;
        canvasWidth_ = (imageWidth_ / POINTER_WINDOW_INIT_SIZE + 1) * POINTER_WINDOW_INIT_SIZE;
        canvasHeight_ = (imageHeight_ / POINTER_WINDOW_INIT_SIZE + 1) * POINTER_WINDOW_INIT_SIZE;
    }
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

int32_t PointerDrawingManager::SetPointerSize(int32_t userId, int32_t size)
{
    CALL_DEBUG_ENTER;
    if (size < MIN_POINTER_SIZE) {
        size = MIN_POINTER_SIZE;
    } else if (size > MAX_POINTER_SIZE) {
        size = MAX_POINTER_SIZE;
    }
    std::string name = POINTER_SIZE;
    GetPreferenceKey(name);
    bool isSuccess = INPUT_SETTING_MANAGER->SetIntValue(userId, MOUSE_KEY_SETTING, name, size);
    if (!isSuccess) {
        MMI_HILOGE("Set pointer size failed, size:%{public}d", size);
        return RET_ERR;
    }
    MMI_HILOGI("Set pointer size successfully, size:%{public}d", size);

    CHKPR(GetSurfaceNode(), RET_OK);
    imageWidth_ = pow(INCREASE_RATIO, size - 1) * displayInfo_.dpi * GetIndependentPixels() / BASELINE_DENSITY;
    imageHeight_ = pow(INCREASE_RATIO, size - 1) * displayInfo_.dpi * GetIndependentPixels() / BASELINE_DENSITY;
    canvasWidth_ = (imageWidth_ / POINTER_WINDOW_INIT_SIZE + 1) * POINTER_WINDOW_INIT_SIZE;
    canvasHeight_ = (imageHeight_ / POINTER_WINDOW_INIT_SIZE + 1) * POINTER_WINDOW_INIT_SIZE;
    int32_t physicalX = lastPhysicalX_;
    int32_t physicalY = lastPhysicalY_;
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
    MAGIC_CURSOR->SetPointerSize(imageWidth_, imageHeight_);
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
    Direction direction = GetDisplayDirection(&displayInfo_);
    AdjustMouseFocusToSoftRenderOrigin(direction, MOUSE_ICON(lastMouseStyle_.id), physicalX, physicalY);
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
    if (HasMagicCursor()) {
        MAGIC_CURSOR->CreatePointerWindow(displayInfo_.rsId, physicalX, physicalY, direction, surfaceNode_);
    } else {
        CreatePointerWindow(displayInfo_.rsId, physicalX, physicalY, direction);
    }
#else
    CreatePointerWindow(displayInfo_.rsId, physicalX, physicalY, direction);
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
    if (lastMouseStyle_.id == MOUSE_ICON::CURSOR_CIRCLE) {
        MMI_HILOGE("Cursor circle does not need to draw size");
    }
    if (InitLayer(MOUSE_ICON(lastMouseStyle_.id)) != RET_OK) {
        MMI_HILOGE("Init layer failed");
        return RET_ERR;
    }
    UpdatePointerVisible();
    return RET_OK;
}

int32_t PointerDrawingManager::GetPointerSize(int32_t userId)
{
    CALL_DEBUG_ENTER;
    std::string name = POINTER_SIZE;
    GetPreferenceKey(name);
    int32_t pointerSize = DEFAULT_POINTER_SIZE;
    INPUT_SETTING_MANAGER->GetIntValue(userId, MOUSE_KEY_SETTING, name, pointerSize);
    MMI_HILOGD("Get pointer size successfully, pointerSize:%{public}d", pointerSize);
    return pointerSize;
}

void PointerDrawingManager::GetPointerImageSize(int32_t &width, int32_t &height)
{
    width = imageWidth_;
    height = imageHeight_;
}

int32_t PointerDrawingManager::GetCurrentUser()
{
    int32_t userId = INVALID_USER;
    auto pointer = WIN_MGR->GetLastPointerEvent();
    if (pointer != nullptr) {
        userId = WIN_MGR->FindDisplayUserId(pointer->GetTargetDisplayId());
    }
    if (userId < 0) {
        userId = ACCOUNT_MGR->QueryCurrentAccountId();
    }
    return userId > 0 ? userId : DEFAULT_USER_ID;
}

int32_t PointerDrawingManager::GetCursorSurfaceId(uint64_t &surfaceId)
{
    auto surfaceNodePtr = GetSurfaceNode();
    surfaceId = ((surfaceNodePtr != nullptr) ? surfaceNodePtr->GetId() : Rosen::INVALID_NODEID);
    MMI_HILOGI("CursorSurfaceId:%{public}" PRIu64, surfaceId);
    return RET_OK;
}

void PointerDrawingManager::OnDisplayInfo(const OLD::DisplayGroupInfo &displayGroupInfo)
{
    CALL_DEBUG_ENTER;
    if (displayGroupInfo.groupId != DEFAULT_GROUP_ID) {
        MMI_HILOGD("groupId:%{public}d", displayGroupInfo.groupId);
        return;
    }
    for (const auto& item : displayGroupInfo.displaysInfo) {
        if (item.rsId == displayInfo_.rsId &&
            item.displaySourceMode == displayInfo_.displaySourceMode) {
            UpdateDisplayInfo(item);
            DrawManager();
            return;
        }
    }
    if (displayGroupInfo.displaysInfo.empty()) {
        MMI_HILOGW("displaysInfo is empty");
        return;
    }
    OLD::DisplayInfo displayInfo = displayGroupInfo.displaysInfo[0];
#ifdef OHOS_BUILD_ENABLE_EXTERNAL_SCREEN
    (void)GetMainScreenDisplayInfo(displayGroupInfo, displayInfo);
#endif // OHOS_BUILD_ENABLE_EXTERNAL_SCREEN
    UpdateDisplayInfo(displayInfo);
    lastPhysicalX_ = displayInfo.validWidth / CALCULATE_MIDDLE;
    lastPhysicalY_ = displayInfo.validHeight / CALCULATE_MIDDLE;
    MouseEventHdr->OnDisplayLost(displayInfo_.rsId);
    auto surfaceNodePtr = GetSurfaceNode();
    if (surfaceNodePtr != nullptr) {
        if (!GetHardCursorEnabled()) {
            MMI_HILOGI("Pointer window DetachToDisplay start screenId_:%{public}" PRIu64, screenId_);
            surfaceNodePtr->DetachToDisplay(screenId_);
            SetSurfaceNode(nullptr);
        }
        Rosen::RSTransaction::FlushImplicitTransaction();
        MMI_HILOGD("Pointer window destroy success");
    }
    MMI_HILOGD("rsId:%{public}" PRIu64 ", displayWidth_:%{public}d, displayHeight_:%{public}d",
        displayInfo_.rsId, displayInfo_.validWidth, displayInfo_.validHeight);
}

void PointerDrawingManager::OnWindowInfo(const WinInfo &info)
{
    CALL_DEBUG_ENTER;
    if (pid_ != info.windowPid || windowId_ != info.windowId) {
        windowId_ = info.windowId;
        pid_ = info.windowPid;
        UpdatePointerVisible();
    }
}

void PointerDrawingManager::UpdatePointerDevice(bool hasPointerDevice, bool isPointerVisible,
    bool isHotPlug)
{
    CALL_DEBUG_ENTER;
    MMI_HILOGI("The hasPointerDevice:%{public}s, isPointerVisible:%{public}s",
        hasPointerDevice ? "true" : "false", isPointerVisible? "true" : "false");
    hasPointerDevice_ = hasPointerDevice;
    if (hasPointerDevice_) {
        bool pointerVisible = isPointerVisible;
        if (!isHotPlug) {
            pointerVisible = (pointerVisible && CursorDrawingInformation::GetInstance().IsPointerVisible());
        }
        CursorDrawingInformation::GetInstance().SetPointerVisible(getpid(), pointerVisible, 0, false);
    } else {
        CursorDrawingInformation::GetInstance().DeletePointerVisible(getpid());
    }
    DrawManager();
    // This scope ensures that the reference count held by surfaceNodePtr is' 0 'before notifying the RS process Flush.
    {
        auto surfaceNodePtr = GetSurfaceNode();
        if (hasPointerDevice_ || (surfaceNodePtr == nullptr)) {
            MMI_HILOGD("There are still pointer devices present.");
            return;
        }
        if (GetHardCursorEnabled()) {
            auto screenPointers = CopyScreenPointers();
            for (auto sp : screenPointers) {
                if (sp.second != nullptr && sp.second->IsMirror()) {
                    sp.second->SetInvisible();
                }
            }
        }
        MMI_HILOGD("Pointer window destroy start");
        surfaceNodePtr->DetachToDisplay(screenId_);
        SetSurfaceNode(nullptr);
        MMI_HILOGI("Detach screenId:%{public}" PRIu64, screenId_);
    }
    Rosen::RSTransaction::FlushImplicitTransaction();
    MMI_HILOGD("Pointer window destroy success");
}

void PointerDrawingManager::AttachAllSurfaceNode()
{
    auto screenPointers = CopyScreenPointers();
    for (auto sp : screenPointers) {
        if (sp.second == nullptr) {
            continue;
        }
        auto surfaceNode = sp.second->GetSurfaceNode();
        if (surfaceNode == nullptr) {
            continue;
        }
        auto screenId = sp.second->GetScreenId();
        if (screenId == screenId_ && GetSurfaceNode() == nullptr) {
            MMI_HILOGI("surfaceNode_ is nullptr skip screenId:%{public}" PRIu64, screenId);
            continue;
        }
        MMI_HILOGI("Attach screenId:%{public}" PRIu64, screenId);
        surfaceNode->AttachToDisplay(screenId);
    }
    if (GetSurfaceNode() == nullptr) {
        screenPointers = CopyScreenPointers();
        for (auto sp : screenPointers) {
            if (sp.second != nullptr && sp.second->IsMirror()) {
                sp.second->SetInvisible();
                MMI_HILOGI("surfaceNode_ is nullptr, hide mirror pointer screenId:%{public}" PRIu64,
                    sp.second->GetScreenId());
            }
        }
    }
    Rosen::RSTransaction::FlushImplicitTransaction();
}

void PointerDrawingManager::DetachAllSurfaceNode()
{
    auto screenPointers = CopyScreenPointers();
    for (auto sp : screenPointers) {
        if (sp.second != nullptr) {
            auto surfaceNode = sp.second->GetSurfaceNode();
            if (surfaceNode != nullptr) {
                auto screenId = sp.second->GetScreenId();
                MMI_HILOGI("Detach screenId:%{public}" PRIu64, screenId);
                surfaceNode->DetachToDisplay(screenId);
            }
        }
    }
    Rosen::RSTransaction::FlushImplicitTransaction();
}

void PointerDrawingManager::DrawManager()
{
    CALL_DEBUG_ENTER;
    auto surfaceNodePtr = GetSurfaceNode();
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
    if (HasMagicCursor() && lastDrawPointerStyle_.id != currentMouseStyle_.id
        && (lastDrawPointerStyle_.id == DEVELOPER_DEFINED_ICON
        || currentMouseStyle_.id == DEVELOPER_DEFINED_ICON)) {
        if (surfaceNodePtr != nullptr) {
            MMI_HILOGI("Pointer window DetachToDisplay start screenId_:%{public}" PRIu64, screenId_);
            surfaceNodePtr->DetachToDisplay(screenId_);
            SetSurfaceNode(nullptr);
            Rosen::RSTransaction::FlushImplicitTransaction();
        }
    }
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
    if (hasDisplay_ && hasPointerDevice_ && (surfaceNodePtr == nullptr)) {
        PointerStyle pointerStyle;
        WIN_MGR->GetPointerStyle(pid_, windowId_, pointerStyle);
        MMI_HILOGI("Pid_:%{public}d, windowId_:%{public}d, pointerStyle.id:%{public}d", pid_,
            windowId_, pointerStyle.id);
        Direction direction = GetDisplayDirection(&displayInfo_);
        lastDrawPointerStyle_ = pointerStyle;
        if (lastPhysicalX_ == -1 || lastPhysicalY_ == -1) {
            if (displayInfo_.validWidth > 0 && displayInfo_.validHeight > 0) {
                DrawPointer(displayInfo_.rsId, displayInfo_.validWidth / CALCULATE_MIDDLE,
                    displayInfo_.validHeight / CALCULATE_MIDDLE, pointerStyle, direction);
                MMI_HILOGI("Draw manager, mouseStyle:%{public}d, last physical is initial value", pointerStyle.id);
            }
            return;
        }
        DrawPointer(displayInfo_.rsId, lastPhysicalX_, lastPhysicalY_, pointerStyle, direction);
        MMI_HILOGI("Draw manager, mouseStyle:%{public}d", pointerStyle.id);
        return;
    }
}

void PointerDrawingManager::InitPixelMaps()
{
    auto pointerColor = GetPointerColor(GetCurrentUser());
    std::lock_guard<std::mutex> guard(mousePixelMapMutex_);
    mousePixelMap_[MOUSE_ICON::LOADING];
    mousePixelMap_[MOUSE_ICON::RUNNING];
    ReloadPixelMaps(mousePixelMap_, pointerColor);
}

bool PointerDrawingManager::Init()
{
    CALL_DEBUG_ENTER;
    self_ = std::shared_ptr<PointerDrawingManager>(this, [](PointerDrawingManager*) {});
    INPUT_DEV_MGR->Attach(self_);
    {
        std::lock_guard<std::mutex> guard(mousePixelMapMutex_);
        mousePixelMap_.clear();
    }
    initLoadingAndLoadingRightPixelTimerId_ = TimerMgr->AddTimer(REPEAT_COOLING_TIME, REPEAT_ONCE, [this]() {
        InitPixelMaps();
        initLoadingAndLoadingRightPixelTimerId_ = DEFAULT_VALUE;
    }, "PointerDrawingManager-Init");
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
    std::lock_guard<std::recursive_mutex> lg(recursiveMtx_);
    auto surfaceNodePtr = GetSurfaceNode();
    CHKPV(surfaceNodePtr);
    RecordCursorIdAndImageAddress();
    if (CursorDrawingInformation::GetInstance().IsPointerVisible() && mouseDisplayState_) {
        surfaceNodePtr->SetVisible(true);
        POINTER_DEV_MGR.isPointerVisible = true;
        if (GetHardCursorEnabled()) {
            if (InitLayer(MOUSE_ICON(lastMouseStyle_.id)) != RET_OK) {
                MMI_HILOGE("Init Layer failed");
                return;
            }
            if (!SetCursorLocation(lastPhysicalX_, lastPhysicalY_)) {
                MMI_HILOGE("SetCursorLocation fail");
            }
        }
        MMI_HILOGI("Pointer window show success, mouseDisplayState_:%{public}s, displayId_:%{public}" PRIu64,
            mouseDisplayState_ ? "true" : "false", displayId_);
    } else {
        if (GetHardCursorEnabled()) {
            PostSoftCursorTask([this]() {
                SoftwareCursorRender(MOUSE_ICON::TRANSPARENT_ICON);
            });
            HideHardwareCursors();
        }
        surfaceNodePtr->SetVisible(false);
        RecordCursorVisibleStatus(false);
        MMI_HILOGI("Pointer window hide success, mouseDisplayState_:%{public}s displayId_:%{public}" PRIu64,
            mouseDisplayState_ ? "true" : "false", displayId_);
    }
    Rosen::RSTransaction::FlushImplicitTransaction();
}

void PointerDrawingManager::DeleteSurfaceNode()
{
    CALL_DEBUG_ENTER;
    MMI_HILOGI("The g_isRsRemoteDied:%{public}d", g_isRsRemoteDied ? 1 : 0);
    auto surfaceNodePtr = GetSurfaceNode();
    if (g_isRsRemoteDied && (surfaceNodePtr != nullptr)) {
        g_isRsRemoteDied = false;
        MMI_HILOGI("Pointer window DetachToDisplay start screenId_:%{public}" PRIu64, screenId_);
        surfaceNodePtr->DetachToDisplay(screenId_);
        SetSurfaceNode(nullptr);
        Rosen::RSTransaction::FlushImplicitTransaction();
    }
}

void PointerDrawingManager::SetPointerLocation(int32_t x, int32_t y, uint64_t rsId)
{
    CALL_DEBUG_ENTER;
    FixCursorPosition(x, y);
    lastPhysicalX_ = x;
    lastPhysicalY_ = y;
    MMI_HILOGD("Pointer window move, x:%{private}d, y:%{private}d", lastPhysicalX_, lastPhysicalY_);
    auto surfaceNodePtr = GetSurfaceNode();
    CHKPV(surfaceNodePtr);
    displayId_ = rsId;
    if (GetHardCursorEnabled()) {
        if (!SetCursorLocation(x, y)) {
            MMI_HILOGE("SetCursorLocation fail");
            return;
        }
    } else {
        Direction direction = static_cast<Direction>((
            ((displayInfo_.direction - displayInfo_.displayDirection) * ANGLE_90 + ANGLE_360) % ANGLE_360) / ANGLE_90);
        AdjustMouseFocusToSoftRenderOrigin(direction, MOUSE_ICON(lastMouseStyle_.id), x, y);
        surfaceNodePtr->SetBounds(x,
            y,
            surfaceNodePtr->GetStagingProperties().GetBounds().z_,
            surfaceNodePtr->GetStagingProperties().GetBounds().w_);
        Rosen::RSTransaction::FlushImplicitTransaction();
    }
    MMI_HILOGD("Pointer window move success");
}

IconStyle PointerDrawingManager::GetIconStyle(const MOUSE_ICON mouseStyle)
{
    auto mouseIcons = CursorDrawingInformation::GetInstance().GetMouseIconsMap();
    auto iter = mouseIcons.find(mouseStyle);
    if (iter == mouseIcons.end()) {
        MMI_HILOGE("Cannot find the mouseStyle:%{public}d", static_cast<int32_t>(mouseStyle));
        return IconStyle();
    }
    return iter->second;
}

int32_t PointerDrawingManager::SetPointerStyle(int32_t pid, int32_t windowId, PointerStyle pointerStyle,
    bool isUiExtension)
{
    CALL_DEBUG_ENTER;
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
        if (GetSurfaceNode() != nullptr) {
            AttachToDisplay();
            if (GetHardCursorEnabled()) {
                PostTask([]() {
                    Rosen::RSTransaction::FlushImplicitTransaction();
                });
            } else {
                Rosen::RSTransaction::FlushImplicitTransaction();
            }
        }
        Direction direction = GetDisplayDirection(&displayInfo_);
        if (lastPhysicalX_ == -1 || lastPhysicalY_ == -1) {
            if (displayInfo_.validWidth > 0 && displayInfo_.validHeight > 0) {
                DrawPointer(displayInfo_.rsId, displayInfo_.validWidth / CALCULATE_MIDDLE,
                    displayInfo_.validHeight / CALCULATE_MIDDLE, pointerStyle, direction);
                MMI_HILOGD("Draw pointer style, mouseStyle:%{public}d", pointerStyle.id);
            }
            return;
        }

        DrawPointer(displayInfo_.rsId, lastPhysicalX_, lastPhysicalY_, pointerStyle, direction);
        MMI_HILOGD("Draw pointer style, mouseStyle:%{public}d", pointerStyle.id);
    }
}

int32_t PointerDrawingManager::EnableHardwareCursorStats(int32_t pid, bool enable)
{
    CALL_DEBUG_ENTER;
    if (GetHardCursorEnabled()) {
        if ((hardwareCursorPointerManager_->EnableStats(enable)) != RET_OK) {
            MMI_HILOGE("Enable stats failed");
            return RET_ERR;
        }
    }
    MMI_HILOGI("EnableHardwareCursorStats, enable:%{private}d", enable);
    return RET_OK;
}

int32_t PointerDrawingManager::GetHardwareCursorStats(int32_t pid, uint32_t &frameCount, uint32_t &vsyncCount)
{
    CALL_DEBUG_ENTER;
    if (GetHardCursorEnabled()) {
        if ((hardwareCursorPointerManager_->GetCursorStats(frameCount, vsyncCount)) != RET_OK) {
            MMI_HILOGE("Query stats failed");
            return RET_ERR;
        }
    }
    MMI_HILOGI("GetHardwareCursorStats, frameCount:%{private}d, vsyncCount:%{private}d", frameCount, vsyncCount);
    return RET_OK;
}

void PointerDrawingManager::SubscribeScreenModeChange(uint64_t tid)
{
    if (!GetHardCursorEnabled()) {
        return;
    }
    workerThreadId_.store(tid);
    std::vector<sptr<OHOS::Rosen::ScreenInfo>> screenInfos;
    if (!screenInfos.empty()) {
        OnScreenModeChange(screenInfos);
    }

    auto callback = [this](const std::vector<sptr<OHOS::Rosen::ScreenInfo>> &screens) {
        if (GetHardCursorEnabled()) {
            this->OnScreenModeChange(screens);
        }
    };
    if (screenModeChangeListener_ != nullptr) {
        OHOS::Rosen::ScreenManagerLite::GetInstance().
            UnregisterScreenModeChangeListener(screenModeChangeListener_);
    }
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
}

void PointerDrawingManager::UnsubscribeScreenModeChange()
{
    CHKPV(screenModeChangeListener_);
    auto ret = OHOS::Rosen::ScreenManagerLite::GetInstance().UnregisterScreenModeChangeListener(
        screenModeChangeListener_);
    if (ret != OHOS::Rosen::DMError::DM_OK) {
        MMI_HILOGE("UnregisterScreenModeChangeListener failed, ret=%{public}d", ret);
        return;
    }
    screenModeChangeListener_ = nullptr;
}

void PointerDrawingManager::RegisterDisplayStatusReceiver()
{
    if (!GetHardCursorEnabled()) {
        return;
    }
    if (initDisplayStatusReceiverFlag_) {
        MMI_HILOGE("Display status receiver has subscribed");
        return;
    }
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF);
    EventFwk::CommonEventSubscribeInfo commonEventSubscribeInfo(matchingSkills);
    commonEventSubscriber_ = std::make_shared<DisplayStatusReceiver>(commonEventSubscribeInfo);
    bool ret = OHOS::EventFwk::CommonEventManager::SubscribeCommonEvent(commonEventSubscriber_);
    if (!ret) {
        commonEventSubscriber_ = nullptr;
    }
    initDisplayStatusReceiverFlag_ = ret;
    MMI_HILOGI("Register display status receiver result:%{public}d", initDisplayStatusReceiverFlag_.load());
}

void PointerDrawingManager::RotateDegree(Direction direction)
{
    if (GetHardCursorEnabled()) {
        return;
    }
    auto surfaceNodePtr = GetSurfaceNode();
    CHKPV(surfaceNodePtr);
    surfaceNodePtr->SetPivot(0, 0);
    float degree = (static_cast<int>(DIRECTION0) - static_cast<int>(direction)) * ROTATION_ANGLE90;
    surfaceNodePtr->SetRotation(degree);
}

int32_t PointerDrawingManager::SkipPointerLayer(bool isSkip)
{
    CALL_INFO_TRACE;
    auto surfaceNodePtr = GetSurfaceNode();
    if (surfaceNodePtr != nullptr) {
        surfaceNodePtr->SetSkipLayer(isSkip);
    }
    return RET_OK;
}

std::vector<std::vector<std::string>> PointerDrawingManager::GetDisplayInfo(OLD::DisplayInfo &di)
{
    std::vector<std::vector<std::string>> displayInfo = {
        {std::to_string(di.id), std::to_string(di.x), std::to_string(di.y), std::to_string(di.width),
         std::to_string(di.height), std::to_string(di.dpi), di.name, di.uniq,
         std::to_string(static_cast<int32_t>(di.direction)), std::to_string(static_cast<int32_t>(di.displayDirection)),
         std::to_string(static_cast<int32_t>(di.displayMode)), std::to_string(di.isCurrentOffScreenRendering),
         std::to_string(di.screenRealWidth), std::to_string(di.screenRealHeight),
         std::to_string(di.screenRealDPI), std::to_string(static_cast<int32_t>(di.displaySourceMode))}};
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
    bool mouseIconUpdate = CursorDrawingInformation::GetInstance().GetMouseIconUpdate();
    std::vector<std::vector<std::string>> data2 = {
        {std::to_string(mouseDisplayState_), std::to_string(mouseIconUpdate), std::to_string(screenId_),
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
    auto dumpPidInfos = CursorDrawingInformation::GetInstance().GetPidInfos();
    for (const auto &pidInfo : dumpPidInfos) {
        pidInfos.push_back({std::to_string(pidInfo.pid), pidInfo.visible ? "true" : "false"});
    }
    DumpFullTable(oss, "Visible Info", pidTitles, pidInfos);
    oss << std::endl;

    std::vector<std::string> hardCursorTitles = {"isHardCursorEnabled"};
    std::vector<std::vector<std::string>> hardCursorInfos;
    hardCursorInfos.push_back({GetHardCursorEnabled() ? "true" : "false"});
    DumpFullTable(oss, "Hard Cursor Info", hardCursorTitles, hardCursorInfos);
    oss << std::endl;

    std::string dumpInfo = oss.str();
    dprintf(fd, dumpInfo.c_str());
}

void PointerDrawingManager::UpdateBindDisplayId(uint64_t rsId)
{
    if (lastDisplayId_ == rsId) {
        return;
    }
    MMI_HILOGI("Mouse traversal occurs, lastDisplayId_:%{public}" PRIu64 ", rsId:%{public}" PRIu64,
        lastDisplayId_, rsId);

    if (GetHardCursorEnabled()) {
        // 隐藏上一个屏幕的软、硬光标
        PostSoftCursorTask([this]() {
            SoftwareCursorRender(MOUSE_ICON::TRANSPARENT_ICON);
        });
        HideHardwareCursors();
        Rosen::RSTransaction::FlushImplicitTransaction();

        // 绑定新屏幕 SurfaceNode 到全局 surfaceNode_
        screenId_ = rsId;
        MMI_HILOGI("The screenId_:%{public}" PRIu64, screenId_);
        AttachToDisplay();

        // 新屏幕上重新绘制软硬光标
        UpdatePointerVisible();
    }

    // 绑定新屏幕 SurfaceNode 到全局 surfaceNode_
    MMI_HILOGI("UpdateBindDisplayId The screenId_:%{public}" PRIu64, screenId_);
    screenId_ = rsId;
    MMI_HILOGI("The screenId_:%{public}" PRIu64, screenId_);
    AttachToDisplay();

    // 新屏幕上软硬光标位置更新
    if (!SetCursorLocation(lastPhysicalX_, lastPhysicalY_)) {
        MMI_HILOGE("SetCursorLocation fail");
    }

    lastDisplayId_ = rsId;
}

bool PointerDrawingManager::ShouldSkipScreen(const sptr<OHOS::Rosen::ScreenInfo> &screen)
{
    if (screen == nullptr) {
        MMI_HILOGW("Screen is null");
        return true;
    }
    if (screen->GetType() == OHOS::Rosen::ScreenType::UNDEFINED) {
        return true;
    }
    if (screen->GetType() == OHOS::Rosen::ScreenType::VIRTUAL &&
        screen->GetSourceMode() != OHOS::Rosen::ScreenSourceMode::SCREEN_EXTEND) {
        return true;
    }
    return false;
}

sptr<OHOS::Rosen::ScreenInfo> PointerDrawingManager::UpdateScreenPointerAndFindMainScreenInfo(
    const std::vector<sptr<OHOS::Rosen::ScreenInfo>> &screens)
{
    sptr<OHOS::Rosen::ScreenInfo> mainScreen = nullptr;
    std::set<uint64_t> screenIds;
    // Update or construct ScreenPointer for new ScreenInfo
    for (const auto &screen : screens) {
        if (ShouldSkipScreen(screen)) {
            continue;
        }
        uint64_t sid = screen->GetRsId();
        screenIds.insert(sid);
        // Find main screenInfo
        if (screen->GetSourceMode() == OHOS::Rosen::ScreenSourceMode::SCREEN_MAIN) {
            mainScreen = screen;
        }
        auto [iter, insertOk] = InsertScreenPointer(sid, nullptr);
        if (!insertOk && iter->second != nullptr) {
            // Update ScreenPointer when it already exist
            auto sp = GetScreenPointer(sid);
            sp->UpdateScreenInfo(screen);
            MMI_HILOGI("Update ScreenPointer, screenId=%{public}" PRIu64, sid);
        } else {
            // Create and init ScreenPointer when it does not exist
            auto sp = std::make_shared<ScreenPointer>(hardwareCursorPointerManager_, handler_, screen);
            if (sp == nullptr || !sp->Init(pointerRenderer_)) {
                MMI_HILOGE("Failed to init ScreenPointer, screenId=%{public}" PRIu64, sid);
                DeleteScreenPointer(sid);
                continue;
            }
            UpdateScreenPointer(sid, sp);
            MMI_HILOGI("Create ScreenPointer, screenId=%{public}" PRIu64, sid);
        }
        if (screen->GetType() == OHOS::Rosen::ScreenType::VIRTUAL &&
            screen->GetSourceMode() == OHOS::Rosen::ScreenSourceMode::SCREEN_EXTEND &&
            iter->second != nullptr) {
            iter->second->SetVirtualExtend(true);
        }
    }
    // Delete ScreenPointers that disappeared
    ClearDisappearedScreenPointer(screenIds);
    // Return main screenInfo
    return mainScreen;
}

void PointerDrawingManager::UpdateScreenScalesAndPadding(const sptr<OHOS::Rosen::ScreenInfo> &mainScreen)
{
    if (mainScreen == nullptr) {
        MMI_HILOGE("MainScreen is null");
        return;
    }

    uint32_t mainWidth = GetScreenInfoWidth(mainScreen);
    uint32_t mainHeight = GetScreenInfoHeight(mainScreen);
    rotation_t mainRotation = static_cast<rotation_t>(mainScreen->GetRotation());
    float mainDPI = mainScreen->GetVirtualPixelRatio();
    // Update screen scale and padding
    auto screenPointers = CopyScreenPointers();
    for (auto& [sid, sp] : screenPointers) {
        if (sp == nullptr) {
            MMI_HILOGE("ScreenPointer is null, screenId=%{public}" PRIu64, sid);
            continue;
        }
        if (sp->IsMirror()) {
            // Update ScreenPointer on the mirror screen
            sp->SetSourceScreenRotation(mainRotation);
            sp->UpdatePadding(mainWidth, mainHeight);
            if (hasDisplay_ && displayInfo_.displaySourceMode == DisplaySourceMode::SCREEN_MAIN) {
                sp->SetDisplayDirection(displayInfo_.displayDirection);
            }
            sp->SetDPI(mainDPI);
        }
#ifdef OHOS_BUILD_EXTERNAL_SCREEN
        if (sp->IsMirror() || sp->IsMain()) {
            mainWidth = sp->GetMirrorWidth() == 0 ? mainWidth : sp->GetMirrorWidth();
            mainHeight = sp->GetMirrorHeight() == 0 ? mainHeight : sp->GetMirrorHeight();
            sp->UpdatePadding(mainWidth, mainHeight);
        }
#endif // OHOS_BUILD_EXTERNAL_SCREEN
    }
}

void PointerDrawingManager::OnScreenModeChange(const std::vector<sptr<OHOS::Rosen::ScreenInfo>> &screens)
{
    MMI_HILOGI("OnScreenModeChange enter, screen size:%{public}zu", screens.size());
    if (screens.empty()) {
        return;
    }
    std::shared_ptr<DelegateInterface> delegateProxy = IPointerDrawingManager::GetInstance()->GetDelegateProxy();
    if (delegateProxy == nullptr) {
        MMI_HILOGE("delegateProxy is nullptr");
        return;
    }
    CursorDrawingComponent::GetInstance();
    delegateProxy->OnPostSyncTask([this, screens] {
        uint64_t workerThreadId = this->workerThreadId_.load();
        if (workerThreadId != GetThisThreadId() && !POINTER_DEV_MGR.isInit) {
            MMI_HILOGE("skip ScreenModeChange callback");
            return RET_OK;
        }
        auto mainScreen = this->UpdateScreenPointerAndFindMainScreenInfo(screens);
        this->UpdateScreenScalesAndPadding(mainScreen);
        this->UpdatePointerVisible();
        return RET_OK;
    });
}

Direction PointerDrawingManager::CalculateRenderDirection(bool isHard)
{
    if (isHard) {
        return displayInfo_.direction;
    } else {
        return static_cast<Direction>((((displayInfo_.direction - displayInfo_.displayDirection) *
            ANGLE_90 + ANGLE_360) % ANGLE_360) / ANGLE_90);
    }
}

void PointerDrawingManager::CreateRenderConfig(RenderConfig& cfg, std::shared_ptr<ScreenPointer> sp,
    MOUSE_ICON mouseStyle, bool isHard)
{
    CHKPV(sp);
    auto mouseIcons = CursorDrawingInformation::GetInstance().GetMouseIconsMap();
    cfg.style_ = mouseStyle;
    cfg.align_ = CursorDrawingInformation::GetInstance().MouseIcon2IconType(mouseStyle);
    cfg.path_ = mouseIcons[mouseStyle].iconPath;
    cfg.color = static_cast<uint32_t>(GetPointerColor(GetCurrentUser()));
    cfg.size = static_cast<uint32_t>(GetPointerSize(GetCurrentUser()));
    cfg.isHard = isHard;
    float scale = isHard ? sp->GetScale() : 1.0f;
    cfg.dpi = sp->GetDPI() * scale;
    Direction direction = CalculateRenderDirection(isHard);
    cfg.direction = sp->IsMirror() ? DIRECTION0 : direction;
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
    auto screenPointers = CopyScreenPointers();
    for (auto it : screenPointers) {
        CHKPV(it.second);
        RenderConfig cfg;
        CreateRenderConfig(cfg, it.second, mouseStyle, true);
        MMI_HILOGI("screen:%{public}" PRIu64 ", mode:%{public}u, dpi:%{public}f, screenId_:%{public}" PRIu64,
            it.first, it.second->GetMode(), cfg.dpi, screenId_);
        if (it.second->IsMirror() || it.first == screenId_) {
            if (DrawHardCursor(it.second, cfg) != RET_OK) {
                MMI_HILOGE("DrawHardCursor failed");
            }
        } else {
            if (!it.second->SetInvisible()) {
                MMI_HILOGE("SetInvisible failed");
            }
        }
    }
    MMI_HILOGD("HardwareCursorRender completed");
}

void PointerDrawingManager::SoftwareCursorRender(MOUSE_ICON mouseStyle)
{
    auto screenPointers = CopyScreenPointers();
    for (auto it : screenPointers) {
        CHKPV(it.second);
        RenderConfig cfg;
        CreateRenderConfig(cfg, it.second, mouseStyle, false);
        MMI_HILOGI("SoftwareCursorRender, screen:%{public}" PRIu64 ", mode:%{public}u,"
                   " dpi:%{public}f, direction:%{public}d, screenId_:%{public}" PRIu64,
                   it.first, it.second->GetMode(), cfg.dpi, cfg.direction, screenId_);
        if (!it.second->IsMirror() && it.first != screenId_) {
            auto mouseIcons = CursorDrawingInformation::GetInstance().GetMouseIconsMap();
            cfg.style_ = MOUSE_ICON::TRANSPARENT_ICON;
            cfg.align_ = CursorDrawingInformation::GetInstance().MouseIcon2IconType(cfg.style_);
            cfg.path_ = mouseIcons[cfg.style_].iconPath;
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
    BytraceAdapter::StartSoftPointerRender(buffer->GetWidth(), buffer->GetHeight(), cfg.style_);
    if (pointerRenderer_.Render(addr, buffer->GetWidth(), buffer->GetHeight(), cfg) != RET_OK) {
        MMI_HILOGE("Render failed");
    }
    BytraceAdapter::StopSoftPointerRender();

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
    MMI_HILOGI("DrawSoftCursor on SurfaceNode success, style=%{public}d", cfg.style_);
    return RET_OK;
}

int32_t PointerDrawingManager::DrawHardCursor(std::shared_ptr<ScreenPointer> sp, const RenderConfig &cfg)
{
    CHKPR(sp, RET_ERR);

    bool isCommonBuffer;
    auto buffer = sp->RequestBuffer(cfg, isCommonBuffer);
    CHKPR(buffer, RET_ERR);
    if (isCommonBuffer) {
        auto addr = static_cast<uint8_t *>(buffer->GetVirAddr());
        CHKPR(addr, RET_ERR);
        BytraceAdapter::StartHardPointerRender(buffer->GetWidth(), buffer->GetHeight(), sp->GetBufferId(),
            sp->GetScreenId(), cfg.style_);
        if (pointerRenderer_.Render(addr, buffer->GetWidth(), buffer->GetHeight(), cfg) != RET_OK) {
            MMI_HILOGE("Render failed");
        }
        BytraceAdapter::StopHardPointerRender();
    }

    MMI_HILOGI("DrawHardCursor on ScreenPointer success, screenId=%{public}" PRIu64 ", style=%{public}d",
        sp->GetScreenId(), cfg.style_);
    auto sret = buffer->FlushCache();
    if (sret != RET_OK) {
        MMI_HILOGE("FlushCache ret: %{public}d", sret);
        return sret;
    }
    return RET_OK;
}

void PointerDrawingManager::UpdateMirrorScreens(std::shared_ptr<ScreenPointer> sp, OLD::DisplayInfo displayInfo)
{
    CHKPV(sp);
    uint32_t mainWidth = sp->GetScreenWidth();
    uint32_t mainHeight = sp->GetScreenHeight();
    auto screenPointers = CopyScreenPointers();
    for (auto it : screenPointers) {
        if (it.second == nullptr) {
            continue;
        }
        if (it.second->IsMirror()) {
            auto& mirrorScreen = it.second;
            bool isDirectionChanged = false;
            if (mirrorScreen->GetSourceScreenRotation() != static_cast<rotation_t>(displayInfo.direction)) {
                MMI_HILOGI("update mirror screen, rotation from %{public}u to %{public}d,",
                    mirrorScreen->GetSourceScreenRotation(), displayInfo.direction);
                mirrorScreen->SetSourceScreenRotation(static_cast<rotation_t>(displayInfo.direction));
                isDirectionChanged = true;
            }
            if (mirrorScreen->GetDisplayDirection() != displayInfo.displayDirection) {
                MMI_HILOGI("update mirror screen, displayDirection from %{public}d to %{public}d",
                    mirrorScreen->GetDisplayDirection(), displayInfo.displayDirection);
                mirrorScreen->SetDisplayDirection(displayInfo.displayDirection);
                isDirectionChanged = true;
            }
            if (isDirectionChanged) {
#ifdef OHOS_BUILD_EXTERNAL_SCREEN
                mainWidth = mirrorScreen->GetMirrorWidth() == 0 ? mainWidth : mirrorScreen->GetMirrorWidth();
                mainHeight = mirrorScreen->GetMirrorHeight() == 0 ? mainHeight : mirrorScreen->GetMirrorHeight();
                mirrorScreen->UpdatePadding(mainWidth, mainHeight);
#else
                mirrorScreen->UpdatePadding(mainWidth, mainHeight);
#endif // OHOS_BUILD_EXTERNAL_SCREEN
            }
            MMI_HILOGD("update mirror screen dpi, mainScreen dpi: %{public}f, original mirrorScreen dpi: %{public}f",
                sp->GetDPI(), mirrorScreen->GetDPI());
            mirrorScreen->SetDPI(sp->GetDPI());
        }
    }
}

std::vector<std::shared_ptr<ScreenPointer>> PointerDrawingManager::GetMirrorScreenPointers()
{
    std::vector<std::shared_ptr<ScreenPointer>> mirrors;
    auto screenPointers = CopyScreenPointers();
    for (auto it : screenPointers) {
        CHKPC(it.second);
        if (it.second->IsMirror()) {
            mirrors.push_back(it.second);
        }
    }
    return mirrors;
}

std::shared_ptr<ScreenPointer> PointerDrawingManager::GetScreenPointer(uint64_t screenId)
{
    std::shared_lock<std::shared_mutex> lock(screenPointersMtx_);
    if (screenPointers_.count(screenId)) {
        return screenPointers_[screenId];
    }
    return nullptr;
}

std::unordered_map<uint64_t, std::shared_ptr<ScreenPointer>> PointerDrawingManager::CopyScreenPointers()
{
    std::shared_lock<std::shared_mutex> lock(screenPointersMtx_);
    return screenPointers_;
}

std::pair<ScreenPointersIter, bool> PointerDrawingManager::InsertScreenPointer(uint64_t screenId,
    std::shared_ptr<ScreenPointer> screenPointer)
{
    std::unique_lock<std::shared_mutex> lock(screenPointersMtx_);
    auto pair = screenPointers_.try_emplace(screenId, screenPointer);
    return pair;
}

std::pair<ScreenPointersIter, bool> PointerDrawingManager::UpdateScreenPointer(uint64_t screenId,
    std::shared_ptr<ScreenPointer> screenPointer)
{
    std::unique_lock<std::shared_mutex> lock(screenPointersMtx_);
    if (!screenPointers_.count(screenId)) {
        MMI_HILOGI("screenPointers_ not contains  %{public}" PRIu64, screenId);
        return {screenPointers_.end(), false};
    }
    auto pair = screenPointers_.insert_or_assign(screenId, screenPointer);
    return pair;
}

bool PointerDrawingManager::DeleteScreenPointer(uint64_t screenId)
{
    std::unique_lock<std::shared_mutex> lock(screenPointersMtx_);
    size_t result = screenPointers_.erase(screenId);
    return (result == 1);
}

void PointerDrawingManager::ClearScreenPointer()
{
    std::unique_lock<std::shared_mutex> lock(screenPointersMtx_);
    screenPointers_.clear();
}

void PointerDrawingManager::ClearDisappearedScreenPointer(const std::set<uint64_t> &screenIds)
{
    std::unique_lock<std::shared_mutex> lock(screenPointersMtx_);
    for (auto it = screenPointers_.begin(); it != screenPointers_.end();) {
        if (screenIds.count(it->first) == 0) {
            MMI_HILOGI("OnScreenModeChange, delete screen %{public}" PRIu64, it->first);
            it = screenPointers_.erase(it);
        } else {
            ++it;
        }
    }
}

int32_t PointerDrawingManager::HardwareCursorMove(int32_t x, int32_t y)
{
    MMI_HILOGD("HardwareCursorMove loc: (%{private}d, %{private}d)", x, y);
    int32_t ret = RET_OK;
    auto sp = GetScreenPointer(displayId_);
    CHKPR(sp, RET_ERR);
    if (!sp->Move(x, y)) {
        ret = RET_ERR;
        MMI_HILOGE("ScreenPointer::Move failed, screenId: %{public}" PRIu64, displayId_);
    }
    auto screenPointers = CopyScreenPointers();
    for (auto it : screenPointers) {
        CHKPC(it.second);
        if (it.second->IsMirror()) {
            if (!it.second->Move(x, y)) {
                ret = RET_ERR;
                MMI_HILOGE("ScreenPointer::Move failed, screenId: %{public}" PRIu64, it.first);
            }
        } else if (it.first != displayId_) {
            if (!it.second->Move(0, 0)) {
                ret = RET_ERR;
                MMI_HILOGE("ScreenPointer::Move failed, screenId: %{public}" PRIu64, it.first);
            }
        }
    }
    return ret;
}

int32_t PointerDrawingManager::CheckHwcReady()
{
    auto sp = GetScreenPointer(displayId_);
    CHKPR(sp, RET_ERR);
    int32_t failCount = 0;
    while (sp != nullptr && !sp->Move(lastPhysicalX_, lastPhysicalY_)) {
        failCount++;
        if (failCount > MAX_FAIL_COUNT) {
            MMI_HILOGE("CheckHwcReady failed, screenId: %{public}" PRIu64, displayId_);
            return RET_ERR;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(CHECK_SLEEP_TIME));
    }
    MMI_HILOGI("CheckHwcReady success, screenId: %{public}" PRIu64 ", check counts: %{public}d", displayId_, failCount);
    return RET_OK;
}

void PointerDrawingManager::SoftwareCursorMove(uint64_t displayId, int32_t x, int32_t y)
{
    auto sp = GetScreenPointer(displayId);
    CHKPV(sp);
    sp->MoveSoft(x, y);

    for (auto& msp : GetMirrorScreenPointers()) {
        CHKPC(msp);
        msp->MoveSoft(x, y);
    }
    Rosen::RSTransaction::FlushImplicitTransaction();
}

void PointerDrawingManager::SoftwareCursorMoveAsync(uint64_t displayId, int32_t x, int32_t y)
{
    PostSoftCursorTask([this, displayId, x, y]() {
        SoftwareCursorMove(displayId, x, y);
    });
}

void PointerDrawingManager::MoveRetryAsync(int32_t x, int32_t y)
{
    moveRetryTimerId_ = TimerMgr->AddTimer(MOVE_RETRY_TIME, MAX_MOVE_RETRY_COUNT, [this, x, y]() {
        PostMoveRetryTask([this, x, y]() {
            moveRetryCount_++;
            MMI_HILOGI("MoveRetryAsync start, x:%{private}d, y:%{private}d, Timer Id:%{public}d,"
                "move retry count:%{public}d", x, y, moveRetryTimerId_, moveRetryCount_);
            if (moveRetryTimerId_ == DEFAULT_VALUE) {
                moveRetryCount_ = 0;
                MMI_HILOGI("MoveRetryAsync timer id is invalid, stop retry");
                return;
            }
            if (HardwareCursorMove(x, y) == RET_OK) {
                int32_t ret = TimerMgr->RemoveTimer(moveRetryTimerId_);
                MMI_HILOGI("Move retry success, cancel timer, TimerId:%{public}d, ret:%{public}d",
                    moveRetryTimerId_, ret);
                moveRetryTimerId_ = DEFAULT_VALUE;
                moveRetryCount_ = 0;
                return;
            }
            MMI_HILOGE("Move retry failed, TimerId:%{public}d", moveRetryTimerId_);
            if (moveRetryCount_ == MAX_MOVE_RETRY_COUNT) {
                MMI_HILOGI("Move retry execeed max count, stop retry");
                moveRetryTimerId_ = DEFAULT_VALUE;
                moveRetryCount_ = 0;
            }
        });
    }, "PointerDrawingManager-MoveRetryAsync");
    MMI_HILOGI("Create MoveRetry Timer, timerId: %{public}d", moveRetryTimerId_);
}

void PointerDrawingManager::ResetMoveRetryTimer()
{
    if (moveRetryTimerId_ != DEFAULT_VALUE) {
        int32_t ret = TimerMgr->RemoveTimer(moveRetryTimerId_);
        MMI_HILOGI("Cancel moveRetry Timer, TimerId:%{public}d, ret:%{public}d", moveRetryTimerId_, ret);
        moveRetryTimerId_ = DEFAULT_VALUE;
    }
    if (moveRetryCount_ > 0) {
        moveRetryCount_ = 0;
    }
}

void PointerDrawingManager::HideHardwareCursors()
{
    auto curSp = GetScreenPointer(screenId_);
    CHKPV(curSp);
    if (!curSp->SetInvisible()) {
        MMI_HILOGE("Hide cursor of current screen failed, screenId_: %{public}" PRIu64, screenId_);
    }

    for (auto msp : GetMirrorScreenPointers()) {
        CHKPC(msp);
        if (!msp->SetInvisible()) {
            MMI_HILOGE("Hide cursor of mirror screen failed, screenId_: %{public}" PRIu64, screenId_);
        }
    }
}

void PointerDrawingManager::DrawScreenCenterPointer(const PointerStyle& pointerStyle)
{
    CALL_DEBUG_ENTER;
    if (hasDisplay_ && hasPointerDevice_) {
        if (GetSurfaceNode() != nullptr) {
            AttachToDisplay();
            Rosen::RSTransaction::FlushImplicitTransaction();
        }
        int32_t validWidth = displayInfo_.validWidth;
        int32_t validHeight = displayInfo_.validHeight;
        Direction direction = GetDisplayDirection(&displayInfo_);
        if (direction == DIRECTION90 || direction == DIRECTION270) {
            std::swap(validWidth, validHeight);
        }
        int32_t x = validWidth / CALCULATE_MIDDLE;
        int32_t y = validHeight / CALCULATE_MIDDLE;
        MMI_HILOGD("DrawScreenCenterPointer, x=%{private}d, y=%{private}d", x, y);
        DrawPointer(displayInfo_.rsId, x, y, pointerStyle, direction);
    }
}

std::shared_ptr<OHOS::Media::PixelMap> PointerDrawingManager::GetUserIconCopy(bool setSurfaceNode)
{
    std::shared_ptr<OHOS::Media::PixelMap> userIcon =
        CursorDrawingInformation::GetInstance().GetUserIconPixelMap();
    if (userIcon == nullptr) {
        MMI_HILOGI("userIcon is nullptr");
        return nullptr;
    }
    MessageParcel data;
    userIcon->Marshalling(data);
    std::shared_ptr<OHOS::Media::PixelMap> pixelMapPtr(OHOS::Media::PixelMap::Unmarshalling(data));
    CHKPP(pixelMapPtr);
    Media::ImageInfo imageInfo;
    pixelMapPtr->GetImageInfo(imageInfo);
    int32_t cursorSize = 1;
    float axis = 1.0f;
    if (followSystem_) {
        cursorSize = GetPointerSize(GetCurrentUser());
        cursorWidth_ = pow(INCREASE_RATIO, cursorSize - 1) * imageInfo.size.width;
        cursorHeight_ = pow(INCREASE_RATIO, cursorSize - 1) * imageInfo.size.height;
        int32_t maxValue = imageInfo.size.width > imageInfo.size.height ? cursorWidth_ : cursorHeight_;
        if (maxValue > MAX_CUSTOM_CURSOR_DIMENSION) {
            axis = (float)MAX_CUSTOM_CURSOR_DIMENSION / (float)std::max(imageInfo.size.width, imageInfo.size.height);
        } else {
            axis = (float)std::max(cursorWidth_, cursorHeight_) /
                (float)std::max(imageInfo.size.width, imageInfo.size.height);
        }
    }
    pixelMapPtr->scale(axis, axis, Media::AntiAliasingOption::LOW);
    cursorWidth_ = static_cast<int32_t>((float)imageInfo.size.width * axis);
    cursorHeight_ = static_cast<int32_t>((float)imageInfo.size.height * axis);
    userIconHotSpotX_ = static_cast<int32_t>((float)focusX_ * axis);
    userIconHotSpotY_ = static_cast<int32_t>((float)focusY_ * axis);
    MMI_HILOGI("cursorWidth:%{public}d, cursorHeight:%{public}d, imageWidth:%{public}d,"
        "imageHeight:%{public}d, focusX:%{private}d, focusY:%{private}d, axis:%{public}f,"
        "userIconHotSpotX_:%{private}d, userIconHotSpotY_:%{private}d",
        cursorWidth_, cursorHeight_, imageInfo.size.width, imageInfo.size.height,
        focusX_, focusY_, axis, userIconHotSpotX_, userIconHotSpotY_);
    if (setSurfaceNode) {
        SetSurfaceNodeBounds();
    }
    return pixelMapPtr;
}

void PointerDrawingManager::SetSurfaceNodeBounds()
{
    if (GetHardCursorEnabled()) {
        return;
    }
    if (canvasWidth_ < cursorWidth_) {
        canvasWidth_ = (cursorWidth_ / POINTER_WINDOW_INIT_SIZE + 1) * POINTER_WINDOW_INIT_SIZE;
    }
    if (canvasHeight_ < cursorHeight_) {
        canvasHeight_ = (cursorHeight_ / POINTER_WINDOW_INIT_SIZE + 1) * POINTER_WINDOW_INIT_SIZE;
    }
    auto surfaceNodePtr = GetSurfaceNode();
    CHKPV(surfaceNodePtr);
    surfaceNodePtr->SetBounds(lastPhysicalX_, lastPhysicalY_, canvasWidth_, canvasHeight_);
}

int32_t PointerDrawingManager::SetCustomCursor(int32_t pid, int32_t windowId, CustomCursor cursor,
    CursorOptions options)
{
    CALL_DEBUG_ENTER;
    followSystem_ = options.followSystem;
    if (GetHardCursorEnabled()) {
        userIconFollowSystem_ = false;
    }
    int32_t ret = UpdateCursorProperty(cursor);
    if (ret != RET_OK) {
        MMI_HILOGE("UpdateCursorProperty is failed");
        return ret;
    }
    CursorDrawingInformation::GetInstance().SetMouseIconUpdate(true);
    PointerStyle style;
    style.id = MOUSE_ICON::DEVELOPER_DEFINED_ICON;
    lastMouseStyle_ = style;
    ret = CursorDrawingInformation::GetInstance().SetPointerStyle(GetCurrentUser(), pid, windowId, style);
    if (ret == RET_ERR) {
        MMI_HILOGE("SetPointerStyle is failed");
    }
    MMI_HILOGD("style.id:%{public}d, userIconHotSpotX_:%{private}d, userIconHotSpotY_:%{private}d",
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
    if (imageInfo.size.width < cursor.focusX || imageInfo.size.height < cursor.focusY) {
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
    CursorDrawingInformation::GetInstance().SetUserIconPixelMap(newPixelMap);
    focusX_ = cursor.focusX;
    focusY_ = cursor.focusY;
    userIconHotSpotX_ = cursor.focusX;
    userIconHotSpotY_ = cursor.focusY;
    MMI_HILOGI("imageWidth:%{public}d, imageHeight:%{public}d, focusX:%{private}d, focusY:%{private}d",
        imageInfo.size.width, imageInfo.size.height, cursor.focusX, cursor.focusY);
    return RET_OK;
}

int32_t PointerDrawingManager::DrawNewDpiPointer()
{
    CursorDrawingInformation::GetInstance().SetMouseIconUpdate(true);
    int32_t updateRes = DrawMovePointer(lastDisplayId_, lastPhysicalX_, lastPhysicalY_,
        lastMouseStyle_, currentDirection_);
    if (updateRes != RET_OK) {
        MMI_HILOGE("Forced refresh DPI drawing failed.");
        return RET_ERR;
    }
    return RET_OK;
}

std::shared_ptr<Rosen::RSSurfaceNode> PointerDrawingManager::GetSurfaceNode()
{
    std::unique_lock<std::mutex> lockGuard(surfaceNodeMutex_);
    return surfaceNode_;
}

void PointerDrawingManager::SetSurfaceNode(std::shared_ptr<Rosen::RSSurfaceNode> ptr)
{
    std::unique_lock<std::mutex> lockGuard(surfaceNodeMutex_);
    surfaceNode_ = ptr;
}

OLD::DisplayInfo PointerDrawingManager::GetCurrentDisplayInfo()
{
    return displayInfo_;
}

void PointerDrawingManager::AdjustMouseFocusToSoftRenderOrigin(Direction direction, const MOUSE_ICON pointerStyle,
    int32_t &physicalX, int32_t &physicalY)
{
    if (pointerStyle == MOUSE_ICON::LOADING) {
        direction = DIRECTION0;
    }

    auto mouseIcons = CursorDrawingInformation::GetInstance().GetMouseIconsMap();
    if (pointerStyle == MOUSE_ICON::DEFAULT) {
        if (mouseIcons[pointerStyle].iconPath == CursorIconPath) {
            AdjustMouseFocus(direction, ICON_TYPE(mouseIcons[MOUSE_ICON(MOUSE_ICON::CURSOR_CIRCLE)].alignmentWay),
                physicalX, physicalY);
        } else if (mouseIcons[pointerStyle].iconPath == CustomCursorIconPath) {
            AdjustMouseFocus(direction,
                ICON_TYPE(mouseIcons[MOUSE_ICON(MOUSE_ICON::AECH_DEVELOPER_DEFINED_ICON)].alignmentWay),
                    physicalX, physicalY);
        } else {
            AdjustMouseFocus(direction, ICON_TYPE(mouseIcons[pointerStyle].alignmentWay), physicalX, physicalY);
        }
    } else {
        AdjustMouseFocus(direction, ICON_TYPE(mouseIcons[pointerStyle].alignmentWay), physicalX, physicalY);
    }
}

bool PointerDrawingManager::IsHardCursorEnabled()
{
    bool isHardCursorEnabled = true;
    CHKPF(hardwareCursorPointerManager_);
    if (g_isHdiRemoteDied) {
        hardwareCursorPointerManager_->SetHdiServiceState(false);
    }
    if (!hardwareCursorPointerManager_->IsSupported()) {
        isHardCursorEnabled = false;
    }
    return isHardCursorEnabled;
}

bool PointerDrawingManager::GetHardCursorEnabled()
{
    return IsHardCursorEnabled();
}

#ifndef OHOS_BUILD_ENABLE_WATCH
void PointerDrawingManager::NotifyPointerEventToRS(int32_t pointAction, int32_t pointCnt, int32_t sourceType)
{
    OHOS::Rosen::RSInterfaces::GetInstance().NotifyTouchEvent(pointAction, pointCnt, sourceType);
}
#endif // OHOS_BUILD_ENABLE_WATCH

void PointerDrawingManager::RecordCursorIdAndImageAddress()
{
    const auto id = lastMouseStyle_.id;
    auto mouseIcons = CursorDrawingInformation::GetInstance().GetMouseIconsMap();
    if (id < 0 || id >= static_cast<int32_t>(mouseIcons.size())) {
        MMI_HILOGE("Invalid cursor id: %{public}d", id);
        return;
    }
    POINTER_DEV_MGR.mouseId_ = id;
    POINTER_DEV_MGR.mouseIcons_ = mouseIcons.at(MOUSE_ICON(id)).iconPath;
}

void PointerDrawingManager::RecordCursorVisibleStatus(bool status)
{
    POINTER_DEV_MGR.isPointerVisible = status;
}

void PointerDrawingManager::UpdatePointerItemCursorInfo(PointerEvent::PointerItem& pointerItem)
{
    pointerItem.SetVisible(POINTER_DEV_MGR.isPointerVisible);
    if (!pointerItem.GetVisible()) {
        return;
    }
    pointerItem.SetStyle(lastMouseStyle_.id);
    int32_t userId = GetCurrentUser();
    pointerItem.SetSizeLevel(GetPointerSize(userId));
    pointerItem.SetColor(static_cast<uint32_t>(GetPointerColor(userId)));
}

void PointerDrawingManager::AllPointerDeviceRemoved()
{
    UnsubscribeScreenModeChange();
    ClearScreenPointer();
}
} // namespace MMI
} // namespace OHOS
