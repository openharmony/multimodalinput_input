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

#include "image/bitmap.h"
#include "image_source.h"
#include "image_type.h"
#include "image_utils.h"
#include "table_dump.h"
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
#include "magic_pointer_drawing_manager.h"
#include "magic_pointer_velocity_tracker.h"
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR

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

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_CURSOR
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "PointerDrawingManager"

namespace OHOS {
namespace MMI {
namespace {
const std::string FOLD_SCREEN_FLAG = system::GetParameter("const.window.foldscreen.type", "");
const std::string IMAGE_POINTER_DEFAULT_PATH = "/system/etc/multimodalinput/mouse_icon/";
const std::string DefaultIconPath = IMAGE_POINTER_DEFAULT_PATH + "Default.svg";
const std::string CursorIconPath = IMAGE_POINTER_DEFAULT_PATH + "Cursor_Circle.png";
const std::string POINTER_COLOR { "pointerColor" };
const std::string POINTER_SIZE { "pointerSize" };
const std::string MAGIC_POINTER_COLOR { "magicPointerColor" };
const std::string MAGIC_POINTER_SIZE { "magicPointerSize"};
const int32_t ROTATE_POLICY = system::GetIntParameter("const.window.device.rotate_policy", 0);
constexpr int32_t WINDOW_ROTATE { 0 };
constexpr int32_t BASELINE_DENSITY { 160 };
constexpr int32_t CALCULATE_MIDDLE { 2 };
constexpr int32_t MAGIC_INDEPENDENT_PIXELS { 30 };
constexpr int32_t DEVICE_INDEPENDENT_PIXELS { 40 };
constexpr int32_t POINTER_WINDOW_INIT_SIZE { 64 };
constexpr int32_t DEFAULT_POINTER_SIZE { 1 };
constexpr int32_t MIN_POINTER_SIZE { 1 };
constexpr int32_t MAX_POINTER_SIZE { 7 };
constexpr int32_t DEFAULT_VALUE { -1 };
constexpr int32_t ANIMATION_DURATION { 500 };
constexpr int32_t DEFAULT_POINTER_STYLE { 0 };
constexpr int32_t CURSOR_CIRCLE_STYLE { 41 };
constexpr int32_t MOUSE_ICON_BAIS { 5 };
constexpr int32_t VISIBLE_LIST_MAX_SIZE { 100 };
constexpr int32_t WAIT_TIME_FOR_MAGIC_CURSOR { 6000 };
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
const std::string MOUSE_FILE_NAME { "mouse_settings.xml" };
bool g_isRsRemoteDied { false };
constexpr uint64_t FOLD_SCREEN_ID_FULL { 0 };
constexpr uint64_t FOLD_SCREEN_ID_MAIN { 5 };
constexpr int32_t CANVAS_SIZE { 256 };
constexpr float IMAGE_PIXEL { 0.0f };
constexpr int32_t QUEUE_SIZE { 5 };
std::mutex mutex_;
} // namespace
} // namespace MMI
} // namespace OHOS

namespace OHOS {
namespace MMI {

static bool IsSingleDisplayFoldDevice()
{
    return (!FOLD_SCREEN_FLAG.empty() && FOLD_SCREEN_FLAG[0] == '1');
}

void RsRemoteDiedCallback()
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    g_isRsRemoteDied = true;
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
    MAGIC_CURSOR->RsRemoteDiedCallbackForMagicCursor();
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
}

void PointerDrawingManager::InitPointerCallback()
{
    MMI_HILOGI("Init RS Callback start");
    std::lock_guard<std::mutex> guard(mutex_);
    g_isRsRemoteDied = false;
    Rosen::OnRemoteDiedCallback callback = RsRemoteDiedCallback;
    Rosen::RSInterfaces::GetInstance().SetOnRemoteDiedCallback(callback);
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
    if (HasMagicCursor() && surfaceNode_ != nullptr) {
        surfaceNode_ = nullptr;
        MAGIC_CURSOR->RsRemoteInitCallbackForMagicCursor();
    }
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
}

PointerDrawingManager::PointerDrawingManager()
{
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
    MMI_HILOGI("magiccurosr InitStyle");
    hasMagicCursor_.name = "isMagicCursor";
    TimerMgr->AddTimer(WAIT_TIME_FOR_MAGIC_CURSOR, 1, [this]() {
        MMI_HILOGD("Timer callback");
        if (hasInitObserver_ == false) {
            int32_t ret = CreatePointerSwitchObserver(hasMagicCursor_);
            if (ret == RET_OK) {
                hasInitObserver_ = true;
                MMI_HILOGD("Create pointer switch observer success on timer");
            }
        }
    });
    MAGIC_CURSOR->InitStyle();
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
    InitStyle();
#ifdef OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    hardwareCursorPointerManager_ = std::make_shared<HardwareCursorPointerManager>();
#endif // OHOS_BUILD_ENABLE_HARDWARE_CURSOR
}

PointerStyle PointerDrawingManager::GetLastMouseStyle()
{
    CALL_DEBUG_ENTER;
    return lastMouseStyle_;
}

bool PointerDrawingManager::SetHardWareLocation(int32_t displayId, int32_t physicalX, int32_t physicalY)
{
#ifdef OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    CHKPF(hardwareCursorPointerManager_);
    hardwareCursorPointerManager_->SetTargetDevice(displayId);
    if (hardwareCursorPointerManager_->IsSupported()) {
        if (hardwareCursorPointerManager_->SetPosition(physicalX, physicalY) != RET_OK) {
            MMI_HILOGE("Set hardware cursor position error");
            return false;
        }
    }
#endif // OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    return true;
}

void PointerDrawingManager::ForceClearPointerVisiableStatus()
{
    MMI_HILOGI("force clear all pointer visiable status");
    pidInfos_.clear();
    UpdatePointerVisible();
}

int32_t PointerDrawingManager::DrawMovePointer(int32_t displayId, int32_t physicalX, int32_t physicalY,
    PointerStyle pointerStyle, Direction direction)
{
    if (surfaceNode_ == nullptr) {
        return RET_ERR;
    }
    if (!SetHardWareLocation(displayId, physicalX, physicalY)) {
        return RET_ERR;
    }
    MMI_HILOGD("Pointer window move success, pointerStyle id: %{public}d", pointerStyle.id);
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
    if (lastMouseStyle_ == pointerStyle && !mouseIconUpdate_ && lastDirection_ == direction) {
        surfaceNode_->SetBounds(physicalX + displayInfo_.x, physicalY + displayInfo_.y,
            surfaceNode_->GetStagingProperties().GetBounds().z_,
            surfaceNode_->GetStagingProperties().GetBounds().w_);
        Rosen::RSTransaction::FlushImplicitTransaction();
        MMI_HILOGD("The lastpointerStyle is equal with pointerStyle, id:%{public}d, size:%{public}d",
            pointerStyle.id, pointerStyle.size);
        return RET_OK;
    }
    if (lastDirection_ != direction) {
        RotateDegree(direction);
        lastDirection_ = direction;
    }
    lastMouseStyle_ = pointerStyle;
    surfaceNode_->SetVisible(false);
    int32_t ret = InitLayer(MOUSE_ICON(lastMouseStyle_.id));
    if (ret != RET_OK) {
        mouseIconUpdate_ = false;
        MMI_HILOGE("Init layer failed");
        return RET_ERR;
    }
    surfaceNode_->SetBounds(physicalX + displayInfo_.x, physicalY + displayInfo_.y,
        surfaceNode_->GetStagingProperties().GetBounds().z_,
        surfaceNode_->GetStagingProperties().GetBounds().w_);
    surfaceNode_->SetVisible(true);
    Rosen::RSTransaction::FlushImplicitTransaction();
    UpdatePointerVisible();
    mouseIconUpdate_ = false;
    MMI_HILOGD("Leave, display:%{public}d, physicalX:%{public}d, physicalY:%{public}d",
        displayId, physicalX, physicalY);
    return RET_OK;
}

void PointerDrawingManager::DrawMovePointer(int32_t displayId, int32_t physicalX, int32_t physicalY)
{
    CALL_DEBUG_ENTER;
    if (surfaceNode_ != nullptr) {
        surfaceNode_->SetBounds(physicalX + displayInfo_.x, physicalY + displayInfo_.y,
            surfaceNode_->GetStagingProperties().GetBounds().z_,
            surfaceNode_->GetStagingProperties().GetBounds().w_);
        Rosen::RSTransaction::FlushImplicitTransaction();
        MMI_HILOGD("Move pointer, physicalX:%{public}d, physicalY:%{public}d", physicalX, physicalY);
    }
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
    std::map<MOUSE_ICON, IconStyle> iconPath = GetMouseIconPath();
    if (pointerStyle.id == MOUSE_ICON::DEFAULT && iconPath[MOUSE_ICON(pointerStyle.id)].iconPath == CursorIconPath) {
        AdjustMouseFocus(direction, ICON_TYPE(GetMouseIconPath()[MOUSE_ICON(MOUSE_ICON::CURSOR_CIRCLE)].alignmentWay),
            physicalX, physicalY);
    } else {
        AdjustMouseFocus(direction, ICON_TYPE(GetMouseIconPath()[MOUSE_ICON(pointerStyle.id)].alignmentWay),
            physicalX, physicalY);
    }
    // Log printing only occurs when the mouse style changes
    if (currentMouseStyle_.id != lastMouseStyle_.id) {
        MMI_HILOGD("MagicCursor AdjustMouseFocus:%{public}d",
            ICON_TYPE(GetMouseIconPath()[MOUSE_ICON(pointerStyle.id)].alignmentWay));
    }
    if (DrawMovePointer(displayId, physicalX, physicalY, pointerStyle, direction) == RET_OK) {
        return;
    }
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
    if (HasMagicCursor()) {
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
    int32_t ret = InitLayer(MOUSE_ICON(lastMouseStyle_.id));
    if (ret != RET_OK) {
        MMI_HILOGE("Init layer failed");
        return;
    }
    UpdatePointerVisible();
    MMI_HILOGI("Leave, display:%{public}d, physicalX:%{public}d, physicalY:%{public}d",
        displayId, physicalX, physicalY);
}

void PointerDrawingManager::UpdateMouseStyle()
{
    CALL_DEBUG_ENTER;
    PointerStyle curPointerStyle;
    GetPointerStyle(pid_, GLOBAL_WINDOW_ID, curPointerStyle);
    if (curPointerStyle.id == CURSOR_CIRCLE_STYLE) {
        lastMouseStyle_.id = curPointerStyle.id;
        int ret = SetPointerStyle(pid_, GLOBAL_WINDOW_ID, curPointerStyle);
        if (ret != RET_OK) {
            MMI_HILOGE("Set pointer style failed");
        }
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
        MAGIC_CURSOR->CreatePointerWindow(displayInfo_.id, physicalX, physicalY, direction, surfaceNode_);
    } else {
        MAGIC_CURSOR->DisableCursorInversion();
        CreatePointerWindow(displayInfo_.id, physicalX, physicalY, direction);
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
            MMI_HILOGD("switch pointer style");
            int64_t nodeId = surfaceNode_->GetId();
            if (nodeId != MAGIC_CURSOR->GetSurfaceNodeId(nodeId)) {
                surfaceNode_->DetachToDisplay(screenId_);
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

int32_t PointerDrawingManager::InitLayer(const MOUSE_ICON mouseStyle)
{
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
    if (HasMagicCursor() && mouseStyle != MOUSE_ICON::DEVELOPER_DEFINED_ICON) {
        MMI_HILOGD("magiccursor enter MAGIC_CURSOR->Initlayer");
        return MAGIC_CURSOR->InitLayer(mouseStyle);
    } else {
        MMI_HILOGD("magiccursor not enter MAGIC_CURSOR->Initlayer");
        return DrawCursor(mouseStyle);
    }
#else
    return DrawCursor(mouseStyle);
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
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
    if (!isInit_) {
        layer->SetQueueSize(QUEUE_SIZE);
        isInit_ = true;
    }
    sptr<OHOS::SurfaceBuffer> buffer = GetSurfaceBuffer(layer);
    if (buffer == nullptr || buffer->GetVirAddr() == nullptr) {
        MMI_HILOGE("Init layer is failed, buffer or virAddr is nullptr");
        surfaceNode_->DetachToDisplay(screenId_);
        surfaceNode_ = nullptr;
        Rosen::RSTransaction::FlushImplicitTransaction();
        MMI_HILOGE("Pointer window destroy success");
        return RET_ERR;
    }

    auto addr = static_cast<uint8_t *>(buffer->GetVirAddr());
    DoDraw(addr, buffer->GetWidth(), buffer->GetHeight(), mouseStyle);
    OHOS::BufferFlushConfig flushConfig = {
        .damage = {
            .w = buffer->GetWidth(),
            .h = buffer->GetHeight(),
        },
    };
    OHOS::SurfaceError ret = layer->FlushBuffer(buffer, -1, flushConfig);
    if (ret != OHOS::SURFACE_ERROR_OK) {
        MMI_HILOGE("Init layer failed, FlushBuffer return ret:%{public}s", SurfaceErrorStr(ret).c_str());
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
        MMI_HILOGE("current pointer is not loading");
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

void PointerDrawingManager::DrawRunningPointerAnimate(const MOUSE_ICON mouseStyle)
{
    CALL_DEBUG_ENTER;
    CHKPV(surfaceNode_);
    CHKPV(canvasNode_);
    if (mouseStyle != MOUSE_ICON::RUNNING &&
        (mouseStyle != MOUSE_ICON::DEFAULT ||
            mouseIcons_[mouseStyle].iconPath != (IMAGE_POINTER_DEFAULT_PATH + "Loading_Left.svg"))) {
        if (canvasNode_ != nullptr) {
            canvasNode_->SetVisible(false);
        }
        MMI_HILOGE("current pointer is not running");
        return;
    }
    canvasNode_->SetVisible(true);
    float ratio = imageWidth_ * 1.0 / canvasWidth_;
    canvasNode_->SetPivot({RUNNING_X_RATIO * ratio, RUNNING_Y_RATIO * ratio});
    std::shared_ptr<OHOS::Media::PixelMap> pixelmap =
        DecodeImageToPixelMap(mouseIcons_[MOUSE_ICON::RUNNING_RIGHT].iconPath);
    CHKPV(pixelmap);
    MMI_HILOGD("Set mouseicon to OHOS system");

#ifndef USE_ROSEN_DRAWING
    auto canvas = static_cast<Rosen::RSRecordingCanvas *>(canvasNode_->BeginRecording(CANVAS_SIZE, CANVAS_SIZE));
    OHOS::Rosen::Drawing::Brush brush;
    brush.SetColor(Rosen::Drawing::Color::COLOR_TRANSPARENT);
    canvas->DrawBackground(brush);
    canvas->DrawPixelMap(pixelmap, 0, 0, SkSamplingOptions(), nullptr);
#else
    Rosen::Drawing::Brush brush;
    Rosen::Drawing::Rect src = Rosen::Drawing::Rect(0, 0, pixelmap->GetWidth(), pixelmap->GetHeight());
    Rosen::Drawing::Rect dst = Rosen::Drawing::Rect(src);
    auto canvas =
        static_cast<Rosen::ExtendRecordingCanvas *>(canvasNode_->BeginRecording(CANVAS_SIZE, CANVAS_SIZE));
    OHOS::Rosen::Drawing::Brush brushBackGround;
    brushBackGround.SetColor(Rosen::Drawing::Color::COLOR_TRANSPARENT);
    canvas->AttachBrush(brush);
    canvas->DrawBackground(brushBackGround);
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
    switch (iconType) {
        case ANGLE_SW: {
            physicalY -= imageHeight_;
            break;
        }
        case ANGLE_CENTER: {
            physicalX -= imageWidth_ / CALCULATE_MIDDLE;
            physicalY -= imageHeight_ / CALCULATE_MIDDLE;
            break;
        }
        case ANGLE_NW_RIGHT: {
            physicalX -= MOUSE_ICON_BAIS;
            [[fallthrough]];
        }
        case ANGLE_NW: {
            if (userIcon_ != nullptr && currentMouseStyle_.id == MOUSE_ICON::DEVELOPER_DEFINED_ICON) {
                physicalX -= userIconHotSpotX_;
                physicalY -= userIconHotSpotY_;
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
    switch (iconType) {
        case ANGLE_SW: {
            physicalY += imageHeight_;
            break;
        }
        case ANGLE_CENTER: {
            physicalX -= imageWidth_ / CALCULATE_MIDDLE;
            physicalY += imageHeight_ / CALCULATE_MIDDLE;
            break;
        }
        case ANGLE_NW_RIGHT: {
            physicalX -= MOUSE_ICON_BAIS;
            [[fallthrough]];
        }
        case ANGLE_NW: {
            if (userIcon_ != nullptr && currentMouseStyle_.id == MOUSE_ICON::DEVELOPER_DEFINED_ICON) {
                physicalX -= userIconHotSpotX_;
                physicalY += userIconHotSpotY_;
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
    switch (iconType) {
        case ANGLE_SW: {
            physicalY += imageHeight_;
            break;
        }
        case ANGLE_CENTER: {
            physicalX += imageWidth_ / CALCULATE_MIDDLE;
            physicalY += imageHeight_ / CALCULATE_MIDDLE;
            break;
        }
        case ANGLE_NW_RIGHT: {
            physicalX += MOUSE_ICON_BAIS;
            [[fallthrough]];
        }
        case ANGLE_NW: {
            if (userIcon_ != nullptr && currentMouseStyle_.id == MOUSE_ICON::DEVELOPER_DEFINED_ICON) {
                physicalX += userIconHotSpotX_;
                physicalY += userIconHotSpotY_;
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
    switch (iconType) {
        case ANGLE_SW: {
            physicalY -= imageHeight_;
            break;
        }
        case ANGLE_CENTER: {
            physicalX += imageWidth_ / CALCULATE_MIDDLE;
            physicalY -= imageHeight_ / CALCULATE_MIDDLE;
            break;
        }
        case ANGLE_NW_RIGHT: {
            physicalX += MOUSE_ICON_BAIS;
            [[fallthrough]];
        }
        case ANGLE_NW: {
            if (userIcon_ != nullptr && currentMouseStyle_.id == MOUSE_ICON::DEVELOPER_DEFINED_ICON) {
                physicalX += userIconHotSpotX_;
                physicalY -= userIconHotSpotY_;
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
            InitLayer(MOUSE_ICON(lastMouseStyle_.id));
        }
        MMI_HILOGI("state:%{public}s", state ? "true" : "false");
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
    if (ROTATE_POLICY == WINDOW_ROTATE) {
        if (displayInfo_.direction == DIRECTION0 || displayInfo_.direction == DIRECTION180) {
            if (physicalX > (displayInfo_.width - imageWidth_ / cursorUnit)) {
                physicalX = displayInfo_.width - imageWidth_ / cursorUnit;
            }
            if (physicalY > (displayInfo_.height - imageHeight_ / cursorUnit)) {
                physicalY = displayInfo_.height - imageHeight_ / cursorUnit;
            }
        } else {
            if (physicalX > (displayInfo_.height - imageHeight_ / cursorUnit)) {
                physicalX = displayInfo_.height - imageHeight_ / cursorUnit;
            }
            if (physicalY > (displayInfo_.width - imageWidth_ / cursorUnit)) {
                physicalY = displayInfo_.width - imageWidth_ / cursorUnit;
            }
        }
    } else {
        if (physicalX > (displayInfo_.width - imageWidth_ / cursorUnit)) {
            physicalX = displayInfo_.width - imageWidth_ / cursorUnit;
        }
        if (physicalY > (displayInfo_.height - imageHeight_ / cursorUnit)) {
            physicalY = displayInfo_.height - imageHeight_ / cursorUnit;
        }
    }
}

void PointerDrawingManager::AttachToDisplay()
{
    CALL_DEBUG_ENTER;
    CHKPV(surfaceNode_);
    if (IsSingleDisplayFoldDevice() && (WIN_MGR->GetDisplayMode() == DisplayMode::MAIN)
        && (screenId_ == FOLD_SCREEN_ID_FULL)) {
        screenId_ = FOLD_SCREEN_ID_MAIN;
    }
    MMI_HILOGI("screenId_: %{public}" PRIu64"", screenId_);
    surfaceNode_->AttachToDisplay(screenId_);
}

void PointerDrawingManager::CreatePointerWindow(int32_t displayId, int32_t physicalX, int32_t physicalY,
    Direction direction)
{
    CALL_DEBUG_ENTER;
    CALL_INFO_TRACE;
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    CHKPV(surfaceNode_);
    surfaceNode_->SetFrameGravity(Rosen::Gravity::RESIZE_ASPECT_FILL);
    surfaceNode_->SetPositionZ(Rosen::RSSurfaceNode::POINTER_WINDOW_POSITION_Z);
    surfaceNode_->SetBounds(physicalX, physicalY, canvasWidth_, canvasHeight_);
#ifdef OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    CHKPV(hardwareCursorPointerManager_);
    hardwareCursorPointerManager_->SetTargetDevice(displayId);
    if (hardwareCursorPointerManager_->IsSupported()) {
        if (hardwareCursorPointerManager_->SetPosition(physicalX, physicalY) != RET_OK) {
            MMI_HILOGE("Set hardware cursor position error");
            return;
        }
    }
#endif // OHOS_BUILD_ENABLE_HARDWARE_CURSOR
#ifndef USE_ROSEN_DRAWING
    surfaceNode_->SetBackgroundColor(SK_ColorTRANSPARENT);
#else
    surfaceNode_->SetBackgroundColor(Rosen::Drawing::Color::COLOR_TRANSPARENT);
#endif

    screenId_ = static_cast<uint64_t>(displayId);
    std::cout << "ScreenId: " << screenId_ << std::endl;
    AttachToDisplay();
    RotateDegree(direction);
    lastDirection_ = direction;

    canvasNode_ = Rosen::RSCanvasNode::Create();
    canvasNode_->SetBounds(0, 0, canvasWidth_, canvasHeight_);
    canvasNode_->SetFrame(0, 0, canvasWidth_, canvasHeight_);
#ifndef USE_ROSEN_DRAWING
    canvasNode_->SetBackgroundColor(SK_ColorTRANSPARENT);
#else
    canvasNode_->SetBackgroundColor(Rosen::Drawing::Color::COLOR_TRANSPARENT);
#endif
    canvasNode_->SetCornerRadius(1);
    canvasNode_->SetPositionZ(Rosen::RSSurfaceNode::POINTER_WINDOW_POSITION_Z);
    canvasNode_->SetRotation(0);
    surfaceNode_->AddChild(canvasNode_, DEFAULT_VALUE);
    Rosen::RSTransaction::FlushImplicitTransaction();
}

sptr<OHOS::Surface> PointerDrawingManager::GetLayer()
{
    CALL_DEBUG_ENTER;
    CHKPP(surfaceNode_);
    return surfaceNode_->GetSurface();
}

sptr<OHOS::SurfaceBuffer> PointerDrawingManager::GetSurfaceBuffer(sptr<OHOS::Surface> layer) const
{
    CALL_DEBUG_ENTER;
    sptr<OHOS::SurfaceBuffer> buffer;
    int32_t releaseFence = -1;
    OHOS::BufferRequestConfig config = {
        .width = canvasWidth_,
        .height = canvasHeight_,
        .strideAlignment = 0x8,
        .format = GRAPHIC_PIXEL_FMT_RGBA_8888,
        .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA,
        .timeout = 100,
    };

    OHOS::SurfaceError ret = layer->RequestBuffer(buffer, releaseFence, config);
    close(releaseFence);
    if (ret != OHOS::SURFACE_ERROR_OK) {
        MMI_HILOGE("Request buffer ret:%{public}s", SurfaceErrorStr(ret).c_str());
        return nullptr;
    }
    return buffer;
}

void PointerDrawingManager::DrawImage(OHOS::Rosen::Drawing::Canvas &canvas, MOUSE_ICON mouseStyle)
{
    CALL_DEBUG_ENTER;
    OHOS::Rosen::Drawing::Pen pen;
    pen.SetAntiAlias(true);
    pen.SetColor(OHOS::Rosen::Drawing::Color::COLOR_BLUE);
    OHOS::Rosen::Drawing::scalar penWidth = 1;
    pen.SetWidth(penWidth);
    canvas.AttachPen(pen);
    std::shared_ptr<Rosen::Drawing::Image> image;
    std::shared_ptr<OHOS::Media::PixelMap> pixelmap;
    if (mouseStyle == MOUSE_ICON::DEVELOPER_DEFINED_ICON) {
        MMI_HILOGD("Set mouseicon by userIcon_");
        image = ExtractDrawingImage(userIcon_);
        SetPixelMap(userIcon_);
    } else {
        if (mouseStyle == MOUSE_ICON::RUNNING) {
            pixelmap = DecodeImageToPixelMap(mouseIcons_[MOUSE_ICON::RUNNING_LEFT].iconPath);
        } else {
            pixelmap = DecodeImageToPixelMap(mouseIcons_[mouseStyle].iconPath);
        }
        CHKPV(pixelmap);
        image = ExtractDrawingImage(pixelmap);
        if (mouseStyle == MOUSE_ICON::DEFAULT) {
            SetPixelMap(pixelmap);
        }
        MMI_HILOGI("Set mouseicon to system");
    }
    CHKPV(image);
    OHOS::Rosen::Drawing::Brush brush;
    brush.SetColor(Rosen::Drawing::Color::COLOR_TRANSPARENT);
    canvas.DrawBackground(brush);
    canvas.DrawImage(*image, IMAGE_PIXEL, IMAGE_PIXEL, Rosen::Drawing::SamplingOptions());
    MMI_HILOGD("Canvas draw image, success");
}

void PointerDrawingManager::SetPixelMap(std::shared_ptr<OHOS::Media::PixelMap> pixelMap)
{
    pixelMap_ = pixelMap;
}
 
int32_t PointerDrawingManager::GetPointerSnapshot(void *pixelMapPtr)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<Media::PixelMap> *newPixelMapPtr = static_cast<std::shared_ptr<Media::PixelMap> *>(pixelMapPtr);
    *newPixelMapPtr = pixelMap_;
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
    if (HasMagicCursor()) {
        MMI_HILOGE("magic pixelmap");
        *newPixelMapPtr = MAGIC_CURSOR->GetPixelMap();
    }
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
    CHKPR(*newPixelMapPtr, ERROR_NULL_POINTER);
    return RET_OK;
}

void PointerDrawingManager::DoDraw(uint8_t *addr, uint32_t width, uint32_t height, const MOUSE_ICON mouseStyle)
{
    CALL_DEBUG_ENTER;
    OHOS::Rosen::Drawing::Bitmap bitmap;
    OHOS::Rosen::Drawing::BitmapFormat format { OHOS::Rosen::Drawing::COLORTYPE_RGBA_8888,
        OHOS::Rosen::Drawing::ALPHATYPE_OPAQUE };
    bitmap.Build(width, height, format);
    OHOS::Rosen::Drawing::Canvas canvas(CANVAS_SIZE, CANVAS_SIZE);
    canvas.Bind(bitmap);
    canvas.Clear(OHOS::Rosen::Drawing::Color::COLOR_TRANSPARENT);
    DrawImage(canvas, mouseStyle);
    static constexpr uint32_t stride = 4;
    uint32_t addrSize = width * height * stride;
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
        MMI_HILOGD("set mouseicon by userIcon_");
        OHOS::Rosen::RSPixelMapUtil::DrawPixelMap(canvas, *userIcon_, 0, 0);
    } else {
        std::shared_ptr<OHOS::Media::PixelMap> pixelmap;
        if (mouseStyle == MOUSE_ICON::RUNNING) {
            pixelmap = DecodeImageToPixelMap(mouseIcons_[MOUSE_ICON::RUNNING_LEFT].iconPath);
        } else {
            pixelmap = DecodeImageToPixelMap(mouseIcons_[mouseStyle].iconPath);
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
    CHKPR(pixelMap, RET_ERR);
    if (pid == -1) {
        MMI_HILOGE("pid is invalid");
        return RET_ERR;
    }
    if (windowId < 0) {
        MMI_HILOGE("windowId is invalid, windowId:%{public}d", windowId);
        return RET_ERR;
    }
    if (WIN_MGR->CheckWindowIdPermissionByPid(windowId, pid) != RET_OK) {
        MMI_HILOGE("windowId not in right pid");
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
    int32_t cursorWidth =
        pow(INCREASE_RATIO, cursorSize - 1) * displayInfo_.dpi * GetIndependentPixels() / BASELINE_DENSITY;
    int32_t cursorHeight =
        pow(INCREASE_RATIO, cursorSize - 1) * displayInfo_.dpi * GetIndependentPixels() / BASELINE_DENSITY;
    cursorWidth = cursorWidth < MIN_CURSOR_SIZE ? MIN_CURSOR_SIZE : cursorWidth;
    cursorHeight = cursorHeight < MIN_CURSOR_SIZE ? MIN_CURSOR_SIZE : cursorHeight;
    float xAxis = (float)cursorWidth / (float)imageInfo.size.width;
    float yAxis = (float)cursorHeight / (float)imageInfo.size.height;
    newPixelMap->scale(xAxis, yAxis, Media::AntiAliasingOption::LOW);
    userIcon_.reset(newPixelMap);
    userIconHotSpotX_ = static_cast<int32_t>((float)focusX * xAxis);
    userIconHotSpotY_ = static_cast<int32_t>((float)focusY * yAxis);
    MMI_HILOGI("cursorWidth:%{public}d, cursorHeight:%{public}d, imageWidth:%{public}d, imageHeight:%{public}d,"
        "focusX:%{public}d, focuxY:%{public}d, xAxis:%{public}f, yAxis:%{public}f, userIconHotSpotX_:%{public}d,"
        "userIconHotSpotY_:%{public}d", cursorWidth, cursorHeight, imageInfo.size.width, imageInfo.size.height,
        focusX, focusY, xAxis, yAxis, userIconHotSpotX_, userIconHotSpotY_);
    return RET_OK;
}

int32_t PointerDrawingManager::SetMouseIcon(int32_t pid, int32_t windowId, void* pixelMap)
{
    CALL_DEBUG_ENTER;
    if (pid == -1) {
        MMI_HILOGE("pid is invalid return -1");
        return RET_ERR;
    }
    CHKPR(pixelMap, RET_ERR);
    if (windowId < 0) {
        MMI_HILOGE("get invalid windowId, %{public}d", windowId);
        return RET_ERR;
    }
    OHOS::Media::PixelMap* pixelMapPtr = static_cast<OHOS::Media::PixelMap*>(pixelMap);
    userIcon_.reset(pixelMapPtr);
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
        MMI_HILOGE("pid is invalid return -1");
        return RET_ERR;
    }
    if (windowId < 0) {
        MMI_HILOGE("invalid windowId, %{public}d", windowId);
        return RET_ERR;
    }
    if (WIN_MGR->CheckWindowIdPermissionByPid(windowId, pid) != RET_OK) {
        MMI_HILOGE("windowId not in right pid");
        return RET_ERR;
    }
    if (hotSpotX < 0 || hotSpotY < 0 || userIcon_ == nullptr) {
        MMI_HILOGE("invalid value");
        return RET_ERR;
    }
    PointerStyle pointerStyle;
    WIN_MGR->GetPointerStyle(pid, windowId, pointerStyle);
    if (pointerStyle.id != MOUSE_ICON::DEVELOPER_DEFINED_ICON) {
        MMI_HILOGE("Get pointer style failed, pid %{publid}d, pointerStyle %{public}d", pid, pointerStyle.id);
        return RET_ERR;
    }
    userIconHotSpotX_ = hotSpotX;
    userIconHotSpotY_ = hotSpotY;
    return RET_OK;
}

std::shared_ptr<OHOS::Media::PixelMap> PointerDrawingManager::DecodeImageToPixelMap(const std::string &imagePath)
{
    CALL_DEBUG_ENTER;
    OHOS::Media::SourceOptions opts;
    uint32_t ret = 0;
    auto imageSource = OHOS::Media::ImageSource::CreateImageSource(imagePath, opts, ret);
    CHKPP(imageSource);
    std::set<std::string> formats;
    ret = imageSource->GetSupportedFormats(formats);
    MMI_HILOGD("Get supported format ret:%{public}u", ret);

    OHOS::Media::DecodeOptions decodeOpts;
    decodeOpts.desiredSize = {
        .width = imageWidth_,
        .height = imageHeight_
    };
    int32_t pointerColor = GetPointerColor();
    if (tempPointerColor_ != DEFAULT_VALUE) {
        decodeOpts.SVGOpts.fillColor = {.isValidColor = true, .color = pointerColor};
        if (pointerColor == MAX_POINTER_COLOR) {
            decodeOpts.SVGOpts.strokeColor = {.isValidColor = true, .color = MIN_POINTER_COLOR};
        } else {
            decodeOpts.SVGOpts.strokeColor = {.isValidColor = true, .color = MAX_POINTER_COLOR};
        }
    }

    std::shared_ptr<OHOS::Media::PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, ret);
    CHKPL(pixelMap);
    return pixelMap;
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

int32_t PointerDrawingManager::SetPointerColor(int32_t color)
{
    CALL_DEBUG_ENTER;
    if (surfaceNode_ != nullptr) {
        float alphaRatio = (static_cast<uint32_t>(color) >> RGB_CHANNEL_BITS_LENGTH) / MAX_ALPHA_VALUE;
        if (alphaRatio > 1) {
            MMI_HILOGW("Invalid alphaRatio:%{public}f", alphaRatio);
        } else {
            surfaceNode_->SetAlpha(1 - alphaRatio);
        }
    }
    MMI_HILOGI("PointerColor:%{public}x", color);
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
    UpdatePointerVisible();
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
    hardwareCursorPointerManager_->SetTargetDevice(displayInfo.id);
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

    if (surfaceNode_ == nullptr) {
        MMI_HILOGI("surfaceNode_ is nullptr");
        return RET_OK;
    }
    imageWidth_ = pow(INCREASE_RATIO, size - 1) * displayInfo_.dpi * GetIndependentPixels() / BASELINE_DENSITY;
    imageHeight_ = pow(INCREASE_RATIO, size - 1) * displayInfo_.dpi * GetIndependentPixels() / BASELINE_DENSITY;
    canvasWidth_ = (imageWidth_ / POINTER_WINDOW_INIT_SIZE + 1) * POINTER_WINDOW_INIT_SIZE;
    canvasHeight_ = (imageHeight_ / POINTER_WINDOW_INIT_SIZE + 1) * POINTER_WINDOW_INIT_SIZE;
    int32_t physicalX = lastPhysicalX_;
    int32_t physicalY = lastPhysicalY_;
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
    MAGIC_CURSOR->SetPointerSize(imageWidth_, imageHeight_);
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
    Direction direction = DIRECTION0;
    if (ROTATE_POLICY == WINDOW_ROTATE) {
        direction = displayInfo_.direction;
    }
    AdjustMouseFocus(direction, ICON_TYPE(GetMouseIconPath()[MOUSE_ICON(lastMouseStyle_.id)].alignmentWay),
        physicalX, physicalY);
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
    if (HasMagicCursor()) {
        MAGIC_CURSOR->CreatePointerWindow(displayInfo_.id, physicalX, physicalY, direction, surfaceNode_);
    } else {
        CreatePointerWindow(displayInfo_.id, physicalX, physicalY, direction);
    }
#else
    CreatePointerWindow(displayInfo_.id, physicalX, physicalY, direction);
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
    ret = InitLayer(MOUSE_ICON(lastMouseStyle_.id));
    if (ret != RET_OK) {
        MMI_HILOGE("Init layer failed");
        return RET_ERR;
    }
    UpdatePointerVisible();
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

void PointerDrawingManager::OnDisplayInfo(const DisplayGroupInfo &displayGroupInfo)
{
    CALL_DEBUG_ENTER;
    for (const auto& item : displayGroupInfo.displaysInfo) {
        if (item.id == displayInfo_.id) {
            UpdateDisplayInfo(item);
            DrawManager();
            return;
        }
    }
    UpdateDisplayInfo(displayGroupInfo.displaysInfo[0]);
    lastPhysicalX_ = displayGroupInfo.displaysInfo[0].width / CALCULATE_MIDDLE;
    lastPhysicalY_ = displayGroupInfo.displaysInfo[0].height / CALCULATE_MIDDLE;
    MouseEventHdr->OnDisplayLost(displayInfo_.id);
    if (surfaceNode_ != nullptr) {
        surfaceNode_->DetachToDisplay(screenId_);
        surfaceNode_ = nullptr;
        Rosen::RSTransaction::FlushImplicitTransaction();
        MMI_HILOGD("Pointer window destroy success");
    }
    MMI_HILOGD("displayId_:%{public}d, displayWidth_:%{public}d, displayHeight_:%{public}d",
        displayInfo_.id, displayInfo_.width, displayInfo_.height);
}

void PointerDrawingManager::OnWindowInfo(const WinInfo &info)
{
    CALL_DEBUG_ENTER;
    windowId_ = info.windowId;
    pid_ = info.windowPid;
}

void PointerDrawingManager::UpdatePointerDevice(bool hasPointerDevice, bool isPointerVisible,
    bool isHotPlug)
{
    CALL_DEBUG_ENTER;
    MMI_HILOGD("hasPointerDevice:%{public}s, isPointerVisible:%{public}s",
        hasPointerDevice ? "true" : "false", isPointerVisible? "true" : "false");
    hasPointerDevice_ = hasPointerDevice;
    if (hasPointerDevice_) {
        bool pointerVisible = isPointerVisible;
        if (!isHotPlug) {
            pointerVisible = (pointerVisible && IsPointerVisible());
        }
        SetPointerVisible(getpid(), pointerVisible, 0);
    } else {
        DeletePointerVisible(getpid());
    }
    DrawManager();
    if (!hasPointerDevice_ && surfaceNode_ != nullptr) {
        MMI_HILOGD("Pointer window destroy start");
        surfaceNode_->DetachToDisplay(screenId_);
        surfaceNode_ = nullptr;
        Rosen::RSTransaction::FlushImplicitTransaction();
        MMI_HILOGD("Pointer window destroy success");
    }
}

void PointerDrawingManager::DrawManager()
{
    CALL_DEBUG_ENTER;
    if (hasDisplay_ && hasPointerDevice_ && surfaceNode_ == nullptr) {
        MMI_HILOGD("Draw pointer begin");
        PointerStyle pointerStyle;
        WIN_MGR->GetPointerStyle(pid_, windowId_, pointerStyle);
        MMI_HILOGD("get pid %{publid}d with pointerStyle %{public}d", pid_, pointerStyle.id);
        Direction direction = DIRECTION0;
        if (ROTATE_POLICY == WINDOW_ROTATE) {
            direction = displayInfo_.direction;
        }
        if (lastPhysicalX_ == -1 || lastPhysicalY_ == -1) {
            DrawPointer(displayInfo_.id, displayInfo_.width / CALCULATE_MIDDLE, displayInfo_.height / CALCULATE_MIDDLE,
                pointerStyle, direction);
            WIN_MGR->SendPointerEvent(PointerEvent::POINTER_ACTION_MOVE);
            MMI_HILOGD("Draw manager, mouseStyle:%{public}d, last physical is initial value", pointerStyle.id);
            return;
        }
        DrawPointer(displayInfo_.id, lastPhysicalX_, lastPhysicalY_, pointerStyle, direction);
        WIN_MGR->SendPointerEvent(PointerEvent::POINTER_ACTION_MOVE);
        MMI_HILOGD("Draw manager, mouseStyle:%{public}d", pointerStyle.id);
        return;
    }
}

bool PointerDrawingManager::Init()
{
    CALL_DEBUG_ENTER;
    INPUT_DEV_MGR->Attach(shared_from_this());
    pidInfos_.clear();
    return true;
}

std::shared_ptr<IPointerDrawingManager> IPointerDrawingManager::GetInstance()
{
    if (iPointDrawMgr_ == nullptr) {
        iPointDrawMgr_ = std::make_shared<PointerDrawingManager>();
    }
    return iPointDrawMgr_;
}

void PointerDrawingManager::UpdatePointerVisible()
{
    CALL_DEBUG_ENTER;
    CHKPV(surfaceNode_);
    if (IsPointerVisible() && mouseDisplayState_) {
        surfaceNode_->SetVisible(true);
        MMI_HILOGI("Pointer window show success, mouseDisplayState_:%{public}s",
            mouseDisplayState_ ? "true" : "false");
    } else {
        surfaceNode_->SetVisible(false);
        MMI_HILOGI("Pointer window hide success, mouseDisplayState_:%{public}s",
            mouseDisplayState_ ? "true" : "false");
    }
    Rosen::RSTransaction::FlushImplicitTransaction();
}

bool PointerDrawingManager::IsPointerVisible()
{
    CALL_DEBUG_ENTER;
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
    MMI_HILOGI("g_isRsRemoteDied:%{public}d", g_isRsRemoteDied ? 1 : 0);
    if (g_isRsRemoteDied && surfaceNode_ != nullptr) {
        g_isRsRemoteDied = false;
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
    for (auto it = pidInfos_.begin(); it != pidInfos_.end(); ++it) {
        if (it->pid == pid) {
            return it->visible;
        }
    }
    return true;
}

int32_t PointerDrawingManager::SetPointerVisible(int32_t pid, bool visible, int32_t priority)
{
    MMI_HILOGI("pid:%{public}d,visible:%{public}s,priority:%{public}d", pid, visible ? "true" : "false", priority);
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
    UpdatePointerVisible();
    return RET_OK;
}

void PointerDrawingManager::SetPointerLocation(int32_t x, int32_t y)
{
    CALL_DEBUG_ENTER;
    FixCursorPosition(x, y);
    lastPhysicalX_ = x;
    lastPhysicalY_ = y;
    MMI_HILOGD("Pointer window move, x:%{public}d, y:%{public}d", lastPhysicalX_, lastPhysicalY_);
    if (surfaceNode_ != nullptr) {
        surfaceNode_->SetBounds(x,
            y,
            surfaceNode_->GetStagingProperties().GetBounds().z_,
            surfaceNode_->GetStagingProperties().GetBounds().w_);
#ifdef OHOS_BUILD_ENABLE_HARDWARE_CURSOR
        CHKPV(hardwareCursorPointerManager_);
        if (hardwareCursorPointerManager_->IsSupported()) {
            if (hardwareCursorPointerManager_->SetPosition(lastPhysicalX_, lastPhysicalY_) != RET_OK) {
                MMI_HILOGE("Set hardware cursor position error.");
                return;
            }
        }
#endif // OHOS_BUILD_ENABLE_HARDWARE_CURSOR
        Rosen::RSTransaction::FlushImplicitTransaction();
        MMI_HILOGD("Pointer window move success");
    }
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
            newIconPath = iconPath[MOUSE_ICON(pointerStyle.id)].iconPath;
        }
        MMI_HILOGD("default path has changed from %{public}s to %{public}s",
            it->second.iconPath.c_str(), newIconPath.c_str());
        UpdateIconPath(MOUSE_ICON(MOUSE_ICON::DEFAULT), newIconPath);
    }
    lastMouseStyle_ = style;
    return RET_OK;
}

std::map<MOUSE_ICON, IconStyle> PointerDrawingManager::GetMouseIconPath()
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
        pointerStyle.id > MOUSE_ICON::RUNNING_RIGHT) {
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
    auto iconPath = GetMouseIconPath();
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
    if (!INPUT_DEV_MGR->HasPointerDevice()) {
        MMI_HILOGD("The pointer device is not exist");
        return RET_OK;
    }
    if (!WIN_MGR->IsNeedRefreshLayer(windowId)) {
        MMI_HILOGD("Not need refresh layer, window type:%{public}d, pointer style:%{public}d",
            windowId, pointerStyle.id);
        return RET_OK;
    }
    if (windowId != GLOBAL_WINDOW_ID && (pointerStyle.id == MOUSE_ICON::DEFAULT &&
        iconPath[MOUSE_ICON(pointerStyle.id)].iconPath != DefaultIconPath)) {
        PointerStyle style;
        WIN_MGR->GetPointerStyle(pid, GLOBAL_WINDOW_ID, style);
        pointerStyle = style;
    }
    if (windowId == windowId_ || windowId == GLOBAL_WINDOW_ID) {
        // Draw mouse style only when the current window is the top-level window
        DrawPointerStyle(pointerStyle);
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
        if (style == CURSOR_CIRCLE_STYLE) {
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
    if (hasDisplay_ && hasPointerDevice_) {
        if (surfaceNode_ != nullptr) {
            AttachToDisplay();
            Rosen::RSTransaction::FlushImplicitTransaction();
        }
        Direction direction = DIRECTION0;
        if (ROTATE_POLICY == WINDOW_ROTATE) {
            direction = displayInfo_.direction;
        }
        if (lastPhysicalX_ == -1 || lastPhysicalY_ == -1) {
            DrawPointer(displayInfo_.id, displayInfo_.width / CALCULATE_MIDDLE, displayInfo_.height / CALCULATE_MIDDLE,
                pointerStyle, direction);
            MMI_HILOGD("Draw pointer style, mouseStyle:%{public}d", pointerStyle.id);
            return;
        }

        DrawPointer(displayInfo_.id, lastPhysicalX_, lastPhysicalY_, pointerStyle, direction);
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
    if ((hardwareCursorPointerManager_->EnableStats(enable)) != RET_OK) {
        MMI_HILOGE("Enable stats failed");
        return RET_ERR;
    }
#endif // OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    MMI_HILOGI("EnableHardwareCursorStats, enable:%{public}d", enable);
    return RET_OK;
}

int32_t PointerDrawingManager::GetHardwareCursorStats(int32_t pid, uint32_t &frameCount, uint32_t &vsyncCount)
{
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    CHKPR(hardwareCursorPointerManager_, ERROR_NULL_POINTER);
    if ((hardwareCursorPointerManager_->GetCursorStats(frameCount, vsyncCount)) != RET_OK) {
        MMI_HILOGE("Query stats failed");
        return RET_ERR;
    }
#endif // OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    MMI_HILOGI("GetHardwareCursorStats, frameCount:%{public}d, vsyncCount:%{public}d", frameCount, vsyncCount);
    return RET_OK;
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
        {SCREENSHOT_CURSOR, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "Screenshot_Cursor.png"}},
        {TEXT_CURSOR, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "Text_Cursor.svg"}},
        {ZOOM_IN, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "Zoom_In.svg"}},
        {ZOOM_OUT, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "Zoom_Out.svg"}},
        {MIDDLE_BTN_EAST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "MID_Btn_East.svg"}},
        {MIDDLE_BTN_WEST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "MID_Btn_West.svg"}},
        {MIDDLE_BTN_SOUTH, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "MID_Btn_South.svg"}},
        {MIDDLE_BTN_NORTH, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "MID_Btn_North.svg"}},
        {MIDDLE_BTN_NORTH_SOUTH, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "MID_Btn_North_South.svg"}},
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
        {DEVELOPER_DEFINED_ICON, {ANGLE_NW, IMAGE_POINTER_DEFAULT_PATH + "Default.svg"}},
    };
    CheckMouseIconPath();
}

void PointerDrawingManager::RotateDegree(Direction direction)
{
    CHKPV(surfaceNode_);
    surfaceNode_->SetPivot(0, 0);
    float degree = (static_cast<int>(DIRECTION0) - static_cast<int>(direction)) * ROTATION_ANGLE90;
    surfaceNode_->SetRotation(degree);
}

void PointerDrawingManager::Dump(int32_t fd, const std::vector<std::string> &args)
{
    CALL_DEBUG_ENTER;
    std::ostringstream oss;
    oss << std::endl;

    auto displayTitles = std::make_tuple("ID", "X", "Y", "Width", "Height", "DPI", "Name", "Uniq",
                                         "Direction", "Display Direction", "Display Mode");
    DisplayInfo &di = displayInfo_;
    auto displayInfo = std::vector{std::make_tuple(di.id, di.x, di.y, di.width, di.height, di.dpi, di.name, di.uniq,
                                                   di.direction, di.displayDirection,
                                                   static_cast<int32_t>(di.displayMode))};
    DumpFullTable(oss, "Display Info", displayTitles, displayInfo);
    oss << std::endl;

    auto titles1 = std::make_tuple("hasDisplay", "hasPointerDevice", "lastPhysicalX", "lastPhysicalY",
                                   "pid", "windowId", "imageWidth", "imageHeight", "canvasWidth", "canvasHeight");
    auto data1 = std::vector{std::make_tuple(hasDisplay_, hasPointerDevice_, lastPhysicalX_, lastPhysicalY_,
                                             pid_, windowId_, imageWidth_, imageHeight_, canvasWidth_, canvasHeight_)};
    DumpFullTable(oss, "Cursor Info", titles1, data1);
    oss << std::endl;

    auto titles2 = std::make_tuple("mouseDisplayState", "mouseIconUpdate", "screenId", "userIconHotSpotX",
                                   "userIconHotSpotY", "tempPointerColor", "lastDirection", "currentDirection");
    auto data2 = std::vector{std::make_tuple(mouseDisplayState_, mouseIconUpdate_, screenId_, userIconHotSpotX_,
                                             userIconHotSpotY_, tempPointerColor_, lastDirection_, currentDirection_)};

    DumpFullTable(oss, "Cursor Info", titles2, data2);
    oss << std::endl;

    auto styleTitles = std::make_tuple("name", "Size", "Color", "ID");
    auto styleData = std::vector{
            std::make_tuple("lastMouseStyle", lastMouseStyle_.size, lastMouseStyle_.color, lastMouseStyle_.id),
            std::make_tuple("currentMouseStyle", currentMouseStyle_.size, currentMouseStyle_.color,
                            currentMouseStyle_.id)};
    DumpFullTable(oss, "Cursor Style Info", styleTitles, styleData);
    oss << std::endl;

    auto pidTitles = std::make_tuple("pid", "visible");
    std::vector<std::tuple<int32_t, bool>> pidInfos;
    for (const auto &pidInfo: pidInfos_) {
        pidInfos.emplace_back(pidInfo.pid, pidInfo.visible);
    }
    DumpFullTable(oss, "Visible Info", pidTitles, pidInfos);
    oss << std::endl;

    std::string dumpInfo = oss.str();
    dprintf(fd, dumpInfo.c_str());
}
} // namespace MMI
} // namespace OHOS
