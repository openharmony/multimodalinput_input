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
#include "input_windows_manager.h"
#include <cstdio>
#include <cstdlib>
#include "app_register.h"
#include "event_dump.h"
#include "mmi_server.h"
#include "util.h"
#include "util_ex.h"
#include "pointer_drawing_manager.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "InputWindowsManager"};
constexpr uint8_t TOP_LEFT_X  = 0;
constexpr uint8_t TOP_LEFT_Y  = 1;
constexpr uint8_t TOP_RIGHT_X = 2;
constexpr uint8_t TOP_RIGHT_Y = 3;
constexpr uint8_t CORNER = 4;
}
} // namespace MMI
} // namespace OHOS

using namespace OHOS::MMI;

static void SeatsInfoDebugPrint(const SeatInfo** seats)
{
    MMI_LOGD("Enter");
    for (int32_t i = 0; seats[i]; i++) {
        MMI_LOGD("-Seat%{public}02d,seatName:%{public}s,deviceFlags:%{public}d,focusWindowId:%{public}d", i + 1,
                 seats[i]->seatName, seats[i]->deviceFlags, seats[i]->focusWindowId);
        MMI_LOGD(".");
    }
}

OHOS::MMI::InputWindowsManager::InputWindowsManager()
{
}

OHOS::MMI::InputWindowsManager::~InputWindowsManager()
{
    Clear();
}
/*
 * FullName:  Init
 * Returns:   bool
 * Qualifier: init windows manager server
 */
bool OHOS::MMI::InputWindowsManager::Init(UDSServer& udsServer)
{
    // save server handle
    udsServer_ = &udsServer;
#ifdef OHOS_WESTEN_MODEL
    SetSeatListener([]() {
        WinMgr->UpdateSeatsInfo();
    });
    SetScreenListener([]() {
        WinMgr->UpdateScreensInfo();
    });
    UpdateSeatsInfo();
    UpdateScreensInfo();
#endif
    return true;
}

void OHOS::MMI::InputWindowsManager::UpdateSeatsInfo()
{
    std::lock_guard<std::mutex> lock(mu_);
    if (seatsInfo_ != nullptr) {
        FreeSeatsInfo(seatsInfo_);
    }
    seatsInfo_ = GetSeatsInfo();
    CHKPV(seatsInfo_);
    if (seatsInfo_[0] && seatsInfo_[0]->focusWindowId > 0) {
        SetFocusId(seatsInfo_[0]->focusWindowId);
    }
    SeatsInfoDebugPrint(const_cast<const SeatInfo**>(seatsInfo_));
}

// LCOV_EXCL_STOP
void OHOS::MMI::InputWindowsManager::UpdateScreensInfo()
{
    std::lock_guard<std::mutex> lock(mu_);
    if (screensInfo_ != nullptr) {
        FreeScreensInfo(screensInfo_);
    }
    screensInfo_ = GetScreensInfo();
    CHKPV(screensInfo_);
    SaveScreenInfoToMap(const_cast<const ScreenInfo**>(screensInfo_));
    PrintDebugInfo();
}

const std::vector<ScreenInfo>& OHOS::MMI::InputWindowsManager::GetScreenInfo() const
{
    return screenInfoVec_;
}

const std::map<int32_t, LayerInfo>& OHOS::MMI::InputWindowsManager::GetLayerInfo() const
{
    return layers_;
}

const std::map<int32_t, MMISurfaceInfo>& OHOS::MMI::InputWindowsManager::GetSurfaceInfo() const
{
    return surfaces_;
}

void OHOS::MMI::InputWindowsManager::InsertSurfaceInfo(const MMISurfaceInfo& tmpSurfaceInfo)
{
    std::lock_guard<std::mutex> lock(mu_);
    surfaces_.insert(std::pair<int32_t, MMISurfaceInfo>(tmpSurfaceInfo.surfaceId, tmpSurfaceInfo));
    MMI_LOGW("OnWindow InsertSurfaceInfo ChangeFocusSurfaceId old:%{public}d,new:%{public}d", focusInfoID_,
             tmpSurfaceInfo.surfaceId);
    focusInfoID_ = tmpSurfaceInfo.surfaceId;
}

void OHOS::MMI::InputWindowsManager::PrintAllNormalSurface()
{
    std::lock_guard<std::mutex> lock(mu_);
    PrintDebugInfo();
}

void OHOS::MMI::InputWindowsManager::SetFocusSurfaceId(int32_t id)
{
    std::lock_guard<std::mutex> lock(mu_);
    SetFocusId(id);
}

void OHOS::MMI::InputWindowsManager::SetTouchFocusSurfaceId(int32_t id)
{
    std::lock_guard<std::mutex> lock(mu_);
    touchFocusId_ = id;
}

int32_t OHOS::MMI::InputWindowsManager::GetFocusSurfaceId() const
{
    return focusInfoID_;
}

int32_t OHOS::MMI::InputWindowsManager::GetTouchFocusSurfaceId() const
{
    return touchFocusId_;
}

void OHOS::MMI::InputWindowsManager::SetFocusId(int32_t id)
{
    focusInfoID_ = id;
}

void OHOS::MMI::InputWindowsManager::PrintDebugInfo()
{
    MMI_LOGD("seats info");
    CHKPV(seatsInfo_);
    int32_t idx = 0;
    for (int32_t i = 0; seatsInfo_[i]; i++) {
        idx = i + 1;
        MMI_LOGD("-Seat%{public}02d,seatName:%{public}s,deviceFlags:%{public}d,focusWindowId:%{public}d", idx,
                 seatsInfo_[i]->seatName, seatsInfo_[i]->deviceFlags, seatsInfo_[i]->focusWindowId);
    }

    MMI_LOGD("screen info");
    for (const auto &j : screenInfoVec_) {
        MMI_LOGD("-screenId:%{public}d,connectorName:%{public}s,screenWidth:%{public}d,screenHeight:"
                 "%{public}d,screenNlayers:%{public}d", j.screenId, j.connectorName, j.width, j.height, j.nLayers);
    }

    MMI_LOGD("layer info");
    for (const auto &k : layers_) {
        MMI_LOGD("-layer_id:%{public}d,on_screen_id:%{public}d,nSurfaces:%{public}d src(xywh):[%{public}d,"
                 "%{public}d,%{public}d,%{public}d],dest(xywh):[%{public}d,%{public}d,%{public}d,%{public}d]"
                 "visibility:%{public}d,opacity:%{public}lf",
                 k.second.layerId, k.second.onScreenId, k.second.nSurfaces, k.second.srcX, k.second.srcY,
                 k.second.srcW, k.second.srcH, k.second.dstX, k.second.dstY, k.second.dstW, k.second.dstH,
                 k.second.visibility, k.second.opacity);
    }

    MMI_LOGD("window info");
    for (const auto &m : surfaces_) {
        auto appFd = AppRegs->FindByWinId(m.second.surfaceId);
        MMI_LOGD("-surface_id:%{public}d,on_screen_id:%{public}d,on_layer_id:%{public}d,src(xywh):[%{public}d,"
                 "%{public}d,%{public}d,%{public}d] desc(xywh):[%{public}d,%{public}d,%{public}d,%{public}d],"
                 "visibility:%{public}d,opacity:%{public}lf, appFd:%{public}d bundlerName:%{public}s appName:"
                 "%{public}s",
                 m.second.surfaceId, m.second.screenId, m.second.onLayerId, m.second.srcX, m.second.srcY,
                 m.second.srcW, m.second.srcH, m.second.dstX, m.second.dstY, m.second.dstW, m.second.dstH,
                 m.second.visibility, m.second.opacity, appFd.fd, appFd.bundlerName.c_str(), appFd.appName.c_str());
    }
}

size_t OHOS::MMI::InputWindowsManager::GetSurfaceIdList(std::vector<int32_t>& ids)
{
    constexpr int32_t TEST_THREE_WINDOWS = 3;
    std::lock_guard<std::mutex> lock(mu_);
    for (const auto &item : surfaces_) {
        if (item.second.surfaceId != focusInfoID_ && TEST_THREE_WINDOWS != item.second.surfaceId) {
            ids.push_back(item.second.surfaceId);
        }
    }
    ids.push_back(focusInfoID_);
    return ids.size();
}

std::string OHOS::MMI::InputWindowsManager::GetSurfaceIdListString()
{
    std::vector<int32_t> ids;
    std::string str;
    auto idsSize = GetSurfaceIdList(ids);
    if (idsSize > 0) {
        str = IdsListToString(ids, ",");
    }
    return str;
}

void OHOS::MMI::InputWindowsManager::Clear()
{
    MMI_LOGD("Enter");
    std::lock_guard<std::mutex> lock(mu_);
    if (seatsInfo_) {
        FreeSeatsInfo(seatsInfo_);
        seatsInfo_ = nullptr;
    }
    if (screensInfo_) {
        FreeScreensInfo(screensInfo_);
        screensInfo_ = nullptr;
    }
    focusInfoID_ = 0;
    screenInfoVec_.clear();
    layers_.clear();
    surfaces_.clear();
    surfacesList_.clear();
    MMI_LOGD("Leave");
}

void OHOS::MMI::InputWindowsManager::Dump(int32_t fd)
{
    std::lock_guard<std::mutex> lock(mu_);
    mprintf(fd, "screenInfos count=%zu", screenInfoVec_.size());
    for (const auto &item : screenInfoVec_) {
        mprintf(fd, "\tscreenId=%d connectorName=%s screenWidth= %d screenHeight=%d screenNlayers=%d",
                item.screenId, item.connectorName, item.width, item.height,
                item.nLayers);
    }
    mprintf(fd, "layerInfos count=%zu", layers_.size());
    for (const auto &item : layers_) {
        mprintf(fd, "\tlayerId=%d dstX=%d dstY=%d dstW=%d dstH=%d srcX=%d"
                "srcY=%d srcW=%d srcH=%d opacity=%f visibility=%d onScreenId=%d nsurfaces=%d",
                item.second.layerId, item.second.dstX, item.second.dstY,
                item.second.dstW, item.second.dstH, item.second.srcX,
                item.second.srcY, item.second.srcW, item.second.srcH,
                item.second.opacity, item.second.visibility,
                item.second.onScreenId, item.second.nSurfaces);
    }
    mprintf(fd, "surfaceInfos count=%zu", surfaces_.size());
    for (auto& item : surfaces_) {
        auto appFd = AppRegs->FindByWinId(item.second.surfaceId);
        mprintf(fd, "\tsurfaceId=%d dstX=%d dstY=%d dstW=%d dstH=%d srcX=%d"
                "srcY=%d srcW=%d srcH=%d opacity=%f visibility=%d onLayerId=%d appFd=%d bundlerName=%s appName=%s",
                item.second.surfaceId, item.second.dstX,
                item.second.dstY, item.second.dstW, item.second.dstH,
                item.second.srcX, item.second.srcY, item.second.srcW,
                item.second.srcH, item.second.opacity, item.second.visibility,
                item.second.onLayerId, appFd.fd, appFd.bundlerName.c_str(), appFd.appName.c_str());
    }
}

/*
 * FullName:  SaveScreenInfoToMap
 * Returns:   void
 * Qualifier: save screen info to MAP
 * Parameter: screen_info**
 */
void OHOS::MMI::InputWindowsManager::SaveScreenInfoToMap(const ScreenInfo** screenInfo)
{
    // check param
    CHK(screenInfo, ERROR_NULL_POINTER);
    CHK(*screenInfo, ERROR_NULL_POINTER);

    // clear windows info
    screenInfoVec_.clear();
    layers_.clear();
    surfaces_.clear();

    // save windows info
    std::vector<int32_t> surfaceList;
    for (int32_t i = 0; screenInfo[i]; i++) {
        // save screen
        screenInfoVec_.push_back(*(screenInfo[i]));
        int32_t nlayers = screenInfo[i]->nLayers;
        LayerInfo** pstrLayerInfo = screenInfo[i]->layers;
        for (int32_t j = 0; j < nlayers; j++) {
            // save
            layers_.insert(std::pair<int32_t, LayerInfo>(pstrLayerInfo[j]->layerId, *(pstrLayerInfo[j])));
            // get nsurfaces
            int32_t nsurfaces = pstrLayerInfo[j]->nSurfaces;
            SurfaceInfo** pstrSurface = pstrLayerInfo[j]->surfaces;
            for (int32_t k = 0; k < nsurfaces; k++) {
                MMISurfaceInfo mySurfaceTmp = {};
                int32_t ret = memcpy_s(&mySurfaceTmp, sizeof(mySurfaceTmp), pstrSurface[k], sizeof(SurfaceInfo));
                CHK(ret == EOK, MEMCPY_SEC_FUN_FAIL);
                mySurfaceTmp.screenId = screenInfo[i]->screenId;
                surfaces_.insert(std::pair<int32_t, MMISurfaceInfo>(mySurfaceTmp.surfaceId, mySurfaceTmp));
                AddId(surfaceList, mySurfaceTmp.surfaceId);
            }
        }
    }
    // Destroyed windows
    if (!surfacesList_.empty()) {
        std::vector<int32_t> delList;
        auto delSize = CalculateDifference(surfacesList_, surfaceList, delList);
        if (delSize > 0) {
            // Processing destroyed windows
            AppRegs->SurfacesDestroyed(delList);
            auto winIdsStr = IdsListToString(delList, ",");
            MMI_LOGD("InputWindowsManager Some windows were destroyed. winIds:%{public}s", winIdsStr.c_str());
        }
    }
    surfacesList_ = surfaceList;
}

bool OHOS::MMI::InputWindowsManager::FindSurfaceByCoordinate(double x, double y, const SurfaceInfo& pstrSurface)
{
    if (x >= pstrSurface.srcX && x <= (pstrSurface.srcX + pstrSurface.srcW) &&
        y >= pstrSurface.srcY && y <= (pstrSurface.srcY + pstrSurface.srcH)) {
        return true;
    }
    return false;
}

bool OHOS::MMI::InputWindowsManager::GetTouchSurfaceId(const double x, const double y, std::vector<int32_t>& ids)
{
    std::lock_guard<std::mutex> lock(mu_);
    if (!surfaces_.empty()) {
        int32_t newLayerId = -1;
        int32_t newSurfaceId = -1;
        for (auto it : surfaces_) {
            auto res = static_cast<MMISurfaceInfo*>(&it.second);
            CHKPF(res);
            if (FindSurfaceByCoordinate(x, y, *res)) {
                if (res->onLayerId > newLayerId) {
                    newLayerId = res->onLayerId;
                    newSurfaceId = res->surfaceId;
                }
            }
        }
        if ((newSurfaceId != -1) && (newSurfaceId != focusInfoID_)) {
            ids.push_back(focusInfoID_);
            ids.push_back(newSurfaceId);
        } else if (newSurfaceId != -1) {
            ids.push_back(focusInfoID_);
        }
        return true;
    }
    return false;
}

const ScreenInfo* OHOS::MMI::InputWindowsManager::GetScreenInfo(int32_t screenId)
{
    std::lock_guard<std::mutex> lock(mu_);
    for (auto& it : screenInfoVec_) {
        if (it.screenId == screenId) {
            return &it;
        }
    }
    return nullptr;
}

const LayerInfo* OHOS::MMI::InputWindowsManager::GetLayerInfo(int32_t layerId)
{
    std::lock_guard<std::mutex> lock(mu_);
    auto it = layers_.find(layerId);
    if (it == layers_.end()) {
        return nullptr;
    }
    return &it->second;
}

const MMISurfaceInfo* OHOS::MMI::InputWindowsManager::GetSurfaceInfo(int32_t sufaceId)
{
    std::lock_guard<std::mutex> lock(mu_);
    auto it = surfaces_.find(sufaceId);
    if (it == surfaces_.end()) {
        return nullptr;
    }
    return &it->second;
}

bool OHOS::MMI::InputWindowsManager::CheckFocusSurface(double x, double y, const MMISurfaceInfo& info) const
{
    if (x >= info.dstX && x <= (info.dstX + info.dstW) &&
        y >= info.dstY && y <= (info.dstY + info.dstH)) {
        return true;
    }
    return false;
}

const MMISurfaceInfo* OHOS::MMI::InputWindowsManager::GetTouchSurfaceInfo(double x, double y)
{
    std::lock_guard<std::mutex> lock(mu_);
    int32_t newLayerId = -1;
    const MMISurfaceInfo* surfacePtr = nullptr;
    for (auto& it : surfaces_) {
        // find window by coordinate
        if (CheckFocusSurface(x, y, it.second) && it.second.onLayerId >= newLayerId) {
            newLayerId = it.second.onLayerId;
            if (it.second.visibility == 1 && AppRegs->FindByWinId(it.second.surfaceId).fd > 0) {
                surfacePtr = &it.second;
            }
        }
    }
    return surfacePtr;
}

void OHOS::MMI::InputWindowsManager::TransfromToSurfaceCoordinate(const MMISurfaceInfo& info,
                                                                  double& x, double& y, bool debug)
{
    double oldX = x;
    double oldY = y;
    x = x - info.dstX;
    y = y - info.dstY;
    if (debug) {
        auto appFd = AppRegs->FindByWinId(info.surfaceId);
        MMI_LOGD("Transfrom touch coordinate. src:[%{public}lf,%{public}lf],focusSurface:%{public}d,"
                 "info:[%{public}d,%{public}d,%{public}d,%{public}d],dest:[%{public}lf,%{public}lf],"
                 "fd:%{public}d,bundler:%{public}s,appName:%{public}s",
                 oldX, oldY, info.surfaceId, info.dstX, info.dstY, info.dstW, info.dstH, x, y, appFd.fd,
                 appFd.bundlerName.c_str(), appFd.appName.c_str());
    }
}

/*********************************新框架接口添加****************************/
int32_t OHOS::MMI::InputWindowsManager::UpdateTarget(std::shared_ptr<InputEvent> inputEvent)
{
#ifdef OHOS_WESTEN_MODEL
    MMI_LOGD("enter");
    int32_t focId = GetFocusSurfaceId();
    CHKR(!(focId < 0), FOCUS_ID_OBTAIN_FAIL, FOCUS_ID_OBTAIN_FAIL);
    auto appInfo = AppRegs->FindByWinId(focId);
    if (appInfo.fd == RET_ERR) {
        return RET_ERR;
    }
    inputEvent->SetTargetWindowId(focId);
    if (!screenInfoVec_.empty()) {
        MMI_LOGD("screenInfoVec_->screenId:%{public}d", screenInfoVec_[0].screenId);
        inputEvent->SetTargetDisplayId(screenInfoVec_[0].screenId);
    } else {
        inputEvent->SetTargetDisplayId(0);
    }
    inputEvent->SetAgentWindowId(focId);
    MMI_LOGD("leave");
    return appInfo.fd;
#else
    MMI_LOGD("enter");
    int32_t pid = GetPidUpdateTarget(inputEvent);
    CHKR(pid > 0, PID_OBTAIN_FAIL, RET_ERR);
    int32_t fd = udsServer_->GetFdByPid(pid);
    CHKR(fd >= 0, FD_OBTAIN_FAIL, RET_ERR);
    MMI_LOGD("leave");
    return fd;
#endif
}

int32_t OHOS::MMI::InputWindowsManager::GetPidUpdateTarget(std::shared_ptr<InputEvent> inputEvent)
{
    MMI_LOGD("enter");
    if (logicalDisplays_.empty()) {
        MMI_LOGE("logicalDisplays_ is empty");
        return RET_ERR;
    }

    if (inputEvent->GetTargetDisplayId() == -1) {
        MMI_LOGD("target display is -1");
        inputEvent->SetTargetDisplayId(logicalDisplays_[0].id);
        inputEvent->SetTargetWindowId(logicalDisplays_[0].focusWindowId);
        auto it = windowInfos_.find(logicalDisplays_[0].focusWindowId);
        if (it == windowInfos_.end()) {
            MMI_LOGE("can't find winfow info, focuswindowId:%{public}d", logicalDisplays_[0].focusWindowId);
            return RET_ERR;
        }
        inputEvent->SetAgentWindowId(it->second.agentWindowId);
        MMI_LOGD("pid:%{public}d", it->second.pid);
        return it->second.pid;
    }

    for (const auto &item : logicalDisplays_) {
        if (item.id != inputEvent->GetTargetDisplayId()) {
            continue;
        }
        MMI_LOGD("target display:%{public}d", inputEvent->GetTargetDisplayId());
        inputEvent->SetTargetWindowId(item.focusWindowId);
        auto it = windowInfos_.find(item.focusWindowId);
        if (it == windowInfos_.end()) {
            MMI_LOGE("can't find winfow info, focuswindowId:%{public}d", item.focusWindowId);
            return RET_ERR;
        }
        inputEvent->SetAgentWindowId(it->second.agentWindowId);
        MMI_LOGD("pid:%{public}d", it->second.pid);
        return it->second.pid;
    }

    MMI_LOGE("leave,cant't find logical display,target display:%{public}d", inputEvent->GetTargetDisplayId());
    return RET_ERR;
}

void OHOS::MMI::InputWindowsManager::UpdateDisplayInfo(const std::vector<PhysicalDisplayInfo> &physicalDisplays,
    const std::vector<LogicalDisplayInfo> &logicalDisplays)
{
    MMI_LOGD("enter");
    physicalDisplays_.clear();
    logicalDisplays_.clear();
    windowInfos_.clear();

    physicalDisplays_ = physicalDisplays;
    logicalDisplays_ = logicalDisplays;
    int32_t numLogicalDisplay = logicalDisplays.size();
    for (int32_t i = 0; i < numLogicalDisplay; i++) {
        size_t numWindow = logicalDisplays[i].windowsInfo_.size();
        for (size_t j = 0; j < numWindow; j++) {
            WindowInfo myWindow = logicalDisplays[i].windowsInfo_[j];
            windowInfos_.insert(std::pair<int32_t, WindowInfo>(myWindow.id, myWindow));
        }
    }
    if (!logicalDisplays.empty()) {
        PointerDrawMgr->TellDisplayInfo(logicalDisplays[0].id, logicalDisplays[0].width, logicalDisplays_[0].height);
    }
    PrintDisplayDebugInfo();
    MMI_LOGD("leave");
}

void OHOS::MMI::InputWindowsManager::PrintDisplayDebugInfo()
{
    MMI_LOGD("physicalDisplays,num:%{public}zu", physicalDisplays_.size());
    for (const auto &item : physicalDisplays_) {
        MMI_LOGD("PhysicalDisplays,id:%{public}d,leftDisplay:%{public}d,upDisplay:%{public}d,"
            "topLeftX:%{public}d,topLeftY:%{public}d,width:%{public}d,height:%{public}d,name:%{public}s,"
            "seatId:%{public}s,seatName:%{public}s,logicWidth:%{public}d,logicHeight:%{public}d,"
            "direction:%{public}d",
            item.id, item.leftDisplayId, item.upDisplayId,
            item.topLeftX, item.topLeftY, item.width,
            item.height, item.name.c_str(), item.seatId.c_str(),
            item.seatName.c_str(), item.logicWidth, item.logicHeight, item.direction);
    }

    MMI_LOGD("logicalDisplays,num:%{public}zu", logicalDisplays_.size());
    for (const auto &item : logicalDisplays_) {
        MMI_LOGD("logicalDisplays, id:%{public}d,topLeftX:%{public}d,topLeftY:%{public}d,"
            "width:%{public}d,height:%{public}d,name:%{public}s,"
            "seatId:%{public}s,seatName:%{public}s,focusWindowId:%{public}d,window num:%{public}zu",
            item.id, item.topLeftX, item.topLeftY,
            item.width, item.height, item.name.c_str(),
            item.seatId.c_str(), item.seatName.c_str(), item.focusWindowId,
            item.windowsInfo_.size());
    }

    MMI_LOGD("window info,num:%{public}zu", windowInfos_.size());
    for (const auto &item : windowInfos_) {
        MMI_LOGD("windowId:%{public}d,id:%{public}d,pid:%{public}d,uid:%{public}d,hotZoneTopLeftX:%{public}d,"
            "hotZoneTopLeftY:%{public}d,hotZoneWidth:%{public}d,hotZoneHeight:%{public}d,display:%{public}d,"
            "agentWindowId:%{public}d,winTopLeftX:%{public}d,winTopLeftY:%{public}d",
            item.first, item.second.id, item.second.pid, item.second.uid, item.second.hotZoneTopLeftX,
            item.second.hotZoneTopLeftY, item.second.hotZoneWidth, item.second.hotZoneHeight,
            item.second.displayId, item.second.agentWindowId, item.second.winTopLeftX, item.second.winTopLeftY);
    }
}

bool OHOS::MMI::InputWindowsManager::TouchPadPointToDisplayPoint_2(libinput_event_touch* touch,
    int32_t& logicalX, int32_t& logicalY, int32_t& logicalDisplayId)
{
    CHKPF(touch);
    if (screensInfo_ != nullptr) {
        if ((*screensInfo_) != nullptr)
        logicalDisplayId = (*screensInfo_)->screenId;
        logicalX = static_cast<int32_t>(libinput_event_touch_get_x_transformed(touch, (*screensInfo_)->width));
        logicalY = static_cast<int32_t>(libinput_event_touch_get_y_transformed(touch, (*screensInfo_)->height));
        return true;
    }
    return false;
}

OHOS::MMI::PhysicalDisplayInfo* OHOS::MMI::InputWindowsManager::GetPhysicalDisplay(int32_t id)
{
    for (auto &it : physicalDisplays_) {
        if (it.id == id) {
            return &it;
        }
    }
    return nullptr;
}

OHOS::MMI::PhysicalDisplayInfo* OHOS::MMI::InputWindowsManager::FindPhysicalDisplayInfo(const std::string seatId,
    const std::string seatName)
{
    for (auto &it : physicalDisplays_) {
        if (it.seatId == seatId && it.seatName == seatName) {
            return &it;
        }
    }
    return nullptr;
}

void OHOS::MMI::InputWindowsManager::TurnTouchScreen(PhysicalDisplayInfo* info, Direction direction,
    int32_t& logicalX, int32_t& logicalY)
{
    if (direction == Direction0) {
        MMI_LOGD("direction is Direction0");
        return;
    }
    if (direction == Direction90) {
        MMI_LOGD("direction is Direction90");
        int32_t temp = logicalX;
        logicalX = info->logicHeight - logicalY;
        logicalY = temp;
        MMI_LOGD("logicalX is %{public}d, logicalY is %{public}d", logicalX, logicalY);
        return;
    }
    if (direction == Direction180) {
        MMI_LOGD("direction is Direction180");
        logicalX = info->logicWidth - logicalX;
        logicalY = info->logicHeight - logicalY;
        return;
    }
    if (direction == Direction270) {
        MMI_LOGD("direction is Direction270");
        int32_t temp = logicalY;
        logicalY = info->logicWidth - logicalX;
        logicalX = temp;
    }
}

bool OHOS::MMI::InputWindowsManager::TransformOfDisplayPoint(libinput_event_touch* touch, Direction& direction,
    int32_t &globalLogicalX, int32_t &globalLogicalY)
{
    CHKPF(touch);
    auto info = FindPhysicalDisplayInfo("seat0", "default0");
    CHKPF(info);

    if ((info->width <= 0) || (info->height <= 0) || (info->logicWidth <= 0) || (info->logicHeight <= 0)) {
        MMI_LOGE("Get DisplayInfo is error");
        return false;
    }

    auto physicalX = libinput_event_touch_get_x_transformed(touch, info->width) + info->topLeftX;
    auto physicalY = libinput_event_touch_get_y_transformed(touch, info->height) + info->topLeftY;
    if ((physicalX >= INT32_MAX) || (physicalY >= INT32_MAX)) {
        MMI_LOGE("Physical display coordinates are out of range");
        return false;
    }
    int32_t localPhysicalX = static_cast<int32_t>(physicalX);
    int32_t localPhysicalY = static_cast<int32_t>(physicalY);

    auto logicX = (1L * info->logicWidth * localPhysicalX / info->width);
    auto logicY = (1L * info->logicHeight * localPhysicalY / info->height);
    if ((logicX >= INT32_MAX) || (logicY >= INT32_MAX)) {
        MMI_LOGE("Physical display logical coordinates out of range");
        return false;
    }
    int32_t localLogcialX = (int32_t)(logicX);
    int32_t localLogcialY = (int32_t)(logicY);

    direction = info->direction;
    TurnTouchScreen(info, direction, localLogcialX, localLogcialY);

    globalLogicalX = localLogcialX;
    globalLogicalY = localLogcialY;

    for (auto left = GetPhysicalDisplay(info->leftDisplayId); left != nullptr;
        left = GetPhysicalDisplay(left->leftDisplayId)) {
        if (direction == Direction0 || direction == Direction180) {
            globalLogicalX += left->logicWidth;
        }
        if (direction == Direction90 || direction == Direction270) {
            globalLogicalX += left->logicHeight;
        }
    }

    for (auto upper = GetPhysicalDisplay(info->upDisplayId); upper != nullptr;
        upper = GetPhysicalDisplay(upper->upDisplayId)) {
        if (direction == Direction0 || direction == Direction180) {
            globalLogicalY += upper->logicHeight;
        }
        if (direction == Direction90 || direction == Direction270) {
            globalLogicalY += upper->logicWidth;
        }
    }

    return true;
}

bool OHOS::MMI::InputWindowsManager::TouchMotionPointToDisplayPoint(libinput_event_touch* touch, Direction& direction,
    int32_t targetDisplayId, int32_t& displayX, int32_t& displayY)
{
    CHKPF(touch);
    int32_t globalLogicalX;
    int32_t globalLogicalY;
    auto isTransform = TransformOfDisplayPoint(touch, direction, globalLogicalX, globalLogicalY);
    if (!isTransform) {
        return isTransform;
    }

    for (const auto &display : logicalDisplays_) {
        if (targetDisplayId == display.id ) {
            MMI_LOGD("targetDisplay is %{public}d, displayX is %{public}d, displayY is %{public}d ",
                targetDisplayId, displayX, displayY);
            displayX = globalLogicalX - display.topLeftX;
            displayY = globalLogicalY - display.topLeftY;
        }
        return true;
    }

    return false;
}

bool OHOS::MMI::InputWindowsManager::TouchDownPointToDisplayPoint(libinput_event_touch* touch, Direction& direction,
    int32_t& logicalX, int32_t& logicalY, int32_t& logicalDisplayId)
{
    CHKPF(touch);
    int32_t globalLogicalX;
    int32_t globalLogicalY;
    auto isTransform = TransformOfDisplayPoint(touch, direction, globalLogicalX, globalLogicalY);
    if (!isTransform) {
        return isTransform;
    }

    for (const auto &display : logicalDisplays_) {
        if (globalLogicalX < display.topLeftX || globalLogicalX > display.topLeftX + display.width) {
            continue;
        }

        if (globalLogicalY < display.topLeftY || globalLogicalY > display.topLeftY + display.height) {
            continue;
        }

        logicalDisplayId = display.id;
        logicalX = globalLogicalX - display.topLeftX;
        logicalY = globalLogicalY - display.topLeftY;
        MMI_LOGD("targetDisplay is %{public}d, displayX is %{public}d, displayY is %{public}d ",
            logicalDisplayId, logicalX, logicalY);
        return true;
    }

    return false;
}

const std::vector<LogicalDisplayInfo>& OHOS::MMI::InputWindowsManager::GetLogicalDisplayInfo() const
{
    return logicalDisplays_;
}

const std::map<int32_t, WindowInfo>& OHOS::MMI::InputWindowsManager::GetWindowInfo() const
{
    return windowInfos_;
}

bool OHOS::MMI::InputWindowsManager::IsTouchWindow(int32_t x, int32_t y, const WindowInfo &info) const
{
    return (x >= info.hotZoneTopLeftX) && (x <= (info.hotZoneTopLeftX + info.hotZoneWidth)) &&
        (y >= info.hotZoneTopLeftY) && (y <= (info.hotZoneTopLeftY + info.hotZoneHeight));
}

void OHOS::MMI::InputWindowsManager::AdjustGlobalCoordinate(int32_t& globalX, int32_t& globalY,
    int32_t width, int32_t height)
{
    if (globalX <= 0) {
        globalX = 0;
    }
    if (globalX >= width) {
        globalX = width;
    }
    if (globalY <= 0) {
        globalY = 0;
    }
    if (globalY >= height) {
        globalY = height;
    }
}

bool OHOS::MMI::InputWindowsManager::IsCheckDisplayIdIfExist(int32_t& displayId)
{
    if (logicalDisplays_.empty()) {
        MMI_LOGE("logicalDisplays_is empty");
        return false;
    }
    if (displayId < 0) {
        displayId = logicalDisplays_[0].id;
        return true;
    }
    for (const auto &item : logicalDisplays_) {
        if (item.id == displayId) {
            return true;
        }
    }
    return false;
}

LogicalDisplayInfo* OHOS::MMI::InputWindowsManager::GetLogicalDisplayById(int32_t displayId)
{
    for (auto &it : logicalDisplays_) {
        if (it.id == displayId) {
            return &it;
        }
    }
    return nullptr;
}

void OHOS::MMI::InputWindowsManager::AdjustCoordinate(double &coordinateX, double &coordinateY)
{
    if (coordinateX < 0) {
        coordinateX = 0;
    }

    if (coordinateY < 0) {
        coordinateY = 0;
    }

    if (logicalDisplays_.empty()) {
        return;
    }

    if (coordinateX > logicalDisplays_[0].width) {
        coordinateX = logicalDisplays_[0].width;
    }
    if (coordinateY > logicalDisplays_[0].height) {
        coordinateY = logicalDisplays_[0].height;
    }
}

void OHOS::MMI::InputWindowsManager::FixCursorPosition(int32_t &globalX, int32_t &globalY,
                                                       int32_t cursorW, int32_t cursorH)
{
    if (globalX < 0) {
        globalX = 0;
    }

    if (globalY < 0) {
        globalY = 0;
    }

    if (logicalDisplays_.empty()) {
        return;
    }

    int32_t size = 16;
    int32_t fcursorW = cursorW / size;
    if ((globalX + fcursorW) > logicalDisplays_[0].width) {
        globalX = logicalDisplays_[0].width - fcursorW;
    }
    int32_t fcursorH = cursorH / size;
    if ((globalY + fcursorH) > logicalDisplays_[0].height) {
        globalY = logicalDisplays_[0].height - fcursorH;
    }
}

int32_t OHOS::MMI::InputWindowsManager::UpdateMouseTargetOld(std::shared_ptr<PointerEvent> pointerEvent)
{
    return RET_ERR;
}

int32_t OHOS::MMI::InputWindowsManager::UpdateMouseTarget(std::shared_ptr<PointerEvent> pointerEvent)
{
    MMI_LOGD("Enter");
    auto displayId = pointerEvent->GetTargetDisplayId();
    if (!IsCheckDisplayIdIfExist(displayId)) {
        MMI_LOGE("This display:%{public}d is not exist", displayId);
        return RET_ERR;
    }
    pointerEvent->SetTargetDisplayId(displayId);

    int32_t pointerId = pointerEvent->GetPointerId();
    PointerEvent::PointerItem pointerItem;
    if (!pointerEvent->GetPointerItem(pointerId, pointerItem)) {
        MMI_LOGE("Can't find pointer item, pointer:%{public}d", pointerId);
        return RET_ERR;
    }
    LogicalDisplayInfo *logicalDisplayInfo = GetLogicalDisplayById(displayId);
    CHKPR(logicalDisplayInfo, ERROR_NULL_POINTER);
    int32_t globalX = pointerItem.GetGlobalX();
    int32_t globalY = pointerItem.GetGlobalY();
    FixCursorPosition(globalX, globalY, IMAGE_SIZE, IMAGE_SIZE);
    PointerDrawMgr->DrawPointer(displayId, globalX, globalY);
    WindowInfo *focusWindow = nullptr;
    int32_t action = pointerEvent->GetPointerAction();
    if ((firstBtnDownWindow_.pid == 0)
        || (action == PointerEvent::POINTER_ACTION_BUTTON_DOWN && pointerEvent->GetPressedButtons().size() == 1)
        || (action == PointerEvent::POINTER_ACTION_MOVE && pointerEvent->GetPressedButtons().empty())) {
        for (auto it : logicalDisplayInfo->windowsInfo_) {
            if (IsTouchWindow(globalX, globalY, it)) {
                focusWindow = &it;
                firstBtnDownWindow_ = *focusWindow;
                break;
            }
        }
    } else {
        focusWindow = &firstBtnDownWindow_ ;
    }
    if (focusWindow == nullptr) {
        MMI_LOGE("Find foucusWindow failed");
        return RET_ERR;
    }
    pointerEvent->SetTargetWindowId(focusWindow->id);
    pointerEvent->SetAgentWindowId(focusWindow->agentWindowId);
    int32_t localX = globalX - focusWindow->winTopLeftX;
    int32_t localY = globalY - focusWindow->winTopLeftY;
    pointerItem.SetLocalX(localX);
    pointerItem.SetLocalY(localY);
    pointerEvent->UpdatePointerItem(pointerId, pointerItem);
    auto fd = udsServer_->GetFdByPid(focusWindow->pid);
    auto size = pointerEvent->GetPressedButtons();

    MMI_LOGD("fd:%{public}d,pid:%{public}d,id:%{public}d,agentWindowId:%{public}d,"
             "globalX:%{public}d,globalY:%{public}d,pressedButtons size:%{public}zu",
             fd, focusWindow->pid, focusWindow->id, focusWindow->agentWindowId,
             globalX, globalY, size.size());
    return fd;
}

int32_t OHOS::MMI::InputWindowsManager::UpdateTouchScreenTargetOld(std::shared_ptr<PointerEvent> pointerEvent)
{
    return RET_ERR;
}

int32_t OHOS::MMI::InputWindowsManager::UpdateTouchScreenTarget(std::shared_ptr<PointerEvent> pointerEvent)
{
    auto displayId = pointerEvent->GetTargetDisplayId();
    if (!IsCheckDisplayIdIfExist(displayId)) {
        MMI_LOGE("This display is not exist");
        return RET_ERR;
    }
    pointerEvent->SetTargetDisplayId(displayId);

    int32_t pointerId = pointerEvent->GetPointerId();
    PointerEvent::PointerItem pointerItem;
    if (!pointerEvent->GetPointerItem(pointerId, pointerItem)) {
        MMI_LOGE("Can't find pointer item, pointer:%{public}d", pointerId);
        return RET_ERR;
    }
    MMI_LOGD("UpdateTouchScreenTarget, display:%{public}d", displayId);
    LogicalDisplayInfo *logicalDisplayInfo = GetLogicalDisplayById(displayId);
    CHKPR(logicalDisplayInfo, ERROR_NULL_POINTER);
    int32_t globalX = pointerItem.GetGlobalX();
    int32_t globalY = pointerItem.GetGlobalY();
    MMI_LOGD("UpdateTouchScreenTarget, globalX:%{public}d,globalY:%{public}d", globalX, globalY);
    AdjustGlobalCoordinate(globalX, globalY, logicalDisplayInfo->width, logicalDisplayInfo->height);
    auto targetWindowId = pointerEvent->GetTargetWindowId();
    MMI_LOGD("UpdateTouchScreenTarget, targetWindow:%{public}d", targetWindowId);
    WindowInfo *touchWindow = nullptr;
    for (auto item : logicalDisplayInfo->windowsInfo_) {
        if (targetWindowId < 0) {
            if (IsTouchWindow(globalX, globalY, item)) {
                touchWindow = &item;
                break;
            }
        } else if (targetWindowId >= 0) {
            if (targetWindowId == item.id) {
                touchWindow = &item;
                break;
            }
        }
    }
    if (touchWindow == nullptr) {
        MMI_LOGE("touchWindow is nullptr");
        return RET_ERR;
    }

    pointerEvent->SetTargetWindowId(touchWindow->id);
    pointerEvent->SetAgentWindowId(touchWindow->agentWindowId);
    int32_t localX = globalX - touchWindow->winTopLeftX;
    int32_t localY = globalY - touchWindow->winTopLeftY;
    pointerItem.SetLocalX(localX);
    pointerItem.SetLocalY(localY);
    pointerEvent->RemovePointerItem(pointerId);
    pointerEvent->AddPointerItem(pointerItem);
    auto fd = udsServer_->GetFdByPid(touchWindow->pid);
    MMI_LOGD("pid:%{public}d,fd:%{public}d,globalX01:%{public}d,"
             "globalY01:%{public}d,localX:%{public}d,localY:%{public}d,"
             "TargetWindowId:%{public}d,AgentWindowId:%{public}d",
             touchWindow->pid, fd, globalX, globalY, localX, localY,
             pointerEvent->GetTargetWindowId(), pointerEvent->GetAgentWindowId());
    return fd;
}

int32_t OHOS::MMI::InputWindowsManager::UpdateTouchPadTargetOld(std::shared_ptr<PointerEvent> pointerEvent)
{
    MMI_LOGD("Enter");
    return RET_ERR;
}

int32_t OHOS::MMI::InputWindowsManager::UpdateTouchPadTarget(std::shared_ptr<PointerEvent> pointerEvent)
{
    MMI_LOGD("Enter");
    return RET_ERR;
}

int32_t OHOS::MMI::InputWindowsManager::UpdateTargetPointer(std::shared_ptr<PointerEvent> pointerEvent)
{
    MMI_LOGD("enter");
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    auto source = pointerEvent->GetSourceType();
    switch (source) {
        case PointerEvent::SOURCE_TYPE_TOUCHSCREEN: {
            return UpdateTouchScreenTarget(pointerEvent);
        }
        case PointerEvent::SOURCE_TYPE_MOUSE: {
            return UpdateMouseTarget(pointerEvent);
        }
        case PointerEvent::SOURCE_TYPE_TOUCHPAD: {
            return UpdateTouchPadTarget(pointerEvent);
        }
        default: {
            MMI_LOGW("Source type is unknown, source:%{public}d", source);
            break;
        }
    }
    MMI_LOGE("Source is not of the correct type, source:%{public}d", source);
    MMI_LOGD("leave");
    return RET_ERR;
}

void OHOS::MMI::InputWindowsManager::UpdateAndAdjustMouseLoction(double& x, double& y)
{
    int32_t integerX = static_cast<int32_t>(x);
    int32_t integerY = static_cast<int32_t>(y);
    const std::vector<struct LogicalDisplayInfo> logicalDisplayInfo = GetLogicalDisplayInfo();
    if (logicalDisplayInfo.empty()) {
        MMI_LOGE("logicalDisplayInfo is empty");
        return;
    }
    for (const auto &item : logicalDisplayInfo) {
        bool isOutside[CORNER] = { false, false, false, false };   
        if (item.id >= 0) {
            if (integerX < item.topLeftX) {
                mouseLoction_.globleX = item.topLeftX;
                x = item.topLeftX;
                isOutside[TOP_LEFT_X] = true;
            } else {
                isOutside[TOP_LEFT_X] = false;
            }
            if (integerX > (item.topLeftX + item.width)) {
                mouseLoction_.globleX = item.topLeftX + item.width;
                x = item.topLeftX + item.width;
                isOutside[TOP_RIGHT_X] = true;
            } else {
                isOutside[TOP_RIGHT_X] = false;
            }
            if (integerY < item.topLeftY) {
                mouseLoction_.globleY = item.topLeftY;
                y = item.topLeftY;
                isOutside[TOP_LEFT_Y] = true;
            } else {
                isOutside[TOP_LEFT_Y] = false;
            }
            if (integerY > (item.topLeftY + item.height)) {
                mouseLoction_.globleY = item.topLeftY + item.height;
                y = item.topLeftY + item.height;
                isOutside[TOP_RIGHT_Y] = true;
            } else {
                isOutside[TOP_RIGHT_Y] = false;
            }
            if ((isOutside[TOP_LEFT_X] != true) && (isOutside[TOP_LEFT_Y] != true) &&
                (isOutside[TOP_RIGHT_X] != true) && (isOutside[TOP_RIGHT_Y] != true)) {
                mouseLoction_.globleX = x;
                mouseLoction_.globleY = y;
                break;
            }
        }
    }
    MMI_LOGI("Mouse Data: globleX:%{public}d,globleY:%{public}d", mouseLoction_.globleX, mouseLoction_.globleY);
}

MouseLocation OHOS::MMI::InputWindowsManager::GetMouseInfo()
{
    return mouseLoction_;
}