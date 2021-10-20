/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

namespace OHOS::MMI {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "InputWindowsManager"};
}
}

using namespace OHOS::MMI;

static void SeatsInfoDebugPrint(const struct SeatInfo** seats)
{
    MMI_LOGT("Seats:");
    for (int i = 0; seats[i]; i++) {
        MMI_LOGT(" -Seat%{public}02d seatName:%{public}s, deviceFlags:%{public}d, focusWindowId:%{public}d", i + 1,
                 seats[i]->seatName, seats[i]->deviceFlags, seats[i]->focusWindowId);
        MMI_LOGT(".");
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
    SetSeatListener([]() {
        WinMgr->UpdateSeatsInfo();
    });
    SetScreenListener([]() {
        WinMgr->UpdateScreensInfo();
    });
    UpdateSeatsInfo();
    UpdateScreensInfo();
    return true;
}

void OHOS::MMI::InputWindowsManager::UpdateSeatsInfo()
{
    std::lock_guard<std::mutex> lock(mu_);
    if (seatsInfo_ != nullptr) {
        FreeSeatsInfo(seatsInfo_);
    }
    seatsInfo_ = GetSeatsInfo();
    if (seatsInfo_ == nullptr) {
        MMI_LOGE("InputWindowsManager::UpdateSeatsInfo seatsInfo = nullptr");
        return;
    }
    if (seatsInfo_[0] && seatsInfo_[0]->focusWindowId > 0) {
        SetFocusId(seatsInfo_[0]->focusWindowId);
    }
    SeatsInfoDebugPrint(const_cast<const SeatInfo**>(seatsInfo_));
}

// LCOV_EXCL_STOP
void OHOS::MMI::InputWindowsManager::UpdateScreensInfo()
{
    std::lock_guard<std::mutex> lock(mu_);
    // free the last screen info
    if (screensInfo_ != nullptr) {
        FreeScreensInfo(screensInfo_);
    }
    screensInfo_ = GetScreensInfo();
    if (screensInfo_ == nullptr) {
        MMI_LOGE("InputWindowsManager::UpdateScreensInfo screensInfo_ = nullptr");
        return;
    }
    // save windows info
    SaveScreenInfoToMap(const_cast<const ScreenInfo**>(screensInfo_));
    PrintDebugInfo();
}

const std::vector<ScreenInfo>& OHOS::MMI::InputWindowsManager::GetScreenInfo() const
{
    return screenInfoVec_;
}

const CLMAP<int32_t, LayerInfo>& OHOS::MMI::InputWindowsManager::GetLayerInfo() const
{
    return layers_;
}

const CLMAP<int32_t, TestSurfaceInfo>& OHOS::MMI::InputWindowsManager::GetSurfaceInfo() const
{
    return mysurfaces_;
}

void OHOS::MMI::InputWindowsManager::InsertSurfaceInfo(const TestSurfaceInfo& tmpSurfaceInfo)
{
    std::lock_guard<std::mutex> lock(mu_);
    mysurfaces_.insert(std::pair<int32_t, TestSurfaceInfo>(tmpSurfaceInfo.surfaceId, tmpSurfaceInfo));
    MMI_LOGW("OnWindow InsertSurfaceInfo ChangeFocusSurfaceId old:%{public}d new:%{public}d", focusInfoID_,
             tmpSurfaceInfo.surfaceId);
    focusInfoID_ = tmpSurfaceInfo.surfaceId;
}

bool OHOS::MMI::InputWindowsManager::EraseSurfaceInfo(int32_t surfaceID)
{
    std::lock_guard<std::mutex> lock(mu_);
    auto it = mysurfaces_.find(surfaceID);
    if (it != mysurfaces_.end()) {
        mysurfaces_.erase(it);
        return true;
    }
    return false;
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
    MMI_LOGD("SetFocusId old:%{public}d new:%{public}d", focusInfoID_, id);
    focusInfoID_ = id;
}

void OHOS::MMI::InputWindowsManager::PrintDebugInfo()
{
    MMI_LOGT("***********seats info***********");
    if (seatsInfo_ == nullptr) {
        MMI_LOGT("seatsInfo_ is nullptr");
        return;
    }
    int32_t idx = 0;
    for (int i = 0; seatsInfo_[i]; i++) {
        idx = i + 1;
        MMI_LOGT(" -Seat%{public}02d: seatName: %{public}s, deviceFlags: %{public}d, focusWindowId: %{public}d", idx,
                 seatsInfo_[i]->seatName, seatsInfo_[i]->deviceFlags, seatsInfo_[i]->focusWindowId);
    }

    MMI_LOGT("***********screen info***********");
    for (auto& j : screenInfoVec_) {
        MMI_LOGT(" -screenId: %{public}d, connectorName: %{public}s, screenWidth: %{public}d, screenHeight: "
                 "%{public}d, screenNlayers: %{public}d", j.screenId, j.connectorName, j.width, j.height, j.nLayers);
    }

    MMI_LOGT("***********layer info***********");
    for (auto& k : layers_) {
        MMI_LOGT(" -layer_id: %{public}d, on_screen_id: %{public}d, nSurfaces: %{public}d src(xywh): [%{public}d, "
                 "%{public}d, %{public}d, %{public}d], dest(xywh): [%{public}d, %{public}d, %{public}d, %{public}d] "
                 "visibility: %{public}d, opacity: %{public}lf",
                 k.second.layerId, k.second.onScreenId, k.second.nSurfaces, k.second.srcX, k.second.srcY,
                 k.second.srcW, k.second.srcH, k.second.dstX, k.second.dstY, k.second.dstW, k.second.dstH,
                 k.second.visibility, k.second.opacity);
    }

    MMI_LOGT("***********window info***********");
    for (auto& m : mysurfaces_) {
        auto appFd = AppRegs->FindByWinId(m.second.surfaceId);
        MMI_LOGT(" -surface_id: %{public}d, on_screen_id: %{public}d, on_layer_id: %{public}d, src(xywh): [%{public}d,"
                 " %{public}d, %{public}d, %{public}d] desc(xywh): [%{public}d, %{public}d, %{public}d, %{public}d], "
                 "visibility: %{public}d, opacity: %{public}lf, appFd: %{public}d bundlerName: %{public}s appName: "
                 "%{public}s",
                 m.second.surfaceId, m.second.screenId, m.second.onLayerId, m.second.srcX, m.second.srcY,
                 m.second.srcW, m.second.srcH, m.second.dstX, m.second.dstY, m.second.dstW, m.second.dstH,
                 m.second.visibility, m.second.opacity, appFd.fd, appFd.bundlerName.c_str(), appFd.appName.c_str());
    }
}

size_t OHOS::MMI::InputWindowsManager::GetSurfaceIdList(IdsList& ids)
{
    const int32_t TEST_THREE_WINDOWS = 3;
    std::lock_guard<std::mutex> lock(mu_);
    for (auto i : mysurfaces_) {
        if (i.second.surfaceId != focusInfoID_ && TEST_THREE_WINDOWS != i.second.surfaceId) {
            ids.push_back(i.second.surfaceId);
        }
    }
    ids.push_back(focusInfoID_);
    return ids.size();
}

std::string OHOS::MMI::InputWindowsManager::GetSurfaceIdListString()
{
    IdsList ids;
    std::string str;
    auto idsSize = GetSurfaceIdList(ids);
    if (idsSize > 0) {
        str = IdsListToString(ids, ",");
    }
    return str;
}

void OHOS::MMI::InputWindowsManager::Clear()
{
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
    mysurfaces_.clear();
}

void OHOS::MMI::InputWindowsManager::Dump(int32_t fd)
{
    std::lock_guard<std::mutex> lock(mu_);
    mprintf(fd, "screenInfos count=%zu", screenInfoVec_.size());
    for (auto& screen_info : screenInfoVec_) {
        mprintf(fd, "\tscreenId=%d connectorName=%s screenWidth= %d screenHeight=%d screenNlayers=%d",
                screen_info.screenId, screen_info.connectorName, screen_info.width, screen_info.height,
                screen_info.nLayers);
    }
    mprintf(fd, "layerInfos count=%zu", layers_.size());
    for (auto& layer_info : layers_) {
        mprintf(fd, "\tlayerId=%d dstX=%d dstY=%d dstW=%d dstH=%d srcX=%d"
                "srcY=%d srcW=%d srcH=%d opacity=%f visibility=%d onScreenId=%d nsurfaces=%d",
                layer_info.second.layerId, layer_info.second.dstX, layer_info.second.dstY,
                layer_info.second.dstW, layer_info.second.dstH, layer_info.second.srcX,
                layer_info.second.srcY, layer_info.second.srcW, layer_info.second.srcH,
                layer_info.second.opacity, layer_info.second.visibility,
                layer_info.second.onScreenId, layer_info.second.nSurfaces);
    }
    mprintf(fd, "surfaceInfos count=%zu", mysurfaces_.size());
    for (auto& mysurface_info : mysurfaces_) {
        auto appFd = AppRegs->FindByWinId(mysurface_info.second.surfaceId);
        mprintf(fd, "\tsurfaceId=%d dstX=%d dstY=%d dstW=%d dstH=%d srcX=%d"
                "srcY=%d srcW=%d srcH=%d opacity=%f visibility=%d onLayerId=%d appFd=%d bundlerName=%s appName=%s",
                mysurface_info.second.surfaceId, mysurface_info.second.dstX,
                mysurface_info.second.dstY, mysurface_info.second.dstW, mysurface_info.second.dstH,
                mysurface_info.second.srcX, mysurface_info.second.srcY, mysurface_info.second.srcW,
                mysurface_info.second.srcH, mysurface_info.second.opacity, mysurface_info.second.visibility,
                mysurface_info.second.onLayerId, appFd.fd, appFd.bundlerName.c_str(), appFd.appName.c_str());
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
    CHK(udsServer_, NULL_POINTER);
    CHK(screenInfo, NULL_POINTER);
    CHK(*screenInfo, NULL_POINTER);

    // clear windows info
    screenInfoVec_.clear();
    layers_.clear();
    mysurfaces_.clear();

    // save windows info
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
                TestSurfaceInfo mySurfaceTmp = {};
                CHK(EOK == memcpy_s(&mySurfaceTmp, sizeof(mySurfaceTmp), pstrSurface[k], sizeof(SurfaceInfo)),
                    MEMCPY_SEC_FUN_FAIL);
                mySurfaceTmp.screenId = screenInfo[i]->screenId;
                mysurfaces_.insert(std::pair<int32_t, TestSurfaceInfo>(mySurfaceTmp.surfaceId, mySurfaceTmp));
            }
        }
    }
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
    // check map empty
    if (!mysurfaces_.empty()) {
        int32_t newLayerId = -1;
        int32_t newSurfaceId = -1;
        for (auto it : mysurfaces_) {
            auto res = static_cast<TestSurfaceInfo*>(&it.second);
            CHKF(res, NULL_POINTER);
            // find window by coordinate
            if (FindSurfaceByCoordinate(x, y, *res)) {
                if (res->onLayerId > newLayerId) {
                    newLayerId = res->onLayerId;
                    newSurfaceId = res->surfaceId;
                }
            }
        }
        // push id
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

const TestSurfaceInfo* OHOS::MMI::InputWindowsManager::GetSurfaceInfo(int32_t sufaceId)
{
    std::lock_guard<std::mutex> lock(mu_);
    auto it = mysurfaces_.find(sufaceId);
    if (it == mysurfaces_.end()) {
        return nullptr;
    }
    return &it->second;
}

bool OHOS::MMI::InputWindowsManager::CheckFocusSurface(double x, double y, const TestSurfaceInfo& info) const
{
    if (x >= info.dstX && x <= (info.dstX + info.dstW) &&
        y >= info.dstY && y <= (info.dstY + info.dstH)) {
        return true;
    }
    return false;
}

const TestSurfaceInfo* OHOS::MMI::InputWindowsManager::GetTouchSurfaceInfo(double x, double y)
{
    std::lock_guard<std::mutex> lock(mu_);
    int32_t newLayerId = -1;
    const TestSurfaceInfo* surfacePtr = nullptr;
    for (auto& it : mysurfaces_) {
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

void OHOS::MMI::InputWindowsManager::TransfromToSurfaceCoordinate(double& x, double& y, const TestSurfaceInfo& info,
                                                                  bool debug)
{
    double oldX = x;
    double oldY = y;
    x = x - info.dstX;
    y = y - info.dstY;
    if (debug) {
        auto appFd = AppRegs->FindByWinId(info.surfaceId);
        MMI_LOGD("Transfrom touch coordinate... src:[%{public}lf, %{public}lf] focusSurface:%{public}d "
                 "surface:[%{public}d, %{public}d, %{public}d, %{public}d] dest:[%{public}lf, %{public}lf] "
                 "fd:%{public}d bundler:%{public}s appName:%{public}s",
                 oldX, oldY, info.surfaceId, info.dstX, info.dstY, info.dstW, info.dstH, x, y, appFd.fd,
                 appFd.bundlerName.c_str(), appFd.appName.c_str());
    }
}
