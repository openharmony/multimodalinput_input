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

#ifndef FOLDING_AREA_TOAST_H
#define FOLDING_AREA_TOAST_H
#include <unordered_map>
#include <vector>
#include "nocopyable.h"
#include "libinput.h"
namespace OHOS {
namespace MMI {
class FoldingAreaToast final {
public:
    FoldingAreaToast();
    ~FoldingAreaToast();
    DISALLOW_COPY_AND_MOVE(FoldingAreaToast);
    void FoldingAreaProcess(struct libinput_event *event);

public:
    int32_t deviceId_;
private:
    std::unordered_map<int32_t, uint16_t> touchId2KeepFrames_;
    std::unordered_map<int32_t, int64_t> touchId2FirstDownTimes_;
    std::unordered_map<int32_t, uint16_t> touchId2KeepDownTimes_;
    std::unordered_map<int32_t, std::pair<uint16_t, uint16_t>> touchId2clickTouchs_;
    std::vector<std::pair<uint16_t, uint16_t>> tacTouchs_;
    std::unordered_map<int32_t, uint16_t> touchId2touchNum_;
    int64_t clickInFoldingAreaBeginTimeStamp_ = 0;
    int32_t touchId_ = 0;
    uint16_t pointX_ = 0;
    uint16_t pointY_ = 0;
private:
    void NotifyFoldingAreaTouchStatus(const int8_t state);
    void FoldingAreaClear(void);
    void FoldingAreaGetTouchid2TouchNum(void);
    void FoldingAreaLongPressProcess(void);
    void FoldingAreaFastClickProcess(void);
    void FoldingAreaCheckDeviceId(struct libinput_event *event);
};
} // namespace MMI
} // namespace OHOS
#endif // FOLDING_AREA_TOAST_H