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

#ifndef I_ANCO_CONSUMER_H
#define I_ANCO_CONSUMER_H

#include "key_event.h"
#include "pointer_event.h"
#include "window_info.h"

namespace OHOS {
namespace MMI {

enum class ANCO_WINDOW_UPDATE_TYPE: uint32_t {
    ALL = 0,
    INCREMENT = 1,
};

struct AncoWindowInfo {
    /**
     * Globally unique identifier of the window
     */
    int32_t id;

    /**
     * A 32-bit flag that represents the window status. If the 0th bitt is 1,
     * the window is untouchable; if the 0th bit is 0, the window is touchable.
     */
    uint32_t flags;

    /**
     * Agent window ID
     */
    WINDOW_UPDATE_ACTION action { WINDOW_UPDATE_ACTION::UNKNOWN };

    /**
     * Window display ID
     */
    int32_t displayId { DEFAULT_DISPLAY_ID };

    /**
     * Window order in Z-index
     */
    float zOrder { 0.0f };

    /**
     * Window transform for changing display x,y to window x,y.
     */
    std::vector<float> transform;

    /**
     * Number of touch response areas (excluding the mouse response areas) in the window.
     * The value cannot exceed the value of MAX_HOTAREA_COUNT.
     */
    std::vector<Rect> defaultHotAreas;

    /**
     * Number of excluded touch response areas in the window.
     */
    std::vector<Rect> ancoExcludedAreas;
};

struct AncoWindows {
    ANCO_WINDOW_UPDATE_TYPE updateType;
    int32_t focusWindowId;
    std::vector<AncoWindowInfo> windows;

    static bool Marshalling(const AncoWindows &windows, Parcel &parcel);
    static bool Unmarshalling(Parcel &parcel, AncoWindows &windows);
};

class IAncoConsumer {
public:
    IAncoConsumer() = default;
    virtual ~IAncoConsumer() = default;

    virtual int32_t SyncInputEvent(std::shared_ptr<PointerEvent> pointerEvent) = 0;
    virtual int32_t SyncInputEvent(std::shared_ptr<KeyEvent> keyEvent) = 0;
    virtual int32_t UpdateWindowInfo(std::shared_ptr<AncoWindows> windows) = 0;
};
} // namespace MMI
} // namespace OHOS
#endif // I_ANCO_CONSUMER_H
