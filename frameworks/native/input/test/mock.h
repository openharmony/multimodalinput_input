/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#ifndef MESSAGE_PARCEL_MOCK_H
#define MESSAGE_PARCEL_MOCK_H

#include <gmock/gmock.h>

#include "input_manager.h"
#include "oh_input_manager.h"

namespace OHOS {
namespace MMI {
class DfsMessageParcel {
public:
    virtual ~DfsMessageParcel() = default;
public:
    virtual int32_t GetPointerLocation(int32_t &displayId, double &displayX, double &displayY) = 0;
public:
    static inline std::shared_ptr<DfsMessageParcel> messageParcel = nullptr;
};

class MessageParcelMock : public DfsMessageParcel {
public:
    MOCK_METHOD3(GetPointerLocation, int32_t(int32_t &displayId, double &displayX, double &displayY));
};
} // namespace MMI
} // namespace OHOS
#endif