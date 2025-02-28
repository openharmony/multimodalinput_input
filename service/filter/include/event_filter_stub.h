/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef EVENT_FILTER_STUB_H
#define EVENT_FILTER_STUB_H

#include "iremote_stub.h"

#include "i_event_filter.h"

namespace OHOS {
namespace MMI {
class EventFilterStub : public IRemoteStub<IEventFilter> {
public:
    EventFilterStub() = default;
    DISALLOW_COPY_AND_MOVE(EventFilterStub);
    virtual ~EventFilterStub() = default;
    int32_t OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& options) override;
protected:
    int32_t StubHandleKeyEvent(MessageParcel& data, MessageParcel& reply);
    int32_t StubHandlePointerEvent(MessageParcel& data, MessageParcel& reply);
};
} // namespace MMI
} // namespace OHOS
#endif // EVENT_FILTER_STUB_H