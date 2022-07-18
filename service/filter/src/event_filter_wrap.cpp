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

#include "event_filter_wrap.h"

#include "error_multimodal.h"
#include "mmi_log.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "EventFilterWrap" };
} // namespace

EventFilterWrap::EventFilterWrap()
{
    CALL_DEBUG_ENTER;
}

EventFilterWrap::~EventFilterWrap()
{
    CALL_DEBUG_ENTER;
}
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
void EventFilterWrap::HandleKeyEvent(std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(keyEvent);
    CHKPV(nextHandler_);
    nextHandler_->HandleKeyEvent(keyEvent);
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

#ifdef OHOS_BUILD_ENABLE_POINTER
void EventFilterWrap::HandlePointerEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPV(pointerEvent);
    if (HandlePointerEventFilter(pointerEvent)) {
        MMI_HILOGI("Pointer event Filter succeeded");
        return;
    }
    CHKPV(nextHandler_);
    nextHandler_->HandlePointerEvent(pointerEvent);
}
#endif // OHOS_BUILD_ENABLE_POINTER

#ifdef OHOS_BUILD_ENABLE_TOUCH
void EventFilterWrap::HandleTouchEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPV(pointerEvent);
    if (HandlePointerEventFilter(pointerEvent)) {
        MMI_HILOGI("Pointer event Filter succeeded");
        return;
    }
    CHKPV(nextHandler_);
    nextHandler_->HandleTouchEvent(pointerEvent);
}
#endif // OHOS_BUILD_ENABLE_TOUCH

int32_t EventFilterWrap::AddInputEventFilter(sptr<IEventFilter> filter)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(lockFilter_);
    filter_ = filter;
    return RET_OK;
}

bool EventFilterWrap::HandlePointerEventFilter(std::shared_ptr<PointerEvent> point)
{
    CALL_DEBUG_ENTER;
    CHKPF(point);
    std::lock_guard<std::mutex> guard(lockFilter_);
    CHKPF(filter_);
    if (filter_->HandlePointerEvent(point)) {
        MMI_HILOGD("Call HandlePointerEvent return true");
        return true;
    }
    return false;
}
} // namespace MMI
} // namespace OHOS
