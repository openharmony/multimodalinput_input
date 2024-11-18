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

#include <parameters.h>
#include "long_press_subscriber_handler.h"

#include "bytrace_adapter.h"
#include "define_multimodal.h"
#include "dfx_hisysevent.h"
#include "error_multimodal.h"
#include "input_event_data_transformation.h"
#include "input_event_handler.h"
#include "net_packet.h"
#include "proto.h"
#include "util_ex.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "LongPressSubscriberHandler"

namespace OHOS {
namespace MMI {
LongPressSubscriberHandler::LongPressSubscriberHandler() {}

LongPressSubscriberHandler::~LongPressSubscriberHandler() {}

int32_t LongPressSubscriberHandler::SubscribeLongPressEvent(SessionPtr sess, int32_t subscribeId,
    const LongPressRequest &longPressRequest)
{
    return RET_OK;
}

int32_t LongPressSubscriberHandler::UnsubscribeLongPressEvent(SessionPtr sess, int32_t subscribeId)
{
    return RET_OK;
}

void LongPressSubscriberHandler::InsertSubScriber(std::shared_ptr<Subscriber> subs)
{
}

void LongPressSubscriberHandler::OnSessionDelete(SessionPtr sess)
{
}

void LongPressSubscriberHandler::NotifySubscriber(const std::shared_ptr<Subscriber> &subscriber)
{
}

bool LongPressSubscriberHandler::InitSessionDeleteCallback()
{
    return false;
}

void LongPressSubscriberHandler::OnSubscribeLongPressEvent(int32_t duration)
{
}
} // namespace MMI
} // namespace OHOS
