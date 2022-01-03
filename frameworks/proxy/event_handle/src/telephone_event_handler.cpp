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

#include "telephone_event_handler.h"
#include "log.h"
#include "proto.h"

namespace OHOS {
namespace MMI {
TelephoneEventHandler::TelephoneEventHandler()
{
    type_ = MmiMessageId::TELEPHONE_EVENT_BEGIN;
}

TelephoneEventHandler::~TelephoneEventHandler()
{
}

bool TelephoneEventHandler::OnAnswer(const MultimodalEvent& event)
{
    return false;
}

bool TelephoneEventHandler::OnRefuse(const MultimodalEvent& event)
{
    return false;
}

bool TelephoneEventHandler::OnHangup(const MultimodalEvent& event)
{
    return false;
}

bool TelephoneEventHandler::OnTelephoneControl(const MultimodalEvent& event)
{
    return false;
}
}
}
