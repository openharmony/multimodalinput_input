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

#include "common_event_handler.h"
#include "log.h"
#include "proto.h"

namespace OHOS {
namespace MMI {
CommonEventHandler::CommonEventHandler()
{
    type_ = MmiMessageId::COMMON_EVENT_BEGIN;
}
CommonEventHandler::~CommonEventHandler()
{
}
bool CommonEventHandler::OnShowMenu(const MultimodalEvent& event)
{
    return false;
}

bool CommonEventHandler::OnSend(const MultimodalEvent& event)
{
    return false;
}

bool CommonEventHandler::OnCopy(const MultimodalEvent& event)
{
    return false;
}

bool CommonEventHandler::OnPaste(const MultimodalEvent& event)
{
    return false;
}

bool CommonEventHandler::OnCut(const MultimodalEvent& event)
{
    return false;
}

bool CommonEventHandler::OnUndo(const MultimodalEvent& event)
{
    return false;
}

bool CommonEventHandler::OnRefresh(const MultimodalEvent& event)
{
    return false;
}

bool CommonEventHandler::OnStartDrag(const MultimodalEvent& event)
{
    return false;
}

bool CommonEventHandler::OnCancel(const MultimodalEvent& event)
{
    return false;
}

bool CommonEventHandler::OnEnter(const MultimodalEvent& event)
{
    return false;
}

bool CommonEventHandler::OnPrevious(const MultimodalEvent& event)
{
    return false;
}

bool CommonEventHandler::OnNext(const MultimodalEvent& event)
{
    return false;
}

bool CommonEventHandler::OnBack(const MultimodalEvent& event)
{
    return false;
}

bool CommonEventHandler::OnPrint(const MultimodalEvent& event)
{
    return false;
}
}
}
