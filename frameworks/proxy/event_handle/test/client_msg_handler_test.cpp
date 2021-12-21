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

#include <gtest/gtest.h>
#include "client_msg_handler.h"
#include "proto.h"
#include "struct_multimodal.h"
#include "event_factory.h"
#include "mmi_client.h"

namespace {
using namespace testing::ext;
using namespace OHOS::MMI;
using namespace OHOS;
using TestMMIClient = OHOS::MMI::MMIClient;

static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "ClientMsgHandlerTest" };

class ClientMsgHandlerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

class ClientMsgHandlerSelf : public OHOS::MMI::ClientMsgHandler {
public:

    bool OnKeyUnitTest(const UDSClient& udsClient, NetPacket& netPkt)
    {
        return OnKey(udsClient, netPkt);
    }
    bool OnTouchUnitTest(INPUT_DEVICE_TYPE msgId)
    {
        TestMMIClient clientObj;
        NetPacket netPacket(MmiMessageId::ON_TOUCH);
        netPacket << msgId;
        const unsigned int bitLength = 2;

        if (msgId == INPUT_DEVICE_CAP_POINTER) {
            netPacket << bitLength;
        }
        return OnTouch(clientObj, netPacket);
    }
    bool OnTouchStandardUnitTest(INPUT_DEVICE_TYPE msgId, int32_t  curReventType)
    {
        TestMMIClient clientObj;
        NetPacket netPacket(MmiMessageId::ON_TOUCH);
        netPacket << msgId << curReventType;
        const unsigned int bitLength = 2;

        if (msgId == INPUT_DEVICE_CAP_POINTER) {
            netPacket << bitLength;
        }
        return OnTouch(clientObj, netPacket);
    }

    bool OnTouchUnitTest2(const UDSClient& udsClient, NetPacket& netPkt)
    {
        return OnTouch(udsClient, netPkt);
    }

    bool OnCopyUnitTest(const UDSClient& udsClient, NetPacket& netPkt)
    {
        return OnCopy(udsClient, netPkt);
    }

    bool OnShowMenuUnitTest(const UDSClient& udsClient, NetPacket& netPkt)
    {
        return OnShowMenu(udsClient, netPkt);
    }

    bool OnSendUnitTest(const UDSClient& udsClient, NetPacket& netPkt)
    {
        return OnSend(udsClient, netPkt);
    }

    bool OnPasteUnitTest(const UDSClient& udsClient, NetPacket& netPkt)
    {
        return OnPaste(udsClient, netPkt);
    }

    bool OnCutUnitTest(const UDSClient& udsClient, NetPacket& netPkt)
    {
        return OnCut(udsClient, netPkt);
    }

    bool OnUndoUnitTest(const UDSClient& udsClient, NetPacket& netPkt)
    {
        return OnUndo(udsClient, netPkt);
    }

    bool OnRefreshUnitTest(const UDSClient& udsClient, NetPacket& netPkt)
    {
        return OnRefresh(udsClient, netPkt);
    }

    bool OnStartDragUnitTest(const UDSClient& udsClient, NetPacket& netPkt)
    {
        return OnStartDrag(udsClient, netPkt);
    }

    bool OnCancelUnitTest(const UDSClient& udsClient, NetPacket& netPkt)
    {
        return OnCancel(udsClient, netPkt);
    }

    bool OnEnterUnitTest(const UDSClient& udsClient, NetPacket& netPkt)
    {
        return OnEnter(udsClient, netPkt);
    }

    bool OnPreviousUnitTest(const UDSClient& udsClient, NetPacket& netPkt)
    {
        return OnPrevious(udsClient, netPkt);
    }

    bool OnNextUnitTest(const UDSClient& udsClient, NetPacket& netPkt)
    {
        return OnNext(udsClient, netPkt);
    }

    bool OnBackUnitTest(const UDSClient& udsClient, NetPacket& netPkt)
    {
        return OnBack(udsClient, netPkt);
    }

    bool OnPrintUnitTest(const UDSClient& udsClient, NetPacket& netPkt)
    {
        return OnPrint(udsClient, netPkt);
    }

    bool OnPlayUnitTest(const UDSClient& udsClient, NetPacket& netPkt)
    {
        return OnPlay(udsClient, netPkt);
    }

    bool OnPauseUnitTest(const UDSClient& udsClient, NetPacket& netPkt)
    {
        return OnPause(udsClient, netPkt);
    }

    bool OnMediaControlUnitTest(const UDSClient& udsClient, NetPacket& netPkt)
    {
        return OnMediaControl(udsClient, netPkt);
    }

    bool OnScreenShotUnitTest(const UDSClient& udsClient, NetPacket& netPkt)
    {
        return OnScreenShot(udsClient, netPkt);
    }

    bool OnScreenSplitUnitTest(const UDSClient& udsClient, NetPacket& netPkt)
    {
        return OnScreenSplit(udsClient, netPkt);
    }

    bool OnStartScreenRecordUnitTest(const UDSClient& udsClient, NetPacket& netPkt)
    {
        return OnStartScreenRecord(udsClient, netPkt);
    }

    bool OnStopScreenRecordUnitTest(const UDSClient& udsClient, NetPacket& netPkt)
    {
        return OnStopScreenRecord(udsClient, netPkt);
    }

    bool OnGotoDesktopUnitTest(const UDSClient& udsClient, NetPacket& netPkt)
    {
        return OnGotoDesktop(udsClient, netPkt);
    }

    bool OnRecentUnitTest(const UDSClient& udsClient, NetPacket& netPkt)
    {
        return OnRecent(udsClient, netPkt);
    }

    bool OnShowNotificationUnitTest(const UDSClient& udsClient, NetPacket& netPkt)
    {
        return OnShowNotification(udsClient, netPkt);
    }

    bool OnLockScreenUnitTest(const UDSClient& udsClient, NetPacket& netPkt)
    {
        return OnLockScreen(udsClient, netPkt);
    }

    bool OnSearchUnitTest(const UDSClient& udsClient, NetPacket& netPkt)
    {
        return OnSearch(udsClient, netPkt);
    }

    bool OnClosePageUnitTest(const UDSClient& udsClient, NetPacket& netPkt)
    {
        return OnClosePage(udsClient, netPkt);
    }

    bool OnLaunchVoiceAssistantUnitTest(const UDSClient& udsClient, NetPacket& netPkt)
    {
        return OnLaunchVoiceAssistant(udsClient, netPkt);
    }

    bool OnMuteUnitTest(const UDSClient& udsClient, NetPacket& netPkt)
    {
        return OnMute(udsClient, netPkt);
    }

    bool OnAnswerUnitTest(const UDSClient& udsClient, NetPacket& netPkt)
    {
        return OnAnswer(udsClient, netPkt);
    }

    bool OnRefuseUnitTest(const UDSClient& udsClient, NetPacket& netPkt)
    {
        return OnRefuse(udsClient, netPkt);
    }

    bool OnHangupUnitTest(const UDSClient& udsClient, NetPacket& netPkt)
    {
        return OnHangup(udsClient, netPkt);
    }

    bool OnTelephoneControlUnitTest(const UDSClient& udsClient, NetPacket& netPkt)
    {
        return OnTelephoneControl(udsClient, netPkt);
    }

    bool GetMultimodeInputInfoUnitTest(const UDSClient& udsClient, NetPacket& netPkt)
    {
        return GetMultimodeInputInfo(udsClient, netPkt);
    }

    bool DeviceAddUnitTest(const UDSClient& udsClient, NetPacket& netPkt)
    {
        return DeviceAdd(udsClient, netPkt);
    }

    bool DeviceRemoveUnitTest(const UDSClient& udsClient, NetPacket& netPkt)
    {
        return DeviceRemove(udsClient, netPkt);
    }
};

HWTEST_F(ClientMsgHandlerTest, Init, TestSize.Level1)
{
    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONKEY_001, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_KEY);

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONKEY_002, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_KEY);

    int32_t typeNum = INPUT_DEVICE_CAP_KEYBOARD;
    int16_t idMsg = 3;
    int32_t aiDeviceFd = 4;
    int32_t fileData = 5;
    int32_t windowId = -1;
    int32_t abilityId = 7;
    uint64_t serverStartTime = 0;
    RegisteredEvent mixData = { 1, "abc123@34", 300, 10000, static_cast<HOS_DEVICE_TYPE>(1), "key_board" };
    netPacket >> mixData >> typeNum >> idMsg >> aiDeviceFd >> fileData >> windowId >> abilityId >> serverStartTime;

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONKEY_003, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_KEY);
    int32_t typeNum = INPUT_DEVICE_CAP_KEYBOARD;
    int16_t idMsg = 3;
    int32_t aiDeviceFd = 4;
    int32_t fileData = 5;
    int32_t windowId = -1;
    int32_t abilityId = 7;
    uint64_t serverStartTime = 0;
    RegisteredEvent mixData = { 1, "abc123@34", 300, 10000, static_cast<HOS_DEVICE_TYPE>(1), "key_board" };
    netPacket >> mixData >> typeNum >> idMsg >> aiDeviceFd >> fileData >> windowId >> abilityId << serverStartTime;

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONKEY_004, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_KEY);

    int32_t typeNum = INPUT_DEVICE_CAP_KEYBOARD;
    int16_t idMsg = 3;
    int32_t aiDeviceFd = 4;
    int32_t fileData = 5;
    int32_t windowId = -1;
    int32_t abilityId = 7;
    uint64_t serverStartTime = 0;
    netPacket >> typeNum >> idMsg >> aiDeviceFd >> fileData >> windowId >> abilityId >> serverStartTime;

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONKEY_005, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_KEY);

    int32_t typeNum = INPUT_DEVICE_CAP_SWITCH;
    int32_t fileData = 11;
    int32_t windowId = -1;
    int32_t abilityId = 33;
    uint64_t serverStartTime = 44;
    RegisteredEvent mixData = {1, "abc123@34", 300, 10000, static_cast<HOS_DEVICE_TYPE>(1), "key_board"};
    netPacket >> typeNum >> mixData >> fileData >> windowId >> abilityId >> serverStartTime;

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONTOUCH_001, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_TOUCH);

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONTOUCH_002, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_TOUCH);

    int32_t typeNum = INPUT_DEVICE_CAP_TOUCH;
    int16_t idMsg = 3;
    int32_t aiDeviceFd = 4;
    int32_t fileData = 5;
    int32_t windowId = -1;
    int32_t abilityId = 7;
    uint64_t serverStartTime = 0;
    RegisteredEvent mixData = { 1, "abc123@34", 500, 10000, static_cast<HOS_DEVICE_TYPE>(0), "touchscreen" };
    netPacket >> mixData >> typeNum >> idMsg >> aiDeviceFd >> fileData >> windowId >> abilityId >> serverStartTime;

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONTOUCH_003, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_TOUCH);

    int32_t typeNum = INPUT_DEVICE_CAP_TOUCH;
    int16_t idMsg = 3;
    int32_t aiDeviceFd = 4;
    int32_t fileData = 5;
    int32_t windowId = -1;
    int32_t abilityId = 7;
    uint64_t serverStartTime = 0;
    RegisteredEvent mixData = { 1, "abc123@34", 500, 10000, static_cast<HOS_DEVICE_TYPE>(0), "touchscreen" };
    netPacket >> mixData >> typeNum >> idMsg >> aiDeviceFd >> fileData >> windowId >> abilityId << serverStartTime;

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONTOUCH_004, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_TOUCH);

    int32_t typeNum = INPUT_DEVICE_CAP_TOUCH;
    int16_t idMsg = 3;
    int32_t aiDeviceFd = 4;
    int32_t fileData = 5;
    int32_t windowId = -1;
    int32_t abilityId = 7;
    uint64_t serverStartTime = 0;
    netPacket >> typeNum >> idMsg >> aiDeviceFd >> fileData >> windowId >> abilityId >> serverStartTime;

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONTOUCH_005, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_TOUCH);

    int32_t typeNum = INPUT_DEVICE_CAP_TOUCH;
    int32_t fileData = 11;
    int32_t windowId = -1;
    int32_t abilityId = 33;
    uint64_t serverStartTime = 44;
    RegisteredEvent mixData = { 1, "abc123@34", 500, 10000, static_cast<HOS_DEVICE_TYPE>(0), "touchscreen" };
    netPacket >> typeNum >> mixData >> fileData >> windowId >> abilityId >> serverStartTime;

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONCOPY_001, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_COPY);

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONCOPY_002, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_COPY);

    int32_t typeNum = INPUT_DEVICE_CAP_KEYBOARD;
    int16_t idMsg = 3;
    int32_t aiDeviceFd = 4;
    int32_t fileData = 5;
    int32_t windowId = -1;
    int32_t abilityId = 7;
    uint64_t serverStartTime = 0;
    RegisteredEvent mixData = { 1, "abc123@34", 300, 10000, static_cast<HOS_DEVICE_TYPE>(1), "keyboard" };
    netPacket >> mixData >> typeNum >> idMsg >> aiDeviceFd >> fileData >> windowId >> abilityId >> serverStartTime;

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONCOPY_003, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_COPY);

    int32_t typeNum = INPUT_DEVICE_CAP_KEYBOARD;
    int16_t idMsg = 3;
    int32_t aiDeviceFd = 4;
    int32_t fileData = 5;
    int32_t windowId = -1;
    int32_t abilityId = 7;
    uint64_t serverStartTime = 0;
    RegisteredEvent mixData = { 1, "abc123@34", 300, 10000, static_cast<HOS_DEVICE_TYPE>(1), "keyboard" };
    netPacket >> mixData >> typeNum >> idMsg >> aiDeviceFd >> fileData >> windowId >> abilityId << serverStartTime;

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONCOPY_004, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_COPY);

    int32_t typeNum = INPUT_DEVICE_CAP_KEYBOARD;
    int16_t idMsg = 3;
    int32_t aiDeviceFd = 4;
    int32_t fileData = 5;
    int32_t windowId = -1;
    int32_t abilityId = 7;
    uint64_t serverStartTime = 0;
    netPacket >> typeNum >> idMsg >> aiDeviceFd >> fileData >> windowId >> abilityId >> serverStartTime;

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONCOPY_005, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_COPY);

    int32_t typeNum = INPUT_DEVICE_CAP_SWITCH;
    int32_t fileData = 11;
    int32_t windowId = -1;
    int32_t abilityId = 33;
    uint64_t serverStartTime = 44;
    RegisteredEvent mixData = { 1, "abc123@34", 300, 10000, static_cast<HOS_DEVICE_TYPE>(1), "keyboard" };
    netPacket >> typeNum >> mixData >> fileData >> windowId >> abilityId >> serverStartTime;

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONSHOWMENU_001, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_SHOW_MENU);

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONSHOWMENU_002, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_SHOW_MENU);

    int32_t typeNum = INPUT_DEVICE_CAP_KEYBOARD;
    int16_t idMsg = 3;
    int32_t aiDeviceFd = 4;
    int32_t fileData = 5;
    int32_t windowId = -1;
    int32_t abilityId = 7;
    uint64_t serverStartTime = 0;
    RegisteredEvent mixData = { 1, "abc123@34", 402, 10000, static_cast<HOS_DEVICE_TYPE>(2), "mouse" };
    netPacket >> mixData >> typeNum >> idMsg >> aiDeviceFd >> fileData >> windowId >> abilityId >> serverStartTime;

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONSHOWMENU_003, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_SHOW_MENU);

    int32_t typeNum = INPUT_DEVICE_CAP_KEYBOARD;
    int16_t idMsg = 3;
    int32_t aiDeviceFd = 4;
    int32_t fileData = 5;
    int32_t windowId = -1;
    int32_t abilityId = 7;
    uint64_t serverStartTime = 0;
    RegisteredEvent mixData = { 1, "abc123@34", 300, 10000, static_cast<HOS_DEVICE_TYPE>(1), "keyboard" };
    netPacket >> mixData >> typeNum >> idMsg >> aiDeviceFd >> fileData >> windowId >> abilityId << serverStartTime;

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONSHOWMENU_004, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_SHOW_MENU);

    int32_t typeNum = INPUT_DEVICE_CAP_KEYBOARD;
    int16_t idMsg = 3;
    int32_t aiDeviceFd = 4;
    int32_t fileData = 5;
    int32_t windowId = -1;
    int32_t abilityId = 7;
    uint64_t serverStartTime = 0;
    netPacket >> typeNum >> idMsg >> aiDeviceFd >> fileData >> windowId >> abilityId >> serverStartTime;

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONSHOWMENU_005, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_SHOW_MENU);

    int32_t typeNum = INPUT_DEVICE_CAP_SWITCH;
    int32_t fileData = 11;
    int32_t windowId = -1;
    int32_t abilityId = 33;
    uint64_t serverStartTime = 44;
    RegisteredEvent mixData = { 1, "abc123@34", 402, 10000, static_cast<HOS_DEVICE_TYPE>(2), "mouse" };
    netPacket >> typeNum >> mixData >> fileData >> windowId >> abilityId >> serverStartTime;

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONSEND_001, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_SEND);

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONSEND_002, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_SEND);

    int32_t typeNum = INPUT_DEVICE_CAP_KEYBOARD;
    int16_t idMsg = 3;
    int32_t aiDeviceFd = 4;
    int32_t fileData = 5;
    int32_t windowId = -1;
    int32_t abilityId = 7;
    uint64_t serverStartTime = 0;
    RegisteredEvent mixData = { 1, "abc123@34", 300, 10000, static_cast<HOS_DEVICE_TYPE>(1), "keyboard" };
    netPacket >> mixData >> typeNum >> idMsg >> aiDeviceFd >> fileData >> windowId >> abilityId >> serverStartTime;

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONSEND_003, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_SEND);

    int32_t typeNum = INPUT_DEVICE_CAP_KEYBOARD;
    int16_t idMsg = 3;
    int32_t aiDeviceFd = 4;
    int32_t fileData = 5;
    int32_t windowId = -1;
    int32_t abilityId = 7;
    uint64_t serverStartTime = 0;
    RegisteredEvent mixData = { 1, "abc123@34", 300, 10000, static_cast<HOS_DEVICE_TYPE>(1), "keyboard" };
    netPacket >> mixData >> typeNum >> idMsg >> aiDeviceFd >> fileData >> windowId >> abilityId << serverStartTime;

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONSEND_004, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_SEND);

    int32_t typeNum = INPUT_DEVICE_CAP_KEYBOARD;
    int16_t idMsg = 3;
    int32_t aiDeviceFd = 4;
    int32_t fileData = 5;
    int32_t windowId = -1;
    int32_t abilityId = 7;
    uint64_t serverStartTime = 0;
    netPacket >> typeNum >> idMsg >> aiDeviceFd >> fileData >> windowId >> abilityId >> serverStartTime;

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONSEND_005, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_SEND);

    int32_t typeNum = INPUT_DEVICE_CAP_SWITCH;
    int32_t fileData = 11;
    int32_t windowId = -1;
    int32_t abilityId = 33;
    uint64_t serverStartTime = 44;
    RegisteredEvent mixData = { 1, "abc123@34", 300, 10000, static_cast<HOS_DEVICE_TYPE>(1), "keyboard" };
    netPacket >> typeNum >> mixData >> fileData >> windowId >> abilityId >> serverStartTime;

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONPASTE_001, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_PASTE);

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONPASTE_002, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_PASTE);

    int32_t typeNum = INPUT_DEVICE_CAP_KEYBOARD;
    int16_t idMsg = 3;
    int32_t aiDeviceFd = 4;
    int32_t fileData = 5;
    int32_t windowId = -1;
    int32_t abilityId = 7;
    uint64_t serverStartTime = 0;
    RegisteredEvent mixData = { 1, "abc123@34", 300, 10000, static_cast<HOS_DEVICE_TYPE>(1), "keyboard" };
    netPacket >> mixData >> typeNum >> idMsg >> aiDeviceFd >> fileData >> windowId >> abilityId >> serverStartTime;

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONPASTE_003, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_PASTE);

    int32_t typeNum = INPUT_DEVICE_CAP_KEYBOARD;
    int16_t idMsg = 3;
    int32_t aiDeviceFd = 4;
    int32_t fileData = 5;
    int32_t windowId = -1;
    int32_t abilityId = 7;
    uint64_t serverStartTime = 0;
    RegisteredEvent mixData = { 1, "abc123@34", 300, 10000, static_cast<HOS_DEVICE_TYPE>(1), "keyboard" };
    netPacket >> mixData >> typeNum >> idMsg >> aiDeviceFd >> fileData >> windowId >> abilityId << serverStartTime;

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONPASTE_004, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_PASTE);

    int32_t typeNum = INPUT_DEVICE_CAP_KEYBOARD;
    int16_t idMsg = 3;
    int32_t aiDeviceFd = 4;
    int32_t fileData = 5;
    int32_t windowId = -1;
    int32_t abilityId = 7;
    uint64_t serverStartTime = 0;
    netPacket >> typeNum >> idMsg >> aiDeviceFd >> fileData >> windowId >> abilityId >> serverStartTime;

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONPASTE_005, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_PASTE);

    int32_t typeNum = INPUT_DEVICE_CAP_SWITCH;
    int32_t fileData = 11;
    int32_t windowId = -1;
    int32_t abilityId = 33;
    uint64_t serverStartTime = 44;
    RegisteredEvent mixData = { 1, "abc123@34", 300, 10000, static_cast<HOS_DEVICE_TYPE>(1), "keyboard" };
    netPacket >> typeNum >> mixData >> fileData >> windowId >> abilityId >> serverStartTime;

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONCUT_001, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_CUT);

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONCUT_002, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_CUT);

    int32_t typeNum = INPUT_DEVICE_CAP_KEYBOARD;
    int16_t idMsg = 3;
    int32_t aiDeviceFd = 4;
    int32_t fileData = 5;
    int32_t windowId = -1;
    int32_t abilityId = 7;
    uint64_t serverStartTime = 0;
    RegisteredEvent mixData = { 1, "abc123@34", 300, 10000, static_cast<HOS_DEVICE_TYPE>(1), "keyboard" };
    netPacket >> mixData >> typeNum >> idMsg >> aiDeviceFd >> fileData >> windowId >> abilityId >> serverStartTime;

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONCUT_003, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_CUT);

    int32_t typeNum = INPUT_DEVICE_CAP_KEYBOARD;
    int16_t idMsg = 3;
    int32_t aiDeviceFd = 4;
    int32_t fileData = 5;
    int32_t windowId = -1;
    int32_t abilityId = 7;
    uint64_t serverStartTime = 0;
    RegisteredEvent mixData = { 1, "abc123@34", 300, 10000, static_cast<HOS_DEVICE_TYPE>(1), "keyboard" };
    netPacket >> mixData >> typeNum >> idMsg >> aiDeviceFd >> fileData >> windowId >> abilityId << serverStartTime;

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONCUT_004, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_CUT);

    int32_t typeNum = INPUT_DEVICE_CAP_KEYBOARD;
    int16_t idMsg = 3;
    int32_t aiDeviceFd = 4;
    int32_t fileData = 5;
    int32_t windowId = -1;
    int32_t abilityId = 7;
    uint64_t serverStartTime = 0;
    netPacket >> typeNum >> idMsg >> aiDeviceFd >> fileData >> windowId >> abilityId >> serverStartTime;

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONCUT_005, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_CUT);

    int32_t typeNum = INPUT_DEVICE_CAP_SWITCH;
    int32_t fileData = 11;
    int32_t windowId = -1;
    int32_t abilityId = 33;
    uint64_t serverStartTime = 44;
    RegisteredEvent mixData = { 1, "abc123@34", 300, 10000, static_cast<HOS_DEVICE_TYPE>(1), "keyboard" };
    netPacket >> typeNum >> mixData >> fileData >> windowId >> abilityId >> serverStartTime;

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONUNDO_001, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_UNDO);

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONUNDO_002, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_UNDO);

    int32_t typeNum = INPUT_DEVICE_CAP_KEYBOARD;
    int16_t idMsg = 3;
    int32_t aiDeviceFd = 4;
    int32_t fileData = 5;
    int32_t windowId = -1;
    int32_t abilityId = 7;
    uint64_t serverStartTime = 0;
    RegisteredEvent mixData = { 1, "abc123@34", 300, 10000, static_cast<HOS_DEVICE_TYPE>(1), "keyboard" };
    netPacket >> mixData >> typeNum >> idMsg >> aiDeviceFd >> fileData >> windowId >> abilityId >> serverStartTime;

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONUNDO_003, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_UNDO);

    int32_t typeNum = INPUT_DEVICE_CAP_KEYBOARD;
    int16_t idMsg = 3;
    int32_t aiDeviceFd = 4;
    int32_t fileData = 5;
    int32_t windowId = -1;
    int32_t abilityId = 7;
    uint64_t serverStartTime = 0;
    RegisteredEvent mixData = { 1, "abc123@34", 300, 10000, static_cast<HOS_DEVICE_TYPE>(1), "keyboard" };
    netPacket >> mixData >> typeNum >> idMsg >> aiDeviceFd >> fileData >> windowId >> abilityId << serverStartTime;

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONUNDO_004, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_UNDO);

    int32_t typeNum = INPUT_DEVICE_CAP_KEYBOARD;
    int16_t idMsg = 3;
    int32_t aiDeviceFd = 4;
    int32_t fileData = 5;
    int32_t windowId = -1;
    int32_t abilityId = 7;
    uint64_t serverStartTime = 0;
    netPacket >> typeNum >> idMsg >> aiDeviceFd >> fileData >> windowId >> abilityId >> serverStartTime;

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONUNDO_005, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_UNDO);

    int32_t typeNum = INPUT_DEVICE_CAP_SWITCH;
    int32_t fileData = 11;
    int32_t windowId = -1;
    int32_t abilityId = 33;
    uint64_t serverStartTime = 44;
    RegisteredEvent mixData = { 1, "abc123@34", 300, 10000, static_cast<HOS_DEVICE_TYPE>(1), "keyboard" };
    netPacket >> typeNum >> mixData >> fileData >> windowId >> abilityId >> serverStartTime;

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONREFRESH, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_REFRESH);

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONSTARTDRAG, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_START_DRAG);

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONCANCEL, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_CANCEL);

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONENTER, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_ENTER);

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONPREVIOUS, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_PREVIOUS);

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONNEXT, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_NEXT);

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONBACK, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_BACK);

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONPRINT, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_PRINT);

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONPLAY, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_PLAY);

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONPAUSE, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_PAUSE);

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONMEDIACONTROL, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_MEDIA_CONTROL);

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONSCREENSHOT, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_SCREEN_SHOT);

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONSCREENSPLIT, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_SCREEN_SPLIT);

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONSTARTSCREENRECORD, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_START_SCREEN_RECORD);

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONSTOPSCREENRECORD, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_STOP_SCREEN_RECORD);

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONGOTODESKTOP, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_GOTO_DESKTOP);

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONRECENT, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_RECENT);

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONSHOWNOTIFICATION, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_SHOW_NOTIFICATION);

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONLOCKSCREEN, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_LOCK_SCREEN);

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONSEARCH, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_SEARCH);

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONCLOSEPAGE, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_CLOSE_PAGE);

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONLAUNCHVOICEASSISTANT, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_LAUNCH_VOICE_ASSISTANT);

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONMUTE, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_MUTE);

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONANSWER, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_ANSWER);

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONREFUSE, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_REFUSE);

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONHANGUP, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_HANG_UP);

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONTELEPHONECONTROL, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_TELEPHONE_CONTROL);

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}
HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_ONJOYSTICK, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_JOYSTICK);

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMsgHandler_GETMMIINFO_ACK, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::GET_MMI_INFO_ACK);

    ClientMsgHandler clientHandlerObj;
    clientHandlerObj.Init();
    clientHandlerObj.OnMsgHandler(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnTouch_keyboard, TestSize.Level1)
{
    ClientMsgHandlerSelf clientMsgHandlerSelf;
    clientMsgHandlerSelf.Init();
    clientMsgHandlerSelf.OnTouchUnitTest(INPUT_DEVICE_CAP_KEYBOARD);
}

/**
 * @tc.name: OnTouch_pointer
 * @tc.desc: detection create event:  INPUT_DEVICE_CAP_POINTER
 * @tc.type: FUNC
 * @tc.require: AR00000000 SR00000000
 */
HWTEST_F(ClientMsgHandlerTest, OnTouch_pointer_001, TestSize.Level1)
{
    ClientMsgHandlerSelf clientMsgHandlerSelf;
    clientMsgHandlerSelf.Init();
    clientMsgHandlerSelf.OnTouchUnitTest(INPUT_DEVICE_CAP_POINTER);
}

/**
 * @tc.name: OnTouch_pointer
 * @tc.desc: detection create event:  INPUT_DEVICE_CAP_POINTER
 * @tc.type: FUNC
 * @tc.require: AR00000000 SR00000000
 */

HWTEST_F(ClientMsgHandlerTest, OnTouch_pointer_002, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_TOUCH);

    int32_t abilityId = 0;
    int32_t screenId = 0;
    int32_t fileData = 0;
    int32_t retResult = RET_ERR;
    uint64_t serverStartTime = 0;
    EventPointer pointData = {};
    netPacket << INPUT_DEVICE_CAP_POINTER;
    netPacket << retResult << pointData << abilityId << screenId << fileData << serverStartTime;

    ClientMsgHandlerSelf clientMsgHandlerSelf;
    clientMsgHandlerSelf.Init();
    clientMsgHandlerSelf.OnTouchUnitTest2(clientObj, netPacket);
}

/**
 * @tc.name: OnTouch_touch
 * @tc.desc: detection create event:  INPUT_DEVICE_CAP_TOUCH
 * @tc.type: FUNC
 * @tc.require: AR00000000 SR00000000
 */
HWTEST_F(ClientMsgHandlerTest, OnTouch_touch, TestSize.Level1)
{
    ClientMsgHandlerSelf clientMsgHandlerSelf;
    clientMsgHandlerSelf.Init();
    clientMsgHandlerSelf.OnTouchUnitTest(INPUT_DEVICE_CAP_TOUCH);
}

/**
 * @tc.name: OnTouch_tabletTool
 * @tc.desc: detection create event:  INPUT_DEVICE_CAP_TABLET_TOOL
 * @tc.type: FUNC
 * @tc.require: AR00000000 SR00000000
 */
HWTEST_F(ClientMsgHandlerTest, OnTouch_tabletTool, TestSize.Level1)
{
    ClientMsgHandlerSelf clientMsgHandlerSelf;
    clientMsgHandlerSelf.Init();
    clientMsgHandlerSelf.OnTouchUnitTest(INPUT_DEVICE_CAP_TABLET_TOOL);
}

HWTEST_F(ClientMsgHandlerTest, OnTouch_StandardtabletPad, TestSize.Level1)
{
    ClientMsgHandlerSelf clientMsgHandlerSelf;
    clientMsgHandlerSelf.Init();
    clientMsgHandlerSelf.OnTouchStandardUnitTest(INPUT_DEVICE_CAP_TABLET_TOOL, 1);
}

/**
 * @tc.name: OnTouch_tabletPad
 * @tc.desc: detection create event:  INPUT_DEVICE_CAP_TABLET_PAD
 * @tc.type: FUNC
 * @tc.require: AR00000000 SR00000000
 */
HWTEST_F(ClientMsgHandlerTest, OnTouch_tabletPad, TestSize.Level1)
{
    ClientMsgHandlerSelf clientMsgHandlerSelf;
    clientMsgHandlerSelf.Init();
    clientMsgHandlerSelf.OnTouchUnitTest(INPUT_DEVICE_CAP_TABLET_PAD);
}

/**
 * @tc.name: OnTouch_capGesture
 * @tc.desc: detection create event:  INPUT_DEVICE_CAP_GESTURE
 * @tc.type: FUNC
 * @tc.require: AR00000000 SR00000000
 */
HWTEST_F(ClientMsgHandlerTest, OnTouch_capGesture, TestSize.Level1)
{
    ClientMsgHandlerSelf clientMsgHandlerSelf;
    clientMsgHandlerSelf.Init();
    clientMsgHandlerSelf.OnTouchUnitTest(INPUT_DEVICE_CAP_GESTURE);
}

/**
 * @tc.name: OnTouch_capSwitch
 * @tc.desc: detection create event:  INPUT_DEVICE_CAP_SWITCH
 * @tc.type: FUNC
 * @tc.require: AR00000000 SR00000000
 */
HWTEST_F(ClientMsgHandlerTest, OnTouch_capSwitch, TestSize.Level1)
{
    ClientMsgHandlerSelf clientMsgHandlerSelf;
    clientMsgHandlerSelf.Init();
    clientMsgHandlerSelf.OnTouchUnitTest(INPUT_DEVICE_CAP_SWITCH);
}

/**
 * @tc.name: OnTouch_capJoystick
 * @tc.desc: detection create event:  INPUT_DEVICE_CAP_JOYSTICK
 * @tc.type: FUNC
 * @tc.require: AR00000000 SR00000000
 */
HWTEST_F(ClientMsgHandlerTest, OnTouch_capJoystick, TestSize.Level1)
{
    ClientMsgHandlerSelf clientMsgHandlerSelf;
    clientMsgHandlerSelf.Init();
    clientMsgHandlerSelf.OnTouchUnitTest(INPUT_DEVICE_CAP_JOYSTICK);
}

HWTEST_F(ClientMsgHandlerTest, OnTouch2, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_TOUCH);

    int32_t typeNum = INPUT_DEVICE_CAP_TOUCH;
    int32_t dataSize = 3;
    int32_t abilityId = 4;
    int32_t screenId = 5;
    int32_t fileData = 6;
    uint64_t serverStartTime = 7;
    EventTouch touchData = {};
    CHK(EOK == memcpy_s(touchData.deviceName, MAX_DEVICENAME, "name", MAX_DEVICENAME),
        MEMCPY_SEC_FUN_FAIL);
    CHK(EOK == memcpy_s(touchData.devicePhys, MAX_DEVICENAME, "HOS_TouchScreen", MAX_DEVICENAME),
        MEMCPY_SEC_FUN_FAIL);
    CHK(EOK == memcpy_s(touchData.uuid, MAX_DEVICENAME, "12345", MAX_DEVICENAME),
        MEMCPY_SEC_FUN_FAIL);
    touchData.eventType = 500;
    touchData.time = 500;
    touchData.slot = 500;
    touchData.seat_slot = 500;
    touchData.deviceType = static_cast<HOS_DEVICE_TYPE>(0);

    netPacket << typeNum;
    netPacket << dataSize << abilityId << screenId << fileData << serverStartTime;
    netPacket << touchData;

    ClientMsgHandlerSelf clientMsgHandlerSelf;
    clientMsgHandlerSelf.Init();
    clientMsgHandlerSelf.OnTouchUnitTest2(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnTouch_capTouchPad, TestSize.Level1)
{
    ClientMsgHandlerSelf clientMsgHandlerSelf;
    clientMsgHandlerSelf.Init();
    clientMsgHandlerSelf.OnTouchUnitTest(INPUT_DEVICE_CAP_TOUCH_PAD);
}

/**
 * @tc.name: DeviceAdd
 * @tc.desc: detection create event:
 * @tc.type: FUNC
 * @tc.require: AR00000000 SR00000000
 */
HWTEST_F(ClientMsgHandlerTest, OnKey_001, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_KEY);

    ClientMsgHandlerSelf clientMsgHandlerSelf;
    clientMsgHandlerSelf.Init();
    clientMsgHandlerSelf.OnKeyUnitTest(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnCopy_001, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_COPY);

    ClientMsgHandlerSelf clientMsgHandlerSelf;
    clientMsgHandlerSelf.Init();
    clientMsgHandlerSelf.OnCopyUnitTest(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnCopy_002, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_COPY);

    int32_t typeNum = INPUT_DEVICE_CAP_JOYSTICK;
    int16_t idMsg = 3;
    int32_t aiDeviceFd = 4;
    int32_t fileData = 5;
    int32_t windowId = -1;
    int32_t abilityId = 7;
    uint64_t serverStartTime = 0;
    RegisteredEvent mixData = { 1, "abc123@34", 403, 10000, static_cast<HOS_DEVICE_TYPE>(7), "JOYSTICK" };

    netPacket << mixData;
    netPacket << typeNum;
    netPacket << idMsg << aiDeviceFd << fileData << windowId << abilityId << serverStartTime;

    ClientMsgHandlerSelf clientMsgHandlerSelf;
    clientMsgHandlerSelf.Init();
    clientMsgHandlerSelf.OnCopyUnitTest(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnCopy_003, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_COPY);

    int32_t typeNum = INPUT_DEVICE_CAP_AISENSOR;
    int16_t idMsg = 3;
    int32_t aiDeviceFd = 4;
    int32_t fileData = 5;
    int32_t windowId = -1;
    int32_t abilityId = 7;
    uint64_t serverStartTime = 0;
    RegisteredEvent mixData = { 1, "abc123@34", 300, 10000, static_cast<HOS_DEVICE_TYPE>(9), "aisensor" };

    netPacket << mixData;
    netPacket << typeNum;
    netPacket << idMsg << aiDeviceFd << fileData << windowId << abilityId << serverStartTime;

    ClientMsgHandlerSelf clientMsgHandlerSelf;
    clientMsgHandlerSelf.Init();
    clientMsgHandlerSelf.OnCopyUnitTest(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnCopy_004, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_COPY);

    int32_t typeNum = INPUT_DEVICE_CAP_AISENSOR;
    int16_t idMsg = 3;
    int32_t aiDeviceFd = 4;
    int32_t fileData = 5;
    int32_t windowId = -1;
    int32_t abilityId = 7;
    uint64_t serverStartTime = 0;

    netPacket << typeNum;
    netPacket << idMsg << aiDeviceFd << fileData << windowId << abilityId << serverStartTime;

    ClientMsgHandlerSelf clientMsgHandlerSelf;
    clientMsgHandlerSelf.Init();
    clientMsgHandlerSelf.OnCopyUnitTest(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnCopy_005, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_COPY);

    int32_t typeNum = INPUT_DEVICE_CAP_SWITCH;
    int32_t fileData = 11;
    int32_t windowId = -1;
    int32_t abilityId = 33;
    uint64_t serverStartTime = 44;
    RegisteredEvent mixData = { 1, "abc123@34", 300, 10000, static_cast<HOS_DEVICE_TYPE>(1), "keyboard" };
    netPacket >> typeNum;
    netPacket >> mixData >> fileData >> windowId >> abilityId >> serverStartTime;

    netPacket << typeNum;
    netPacket << mixData << fileData << windowId << abilityId << serverStartTime;

    ClientMsgHandlerSelf clientMsgHandlerSelf;
    clientMsgHandlerSelf.Init();
    clientMsgHandlerSelf.OnCopyUnitTest(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnShowMenu, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_SHOW_MENU);

    ClientMsgHandlerSelf clientMsgHandlerSelf;
    clientMsgHandlerSelf.Init();
    clientMsgHandlerSelf.OnShowMenuUnitTest(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnSend, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_SEND);

    ClientMsgHandlerSelf clientMsgHandlerSelf;
    clientMsgHandlerSelf.Init();
    clientMsgHandlerSelf.OnSendUnitTest(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnPaste, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_PASTE);

    ClientMsgHandlerSelf clientMsgHandlerSelf;
    clientMsgHandlerSelf.Init();
    clientMsgHandlerSelf.OnPasteUnitTest(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnCut, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_CUT);

    ClientMsgHandlerSelf clientMsgHandlerSelf;
    clientMsgHandlerSelf.Init();
    clientMsgHandlerSelf.OnCutUnitTest(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnUndo, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_UNDO);

    ClientMsgHandlerSelf clientMsgHandlerSelf;
    clientMsgHandlerSelf.Init();
    clientMsgHandlerSelf.OnUndoUnitTest(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnRefresh, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_REFRESH);

    ClientMsgHandlerSelf clientMsgHandlerSelf;
    clientMsgHandlerSelf.Init();
    clientMsgHandlerSelf.OnRefreshUnitTest(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnStartDrag, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_START_DRAG);

    ClientMsgHandlerSelf clientMsgHandlerSelf;
    clientMsgHandlerSelf.Init();
    clientMsgHandlerSelf.OnStartDragUnitTest(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnCancel, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_CANCEL);

    ClientMsgHandlerSelf clientMsgHandlerSelf;
    clientMsgHandlerSelf.Init();
    clientMsgHandlerSelf.OnCancelUnitTest(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnEnter, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_ENTER);

    ClientMsgHandlerSelf clientMsgHandlerSelf;
    clientMsgHandlerSelf.Init();
    clientMsgHandlerSelf.OnEnterUnitTest(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnPrevious, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_PREVIOUS);

    ClientMsgHandlerSelf clientMsgHandlerSelf;
    clientMsgHandlerSelf.Init();
    clientMsgHandlerSelf.OnPreviousUnitTest(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnNext, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_NEXT);

    ClientMsgHandlerSelf clientMsgHandlerSelf;
    clientMsgHandlerSelf.Init();
    clientMsgHandlerSelf.OnNextUnitTest(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnBack, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_BACK);

    ClientMsgHandlerSelf clientMsgHandlerSelf;
    clientMsgHandlerSelf.Init();
    clientMsgHandlerSelf.OnBackUnitTest(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnPrint, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_PRINT);

    ClientMsgHandlerSelf clientMsgHandlerSelf;
    clientMsgHandlerSelf.Init();
    clientMsgHandlerSelf.OnPrintUnitTest(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnPlay, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_PLAY);

    ClientMsgHandlerSelf clientMsgHandlerSelf;
    clientMsgHandlerSelf.Init();
    clientMsgHandlerSelf.OnPlayUnitTest(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnPause, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_PAUSE);

    ClientMsgHandlerSelf clientMsgHandlerSelf;
    clientMsgHandlerSelf.Init();
    clientMsgHandlerSelf.OnPauseUnitTest(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMediaControl, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_MEDIA_CONTROL);

    ClientMsgHandlerSelf clientMsgHandlerSelf;
    clientMsgHandlerSelf.Init();
    clientMsgHandlerSelf.OnMediaControlUnitTest(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnScreenShot, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_SCREEN_SHOT);

    ClientMsgHandlerSelf clientMsgHandlerSelf;
    clientMsgHandlerSelf.Init();
    clientMsgHandlerSelf.OnScreenShotUnitTest(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnScreenSplit, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_SCREEN_SPLIT);

    ClientMsgHandlerSelf clientMsgHandlerSelf;
    clientMsgHandlerSelf.Init();
    clientMsgHandlerSelf.OnScreenSplitUnitTest(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnStartScreenRecord, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_START_SCREEN_RECORD);

    ClientMsgHandlerSelf clientMsgHandlerSelf;
    clientMsgHandlerSelf.Init();
    clientMsgHandlerSelf.OnStartScreenRecordUnitTest(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnStopScreenRecord, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_STOP_SCREEN_RECORD);

    ClientMsgHandlerSelf clientMsgHandlerSelf;
    clientMsgHandlerSelf.Init();
    clientMsgHandlerSelf.OnStopScreenRecordUnitTest(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnGotoDesktop, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_GOTO_DESKTOP);

    ClientMsgHandlerSelf clientMsgHandlerSelf;
    clientMsgHandlerSelf.Init();
    clientMsgHandlerSelf.OnGotoDesktopUnitTest(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnRecent, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_RECENT);

    ClientMsgHandlerSelf clientMsgHandlerSelf;
    clientMsgHandlerSelf.Init();
    clientMsgHandlerSelf.OnRecentUnitTest(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnShowNotification, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_SHOW_NOTIFICATION);

    ClientMsgHandlerSelf clientMsgHandlerSelf;
    clientMsgHandlerSelf.Init();
    clientMsgHandlerSelf.OnShowNotificationUnitTest(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnLockScreen, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_LOCK_SCREEN);

    ClientMsgHandlerSelf clientMsgHandlerSelf;
    clientMsgHandlerSelf.Init();
    clientMsgHandlerSelf.OnLockScreenUnitTest(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnSearch, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_SEARCH);

    ClientMsgHandlerSelf clientMsgHandlerSelf;
    clientMsgHandlerSelf.Init();
    clientMsgHandlerSelf.OnSearchUnitTest(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnClosePage, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_CLOSE_PAGE);

    ClientMsgHandlerSelf clientMsgHandlerSelf;
    clientMsgHandlerSelf.Init();
    clientMsgHandlerSelf.OnClosePageUnitTest(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnLaunchVoiceAssistant, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_LAUNCH_VOICE_ASSISTANT);

    ClientMsgHandlerSelf clientMsgHandlerSelf;
    clientMsgHandlerSelf.Init();
    clientMsgHandlerSelf.OnLaunchVoiceAssistantUnitTest(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnMute, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_MUTE);

    ClientMsgHandlerSelf clientMsgHandlerSelf;
    clientMsgHandlerSelf.Init();
    clientMsgHandlerSelf.OnMuteUnitTest(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnAnswer, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_ANSWER);

    ClientMsgHandlerSelf clientMsgHandlerSelf;
    clientMsgHandlerSelf.Init();
    clientMsgHandlerSelf.OnAnswerUnitTest(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnRefuse, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_REFUSE);

    ClientMsgHandlerSelf clientMsgHandlerSelf;
    clientMsgHandlerSelf.Init();
    clientMsgHandlerSelf.OnRefuseUnitTest(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnHangup, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_HANG_UP);

    ClientMsgHandlerSelf clientMsgHandlerSelf;
    clientMsgHandlerSelf.Init();
    clientMsgHandlerSelf.OnHangupUnitTest(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, OnTelephoneControl, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_TELEPHONE_CONTROL);

    ClientMsgHandlerSelf clientMsgHandlerSelf;
    clientMsgHandlerSelf.Init();
    clientMsgHandlerSelf.OnTelephoneControlUnitTest(clientObj, netPacket);
}

HWTEST_F(ClientMsgHandlerTest, GetMultimodeInputInfo, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::GET_MMI_INFO_ACK);

    ClientMsgHandlerSelf clientMsgHandlerSelf;
    clientMsgHandlerSelf.Init();
    clientMsgHandlerSelf.GetMultimodeInputInfoUnitTest(clientObj, netPacket);
}

/**
 * @tc.name: DeviceAdd
 * @tc.desc: detection create event:
 * @tc.type: FUNC
 * @tc.require: AR00000000 SR00000000
 */
HWTEST_F(ClientMsgHandlerTest, DeviceAdd, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_DEVICE_ADDED);

    ClientMsgHandlerSelf clientMsgHandlerSelf;
    clientMsgHandlerSelf.Init();
    clientMsgHandlerSelf.DeviceAddUnitTest(clientObj, netPacket);
}

/**
 * @tc.name: DeviceRemove
 * @tc.desc: detection create event:
 * @tc.type: FUNC
 * @tc.require: AR00000000 SR00000000
 */
HWTEST_F(ClientMsgHandlerTest, DeviceRemove, TestSize.Level1)
{
    TestMMIClient clientObj;
    NetPacket netPacket(MmiMessageId::ON_DEVICE_REMOVED);

    ClientMsgHandlerSelf clientMsgHandlerSelf;
    clientMsgHandlerSelf.Init();
    clientMsgHandlerSelf.DeviceRemoveUnitTest(clientObj, netPacket);
}
} // namespace
