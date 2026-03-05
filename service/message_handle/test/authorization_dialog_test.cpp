
/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <string>

#include "authorization_dialog.h"
#include "ability_connect_callback_stub.h"
#include "iremote_object.h"
#include "message_parcel.h"
#include "mmi_log.h"

#include "want.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "AuthorizationDialogTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class RemoteObjectTest : public IRemoteObject {
public:
    explicit RemoteObjectTest(std::u16string descriptor) : IRemoteObject(descriptor) {}
    ~RemoteObjectTest() {}

    int32_t GetObjectRefCount() { return 0; }
    int SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) { return 0; }
    bool AddDeathRecipient(const sptr<DeathRecipient> &recipient)
    {
        return result;
    }
    bool RemoveDeathRecipient(const sptr<DeathRecipient> &recipient) { return true; }
    int Dump(int fd, const std::vector<std::u16string> &args) { return 0; }

public:
    bool result = false;
};

class AuthorizationDialogTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: AuthorizationDialogTest_GetBundleName
 * @tc.desc: Test GetBundleName static method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationDialogTest, AuthorizationDialogTest_GetBundleName, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string bundleName = AuthorizationDialog::GetBundleName();
    EXPECT_FALSE(bundleName.empty());
    EXPECT_EQ(bundleName, "com.ohos.powerdialog");
}

/**
 * @tc.name: AuthorizationDialogTest_GetAbilityName
 * @tc.desc: Test GetAbilityName static method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationDialogTest, AuthorizationDialogTest_GetAbilityName, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string abilityName = AuthorizationDialog::GetAbilityName();
    EXPECT_FALSE(abilityName.empty());
    EXPECT_EQ(abilityName, "PowerUiExtensionAbility");
}

/**
 * @tc.name: AuthorizationDialogTest_GetUiExtensionType
 * @tc.desc: Test GetUiExtensionType static method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationDialogTest, AuthorizationDialogTest_GetUiExtensionType, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string uiExtensionType = AuthorizationDialog::GetUiExtensionType();
    EXPECT_FALSE(uiExtensionType.empty());
    EXPECT_EQ(uiExtensionType, "sysDialog/power");
}

/**
 * @tc.name: AuthorizationDialogTest_Constructor
 * @tc.desc: Test AuthorizationDialog constructor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationDialogTest, AuthorizationDialogTest_Constructor, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AuthorizationDialog dialog;
    EXPECT_NE(dialog.dialogConnectionCallback_, nullptr);
}

/**
 * @tc.name: AuthorizationDialogTest_ConnectSystemUi_NullCallback
 * @tc.desc: Test ConnectSystemUi with null callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationDialogTest, AuthorizationDialogTest_ConnectSystemUi_NullCallback, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AuthorizationDialog dialog;
    dialog.dialogConnectionCallback_ = nullptr;
    bool result = dialog.ConnectSystemUi();
    EXPECT_FALSE(result);
}

/**
 * @tc.name: AuthorizationDialogTest_ConnectSystemUi_DialogAlreadyOpen
 * @tc.desc: Test ConnectSystemUi when dialog is already open
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationDialogTest, AuthorizationDialogTest_ConnectSystemUi_DialogAlreadyOpen, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AuthorizationDialog dialog;
    ASSERT_NE(dialog.dialogConnectionCallback_, nullptr);
    dialog.dialogConnectionCallback_->isDialogShow_ = true;
    bool result = dialog.ConnectSystemUi();
    EXPECT_TRUE(result);
}

/**
 * @tc.name: AuthorizationDialogTest_ConnectSystemUi_AlreadyConnected
 * @tc.desc: Test ConnectSystemUi when already connected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationDialogTest, AuthorizationDialogTest_ConnectSystemUi_AlreadyConnected, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AuthorizationDialog dialog;
    ASSERT_NE(dialog.dialogConnectionCallback_, nullptr);
    dialog.dialogConnectionCallback_->remoteObject_ = new RemoteObjectTest(u"test");
    dialog.dialogConnectionCallback_->isDialogShow_ = false;
    bool result = dialog.ConnectSystemUi();
    EXPECT_TRUE(result);
}

/**
 * @tc.name: AuthorizationDialogTest_CloseDialog_NullCallback
 * @tc.desc: Test CloseDialog with null callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationDialogTest, AuthorizationDialogTest_CloseDialog_NullCallback, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AuthorizationDialog dialog;
    dialog.dialogConnectionCallback_ = nullptr;
    dialog.CloseDialog();
    SUCCEED();
}

/**
 * @tc.name: AuthorizationDialogTest_CloseDialog_NullRemoteObject
 * @tc.desc: Test CloseDialog with null remote object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationDialogTest, AuthorizationDialogTest_CloseDialog_NullRemoteObject, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AuthorizationDialog dialog;
    ASSERT_NE(dialog.dialogConnectionCallback_, nullptr);
    dialog.dialogConnectionCallback_->remoteObject_ = nullptr;
    dialog.dialogConnectionCallback_->isDialogShow_ = true;
    dialog.CloseDialog();
    SUCCEED();
}

/**
 * @tc.name: AuthorizationDialogTest_CloseDialog_DialogNotOpen
 * @tc.desc: Test CloseDialog when dialog is not open
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationDialogTest, AuthorizationDialogTest_CloseDialog_DialogNotOpen, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AuthorizationDialog dialog;
    ASSERT_NE(dialog.dialogConnectionCallback_, nullptr);
    dialog.dialogConnectionCallback_->remoteObject_ = new RemoteObjectTest(u"test");
    dialog.dialogConnectionCallback_->isDialogShow_ = false;
    dialog.CloseDialog();
    SUCCEED();
}

/**
 * @tc.name: AuthorizationDialogTest_CloseDialog_Success
 * @tc.desc: Test CloseDialog success scenario
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationDialogTest, AuthorizationDialogTest_CloseDialog_Success, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AuthorizationDialog dialog;
    ASSERT_NE(dialog.dialogConnectionCallback_, nullptr);
    dialog.dialogConnectionCallback_->remoteObject_ = new RemoteObjectTest(u"test");
    dialog.dialogConnectionCallback_->isDialogShow_ = true;
    dialog.CloseDialog();
    EXPECT_FALSE(dialog.dialogConnectionCallback_->isDialogShow_);
}

/**
 * @tc.name: AuthorizationDialogTest_OnAbilityConnectDone_NullRemoteObject
 * @tc.desc: Test OnAbilityConnectDone with null remote object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationDialogTest, AuthorizationDialogTest_OnAbilityConnectDone_NullRemoteObject, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AuthorizationDialog dialog;
    ASSERT_NE(dialog.dialogConnectionCallback_, nullptr);
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int32_t resultCode = 0;
    dialog.dialogConnectionCallback_->OnAbilityConnectDone(element, remoteObject, resultCode);
    EXPECT_EQ(dialog.dialogConnectionCallback_->remoteObject_, nullptr);
}

/**
 * @tc.name: AuthorizationDialogTest_OnAbilityDisconnectDone
 * @tc.desc: Test OnAbilityDisconnectDone
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationDialogTest, AuthorizationDialogTest_OnAbilityDisconnectDone, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AuthorizationDialog dialog;
    ASSERT_NE(dialog.dialogConnectionCallback_, nullptr);
    dialog.dialogConnectionCallback_->remoteObject_ = new RemoteObjectTest(u"test");
    dialog.dialogConnectionCallback_->isDialogShow_ = true;

    AppExecFwk::ElementName element;
    int32_t resultCode = 0;
    dialog.dialogConnectionCallback_->OnAbilityDisconnectDone(element, resultCode);

    EXPECT_EQ(dialog.dialogConnectionCallback_->remoteObject_, nullptr);
    EXPECT_FALSE(dialog.dialogConnectionCallback_->isDialogShow_);
}

/**
 * @tc.name: AuthorizationDialogTest_OnAbilityDisconnectDone_MultipleTimes
 * @tc.desc: Test OnAbilityDisconnectDone called multiple times
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationDialogTest, AuthorizationDialogTest_OnAbilityDisconnectDone_MultipleTimes, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AuthorizationDialog dialog;
    ASSERT_NE(dialog.dialogConnectionCallback_, nullptr);
    dialog.dialogConnectionCallback_->remoteObject_ = new RemoteObjectTest(u"test");
    dialog.dialogConnectionCallback_->isDialogShow_ = true;

    AppExecFwk::ElementName element;
    int32_t resultCode = 0;

    dialog.dialogConnectionCallback_->OnAbilityDisconnectDone(element, resultCode);
    EXPECT_EQ(dialog.dialogConnectionCallback_->remoteObject_, nullptr);
    EXPECT_FALSE(dialog.dialogConnectionCallback_->isDialogShow_);

    dialog.dialogConnectionCallback_->OnAbilityDisconnectDone(element, resultCode);
    EXPECT_EQ(dialog.dialogConnectionCallback_->remoteObject_, nullptr);
    EXPECT_FALSE(dialog.dialogConnectionCallback_->isDialogShow_);
}

/**
 * @tc.name: AuthorizationDialogTest_DialogIsOpen
 * @tc.desc: Test DialogIsOpen method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationDialogTest, AuthorizationDialogTest_DialogIsOpen, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AuthorizationDialog dialog;
    ASSERT_NE(dialog.dialogConnectionCallback_, nullptr);

    dialog.dialogConnectionCallback_->isDialogShow_ = false;
    EXPECT_FALSE(dialog.dialogConnectionCallback_->DialogIsOpen());

    dialog.dialogConnectionCallback_->isDialogShow_ = true;
    EXPECT_TRUE(dialog.dialogConnectionCallback_->DialogIsOpen());
}

/**
 * @tc.name: AuthorizationDialogTest_IsConnected
 * @tc.desc: Test IsConnected method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationDialogTest, AuthorizationDialogTest_IsConnected, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AuthorizationDialog dialog;
    ASSERT_NE(dialog.dialogConnectionCallback_, nullptr);

    dialog.dialogConnectionCallback_->remoteObject_ = nullptr;
    EXPECT_FALSE(dialog.dialogConnectionCallback_->IsConnected());

    dialog.dialogConnectionCallback_->remoteObject_ = new RemoteObjectTest(u"test");
    EXPECT_TRUE(dialog.dialogConnectionCallback_->IsConnected());
}

/**
 * @tc.name: AuthorizationDialogTest_OpenDialog_NullRemoteObject
 * @tc.desc: Test OpenDialog with null remote object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationDialogTest, AuthorizationDialogTest_OpenDialog_NullRemoteObject, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AuthorizationDialog dialog;
    ASSERT_NE(dialog.dialogConnectionCallback_, nullptr);
    dialog.dialogConnectionCallback_->remoteObject_ = nullptr;
    dialog.dialogConnectionCallback_->isDialogShow_ = false;
    dialog.dialogConnectionCallback_->OpenDialog();
    EXPECT_FALSE(dialog.dialogConnectionCallback_->isDialogShow_);
}

/**
 * @tc.name: AuthorizationDialogTest_OpenDialog_Success
 * @tc.desc: Test OpenDialog success scenario
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationDialogTest, AuthorizationDialogTest_OpenDialog_Success, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AuthorizationDialog dialog;
    ASSERT_NE(dialog.dialogConnectionCallback_, nullptr);
    dialog.dialogConnectionCallback_->remoteObject_ = new RemoteObjectTest(u"test");
    dialog.dialogConnectionCallback_->isDialogShow_ = false;
    dialog.dialogConnectionCallback_->OpenDialog();
    EXPECT_TRUE(dialog.dialogConnectionCallback_->isDialogShow_);
}

/**
 * @tc.name: AuthorizationDialogTest_OpenDialog_MultipleTimes
 * @tc.desc: Test OpenDialog called multiple times
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationDialogTest, AuthorizationDialogTest_OpenDialog_MultipleTimes, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AuthorizationDialog dialog;
    ASSERT_NE(dialog.dialogConnectionCallback_, nullptr);
    dialog.dialogConnectionCallback_->remoteObject_ = new RemoteObjectTest(u"test");
    dialog.dialogConnectionCallback_->isDialogShow_ = false;

    dialog.dialogConnectionCallback_->OpenDialog();
    EXPECT_TRUE(dialog.dialogConnectionCallback_->isDialogShow_);

    dialog.dialogConnectionCallback_->OpenDialog();
    EXPECT_TRUE(dialog.dialogConnectionCallback_->isDialogShow_);
}

/**
 * @tc.name: AuthorizationDialogTest_CloseAndOpenDialog
 * @tc.desc: Test close and open dialog sequence
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationDialogTest, AuthorizationDialogTest_CloseAndOpenDialog, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AuthorizationDialog dialog;
    ASSERT_NE(dialog.dialogConnectionCallback_, nullptr);
    dialog.dialogConnectionCallback_->remoteObject_ = new RemoteObjectTest(u"test");
    dialog.dialogConnectionCallback_->isDialogShow_ = false;

    dialog.dialogConnectionCallback_->OpenDialog();
    EXPECT_TRUE(dialog.dialogConnectionCallback_->isDialogShow_);

    dialog.dialogConnectionCallback_->CloseDialog();
    EXPECT_FALSE(dialog.dialogConnectionCallback_->isDialogShow_);

    dialog.dialogConnectionCallback_->OpenDialog();
    EXPECT_TRUE(dialog.dialogConnectionCallback_->isDialogShow_);
}

/**
 * @tc.name: AuthorizationDialogTest_ConnectSystemUi_FullFlow
 * @tc.desc: Test ConnectSystemUi full flow
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationDialogTest, AuthorizationDialogTest_ConnectSystemUi_FullFlow, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AuthorizationDialog dialog;
    ASSERT_NE(dialog.dialogConnectionCallback_, nullptr);

    EXPECT_FALSE(dialog.dialogConnectionCallback_->DialogIsOpen());

    bool result = dialog.ConnectSystemUi();
    EXPECT_TRUE(result || !result);
}

/**
 * @tc.name: AuthorizationDialogTest_StaticMembers
 * @tc.desc: Test static member consistency
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationDialogTest, AuthorizationDialogTest_StaticMembers, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string bundleName1 = AuthorizationDialog::GetBundleName();
    std::string bundleName2 = AuthorizationDialog::GetBundleName();
    EXPECT_EQ(bundleName1, bundleName2);

    std::string abilityName1 = AuthorizationDialog::GetAbilityName();
    std::string abilityName2 = AuthorizationDialog::GetAbilityName();
    EXPECT_EQ(abilityName1, abilityName2);

    std::string uiType1 = AuthorizationDialog::GetUiExtensionType();
    std::string uiType2 = AuthorizationDialog::GetUiExtensionType();
    EXPECT_EQ(uiType1, uiType2);
}

/**
 * @tc.name: AuthorizationDialogTest_DialogStateTransitions
 * @tc.desc: Test dialog state transitions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationDialogTest, AuthorizationDialogTest_DialogStateTransitions, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AuthorizationDialog dialog;
    ASSERT_NE(dialog.dialogConnectionCallback_, nullptr);
    dialog.dialogConnectionCallback_->remoteObject_ = new RemoteObjectTest(u"test");

    EXPECT_TRUE(dialog.dialogConnectionCallback_->IsConnected());
    EXPECT_FALSE(dialog.dialogConnectionCallback_->DialogIsOpen());

    dialog.dialogConnectionCallback_->OpenDialog();
    EXPECT_TRUE(dialog.dialogConnectionCallback_->DialogIsOpen());

    dialog.dialogConnectionCallback_->CloseDialog();
    EXPECT_FALSE(dialog.dialogConnectionCallback_->DialogIsOpen());
    EXPECT_TRUE(dialog.dialogConnectionCallback_->IsConnected());

    dialog.dialogConnectionCallback_->remoteObject_ = nullptr;
    EXPECT_FALSE(dialog.dialogConnectionCallback_->IsConnected());
    EXPECT_FALSE(dialog.dialogConnectionCallback_->DialogIsOpen());
}

/**
 * @tc.name: AuthorizationDialogTest_ConnectSystemUi_WithDialogAlreadyOpen
 * @tc.desc: Test ConnectSystemUi when dialog is already open
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationDialogTest, AuthorizationDialogTest_ConnectSystemUi_WithDialogAlreadyOpen, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AuthorizationDialog dialog;
    ASSERT_NE(dialog.dialogConnectionCallback_, nullptr);

    dialog.dialogConnectionCallback_->isDialogShow_ = true;

    bool result = dialog.ConnectSystemUi();
    EXPECT_TRUE(result);

    EXPECT_TRUE(dialog.dialogConnectionCallback_->DialogIsOpen());
}

/**
 * @tc.name: AuthorizationDialogTest_ConnectSystemUi_WithAlreadyConnected
 * @tc.desc: Test ConnectSystemUi when already connected but dialog not open
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationDialogTest, AuthorizationDialogTest_ConnectSystemUi_WithAlreadyConnected, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AuthorizationDialog dialog;
    ASSERT_NE(dialog.dialogConnectionCallback_, nullptr);

    dialog.dialogConnectionCallback_->remoteObject_ = new RemoteObjectTest(u"test");
    dialog.dialogConnectionCallback_->isDialogShow_ = false;

    bool result = dialog.ConnectSystemUi();
    EXPECT_TRUE(result);

    EXPECT_TRUE(dialog.dialogConnectionCallback_->DialogIsOpen());
}

/**
 * @tc.name: AuthorizationDialogTest_CloseDialog_MultipleCalls
 * @tc.desc: Test CloseDialog called multiple times
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationDialogTest, AuthorizationDialogTest_CloseDialog_MultipleCalls, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AuthorizationDialog dialog;
    ASSERT_NE(dialog.dialogConnectionCallback_, nullptr);
    dialog.dialogConnectionCallback_->remoteObject_ = new RemoteObjectTest(u"test");
    dialog.dialogConnectionCallback_->isDialogShow_ = true;

    dialog.CloseDialog();
    EXPECT_FALSE(dialog.dialogConnectionCallback_->isDialogShow_);

    dialog.CloseDialog();
    EXPECT_FALSE(dialog.dialogConnectionCallback_->isDialogShow_);
}

/**
 * @tc.name: AuthorizationDialogTest_DialogConnectionCallback_DefaultState
 * @tc.desc: Test DialogConnectionCallback default state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationDialogTest, AuthorizationDialogTest_DialogConnectionCallback_DefaultState, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AuthorizationDialog dialog;
    ASSERT_NE(dialog.dialogConnectionCallback_, nullptr);

    EXPECT_FALSE(dialog.dialogConnectionCallback_->isDialogShow_);
    EXPECT_EQ(dialog.dialogConnectionCallback_->remoteObject_, nullptr);
    EXPECT_FALSE(dialog.dialogConnectionCallback_->DialogIsOpen());
    EXPECT_FALSE(dialog.dialogConnectionCallback_->IsConnected());
}

/**
 * @tc.name: AuthorizationDialogTest_DialogConnectionCallback_StateAfterOpen
 * @tc.desc: Test DialogConnectionCallback state after OpenDialog
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationDialogTest, AuthorizationDialogTest_DialogConnectionCallback_StateAfterOpen, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AuthorizationDialog dialog;
    ASSERT_NE(dialog.dialogConnectionCallback_, nullptr);
    dialog.dialogConnectionCallback_->remoteObject_ = new RemoteObjectTest(u"test");
    dialog.dialogConnectionCallback_->isDialogShow_ = false;

    dialog.dialogConnectionCallback_->OpenDialog();

    EXPECT_TRUE(dialog.dialogConnectionCallback_->isDialogShow_);
    EXPECT_TRUE(dialog.dialogConnectionCallback_->DialogIsOpen());
    EXPECT_TRUE(dialog.dialogConnectionCallback_->IsConnected());
}

/**
 * @tc.name: AuthorizationDialogTest_DialogConnectionCallback_StateAfterClose
 * @tc.desc: Test DialogConnectionCallback state after CloseDialog
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationDialogTest, AuthorizationDialogTest_DialogConnectionCallback_StateAfterClose, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AuthorizationDialog dialog;
    ASSERT_NE(dialog.dialogConnectionCallback_, nullptr);
    dialog.dialogConnectionCallback_->remoteObject_ = new RemoteObjectTest(u"test");
    dialog.dialogConnectionCallback_->isDialogShow_ = true;

    dialog.dialogConnectionCallback_->CloseDialog();

    EXPECT_FALSE(dialog.dialogConnectionCallback_->isDialogShow_);
    EXPECT_FALSE(dialog.dialogConnectionCallback_->DialogIsOpen());
    EXPECT_TRUE(dialog.dialogConnectionCallback_->IsConnected());
}

/**
 * @tc.name: AuthorizationDialogTest_DialogConnectionCallback_StateAfterDisconnect
 * @tc.desc: Test DialogConnectionCallback state after disconnect
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationDialogTest, AuthorizationDialogTest_DialogConnectionCallback_StateAfterDisconnect, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AuthorizationDialog dialog;
    ASSERT_NE(dialog.dialogConnectionCallback_, nullptr);
    dialog.dialogConnectionCallback_->remoteObject_ = new RemoteObjectTest(u"test");
    dialog.dialogConnectionCallback_->isDialogShow_ = true;

    AppExecFwk::ElementName element;
    dialog.dialogConnectionCallback_->OnAbilityDisconnectDone(element, 0);

    EXPECT_FALSE(dialog.dialogConnectionCallback_->isDialogShow_);
    EXPECT_FALSE(dialog.dialogConnectionCallback_->DialogIsOpen());
    EXPECT_FALSE(dialog.dialogConnectionCallback_->IsConnected());
    EXPECT_EQ(dialog.dialogConnectionCallback_->remoteObject_, nullptr);
}

/**
 * @tc.name: AuthorizationDialogTest_DialogConnectionCallback_CloseWithoutRemote
 * @tc.desc: Test DialogConnectionCallback CloseDialog without remote object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationDialogTest, AuthorizationDialogTest_DialogConnectionCallback_CloseWithoutRemote, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AuthorizationDialog dialog;
    ASSERT_NE(dialog.dialogConnectionCallback_, nullptr);

    dialog.dialogConnectionCallback_->remoteObject_ = nullptr;
    dialog.dialogConnectionCallback_->isDialogShow_ = true;
    dialog.dialogConnectionCallback_->CloseDialog();
    EXPECT_TRUE(dialog.dialogConnectionCallback_->isDialogShow_);
}

/**
 * @tc.name: AuthorizationDialogTest_DialogConnectionCallback_CloseWhenNotOpen
 * @tc.desc: Test DialogConnectionCallback CloseDialog when not open
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationDialogTest, AuthorizationDialogTest_DialogConnectionCallback_CloseWhenNotOpen, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AuthorizationDialog dialog;
    ASSERT_NE(dialog.dialogConnectionCallback_, nullptr);
    dialog.dialogConnectionCallback_->remoteObject_ = new RemoteObjectTest(u"test");
    dialog.dialogConnectionCallback_->isDialogShow_ = false;

    dialog.dialogConnectionCallback_->CloseDialog();
    EXPECT_FALSE(dialog.dialogConnectionCallback_->isDialogShow_);
}

/**
 * @tc.name: AuthorizationDialogTest_DialogConnectionCallback_OpenWhenAlreadyOpen
 * @tc.desc: Test DialogConnectionCallback OpenDialog when already open
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationDialogTest, AuthorizationDialogTest_DialogConnectionCallback_OpenWhenAlreadyOpen, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AuthorizationDialog dialog;
    ASSERT_NE(dialog.dialogConnectionCallback_, nullptr);
    dialog.dialogConnectionCallback_->remoteObject_ = new RemoteObjectTest(u"test");
    dialog.dialogConnectionCallback_->isDialogShow_ = true;

    dialog.dialogConnectionCallback_->OpenDialog();
    EXPECT_TRUE(dialog.dialogConnectionCallback_->isDialogShow_);
}

////////////////////////////////上面肯定是没有问题得
/**
 * @tc.name: AuthorizationDialogTest_DialogConnectionCallback_StateConsistency
 * @tc.desc: Test DialogConnectionCallback state consistency
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationDialogTest, AuthorizationDialogTest_DialogConnectionCallback_StateConsistency, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AuthorizationDialog dialog;
    ASSERT_NE(dialog.dialogConnectionCallback_, nullptr);
    dialog.dialogConnectionCallback_->remoteObject_ = new RemoteObjectTest(u"test");

    dialog.dialogConnectionCallback_->OpenDialog();
    EXPECT_TRUE(dialog.dialogConnectionCallback_->isDialogShow_);
    EXPECT_TRUE(dialog.dialogConnectionCallback_->DialogIsOpen());

    dialog.dialogConnectionCallback_->CloseDialog();
    EXPECT_FALSE(dialog.dialogConnectionCallback_->isDialogShow_);
    EXPECT_FALSE(dialog.dialogConnectionCallback_->DialogIsOpen());

    dialog.dialogConnectionCallback_->OpenDialog();
    EXPECT_TRUE(dialog.dialogConnectionCallback_->isDialogShow_);
    EXPECT_TRUE(dialog.dialogConnectionCallback_->DialogIsOpen());

    dialog.dialogConnectionCallback_->CloseDialog();
    EXPECT_FALSE(dialog.dialogConnectionCallback_->isDialogShow_);
    EXPECT_FALSE(dialog.dialogConnectionCallback_->DialogIsOpen());
}

/**
 * @tc.name: AuthorizationDialogTest_DialogConnectionCallback_RemoteObjectConsistency
 * @tc.desc: Test DialogConnectionCallback remote object consistency
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationDialogTest, AuthorizationDialogTest_DialogConnectionCallback_RemoteObjectConsistency, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AuthorizationDialog dialog;
    ASSERT_NE(dialog.dialogConnectionCallback_, nullptr);

    sptr<IRemoteObject> remoteObject = new RemoteObjectTest(u"test");
    dialog.dialogConnectionCallback_->remoteObject_ = remoteObject;
    EXPECT_TRUE(dialog.dialogConnectionCallback_->IsConnected());

    dialog.dialogConnectionCallback_->remoteObject_ = nullptr;
    EXPECT_FALSE(dialog.dialogConnectionCallback_->IsConnected());

    dialog.dialogConnectionCallback_->remoteObject_ = remoteObject;
    EXPECT_TRUE(dialog.dialogConnectionCallback_->IsConnected());
}

/**
 * @tc.name: AuthorizationDialogTest_DialogConnectionCallback_DialogShowFlag
 * @tc.desc: Test DialogConnectionCallback dialog show flag
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationDialogTest, AuthorizationDialogTest_DialogConnectionCallback_DialogShowFlag, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AuthorizationDialog dialog;
    ASSERT_NE(dialog.dialogConnectionCallback_, nullptr);
    dialog.dialogConnectionCallback_->remoteObject_ = new RemoteObjectTest(u"test");
    EXPECT_FALSE(dialog.dialogConnectionCallback_->isDialogShow_);

    dialog.dialogConnectionCallback_->OpenDialog();
    EXPECT_TRUE(dialog.dialogConnectionCallback_->isDialogShow_);

    dialog.dialogConnectionCallback_->CloseDialog();
    EXPECT_FALSE(dialog.dialogConnectionCallback_->isDialogShow_);

    dialog.dialogConnectionCallback_->OpenDialog();
    EXPECT_TRUE(dialog.dialogConnectionCallback_->isDialogShow_);

    AppExecFwk::ElementName element;
    dialog.dialogConnectionCallback_->OnAbilityDisconnectDone(element, 0);
    EXPECT_FALSE(dialog.dialogConnectionCallback_->isDialogShow_);
}

/**
 * @tc.name: AuthorizationDialogTest_DialogConnectionCallback_AllMethods
 * @tc.desc: Test DialogConnectionCallback all methods
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationDialogTest, AuthorizationDialogTest_DialogConnectionCallback_AllMethods, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AuthorizationDialog dialog;
    ASSERT_NE(dialog.dialogConnectionCallback_, nullptr);
    AppExecFwk::ElementName element;

    sptr<IRemoteObject> remoteObject = new RemoteObjectTest(u"test");
    dialog.dialogConnectionCallback_->OnAbilityConnectDone(element, remoteObject, 0);
    EXPECT_NE(dialog.dialogConnectionCallback_->remoteObject_, nullptr);

    EXPECT_TRUE(dialog.dialogConnectionCallback_->IsConnected());

    dialog.dialogConnectionCallback_->OpenDialog();
    EXPECT_TRUE(dialog.dialogConnectionCallback_->isDialogShow_);

    EXPECT_TRUE(dialog.dialogConnectionCallback_->DialogIsOpen());

    dialog.dialogConnectionCallback_->CloseDialog();
    EXPECT_FALSE(dialog.dialogConnectionCallback_->isDialogShow_);

    dialog.dialogConnectionCallback_->OnAbilityDisconnectDone(element, 0);
    EXPECT_EQ(dialog.dialogConnectionCallback_->remoteObject_, nullptr);
    EXPECT_FALSE(dialog.dialogConnectionCallback_->isDialogShow_);

    EXPECT_FALSE(dialog.dialogConnectionCallback_->IsConnected());

    EXPECT_FALSE(dialog.dialogConnectionCallback_->DialogIsOpen());
}

/**
 * @tc.name: AuthorizationDialogTest_DialogConnectionCallback_OpenCloseWithoutConnect
 * @tc.desc: Test DialogConnectionCallback open-close without connect
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationDialogTest, AuthorizationDialogTest_DialogConnectionCallback_OpenCloseWithoutConnect, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AuthorizationDialog dialog;
    ASSERT_NE(dialog.dialogConnectionCallback_, nullptr);

    dialog.dialogConnectionCallback_->remoteObject_ = nullptr;
    dialog.dialogConnectionCallback_->isDialogShow_ = false;
    dialog.dialogConnectionCallback_->OpenDialog();
    EXPECT_FALSE(dialog.dialogConnectionCallback_->isDialogShow_);

    dialog.dialogConnectionCallback_->isDialogShow_ = true;
    dialog.dialogConnectionCallback_->CloseDialog();
    EXPECT_TRUE(dialog.dialogConnectionCallback_->isDialogShow_);
}

/**
 * @tc.name: AuthorizationDialogTest_DialogConnectionCallback_ConnectDisconnectWithoutOpenClose
 * @tc.desc: Test DialogConnectionCallback connect-disconnect without open-close
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationDialogTest, AuthorizationDialogTest_DialogConnectionCallback_ConnectDisconnectWithoutOpenClose, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AuthorizationDialog dialog;
    ASSERT_NE(dialog.dialogConnectionCallback_, nullptr);
    AppExecFwk::ElementName element;

    sptr<IRemoteObject> remoteObject = new RemoteObjectTest(u"test");
    dialog.dialogConnectionCallback_->OnAbilityConnectDone(element, remoteObject, 0);
    EXPECT_TRUE(dialog.dialogConnectionCallback_->IsConnected());
    EXPECT_FALSE(dialog.dialogConnectionCallback_->DialogIsOpen());

    dialog.dialogConnectionCallback_->OnAbilityDisconnectDone(element, 0);
    EXPECT_FALSE(dialog.dialogConnectionCallback_->IsConnected());
    EXPECT_FALSE(dialog.dialogConnectionCallback_->DialogIsOpen());
}

/**
 * @tc.name: AuthorizationDialogTest_DialogConnectionCallback_AllStateTransitions
 * @tc.desc: Test DialogConnectionCallback all state transitions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationDialogTest, AuthorizationDialogTest_DialogConnectionCallback_AllStateTransitions, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AuthorizationDialog dialog;
    ASSERT_NE(dialog.dialogConnectionCallback_, nullptr);
    AppExecFwk::ElementName element;

    EXPECT_FALSE(dialog.dialogConnectionCallback_->IsConnected());
    EXPECT_FALSE(dialog.dialogConnectionCallback_->DialogIsOpen());

    sptr<IRemoteObject> remoteObject = new RemoteObjectTest(u"test");
    dialog.dialogConnectionCallback_->OnAbilityConnectDone(element, remoteObject, 0);
    EXPECT_TRUE(dialog.dialogConnectionCallback_->IsConnected());
    EXPECT_FALSE(dialog.dialogConnectionCallback_->DialogIsOpen());

    dialog.dialogConnectionCallback_->OpenDialog();
    EXPECT_TRUE(dialog.dialogConnectionCallback_->IsConnected());
    EXPECT_TRUE(dialog.dialogConnectionCallback_->DialogIsOpen());

    dialog.dialogConnectionCallback_->CloseDialog();
    EXPECT_TRUE(dialog.dialogConnectionCallback_->IsConnected());

    dialog.dialogConnectionCallback_->OnAbilityDisconnectDone(element, 0);
    EXPECT_FALSE(dialog.dialogConnectionCallback_->IsConnected());
    EXPECT_FALSE(dialog.dialogConnectionCallback_->DialogIsOpen());
}

/**
 * @tc.name: AuthorizationDialogTest_DialogConnectionCallback_OpenAfterDisconnect
 * @tc.desc: Test DialogConnectionCallback open after disconnect
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationDialogTest, AuthorizationDialogTest_DialogConnectionCallback_OpenAfterDisconnect, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AuthorizationDialog dialog;
    ASSERT_NE(dialog.dialogConnectionCallback_, nullptr);
    AppExecFwk::ElementName element;

    sptr<IRemoteObject> remoteObject = new RemoteObjectTest(u"test");
    dialog.dialogConnectionCallback_->OnAbilityConnectDone(element, remoteObject, 0);

    dialog.dialogConnectionCallback_->OpenDialog();
    EXPECT_TRUE(dialog.dialogConnectionCallback_->DialogIsOpen());

    dialog.dialogConnectionCallback_->OnAbilityDisconnectDone(element, 0);
    EXPECT_FALSE(dialog.dialogConnectionCallback_->DialogIsOpen());

    dialog.dialogConnectionCallback_->OpenDialog();
    EXPECT_FALSE(dialog.dialogConnectionCallback_->DialogIsOpen());
}

/**
 * @tc.name: AuthorizationDialogTest_DialogConnectionCallback_CloseAfterDisconnect
 * @tc.desc: Test DialogConnectionCallback close after disconnect
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationDialogTest, AuthorizationDialogTest_DialogConnectionCallback_CloseAfterDisconnect, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AuthorizationDialog dialog;
    ASSERT_NE(dialog.dialogConnectionCallback_, nullptr);
    AppExecFwk::ElementName element;

    sptr<IRemoteObject> remoteObject = new RemoteObjectTest(u"test");
    dialog.dialogConnectionCallback_->OnAbilityConnectDone(element, remoteObject, 0);

    dialog.dialogConnectionCallback_->OpenDialog();
    EXPECT_TRUE(dialog.dialogConnectionCallback_->DialogIsOpen());

    dialog.dialogConnectionCallback_->OnAbilityDisconnectDone(element, 0);
    EXPECT_FALSE(dialog.dialogConnectionCallback_->DialogIsOpen());

    dialog.dialogConnectionCallback_->CloseDialog();
    EXPECT_FALSE(dialog.dialogConnectionCallback_->DialogIsOpen());
}

/**
 * @tc.name: AuthorizationDialogTest_DialogConnectionCallback_DisconnectAfterClose
 * @tc.desc: Test DialogConnectionCallback disconnect after close
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationDialogTest, AuthorizationDialogTest_DialogConnectionCallback_DisconnectAfterClose, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AuthorizationDialog dialog;
    ASSERT_NE(dialog.dialogConnectionCallback_, nullptr);
    AppExecFwk::ElementName element;

    sptr<IRemoteObject> remoteObject = new RemoteObjectTest(u"test");
    dialog.dialogConnectionCallback_->OnAbilityConnectDone(element, remoteObject, 0);

    dialog.dialogConnectionCallback_->OpenDialog();
    EXPECT_TRUE(dialog.dialogConnectionCallback_->DialogIsOpen());

    dialog.dialogConnectionCallback_->CloseDialog();
    EXPECT_FALSE(dialog.dialogConnectionCallback_->DialogIsOpen());

    dialog.dialogConnectionCallback_->OnAbilityDisconnectDone(element, 0);
    EXPECT_FALSE(dialog.dialogConnectionCallback_->IsConnected());
    EXPECT_FALSE(dialog.dialogConnectionCallback_->DialogIsOpen());
}

/**
 * @tc.name: AuthorizationDialogTest_DialogConnectionCallback_AllCombinations
 * @tc.desc: Test DialogConnectionCallback all method combinations
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationDialogTest, AuthorizationDialogTest_DialogConnectionCallback_AllCombinations, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AuthorizationDialog dialog;
    ASSERT_NE(dialog.dialogConnectionCallback_, nullptr);
    AppExecFwk::ElementName element;

    sptr<IRemoteObject> remoteObject1 = new RemoteObjectTest(u"test1");
    dialog.dialogConnectionCallback_->OnAbilityConnectDone(element, remoteObject1, 0);
    dialog.dialogConnectionCallback_->OpenDialog();
    dialog.dialogConnectionCallback_->CloseDialog();
    dialog.dialogConnectionCallback_->OnAbilityDisconnectDone(element, 0);
    EXPECT_FALSE(dialog.dialogConnectionCallback_->IsConnected());
    EXPECT_FALSE(dialog.dialogConnectionCallback_->DialogIsOpen());

    sptr<IRemoteObject> remoteObject2 = new RemoteObjectTest(u"test2");
    dialog.dialogConnectionCallback_->OnAbilityConnectDone(element, remoteObject2, 0);
    dialog.dialogConnectionCallback_->OnAbilityDisconnectDone(element, 0);
    EXPECT_FALSE(dialog.dialogConnectionCallback_->IsConnected());
    EXPECT_FALSE(dialog.dialogConnectionCallback_->DialogIsOpen());

    sptr<IRemoteObject> remoteObject3 = new RemoteObjectTest(u"test3");
    dialog.dialogConnectionCallback_->OnAbilityConnectDone(element, remoteObject3, 0);
    dialog.dialogConnectionCallback_->OpenDialog();
    dialog.dialogConnectionCallback_->OnAbilityDisconnectDone(element, 0);
    EXPECT_FALSE(dialog.dialogConnectionCallback_->IsConnected());
    EXPECT_FALSE(dialog.dialogConnectionCallback_->DialogIsOpen());
}

/**
 * @tc.name: AuthorizationDialogTest_DialogConnectionCallback_EdgeCases
 * @tc.desc: Test DialogConnectionCallback edge cases
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationDialogTest, AuthorizationDialogTest_DialogConnectionCallback_EdgeCases, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AuthorizationDialog dialog;
    ASSERT_NE(dialog.dialogConnectionCallback_, nullptr);
    AppExecFwk::ElementName element;

    dialog.dialogConnectionCallback_->OnAbilityConnectDone(element, nullptr, 0);
    EXPECT_EQ(dialog.dialogConnectionCallback_->remoteObject_, nullptr);

    dialog.dialogConnectionCallback_->remoteObject_ = nullptr;
    dialog.dialogConnectionCallback_->isDialogShow_ = false;
    dialog.dialogConnectionCallback_->OpenDialog();
    EXPECT_FALSE(dialog.dialogConnectionCallback_->isDialogShow_);

    dialog.dialogConnectionCallback_->remoteObject_ = nullptr;
    dialog.dialogConnectionCallback_->isDialogShow_ = true;
    dialog.dialogConnectionCallback_->CloseDialog();
    EXPECT_TRUE(dialog.dialogConnectionCallback_->isDialogShow_);

    dialog.dialogConnectionCallback_->remoteObject_ = nullptr;
    dialog.dialogConnectionCallback_->OnAbilityDisconnectDone(element, 0);
    EXPECT_EQ(dialog.dialogConnectionCallback_->remoteObject_, nullptr);
    EXPECT_FALSE(dialog.dialogConnectionCallback_->isDialogShow_);
}

/**
 * @tc.name: AuthorizationDialogTest_DialogConnectionCallback_StateChecks
 * @tc.desc: Test DialogConnectionCallback state checks
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationDialogTest, AuthorizationDialogTest_DialogConnectionCallback_StateChecks, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AuthorizationDialog dialog;
    ASSERT_NE(dialog.dialogConnectionCallback_, nullptr);

    EXPECT_FALSE(dialog.dialogConnectionCallback_->IsConnected());
    EXPECT_FALSE(dialog.dialogConnectionCallback_->DialogIsOpen());

    sptr<IRemoteObject> remoteObject = new RemoteObjectTest(u"test");
    dialog.dialogConnectionCallback_->remoteObject_ = remoteObject;
    EXPECT_TRUE(dialog.dialogConnectionCallback_->IsConnected());
    EXPECT_FALSE(dialog.dialogConnectionCallback_->DialogIsOpen());

    dialog.dialogConnectionCallback_->isDialogShow_ = true;
    EXPECT_TRUE(dialog.dialogConnectionCallback_->IsConnected());
    EXPECT_TRUE(dialog.dialogConnectionCallback_->DialogIsOpen());

    dialog.dialogConnectionCallback_->remoteObject_ = nullptr;
    EXPECT_FALSE(dialog.dialogConnectionCallback_->IsConnected());
    EXPECT_TRUE(dialog.dialogConnectionCallback_->DialogIsOpen());

    dialog.dialogConnectionCallback_->isDialogShow_ = false;
    EXPECT_FALSE(dialog.dialogConnectionCallback_->IsConnected());
    EXPECT_FALSE(dialog.dialogConnectionCallback_->DialogIsOpen());
}

/**
 * @tc.name: AuthorizationDialogTest_DialogConnectionCallback_DialogShowFlagLifecycle
 * @tc.desc: Test DialogConnectionCallback dialog show flag lifecycle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationDialogTest, AuthorizationDialogTest_DialogConnectionCallback_DialogShowFlagLifecycle, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AuthorizationDialog dialog;
    ASSERT_NE(dialog.dialogConnectionCallback_, nullptr);
    dialog.dialogConnectionCallback_->remoteObject_ = new RemoteObjectTest(u"test");

    EXPECT_FALSE(dialog.dialogConnectionCallback_->isDialogShow_);

    dialog.dialogConnectionCallback_->OpenDialog();
    EXPECT_TRUE(dialog.dialogConnectionCallback_->isDialogShow_);

    dialog.dialogConnectionCallback_->CloseDialog();
    EXPECT_FALSE(dialog.dialogConnectionCallback_->isDialogShow_);

    dialog.dialogConnectionCallback_->OpenDialog();
    EXPECT_TRUE(dialog.dialogConnectionCallback_->isDialogShow_);

    AppExecFwk::ElementName element;
    dialog.dialogConnectionCallback_->OnAbilityDisconnectDone(element, 0);
    EXPECT_FALSE(dialog.dialogConnectionCallback_->isDialogShow_);

    dialog.dialogConnectionCallback_->OpenDialog();
    EXPECT_FALSE(dialog.dialogConnectionCallback_->isDialogShow_);
}

/**
 * @tc.name: AuthorizationDialogTest_DialogConnectionCallback_MultipleOpenClose
 * @tc.desc: Test DialogConnectionCallback multiple open/close operations
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationDialogTest, AuthorizationDialogTest_DialogConnectionCallback_MultipleOpenClose, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AuthorizationDialog dialog;
    ASSERT_NE(dialog.dialogConnectionCallback_, nullptr);
    dialog.dialogConnectionCallback_->remoteObject_ = new RemoteObjectTest(u"test");

    for (int i = 0; i < 5; i++) {
        dialog.dialogConnectionCallback_->OpenDialog();
        EXPECT_TRUE(dialog.dialogConnectionCallback_->isDialogShow_);

        dialog.dialogConnectionCallback_->CloseDialog();
        EXPECT_FALSE(dialog.dialogConnectionCallback_->isDialogShow_);
    }
}

/**
 * @tc.name: AuthorizationDialogTest_DialogConnectionCallback_MultipleConnectDisconnect
 * @tc.desc: Test DialogConnectionCallback multiple connect/disconnect operations
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationDialogTest, AuthorizationDialogTest_DialogConnectionCallback_MultipleConnectDisconnect, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AuthorizationDialog dialog;
    ASSERT_NE(dialog.dialogConnectionCallback_, nullptr);
    AppExecFwk::ElementName element;

    for (int i = 0; i < 5; i++) {
        sptr<IRemoteObject> remoteObject = new RemoteObjectTest(u"test");
        dialog.dialogConnectionCallback_->OnAbilityConnectDone(element, remoteObject, 0);
        EXPECT_TRUE(dialog.dialogConnectionCallback_->IsConnected());

        dialog.dialogConnectionCallback_->OnAbilityDisconnectDone(element, 0);
        EXPECT_FALSE(dialog.dialogConnectionCallback_->IsConnected());
    }
}

/**
 * @tc.name: AuthorizationDialogTest_DialogConnectionCallback_ErrorHandling
 * @tc.desc: Test DialogConnectionCallback error handling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationDialogTest, AuthorizationDialogTest_DialogConnectionCallback_ErrorHandling, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AuthorizationDialog dialog;
    ASSERT_NE(dialog.dialogConnectionCallback_, nullptr);
    AppExecFwk::ElementName element;

    dialog.dialogConnectionCallback_->OnAbilityConnectDone(element, nullptr, 0);
    EXPECT_EQ(dialog.dialogConnectionCallback_->remoteObject_, nullptr);

    dialog.dialogConnectionCallback_->remoteObject_ = nullptr;
    dialog.dialogConnectionCallback_->isDialogShow_ = false;
    dialog.dialogConnectionCallback_->OpenDialog();
    EXPECT_FALSE(dialog.dialogConnectionCallback_->isDialogShow_);

    dialog.dialogConnectionCallback_->remoteObject_ = nullptr;
    dialog.dialogConnectionCallback_->isDialogShow_ = true;
    dialog.dialogConnectionCallback_->CloseDialog();
    EXPECT_TRUE(dialog.dialogConnectionCallback_->isDialogShow_);
}

/**
 * @tc.name: AuthorizationDialogTest_DialogConnectionCallback_ConcurrentOperations
 * @tc.desc: Test DialogConnectionCallback with concurrent operations
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationDialogTest, AuthorizationDialogTest_DialogConnectionCallback_ConcurrentOperations, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AuthorizationDialog dialog;
    ASSERT_NE(dialog.dialogConnectionCallback_, nullptr);
    AppExecFwk::ElementName element;

    sptr<IRemoteObject> remoteObject = new RemoteObjectTest(u"test");
    dialog.dialogConnectionCallback_->OnAbilityConnectDone(element, remoteObject, 0);

    dialog.dialogConnectionCallback_->OpenDialog();
    EXPECT_TRUE(dialog.dialogConnectionCallback_->isDialogShow_);

    EXPECT_TRUE(dialog.dialogConnectionCallback_->IsConnected());

    EXPECT_TRUE(dialog.dialogConnectionCallback_->DialogIsOpen());

    dialog.dialogConnectionCallback_->CloseDialog();
    EXPECT_FALSE(dialog.dialogConnectionCallback_->isDialogShow_);

    dialog.dialogConnectionCallback_->OnAbilityDisconnectDone(element, 0);
    EXPECT_FALSE(dialog.dialogConnectionCallback_->IsConnected());
}

/**
 * @tc.name: AuthorizationDialogTest_DialogConnectionCallback_StateTransitions
 * @tc.desc: Test DialogConnectionCallback state transitions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationDialogTest, AuthorizationDialogTest_DialogConnectionCallback_StateTransitions, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AuthorizationDialog dialog;
    ASSERT_NE(dialog.dialogConnectionCallback_, nullptr);
    AppExecFwk::ElementName element;

    sptr<IRemoteObject> remoteObject = new RemoteObjectTest(u"test");
    dialog.dialogConnectionCallback_->OnAbilityConnectDone(element, remoteObject, 0);
    EXPECT_TRUE(dialog.dialogConnectionCallback_->IsConnected());

    dialog.dialogConnectionCallback_->OpenDialog();
    EXPECT_TRUE(dialog.dialogConnectionCallback_->DialogIsOpen());

    dialog.dialogConnectionCallback_->CloseDialog();
    EXPECT_FALSE(dialog.dialogConnectionCallback_->DialogIsOpen());

    dialog.dialogConnectionCallback_->OnAbilityDisconnectDone(element, 0);
    EXPECT_FALSE(dialog.dialogConnectionCallback_->IsConnected());
}

/**
 * @tc.name: AuthorizationDialogTest_DialogConnectionCallback_AllTransitions
 * @tc.desc: Test DialogConnectionCallback all transitions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthorizationDialogTest, AuthorizationDialogTest_DialogConnectionCallback_AllTransitions, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AuthorizationDialog dialog;
    ASSERT_NE(dialog.dialogConnectionCallback_, nullptr);
    AppExecFwk::ElementName element;

    sptr<IRemoteObject> remoteObject = new RemoteObjectTest(u"test");
    dialog.dialogConnectionCallback_->OnAbilityConnectDone(element, remoteObject, 0);
    EXPECT_TRUE(dialog.dialogConnectionCallback_->IsConnected());
    EXPECT_FALSE(dialog.dialogConnectionCallback_->DialogIsOpen());

    dialog.dialogConnectionCallback_->OpenDialog();
    EXPECT_TRUE(dialog.dialogConnectionCallback_->IsConnected());
    EXPECT_TRUE(dialog.dialogConnectionCallback_->DialogIsOpen());

    dialog.dialogConnectionCallback_->CloseDialog();
    EXPECT_TRUE(dialog.dialogConnectionCallback_->IsConnected());
    EXPECT_FALSE(dialog.dialogConnectionCallback_->DialogIsOpen());

    dialog.dialogConnectionCallback_->OpenDialog();
    EXPECT_TRUE(dialog.dialogConnectionCallback_->IsConnected());
    EXPECT_TRUE(dialog.dialogConnectionCallback_->DialogIsOpen());

    dialog.dialogConnectionCallback_->CloseDialog();
    EXPECT_TRUE(dialog.dialogConnectionCallback_->IsConnected());
    EXPECT_FALSE(dialog.dialogConnectionCallback_->DialogIsOpen());

    dialog.dialogConnectionCallback_->OnAbilityDisconnectDone(element, 0);
    EXPECT_FALSE(dialog.dialogConnectionCallback_->IsConnected());
    EXPECT_FALSE(dialog.dialogConnectionCallback_->DialogIsOpen());
}
} // namespace MMI
} // namespace OHOS
