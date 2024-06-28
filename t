[1mdiff --git a/BUILD.gn b/BUILD.gn[m
[1mindex d1dcd7002..497e4e5a8 100644[m
[1m--- a/BUILD.gn[m
[1m+++ b/BUILD.gn[m
[36m@@ -145,6 +145,7 @@[m [mgroup("mmi_tests") {[m
     "frameworks/proxy:InputManagerInjectTest",[m
     "frameworks/proxy:InputManagerManualTest",[m
     "frameworks/proxy:InputManagerTest",[m
[32m+[m[32m    "frameworks/proxy:InputManagerPointerTest",[m
     "frameworks/proxy:KeyEventTest",[m
     "frameworks/proxy:PointerEventTest",[m
     "frameworks/proxy:ut-mmi-proxy-out",[m
[1mdiff --git a/frameworks/proxy/BUILD.gn b/frameworks/proxy/BUILD.gn[m
[1mindex ebdb0fe6a..7755c45c2 100644[m
[1m--- a/frameworks/proxy/BUILD.gn[m
[1m+++ b/frameworks/proxy/BUILD.gn[m
[36m@@ -404,32 +404,6 @@[m [mohos_unittest("InputManagerTest") {[m
   ][m
 }[m
 [m
[31m-ohos_unittest("InputManagerPointerTest") {[m
[31m-  module_out_path = module_output_path[m
[31m-[m
[31m-  sources = [ "events/test/input_manager_pointer_test.cpp" ][m
[31m-[m
[31m-  configs = [[m
[31m-    "${mmi_path}:coverage_flags",[m
[31m-    ":libmmi_test_util",[m
[31m-  ][m
[31m-[m
[31m-  deps = [[m
[31m-    "${mmi_path}/frameworks/proxy:libmmi-client",[m
[31m-    "${mmi_path}/util:libmmi-util",[m
[31m-    "//third_party/googletest:gmock_main",[m
[31m-    "//third_party/googletest:gtest_main",[m
[31m-  ][m
[31m-  external_deps = [[m
[31m-    "access_token:libaccesstoken_sdk",[m
[31m-    "access_token:libnativetoken",[m
[31m-    "access_token:libtoken_setproc",[m
[31m-    "c_utils:utils",[m
[31m-    "hilog:libhilog",[m
[31m-    "ipc:ipc_single",[m
[31m-  ][m
[31m-}[m
[31m-[m
 ohos_unittest("InputManagerInjectTest") {[m
   module_out_path = module_output_path[m
   include_dirs = [[m
[1mdiff --git a/service/connect_manager/test/multimodal_input_connect_stub_ex_test.cpp b/service/connect_manager/test/multimodal_input_connect_stub_ex_test.cpp[m
[1mindex 42200d3c6..36293cbae 100644[m
[1m--- a/service/connect_manager/test/multimodal_input_connect_stub_ex_test.cpp[m
[1m+++ b/service/connect_manager/test/multimodal_input_connect_stub_ex_test.cpp[m
[36m@@ -6899,5 +6899,96 @@[m [mHWTEST_F(MultimodalInputConnectStubTest, StubAddVirtualInputDevice_004, TestSize[m
     MessageParcel reply;[m
     EXPECT_NO_FATAL_FAILURE(stub->StubAddVirtualInputDevice(data, reply));[m
 }[m
[32m+[m
[32m+[m[32m/**[m
[32m+[m[32m * @tc.name: StubGetTouchpadThreeFingersTapSwitch_001[m
[32m+[m[32m * @tc.desc: Test the function StubGetTouchpadThreeFingersTapSwitch[m
[32m+[m[32m * @tc.type: FUNC[m
[32m+[m[32m * @tc.require:[m
[32m+[m[32m */[m
[32m+[m[32mHWTEST_F(MultimodalInputConnectStubTest, StubGetTouchpadThreeFingersTapSwitch_001, TestSize.Level1)[m
[32m+[m[32m{[m
[32m+[m[32m    CALL_TEST_DEBUG;[m
[32m+[m[32m    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(false));[m
[32m+[m[32m    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();[m
[32m+[m[32m    ASSERT_NE(stub, nullptr);[m
[32m+[m[32m    MessageParcel data;[m
[32m+[m[32m    MessageParcel reply;[m
[32m+[m[32m    EXPECT_NO_FATAL_FAILURE(stub->StubGetTouchpadThreeFingersTapSwitch(data, reply));[m
[32m+[m[32m}[m
[32m+[m
[32m+[m[32m/**[m
[32m+[m[32m * @tc.name: StubGetTouchpadThreeFingersTapSwitch_002[m
[32m+[m[32m * @tc.desc: Test the function StubGetTouchpadThreeFingersTapSwitch[m
[32m+[m[32m * @tc.type: FUNC[m
[32m+[m[32m * @tc.require:[m
[32m+[m[32m */[m
[32m+[m[32mHWTEST_F(MultimodalInputConnectStubTest, StubGetTouchpadThreeFingersTapSwitch_002, TestSize.Level1)[m
[32m+[m[32m{[m
[32m+[m[32m    CALL_TEST_DEBUG;[m
[32m+[m[32m    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));[m
[32m+[m[32m    EXPECT_CALL(*messageParcelMock_, WriteBool(_)).WillOnce(Return(true));[m
[32m+[m[32m    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();[m
[32m+[m[32m    ASSERT_NE(stub, nullptr);[m
[32m+[m[32m    MessageParcel data;[m
[32m+[m[32m    MessageParcel reply;[m
[32m+[m[32m    EXPECT_NO_FATAL_FAILURE(stub->StubGetTouchpadThreeFingersTapSwitch(data, reply));[m
[32m+[m[32m}[m
[32m+[m
[32m+[m[32m/**[m
[32m+[m[32m * @tc.name: StubGetTouchpadThreeFingersTapSwitch_003[m
[32m+[m[32m * @tc.desc: Test the function StubGetTouchpadThreeFingersTapSwitch[m
[32m+[m[32m * @tc.type: FUNC[m
[32m+[m[32m * @tc.require:[m
[32m+[m[32m */[m
[32m+[m[32mHWTEST_F(MultimodalInputConnectStubTest, StubGetTouchpadThreeFingersTapSwitch_003, TestSize.Level1)[m
[32m+[m[32m{[m
[32m+[m[32m    CALL_TEST_DEBUG;[m
[32m+[m[32m    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));[m
[32m+[m[32m    EXPECT_CALL(*messageParcelMock_, WriteBool(_)).WillOnce(Return(true));[m
[32m+[m[32m    EXPECT_CALL(*messageParcelMock_, ReadBool(_)).WillOnce(Return(true));[m
[32m+[m[32m    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();[m
[32m+[m[32m    ASSERT_NE(stub, nullptr);[m
[32m+[m[32m    MessageParcel data;[m
[32m+[m[32m    MessageParcel reply;[m
[32m+[m[32m    EXPECT_NO_FATAL_FAILURE(stub->StubGetTouchpadThreeFingersTapSwitch(data, reply));[m
[32m+[m[32m}[m
[32m+[m
[32m+[m[32m/**[m
[32m+[m[32m * @tc.name: StubSetTouchpadThreeFingersTapSwitch_001[m
[32m+[m[32m * @tc.desc: Test the function StubSetTouchpadThreeFingersTapSwitch[m
[32m+[m[32m * @tc.type: FUNC[m
[32m+[m[32m * @tc.require:[m
[32m+[m[32m */[m
[32m+[m[32mHWTEST_F(MultimodalInputConnectStubTest, StubSetTouchpadThreeFingersTapSwitch_001, TestSize.Level1)[m
[32m+[m[32m{[m
[32m+[m[32m    CALL_TEST_DEBUG;[m
[32m+[m[32m    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(false));[m
[32m+[m[32m    EXPECT_CALL(*messageParcelMock_, ReadBool(_)).WillOnce(Return(true));[m
[32m+[m[32m    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();[m
[32m+[m[32m    ASSERT_NE(stub, nullptr);[m
[32m+[m[32m    MessageParcel data;[m
[32m+[m[32m    MessageParcel reply;[m
[32m+[m[32m    EXPECT_NO_FATAL_FAILURE(stub->StubSetTouchpadThreeFingersTapSwitch(data, reply));[m
[32m+[m[32m}[m
[32m+[m
[32m+[m[32m/**[m
[32m+[m[32m * @tc.name: StubSetTouchpadThreeFingersTapSwitch_002[m
[32m+[m[32m * @tc.desc: Test the function StubSetTouchpadThreeFingersTapSwitch[m
[32m+[m[32m * @tc.type: FUNC[m
[32m+[m[32m * @tc.require:[m
[32m+[m[32m */[m
[32m+[m[32mHWTEST_F(MultimodalInputConnectStubTest, StubSetTouchpadThreeFingersTapSwitch_002, TestSize.Level1)[m
[32m+[m[32m{[m
[32m+[m[32m    CALL_TEST_DEBUG;[m
[32m+[m[32m    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(false));[m
[32m+[m[32m    EXPECT_CALL(*messageParcelMock_, ReadBool(_)).WillOnce(Return(true));[m
[32m+[m[32m    EXPECT_CALL(*messageParcelMock_, ReadBool(_)).WillOnce(Return(true));[m
[32m+[m[32m    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();[m
[32m+[m[32m    ASSERT_NE(stub, nullptr);[m
[32m+[m[32m    MessageParcel data;[m
[32m+[m[32m    MessageParcel reply;[m
[32m+[m[32m    EXPECT_NO_FATAL_FAILURE(stub->StubSetTouchpadThreeFingersTapSwitch(data, reply));[m
[32m+[m[32m}[m
 } // namespace MMI[m
 } // namespace OHOS[m
\ No newline at end of file[m
