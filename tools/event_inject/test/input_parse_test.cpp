/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include <cstring>
#include "input_parse.h"

namespace OHOS {
namespace MMI {
using namespace testing::ext;

class InputParseTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: GetJsonData_String_001
 * @tc.desc: Test GetJsonData with string value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputParseTest, GetJsonData_String_001, TestSize.Level1)
{
    const char* jsonStr = R"({"testKey":"testValue"})";
    cJSON* json = cJSON_Parse(jsonStr);
    ASSERT_NE(json, nullptr);

    std::string val;
    GetJsonData(json, "testKey", val);
    EXPECT_EQ(val, "testValue");

    cJSON_Delete(json);
}

/**
 * @tc.name: GetJsonData_String_InvalidJson_001
 * @tc.desc: Test GetJsonData with invalid json object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputParseTest, GetJsonData_String_InvalidJson_001, TestSize.Level1)
{
    cJSON* json = cJSON_CreateIntArray(nullptr, 0);
    std::string val;
    GetJsonData(json, "testKey", val); // Should not crash
    cJSON_Delete(json);
}

/**
 * @tc.name: GetJsonData_String_NoKey_001
 * @tc.desc: Test GetJsonData when key doesn't exist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputParseTest, GetJsonData_String_NoKey_001, TestSize.Level1)
{
    const char* jsonStr = R"({"otherKey":"otherValue"})";
    cJSON* json = cJSON_Parse(jsonStr);
    ASSERT_NE(json, nullptr);

    std::string val;
    GetJsonData(json, "testKey", val);
    EXPECT_TRUE(val.empty());

    cJSON_Delete(json);
}

/**
 * @tc.name: GetJsonData_Template_001
 * @tc.desc: Test GetJsonData template function with integer value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputParseTest, GetJsonData_Template_001, TestSize.Level1)
{
    const char* jsonStr = R"({"intValue":123})";
    cJSON* json = cJSON_Parse(jsonStr);
    ASSERT_NE(json, nullptr);

    int32_t val = 0;
    GetJsonData(json, "intValue", val);
    EXPECT_EQ(val, 123);

    cJSON_Delete(json);
}

/**
 * @tc.name: GetJsonData_Template_InvalidJson_001
 * @tc.desc: Test GetJsonData template function with invalid json
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputParseTest, GetJsonData_Template_InvalidJson_001, TestSize.Level1)
{
    cJSON* json = cJSON_CreateString("not_object");
    int32_t val = 0;
    GetJsonData(json, "intValue", val); // Should not crash
    cJSON_Delete(json);
}

/**
 * @tc.name: GetJsonData_Vector_001
 * @tc.desc: Test GetJsonData with vector values
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputParseTest, GetJsonData_Vector_001, TestSize.Level1)
{
    const char* jsonStr = R"({"array":[1,2,3]})";
    cJSON* json = cJSON_Parse(jsonStr);
    ASSERT_NE(json, nullptr);

    std::vector<int32_t> vals;
    GetJsonData(json, "array", vals);
    EXPECT_EQ(vals.size(), 3u);
    EXPECT_EQ(vals[0], 1);
    EXPECT_EQ(vals[1], 2);
    EXPECT_EQ(vals[2], 3);

    cJSON_Delete(json);
}

/**
 * @tc.name: GetJsonData_Vector_InvalidJson_001
 * @tc.desc: Test GetJsonData with vector when json is not object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputParseTest, GetJsonData_Vector_InvalidJson_001, TestSize.Level1)
{
    cJSON* json = cJSON_CreateString("invalid");
    std::vector<int32_t> vals;
    GetJsonData(json, "array", vals); // Should not crash
    cJSON_Delete(json);
}

/**
 * @tc.name: GetJsonData_Vector_NoKey_001
 * @tc.desc: Test GetJsonData with vector when key doesn't exist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputParseTest, GetJsonData_Vector_NoKey_001, TestSize.Level1)
{
    const char* jsonStr = R"({"otherKey":"value"})";
    cJSON* json = cJSON_Parse(jsonStr);
    ASSERT_NE(json, nullptr);

    std::vector<int32_t> vals;
    GetJsonData(json, "array", vals);
    EXPECT_TRUE(vals.empty());

    cJSON_Delete(json);
}

/**
 * @tc.name: GetJsonData_Vector_NotArray_001
 * @tc.desc: Test GetJsonData with vector when value is not array
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputParseTest, GetJsonData_Vector_NotArray_001, TestSize.Level1)
{
    const char* jsonStr = R"({"array":"not_array"})";
    cJSON* json = cJSON_Parse(jsonStr);
    ASSERT_NE(json, nullptr);

    std::vector<int32_t> vals;
    GetJsonData(json, "array", vals);
    EXPECT_TRUE(vals.empty());

    cJSON_Delete(json);
}

/**
 * @tc.name: ParseEvents_001
 * @tc.desc: Test ParseEvents with valid event array
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputParseTest, ParseEvents_001, TestSize.Level1)
{
    const char* jsonStr = R"([[100,200],[300,400]])";
    cJSON* eventInfo = cJSON_Parse(jsonStr);
    ASSERT_NE(eventInfo, nullptr);

    DeviceEvent event;
    bool result = ParseEvents(eventInfo, event);
    EXPECT_TRUE(result);
    EXPECT_EQ(event.posXY.size(), 2u);
    EXPECT_EQ(event.posXY[0].xPos, 100);
    EXPECT_EQ(event.posXY[0].yPos, 200);
    EXPECT_EQ(event.posXY[1].xPos, 300);
    EXPECT_EQ(event.posXY[1].yPos, 400);

    cJSON_Delete(eventInfo);
}

/**
 * @tc.name: ParseEvents_InvalidArray_001
 * @tc.desc: Test ParseEvents with invalid event array
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputParseTest, ParseEvents_InvalidArray_001, TestSize.Level1)
{
    cJSON* eventInfo = cJSON_CreateString("not_array");
    DeviceEvent event;
    bool result = ParseEvents(eventInfo, event);
    EXPECT_FALSE(result);
    cJSON_Delete(eventInfo);
}

/**
 * @tc.name: ParseEvents_InvalidXPos_001
 * @tc.desc: Test ParseEvents with invalid xPos
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputParseTest, ParseEvents_InvalidXPos_001, TestSize.Level1)
{
    const char* jsonStr = R"([["invalid",200]])";
    cJSON* eventInfo = cJSON_Parse(jsonStr);
    ASSERT_NE(eventInfo, nullptr);

    DeviceEvent event;
    bool result = ParseEvents(eventInfo, event);
    EXPECT_FALSE(result);

    cJSON_Delete(eventInfo);
}

/**
 * @tc.name: ParseEvents_InvalidYPos_001
 * @tc.desc: Test ParseEvents with invalid yPos
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputParseTest, ParseEvents_InvalidYPos_001, TestSize.Level1)
{
    const char* jsonStr = R"([[100,"invalid"]])";
    cJSON* eventInfo = cJSON_Parse(jsonStr);
    ASSERT_NE(eventInfo, nullptr);

    DeviceEvent event;
    bool result = ParseEvents(eventInfo, event);
    EXPECT_FALSE(result);

    cJSON_Delete(eventInfo);
}

/**
 * @tc.name: ParseEventsObj_001
 * @tc.desc: Test ParseEventsObj with valid object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputParseTest, ParseEventsObj_001, TestSize.Level1)
{
    const char* jsonStr = R"({
        "eventType": "touch",
        "event": [1,2,3],
        "keyValue": 65,
        "blockTime": 100,
        "ringEvents": [4,5,6],
        "direction": 1,
        "distance": 50,
        "xPos": 100,
        "yPos": 200,
        "tiltX": 10,
        "tiltY": 20,
        "pressure": 255,
        "trackingId": 1,
        "reportType": 2,
        "keyStatus": 1
    })";
    cJSON* eventInfo = cJSON_Parse(jsonStr);
    ASSERT_NE(eventInfo, nullptr);

    DeviceEvent event;
    ParseEventsObj(eventInfo, event);
    
    EXPECT_EQ(event.eventType, "touch");
    EXPECT_EQ(event.event.size(), 3u);
    EXPECT_EQ(event.keyValue, 65);
    EXPECT_EQ(event.blockTime, 100);
    EXPECT_EQ(event.ringEvents.size(), 3u);
    EXPECT_EQ(event.direction, 1);
    EXPECT_EQ(event.distance, 50);
    EXPECT_EQ(event.xPos, 100);
    EXPECT_EQ(event.yPos, 200);
    EXPECT_EQ(event.tiltX, 10);
    EXPECT_EQ(event.tiltY, 20);
    EXPECT_EQ(event.pressure, 255);
    EXPECT_EQ(event.trackingId, 1);
    EXPECT_EQ(event.reportType, 2);
    EXPECT_EQ(event.keyStatus, 1);

    cJSON_Delete(eventInfo);
}

/**
 * @tc.name: ParseEventsObj_InvalidJson_001
 * @tc.desc: Test ParseEventsObj with invalid json
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputParseTest, ParseEventsObj_InvalidJson_001, TestSize.Level1)
{
    cJSON* eventInfo = cJSON_CreateString("invalid");
    DeviceEvent event;
    ParseEventsObj(eventInfo, event); // Should not crash
    cJSON_Delete(eventInfo);
}

/**
 * @tc.name: ParseData_Array_001
 * @tc.desc: Test ParseData with array events
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputParseTest, ParseData_Array_001, TestSize.Level1)
{
    const char* jsonStr = R"([
        [[100,200],[300,400]],
        [[500,600]]
    ])";
    cJSON* events = cJSON_Parse(jsonStr);
    ASSERT_NE(events, nullptr);

    std::vector<DeviceEvent> eventData;
    bool result = ParseData(events, eventData);
    EXPECT_TRUE(result);
    EXPECT_EQ(eventData.size(), 2u);
    EXPECT_EQ(eventData[0].posXY.size(), 2u);
    EXPECT_EQ(eventData[1].posXY.size(), 1u);

    cJSON_Delete(events);
}

/**
 * @tc.name: ParseData_Object_001
 * @tc.desc: Test ParseData with object events
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputParseTest, ParseData_Object_001, TestSize.Level1)
{
    const char* jsonStr = R"([
        {"eventType": "touch", "xPos": 100},
        {"eventType": "key", "keyValue": 65}
    ])";
    cJSON* events = cJSON_Parse(jsonStr);
    ASSERT_NE(events, nullptr);

    std::vector<DeviceEvent> eventData;
    bool result = ParseData(events, eventData);
    EXPECT_TRUE(result);
    EXPECT_EQ(eventData.size(), 2u);
    EXPECT_EQ(eventData[0].eventType, "touch");
    EXPECT_EQ(eventData[0].xPos, 100);
    EXPECT_EQ(eventData[1].eventType, "key");
    EXPECT_EQ(eventData[1].keyValue, 65);

    cJSON_Delete(events);
}

/**
 * @tc.name: ParseData_InvalidArray_001
 * @tc.desc: Test ParseData with invalid events array
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputParseTest, ParseData_InvalidArray_001, TestSize.Level1)
{
    cJSON* events = cJSON_CreateString("invalid");
    std::vector<DeviceEvent> eventData;
    bool result = ParseData(events, eventData);
    EXPECT_FALSE(result);
    cJSON_Delete(events);
}

/**
 * @tc.name: ParseData_InvalidEvent_001
 * @tc.desc: Test ParseData with invalid event type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputParseTest, ParseData_InvalidEvent_001, TestSize.Level1)
{
    const char* jsonStr = R"(["invalid_event_type"])";
    cJSON* events = cJSON_Parse(jsonStr);
    ASSERT_NE(events, nullptr);

    std::vector<DeviceEvent> eventData;
    bool result = ParseData(events, eventData);
    EXPECT_FALSE(result);

    cJSON_Delete(events);
}

/**
 * @tc.name: Pos_ToString_001
 * @tc.desc: Test Pos::ToString method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputParseTest, Pos_ToString_001, TestSize.Level1)
{
    Pos pos;
    pos.xPos = 100;
    pos.yPos = 200;
    std::string str = pos.ToString();
    EXPECT_EQ(str, "pos(100,200)");
}

/**
 * @tc.name: DeviceEvent_ToString_001
 * @tc.desc: Test DeviceEvent::ToString method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputParseTest, DeviceEvent_ToString_001, TestSize.Level1)
{
    DeviceEvent event;
    event.eventType = "touch";
    event.event = {1, 2, 3};
    event.keyValue = 65;
    event.blockTime = 100;
    event.ringEvents = {4, 5};
    event.direction = 1;
    event.distance = 50;
    event.xPos = 100;
    event.yPos = 200;
    event.tiltX = 10;
    event.tiltY = 20;
    event.pressure = 255;
    event.trackingId = 1;
    event.reportType = 2;
    event.keyStatus = 1;
    
    Pos pos;
    pos.xPos = 300;
    pos.yPos = 400;
    event.posXY.push_back(pos);

    std::string str = event.ToString();
    EXPECT_FALSE(str.empty());
    // Just verify it produces output without crashing
}

/**
 * @tc.name: DeviceItem_ToString_001
 * @tc.desc: Test DeviceItem::ToString method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputParseTest, DeviceItem_ToString_001, TestSize.Level1)
{
    DeviceItem item;
    item.deviceName = "test_device";
    item.deviceIndex = 1;
    
    DeviceEvent event;
    event.eventType = "touch";
    item.events.push_back(event);

    std::string str = item.ToString();
    EXPECT_FALSE(str.empty());
    // Just verify it produces output without crashing
}

/**
 * @tc.name: DataInit_ValidData_001
 * @tc.desc: Test DataInit with valid data containing events
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputParseTest, DataInit_ValidData_001, TestSize.Level1)
{
    const std::string fileData = R"([
        {
            "deviceName": "touch_screen",
            "deviceIndex": 1,
            "events": [
                [[100,200],[300,400]],
                {"eventType": "touch", "xPos": 150}
            ]
        }
    ])";
    
    DeviceItems items = DataInit(fileData, false);
    EXPECT_EQ(items.size(), 1u);
    EXPECT_EQ(items[0].deviceName, "touch_screen");
    EXPECT_EQ(items[0].deviceIndex, 1);
    EXPECT_EQ(items[0].events.size(), 2u);
}

/**
 * @tc.name: DataInit_ValidSingleEventData_001
 * @tc.desc: Test DataInit with singleEvent instead of events
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputParseTest, DataInit_ValidSingleEventData_001, TestSize.Level1)
{
    const std::string fileData = R"([
        {
            "deviceName": "keyboard",
            "deviceIndex": 2,
            "singleEvent": [
                {"eventType": "key", "keyValue": 65}
            ]
        }
    ])";
    
    DeviceItems items = DataInit(fileData, false);
    EXPECT_EQ(items.size(), 1u);
    EXPECT_EQ(items[0].deviceName, "keyboard");
    EXPECT_EQ(items[0].deviceIndex, 2);
    EXPECT_EQ(items[0].events.size(), 1u);
    EXPECT_EQ(items[0].events[0].eventType, "key");
}

/**
 * @tc.name: DataInit_InvalidJson_001
 * @tc.desc: Test DataInit with invalid JSON
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputParseTest, DataInit_InvalidJson_001, TestSize.Level1)
{
    const std::string fileData = R"(invalid_json)";
    DeviceItems items = DataInit(fileData, false);
    EXPECT_TRUE(items.empty());
}

/**
 * @tc.name: DataInit_InvalidDeviceInfo_001
 * @tc.desc: Test DataInit with invalid device info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputParseTest, DataInit_InvalidDeviceInfo_001, TestSize.Level1)
{
    const std::string fileData = R"(["not_an_object"])";
    DeviceItems items = DataInit(fileData, false);
    EXPECT_TRUE(items.empty());
}

/**
 * @tc.name: DataInit_InvalidDeviceName_001
 * @tc.desc: Test DataInit with invalid device name
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputParseTest, DataInit_InvalidDeviceName_001, TestSize.Level1)
{
    const std::string fileData = R"([{"deviceName": 123}])";
    DeviceItems items = DataInit(fileData, false);
    EXPECT_TRUE(items.empty());
}

/**
 * @tc.name: DataInit_MissingEvents_001
 * @tc.desc: Test DataInit when both events and singleEvent are missing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputParseTest, DataInit_MissingEvents_001, TestSize.Level1)
{
    const std::string fileData = R"([{"deviceName": "test"}])";
    DeviceItems items = DataInit(fileData, false);
    EXPECT_TRUE(items.empty());
}

/**
 * @tc.name: DataInit_InvalidEvents_001
 * @tc.desc: Test DataInit with invalid events format
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputParseTest, DataInit_InvalidEvents_001, TestSize.Level1)
{
    const std::string fileData = R"([
        {
            "deviceName": "test",
            "events": "not_an_array"
        }
    ])";
    DeviceItems items = DataInit(fileData, false);
    EXPECT_TRUE(items.empty());
}

/**
 * @tc.name: DataInit_ParseDataFailure_001
 * @tc.desc: Test DataInit when ParseData fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputParseTest, DataInit_ParseDataFailure_001, TestSize.Level1)
{
    const std::string fileData = R"([
        {
            "deviceName": "test",
            "events": ["invalid_event_format"]
        }
    ])";
    DeviceItems items = DataInit(fileData, false);
    EXPECT_TRUE(items.empty());
}
} // namespace MMI
} // namespace OHOS
