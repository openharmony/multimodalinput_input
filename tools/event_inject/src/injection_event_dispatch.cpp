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

#include "injection_event_dispatch.h"
#include "message_send_recv_stat_mgr.h"
#include "proto.h"
#include "util.h"

using namespace std;
using namespace OHOS::MMI;

namespace {
    static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "InjectionEventDispatch" };
}

void InjectionEventDispatch::Init()
{
    InitManageFunction();
    InitDeviceInfo();
}

void InjectionEventDispatch::InitManageFunction()
{
    InjectFunctionMap funs[] = {
#ifdef OHOS_BUILD_AI
        {"aisensor", SEND_EVENT_TO_HDI, false, bind(&InjectionEventDispatch::OnAisensor, this)},
        {"aisensor-all", SEND_EVENT_TO_HDI, true, bind(&InjectionEventDispatch::OnAisensorAll, this)},
        {"aisensor-each", SEND_EVENT_TO_HDI, true, bind(&InjectionEventDispatch::OnAisensorEach, this)},
#endif
        {"hdi", SEND_EVENT_TO_HDI, true, bind(&InjectionEventDispatch::OnHdi, this)},
        {"hdi-hot", SEND_EVENT_TO_HDI, true, bind(&InjectionEventDispatch::OnHdiHot, this)},
        {"hdi-status", SEND_EVENT_TO_HDI, true, bind(&InjectionEventDispatch::OnHdiStatus, this)},
        {"knuckle-all", SEND_EVENT_TO_HDI, true, bind(&InjectionEventDispatch::OnKnuckleAll, this)},
        {"knuckle-each", SEND_EVENT_TO_HDI, true, bind(&InjectionEventDispatch::OnKnuckleEach, this)},
        {"help", SEND_EVENT_TO_DEVICE, false, bind(&InjectionEventDispatch::OnHelp, this)},
#ifdef OHOS_BUILD_HDF
        {"json", SEND_EVENT_TO_HDI, true, bind(&InjectionEventDispatch::OnJson, this)},
#else
        {"sendevent", SEND_EVENT_TO_DEVICE, false, bind(&InjectionEventDispatch::OnSendEvent, this)},
        {"json", SEND_EVENT_TO_DEVICE, false, bind(&InjectionEventDispatch::OnJson, this)},
#endif
    };

    for (auto &it : funs) {
        CHKC(RegistInjectEvent(it), EVENT_REG_FAIL);
    }
}

int32_t InjectionEventDispatch::OnJson()
{
    MMI_LOGD("Enter");
    const string path = injectArgvs_.at(JSON_FILE_PATH_INDEX);
    std::ifstream reader(path);
    if (!reader) {
        MMI_LOGE("json file is empty");
        return RET_ERR;
    }
    Json inputEventArrays;
    reader >> inputEventArrays;
    reader.close();

    int32_t ret = manageInjectDevice_.TransformJsonData(inputEventArrays);
    MMI_LOGI("Leave");
    return ret;
}

bool InjectionEventDispatch::GetStartSocketPermission(string id)
{
    auto it = needStartSocket_.find(id);
    if (it == needStartSocket_.end()) {
        return false;
    }

    return it->second;
}

string InjectionEventDispatch::GetFunId()
{
    return funId_;
}

void InjectionEventDispatch::HandleInjectCommandItems()
{
    MMI_LOGD("Enter");

    string id = GetFunId();
    auto fun = GetFun(id);
    if (!fun) {
        MMI_LOGE("event injection Unknown fuction id:%{public}s", id.c_str());
        return;
    }

    auto ret = (*fun)();
    if (ret == RET_OK) {
        MMI_LOGI("injecte function success id:%{public}s", id.c_str());
    } else {
        MMI_LOGE("injecte function faild id:%{public}s", id.c_str());
    }

    return;
}

bool InjectionEventDispatch::VirifyArgvs(const int32_t &argc, const vector<string> &argv)
{
    MMI_LOGD("enter");
    if (argc < ARGV_VALID || argv.at(ARGVS_TARGET_INDEX).empty()) {
        MMI_LOGE("Invaild Input Para, Plase Check the validity of the para. errCode:%{public}d", PARAM_INPUT_FAIL);
        return false;
    }

    bool result = false;
    for (const auto &item : injectFuns_) {
        string temp(argv.at(ARGVS_TARGET_INDEX));
        if (temp == item.first) {
            funId_ = temp;
            result = true;
            break;
        }
    }
    if (result) {
        injectArgvs_.clear();
        for (uint64_t i = 1; i < static_cast<uint64_t>(argc); i++) {
            injectArgvs_.push_back(argv[i]);
        }
        argvNum_ = argc - 1;
    }

    return result;
}

bool InjectionEventDispatch::StartSocket()
{
    MMI_LOGD("enter");
    return TestAuxToolClient::GetInstance().Start(false);
}

bool InjectionEventDispatch::SendMsg(NetPacket ckt)
{
    if (TestAuxToolClient::GetInstance().SendMsg(ckt)) {
        MessageSendRecvStatMgr::GetInstance().Increase();
        return true;
    }

    return false;
}

void InjectionEventDispatch::Run()
{
    MMI_LOGD("enter");
    string id = GetFunId();
    auto fun = GetFun(id);
    if (!fun) {
        MMI_LOGE("event injection Unknown fuction id:%{public}s", id.c_str());
        return;
    }
    bool needStartSocket = GetStartSocketPermission(id);
    int32_t ret = RET_ERR;
    if (needStartSocket) {
        if (!StartSocket()) {
            MMI_LOGE("inject tools start socket error");
            return;
        }
        HandleInjectCommandItems();
    } else {
        ret = (*fun)();
        if (ret == RET_OK) {
            MMI_LOGI("injecte function success id:%{public}s", id.c_str());
        } else {
            MMI_LOGE("injecte function faild id:%{public}s", id.c_str());
        }
    }
}

int32_t InjectionEventDispatch::ExecuteFunction(string funId)
{
    if (funId.empty()) {
        return RET_ERR;
    }
    auto fun = GetFun(funId);
    if (!fun) {
        MMI_LOGE("event injection Unknown fuction id:%{public}s", funId.c_str());
        return false;
    }
    int32_t ret = RET_ERR;
    MMI_LOGI("Inject tools into function:%{public}s", funId.c_str());
    ret = (*fun)();
    if (ret == RET_OK) {
        MMI_LOGI("injecte function success id:%{public}s", funId.c_str());
    } else {
        MMI_LOGE("injecte function faild id:%{public}s", funId.c_str());
    }

    return ret;
}

int32_t InjectionEventDispatch::OnAisensor()
{
    MMI_LOGD("Enter");
    int32_t exRet = RET_ERR;

    if (argvNum_ < AI_SENDOR_MIN_ARGV_NUMS) {
        MMI_LOGE("Wrong number of input parameters. errCode:%{public}d", PARAM_INPUT_FAIL);
        return RET_ERR;
    }
    string flag = injectArgvs_[AI_SENSOR_TARGET_INDEX];
    if (flag == "all") {
        exRet = ExecuteFunction("aisensor-all");
    } else if (flag == "each") {
        exRet = ExecuteFunction("aisensor-each");
    } else {
        // nothing to do.
    }

    return exRet;
}

int32_t InjectionEventDispatch::OnAisensorOne(MmiMessageId code, uint32_t value)
{
    MMI_LOGT("enter, code = %u, value = %u", code, value);
    timeval time;
    RawInputEvent rawEvent = {};
    int32_t msgType = MSG_TYPE_DEVICE_INFO;
    gettimeofday(&time, 0);
    rawEvent.ev_type = INPUT_DEVICE_CAP_AI_SENSOR;
    rawEvent.ev_code = static_cast<uint32_t>(code);
    rawEvent.ev_value = value;
    rawEvent.stamp = static_cast<uint32_t>(time.tv_usec);
    NetPacket cktAi(MmiMessageId::SENIOR_INPUT_FUNC);
    cktAi << msgType << rawEvent;
    if (!SendMsg(cktAi)) {
        MMI_LOGE("Send AI Msg fail. errCode:%{public}d", MSG_SEND_FAIL);
        return RET_ERR;
    }
    return RET_OK;
}

int32_t InjectionEventDispatch::OnKnuckleOne(MmiMessageId code, uint32_t value)
{
    timeval time;
    RawInputEvent rawEvent = {};
    int32_t msgType = MSG_TYPE_DEVICE_INFO;
    gettimeofday(&time, 0);
    rawEvent.ev_type = INPUT_DEVICE_CAP_AI_SENSOR;
    rawEvent.ev_code = static_cast<uint32_t>(code);
    rawEvent.ev_value = value;
    rawEvent.stamp = static_cast<uint32_t>(time.tv_usec);
    NetPacket cktKnuckle(MmiMessageId::SENIOR_INPUT_FUNC);
    cktKnuckle << msgType << rawEvent;
    if (!SendMsg(cktKnuckle)) {
        MMI_LOGE("Send Knuckle Msg fail. errCode:%{public}d", MSG_SEND_FAIL);
        return RET_ERR;
    }
    return RET_OK;
}

int32_t InjectionEventDispatch::OnAisensorEach()
{
    if (argvNum_ != AI_EACH_ARGV_INVALID) {
        MMI_LOGE("Wrong number of input parameters. errCode:%{public}d", PARAM_INPUT_FAIL);
        return RET_ERR;
    }

    const std::string& inputString = injectArgvs_[AI_SENSOR_CODE_INDEX];
    bool ret = std::all_of(inputString.begin(), inputString.end(), [](char c) {
        return isdigit(c);
        });
    if (!ret) {
        MMI_LOGE("Invaild Input Para, Plase Check the validity of the para. errCode:%{public}d", PARAM_INPUT_FAIL);
        return RET_ERR;
    }

    int32_t msgType = MSG_TYPE_DEVICE_INIT;
    int32_t devIndex = 0;
    int32_t devType = INPUT_DEVICE_CAP_AISENSOR;

    NetPacket cktAiInit(MmiMessageId::SENIOR_INPUT_FUNC);
    cktAiInit << msgType << devIndex << devType;
    if (!SendMsg(cktAiInit)) {
        MMI_LOGE("Send AI Msg fail. errCode:%{public}d", MSG_SEND_FAIL);
    }

    timeval time;
    RawInputEvent rawEvent = {};
    gettimeofday(&time, 0);
    msgType = MSG_TYPE_DEVICE_INFO;
    rawEvent.ev_type = INPUT_DEVICE_CAP_AI_SENSOR;
    rawEvent.ev_code = static_cast<uint32_t>(stoi(injectArgvs_[AI_SENSOR_CODE_INDEX]));
    rawEvent.ev_value = static_cast<uint32_t>(stoi(injectArgvs_[AI_SENSOR_VALUE_INDEX]));
    rawEvent.stamp = static_cast<uint32_t>(time.tv_usec);
    NetPacket cktAi(MmiMessageId::SENIOR_INPUT_FUNC);
    cktAi << msgType << rawEvent;
    if (!SendMsg(cktAi)) {
        MMI_LOGE("Send AI Msg fail! errCode:%{public}d", MSG_SEND_FAIL);
        return RET_ERR;
    }
    return RET_OK;
}

int32_t InjectionEventDispatch::OnKnuckleEach()
{
    if (argvNum_ != AI_EACH_ARGV_INVALID) {
        MMI_LOGE("Wrong number of input parameters. errCode:%{public}d", PARAM_INPUT_FAIL);
        return RET_ERR;
    }

    const std::string& inputString = injectArgvs_[AI_SENSOR_CODE_INDEX];
    bool ret = std::all_of(inputString.begin(), inputString.end(), [](char c) {
        return isdigit(c);
        });
    if (!ret) {
        MMI_LOGE("Invaild Input Para, Plase Check the validity of the para. errCode:%{public}d", PARAM_INPUT_FAIL);
        return RET_ERR;
    }

    int32_t msgType = MSG_TYPE_DEVICE_INIT;
    int32_t devIndex = 0;
    int32_t devType = INPUT_DEVICE_CAP_KNUCKLE;

    NetPacket cktAiInit(MmiMessageId::SENIOR_INPUT_FUNC);
    cktAiInit << msgType << devIndex << devType;
    SendMsg(cktAiInit);

    timeval time;
    RawInputEvent rawEvent = {};
    gettimeofday(&time, 0);
    msgType = MSG_TYPE_DEVICE_INFO;
    rawEvent.ev_type = INPUT_DEVICE_CAP_AI_SENSOR;
    rawEvent.ev_code = static_cast<uint32_t>(stoi(injectArgvs_[AI_SENSOR_CODE_INDEX]));
    rawEvent.ev_value = static_cast<uint32_t>(stoi(injectArgvs_[AI_SENSOR_VALUE_INDEX]));
    rawEvent.stamp = static_cast<uint32_t>(time.tv_usec);
    NetPacket cktKnuckle(MmiMessageId::SENIOR_INPUT_FUNC);
    cktKnuckle << msgType << rawEvent;
    if (!SendMsg(cktKnuckle)) {
        MMI_LOGE("Send AI Msg fail! errCode:%{public}d", MSG_SEND_FAIL);
        return RET_ERR;
    }
    return RET_OK;
}

int32_t InjectionEventDispatch::OnHelp()
{
    InjectionToolsHelpFunc helpFunc;
    string ret = helpFunc.GetHelpText();
    MMI_LOGI("%s", ret.c_str());

    return RET_OK;
}

int32_t InjectionEventDispatch::OnAisensorAll()
{
    MMI_LOGD("enter");
    uint16_t cycleNum = 0;
    if (argvNum_ == AI_SENSOR_DEFAULT_NUMS) {
        cycleNum = AI_SENSOR_DEFAULT_CYCLE_NUMS;
    } else if (argvNum_ == AI_SENSOR_CYCLE_NUMS) {
        cycleNum = static_cast<uint16_t>(stoi(injectArgvs_[AI_SENSOR_CYCLE_INDEX]));
    } else {
        // nothing to do.
    }

    ProcessAiSensorInfoCycleNum(cycleNum);

    return RET_OK;
}

int32_t InjectionEventDispatch::OnKnuckleAll()
{
    uint16_t cycleNum = 0;
    if (argvNum_ == AI_SENSOR_DEFAULT_NUMS) {
        cycleNum = AI_SENSOR_DEFAULT_CYCLE_NUMS;
    } else if (argvNum_ == AI_SENSOR_CYCLE_NUMS) {
        cycleNum = static_cast<uint16_t>(stoi(injectArgvs_[AI_SENSOR_CYCLE_INDEX]));
    } else {
        // nothing to do.
    }

    ProcessKnuckleInfoCycleNum(cycleNum);

    return RET_OK;
}

int32_t InjectionEventDispatch::OnHdi()
{
    MMI_LOGD("Enter");
    if ((injectArgvs_.size() < HDI_MIN_ARGV_NUMS) || (injectArgvs_.size() > HDI_MAX_ARGV_NUMS)) {
        MMI_LOGE("Wrong number of input parameters! errCode:%{public}d", PARAM_INPUT_FAIL);
        return RET_ERR;
    }
    string hdiFunctionId = "hdi-" + injectArgvs_[HDF_TARGET_INDEX];
    int32_t ret = ExecuteFunction(hdiFunctionId);

    return ret;
}

int32_t InjectionEventDispatch::OnHdiStatus()
{
    MMI_LOGD("Enter");
    if (injectArgvs_.size() != HDI_STATUS_COUNTS) {
        MMI_LOGE("Wrong number of input parameters! errCode:%{public}d", PARAM_INPUT_FAIL);
        return RET_ERR;
    }
    int32_t sendType = static_cast<int32_t>(SHOW_DEVICE_INFO);
    NetPacket cktHdi(MmiMessageId::HDI_INJECT);
    cktHdi << sendType;
    if (!(SendMsg(cktHdi))) {
        MMI_LOGE("hdi hot plug to server errot");
        return RET_OK;
    }

    return RET_OK;
}

int32_t InjectionEventDispatch::OnHdiHot()
{
    if (injectArgvs_.size() != HDI_HOT_COUNTS) {
        MMI_LOGE("Wrong number of input parameters! errCode:%{public}d", PARAM_INPUT_FAIL);
        return RET_ERR;
    }

    string deviceStatusText = injectArgvs_[HDI_STATUS_INDEX];
    int32_t status = GetDeviceStatus(deviceStatusText);
    if (status == RET_ERR) {
        MMI_LOGE("OnHdiHot status error ,status:%{public}d", status);
        return RET_ERR;
    }

    string deviceNameText = injectArgvs_.at(HDI_DEVICE_NAME_INDEX);
    int32_t index = GetDeviceIndex(deviceNameText);
    MMI_LOGI("OnHdiHot index  = %d", index);
    if (index == RET_ERR) {
        MMI_LOGE("OnHdiHot index error ,index:%{public}d", index);
        return RET_ERR;
    }

    int32_t sendType = static_cast<int32_t>(SET_HOT_PLUGS);
    uint32_t devIndex = static_cast<uint32_t>(index);
    uint32_t devSatatus = static_cast<uint32_t>(status);
    NetPacket cktHdi(MmiMessageId::HDI_INJECT);
    cktHdi << sendType << devIndex << devSatatus;
    if (!(SendMsg(cktHdi))) {
        MMI_LOGE("hdi hot plug to server error");
        return RET_OK;
    }
    MMI_LOGI("On hdi hot SendMsg");
    return RET_OK;
}

int32_t InjectionEventDispatch::GetDeviceIndex(const string& deviceNameText)
{
    if (deviceNameText.empty()) {
        MMI_LOGE("Get device index failed");
        return RET_ERR;
    }
    for (const auto &item : allDevices_) {
        if (deviceNameText == item.chipName) {
            return item.devIndex;
        }
    }
    return RET_ERR;
}

int32_t InjectionEventDispatch::GetDeviceStatus(const string &deviceStatusText)
{
    if (deviceStatusText.empty()) {
        MMI_LOGE("Get device status failed");
        return RET_ERR;
    }
    if (deviceStatusText == "add") {
        return HDI_ADD;
    } else if (deviceStatusText == "remove") {
        return HDI_REMOVE;
    }
    return RET_ERR;
}

#ifndef OHOS_BUILD_HDF
int32_t InjectionEventDispatch::OnSendEvent()
{
    if (injectArgvs_.size() != SEND_EVENT_ARGV_COUNTS) {
        MMI_LOGE("Wrong number of input parameters, errCode:%d", PARAM_INPUT_FAIL);
        return RET_ERR;
    }

    string deviceNode = injectArgvs_[SEND_EVENT_DEV_NODE_INDEX];
    if (deviceNode.empty()) {
        MMI_LOGE("device node:%s is not exit", deviceNode.c_str());
        return RET_ERR;
    }
    timeval tm;
    gettimeofday(&tm, 0);
    input_event event = {};
    event.input_event_sec = tm.tv_sec;
    event.input_event_usec = tm.tv_usec;
    event.type = static_cast<uint16_t>(std::stoi(injectArgvs_[SEND_EVENT_TYPE_INDEX]));
    event.code = static_cast<uint16_t>(std::stoi(injectArgvs_[SEND_EVENT_CODE_INDEX]));
    event.value = static_cast<int32_t>(std::stoi(injectArgvs_[SEND_EVENT_VALUE_INDEX]));

    int32_t fd = open(deviceNode.c_str(), O_RDWR);
    if (fd < 0) {
        MMI_LOGE("open device node:%s faild", deviceNode.c_str());
        return RET_ERR;
    }
    write(fd, &event, sizeof(event));
    if (fd >= 0) {
        close(fd);
    }
    return RET_OK;
}
#endif

void InjectionEventDispatch::InitDeviceInfo()
{
    DeviceInformation deviceInfoArray[] = {
        {HDI_REMOVE, INPUT_DEVICE_POINTER_INDEX, HDF_MOUSE_DEV_TYPE, HDF_DEVICE_FD_DEFAULT_STATUS, "mouse"},
        {HDI_REMOVE, INPUT_DEVICE_KEYBOARD_INDEX, HDF_KEYBOARD_DEV_TYPE, HDF_DEVICE_FD_DEFAULT_STATUS, "keyboard"},
        {HDI_REMOVE, INPUT_DEVICE_TOUCH_INDEX, HDF_TOUCH_DEV_TYPE, HDF_DEVICE_FD_DEFAULT_STATUS, "touch"},
        {HDI_REMOVE, INPUT_DEVICE_TABLET_TOOL_INDEX, HDF_TABLET_DEV_TYPE, HDF_DEVICE_FD_DEFAULT_STATUS, "pen"},
        {HDI_REMOVE, INPUT_DEVICE_TABLET_PAD_INDEX, HDF_TABLET_PAD_DEV_TYPE, HDF_DEVICE_FD_DEFAULT_STATUS, "pad"},
        {HDI_REMOVE, INPUT_DEVICE_FINGER_INDEX, HDF_TOUCH_FINGER_DEV_TYPE, HDF_DEVICE_FD_DEFAULT_STATUS, "finger"},
        {HDI_REMOVE, INPUT_DEVICE_SWITCH_INDEX, HDF_SWITCH_DEV_TYPE, HDF_DEVICE_FD_DEFAULT_STATUS, "knob"},
        {HDI_REMOVE, INPUT_DEVICE_TRACKPAD5_INDEX, HDF_TRACK_PAD_DEV_TYPE, HDF_DEVICE_FD_DEFAULT_STATUS, "trackPad"},
        {HDI_REMOVE, INPUT_DEVICE_JOYSTICK_INDEX, HDF_JOYSTICK_DEV_TYPE, HDF_DEVICE_FD_DEFAULT_STATUS, "joyStick"},
        {HDI_REMOVE, INPUT_DEVICE_GAMEPAD_INDEX, HDF_GAMEPAD_DEV_TYPE, HDF_DEVICE_FD_DEFAULT_STATUS, "gamePad"},
        {HDI_REMOVE, INPUT_DEVICE_TOUCH_PAD, HDF_TOUCH_PAD_DEV_TYPE, HDF_DEVICE_FD_DEFAULT_STATUS, "touchPad"},
        {HDI_REMOVE, INPUT_DEVICE_REMOTE_CONTROL, HDF_TRACK_BALL_DEV_TYPE, HDF_DEVICE_FD_DEFAULT_STATUS,
         "remoteControl"},
    };

    int32_t counts = sizeof(deviceInfoArray) / sizeof(DeviceInformation);
    allDevices_.insert(allDevices_.begin(), deviceInfoArray, deviceInfoArray + counts);
}

int32_t InjectionEventDispatch::GetDevTypeIndex(int32_t devIndex)
{
    for (const auto &item : allDevices_) {
        if (devIndex == item.devIndex) {
            return item.devType;
        }
    }
    return RET_ERR;
}

int32_t InjectionEventDispatch::GetDevIndexType(int32_t devType)
{
    for (const auto &item : allDevices_) {
        if (item.devType == devType) {
            return item.devIndex;
        }
    }
    return RET_ERR;
}

void OHOS::MMI::InjectionEventDispatch::ProcessAiSensorInfoCycleNum(uint16_t cycleNum)
{
    MMI_LOGD("enter");
    static const vector<MmiMessageId> aiSensorAllowProcCodes {
        MmiMessageId::ON_SHOW_MENU,
        MmiMessageId::ON_SEND,
        MmiMessageId::ON_COPY,
        MmiMessageId::ON_PASTE,
        MmiMessageId::ON_CUT,
        MmiMessageId::ON_UNDO,
        MmiMessageId::ON_REFRESH,
        MmiMessageId::ON_CANCEL,
        MmiMessageId::ON_ENTER,
        MmiMessageId::ON_PREVIOUS,
        MmiMessageId::ON_NEXT,
        MmiMessageId::ON_BACK,
        MmiMessageId::ON_PRINT,
        MmiMessageId::ON_PLAY,
        MmiMessageId::ON_PAUSE,
        MmiMessageId::ON_SCREEN_SHOT,
        MmiMessageId::ON_SCREEN_SPLIT,
        MmiMessageId::ON_START_SCREEN_RECORD,
        MmiMessageId::ON_STOP_SCREEN_RECORD,
        MmiMessageId::ON_GOTO_DESKTOP,
        MmiMessageId::ON_RECENT,
        MmiMessageId::ON_SHOW_NOTIFICATION,
        MmiMessageId::ON_LOCK_SCREEN,
        MmiMessageId::ON_SEARCH,
        MmiMessageId::ON_CLOSE_PAGE,
        MmiMessageId::ON_LAUNCH_VOICE_ASSISTANT,
        MmiMessageId::ON_MUTE,
        MmiMessageId::ON_ANSWER,
        MmiMessageId::ON_REFUSE,
        MmiMessageId::ON_HANG_UP,
        MmiMessageId::ON_START_DRAG,
        MmiMessageId::ON_MEDIA_CONTROL,
        MmiMessageId::ON_TELEPHONE_CONTROL
    };

    int32_t msgType = MSG_TYPE_DEVICE_INIT;
    int32_t devIndex = 0;
    int32_t devType = INPUT_DEVICE_CAP_AISENSOR;

    NetPacket cktAiInit(MmiMessageId::SENIOR_INPUT_FUNC);
    cktAiInit << msgType << devIndex << devType;
    SendMsg(cktAiInit);

    for (uint32_t item = 0; item < cycleNum; item++) {
        for (auto i : aiSensorAllowProcCodes) {
            OnAisensorOne(i, item);
        }
    }
}

void OHOS::MMI::InjectionEventDispatch::ProcessKnuckleInfoCycleNum(uint16_t cycleNum)
{
    static const vector<MmiMessageId> aiSensorAllowProcCodes = {
        MmiMessageId::ON_SCREEN_SHOT,
        MmiMessageId::ON_SCREEN_SPLIT,
        MmiMessageId::ON_START_SCREEN_RECORD,
        MmiMessageId::ON_STOP_SCREEN_RECORD,
    };

    int32_t msgType = MSG_TYPE_DEVICE_INIT;
    int32_t devIndex = 0;
    int32_t devType = INPUT_DEVICE_CAP_KNUCKLE;

    NetPacket cktAiInit(MmiMessageId::SENIOR_INPUT_FUNC);
    cktAiInit << msgType << devIndex << devType;
    SendMsg(cktAiInit);

    for (uint32_t item = 0; item < cycleNum; item++) {
        for (auto i : aiSensorAllowProcCodes) {
            OnKnuckleOne(i, item);
        }
    }
}