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

#include "injection_tools_help_func.h"

using namespace std;
using namespace OHOS::MMI;

string InjectionToolsHelpFunc::GetHelpText()
{
    string ret = "\n                           Harmony device event injection ...\n\n"
        "---------------------------------global commands:----------------------------------\n"
        "aisensor-all    -Inject all voice events\n"
        "aisensor-each   -Inject a single voice event\n"
        "knuckle-all     -Inject all knuckle events\n"
        "knuckle-each    -Inject a single knuckle event\n"
        "hdi             -Inject HDF events\n"
        "\n"
        "---------------------------------function commands:----------------------------------\n"
        "AI functions:\n"
        " aisensor-all loop                     - Loop is the number of injections\n"
        " aisensor-each event_code event_value  - The event_ code is the code value of the event.\n"
        "                                         The value range is in (1101-1115), (2001), (3001-3004),\n"
        "                                         (4001-4012) or (5001-5004);\n"
        "                                         the event_ value is the code value of the event,\n"
        "                                         and the value range is in (0-1).\n"
        "\n"
        "Knuckle functions:\n"
        " knuckle-all loop                      - Loop is the number of injections\n"
        " knuckle-each event_code event_index   - The event_ code is the code value of the event.\n"
        "                                         The value range is in (4001-4004),\n"
        "                                         and the event_ index is the index value of the event.\n"
        "\n"
        "HDF functions:\n"
        " hdi-status                            - Query the device status.\n"
        " hdi-hot add devicename                - Hot plug in the device, the devicename can support mouse,\n"
        "                                         keyboard and touch.\n"
        " hdi-hot remove devicename             - Hot unplug the device, the devicename can support mouse,\n"
        "                                         keyboard and touch.\n"
        "\n"
        "Exception test:\n"
        " exception Paracount Faultcode Faultpara  - When the fault code value is 1001,\n"
        "                                            it provides the function for service status self-test,\n"
        "                                            and the fault parameter indicates the blocking time\n"
        "                                          - When the fault code value is 1002,\n"
        "                                            the exception scenario structure is input,\n"
        "                                            and the fault parameter value is in (101-107).\n";
    return ret;
}
