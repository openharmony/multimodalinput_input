/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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


import infraredEmitter from '@ohos.multimodalInput.infraredEmitter';

const Tag:String = "infraredEmitter"

function wait(delay: long) {
    let start = new Date().getTime();
    while (new Date().getTime() - start < delay) {
    }
}


function test_transmitInfrared() {
    let fun_name = 'test_transmitInfrared';
    console.log(Tag, `into func ${fun_name}`);
    try {
        infraredEmitter.transmitInfrared(38000, [100, 200, 300, 400]);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_getInfraredFrequencies() {
    let fun_name = 'test_getInfraredFrequencies';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let frequencies = infraredEmitter.getInfraredFrequencies();
        console.log(Tag, `frequencies: ${JSON.stringify(frequencies)}`);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function main() {
    console.println(Tag + ` into main`);
    console.log(Tag + ` *************************************************`);
    test_transmitInfrared();
    test_getInfraredFrequencies();
    console.log(Tag + ` out main`);
}