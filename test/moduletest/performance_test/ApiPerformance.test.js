/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
import inputDevice from '@ohos.multimodalInput.inputDevice';
import inputEventClient from '@ohos.multimodalInput.inputEventClient';
import inputConsumer from '@ohos.multimodalInput.inputConsumer';
import {describe, beforeAll, beforeEach, afterEach, afterAll, it, expect} from 'deccjsunit/index'


describe("apiPerformanceTest", function () {

    beforeAll(function() {
        // input testsuit setup step，setup invoked before all testcases
         console.info('beforeAll caled')
    })

    afterAll(function() {
         // input testsuit teardown step，teardown invoked after all testcases
         console.info('afterAll caled')
    })

    beforeEach(function() {
        // input testcase setup step，setup invoked before each testcases
         console.info('beforeEach caled')
    })

    afterEach(function() {
        // input testcase teardown step，teardown invoked after each testcases
         console.info('afterEach caled')
    })

	/*
	* @tc.name:MulJsTest001
	* @tc.desc:JS API performance
	* @tc.type: FUNC
	* @tc.require: Issue Number
	*/
	it("MulJsTest001", 0, function () {
		console.info('----------------------MulJsTest001 start----------------------------');
		var start = new Date().getTime();
        for (var i = 1; i<=1000 ;i++) {
            inputDevice.getDevice(1,(data,err)=>{
            });
        }
        var end = new Date().getTime();
		var allTime = (end - start);
		console.info("getDevice running totalTime:" + allTime + "ms");
        var time = (end-start)/1000;
        console.info("getDevice running averageTime:" + time + "ms");
	})

	/*
	* @tc.name:MulJsTest002
	* @tc.desc:JS API performance
	* @tc.type: FUNC
	* @tc.require: Issue Number
	*/
	it("MulJsTest002", 0, function () {
		console.info('----------------------MulJsTest002 start----------------------------');
		var start = new Date().getTime();
        for (var i = 1; i<=1000 ;i++) {
            inputDevice.getDeviceIds((data,err)=>{
            });
        }
        var end = new Date().getTime();
		var allTime = (end - start);
		console.info("getDeviceIds running totalTime:" + allTime + "ms");
        var time = (end-start)/1000;
        console.info("getDeviceIds running averageTime:" + time + "ms");
	})

	/*
	* @tc.name:MulJsTest003
	* @tc.desc:JS API performance
	* @tc.type: FUNC
	* @tc.require: Issue Number
	*/
	it("MulJsTest003", 0, function () {
		console.info('----------------------MulJsTest003 start----------------------------');
		var start = new Date().getTime();
        for (var i = 1; i<=1000 ;i++) {
            inputEventClient.on("showMenu",(data,err)=>{
            });
        }
        var end = new Date().getTime();
		var allTime = (end - start);
		console.info("inputEventClient_on running totalTime:" + allTime + "ms");
        var time = (end-start)/1000;
        console.info("inputEventClient_on running averageTime:" + time + "ms");
	})

	/*
	* @tc.name:MulJsTest004
	* @tc.desc:JS API performance
	* @tc.type: FUNC
	* @tc.require: Issue Number
	*/
	it("MulJsTest004", 0, function () {
		console.info('----------------------MulJsTest004 start----------------------------');
		var start = new Date().getTime();
        for (var i = 1; i<=1000 ;i++) {
            inputEventClient.off("showMenu",(data,err)=>{
            });
        }
        var end = new Date().getTime();
		var allTime = (end - start);
		console.info("inputEventClient_off running totalTime:" + allTime + "ms");
        var time = (end-start)/1000;
        console.info("inputEventClient_off running averageTime:" + time + "ms");
	})

	/*
	* @tc.name:MulJsTest005
	* @tc.desc:JS API performance
	* @tc.type: FUNC
	* @tc.require: Issue Number
	*/
	it("MulJsTest005", 0, function () {
		console.info('----------------------MulJsTest005 start----------------------------');
		var start = new Date().getTime();
        for (var i = 1; i<=1000 ;i++) {
            inputConsumer.on('key', {preKeys:[],'finalKey':22, 'isFinalKeyDown':true,'finalKeyDownDuration':0},(data,err)=>{
            });
        }
        var end = new Date().getTime();
		var allTime = (end - start);
		console.info("inputConsumer_on running totalTime:" + allTime + "ms");
        var time = (end-start)/1000;
        console.info("inputConsumer_on running averageTime:" + time + "ms");
	})

	/*
	* @tc.name:MulJsTest006
	* @tc.desc:JS API performance
	* @tc.type: FUNC
	* @tc.require: Issue Number
	*/
	it("MulJsTest006", 0, function () {
        console.info('----------------------MulJsTest006 start----------------------------');
        var start = new Date().getTime();
        for (var i = 1; i<=1000 ;i++) {
            inputConsumer.off('key', {preKeys:[],'finalKey':22, 'isFinalKeyDown':true,'finalKeyDownDuration':0},(data,err)=>{
            });
        }
        var end = new Date().getTime();
		var allTime = (end - start);
		console.info("inputConsumer_off running totalTime:" + allTime + "ms");
        var time = (end-start)/1000;
        console.info("inputConsumer_off running averageTime:" + time + "ms");
	})
})