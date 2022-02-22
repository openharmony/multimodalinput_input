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

import inputEventClient from '@ohos.multimodalInput.inputEventClient';
import { describe, beforeAll, beforeEach, afterEach, afterAll, it, expect } from 'deccjsunit/index'

const REGISTERED_SUCCESS = 1;
const REGISTERED_FAILED = -1;
const EventCallback = {
    ON_SHOW_MENU: 0,
    ON_SEND: 1,
    ON_COPY: 2,
    ON_PASTE: 3,
    ON_CUT: 4,
    ON_UNDO: 5,
    ON_REFRESH: 6,
    ON_CANCEL: 8,
    ON_ENTER: 9,
    ON_PREVIOUS: 10,
    ON_NEXT: 11,
    ON_BACK: 12,
    ON_PRINT: 13,
    ON_ANSWER: 14,
    ON_REFUSE: 15,
    ON_HANGUP: 16,
    ON_TELEPHONE_CONTROL: 17,
    ON_PLAY: 18,
    ON_PAUSE: 19,
    ON_MEDIA_CONTROL: 20,
};

const EVENT_UUID = 'uuid-ut';
const EVENT_SOURCE_TYPE = 65535;
const EVENT_DEVICE_ID = 65535;
const CLEAR_ALL_TYPE = 255;
const WINDOW_ID = 123;
const UNIT_TEST_SUCCESS = 0;

describe('ts_unit_test', function () {
  beforeEach(() => {
    let allEvent = {
      uuid: EVENT_UUID,
      occurredTime: Date.now(),
      sourceDevice: EVENT_SOURCE_TYPE,
      inputDeviceId: EVENT_DEVICE_ID,
      type: CLEAR_ALL_TYPE,
    }
    let ret = inputEventClient.unitTest(WINDOW_ID, allEvent);
    expect(ret).assertEqual(UNIT_TEST_SUCCESS);
  })

  afterEach(() => {
    let allEvent = {
      uuid: EVENT_UUID,
      occurredTime: Date.now(),
      sourceDevice: EVENT_SOURCE_TYPE,
      inputDeviceId: EVENT_DEVICE_ID,
      type: CLEAR_ALL_TYPE,
    }
    let ret = inputEventClient.unitTest(WINDOW_ID, allEvent);
    expect(ret).assertEqual(UNIT_TEST_SUCCESS);
  })


  it('inputEventClient::answer_test-02', 0, function () {
    const registerResult = inputEventClient.on(WINDOW_ID, 'answer', 32323);
    expect(registerResult).assertEqual(REGISTERED_FAILED);
  })

  it('inputEventClient::answer_test-03', 0, function () {
    const multimodalEvent = {
      uuid: EVENT_UUID,
      occurredTime: Date.now(),
      sourceDevice: EVENT_SOURCE_TYPE,
      inputDeviceId:EVENT_DEVICE_ID,
      type: EventCallback.ON_ANSWER,
    }

    const eventHandle = (event) => {
      expect(event.uuid).assertEqual(multimodalEvent.uuid);
      expect(event.occurredTime).assertEqual(multimodalEvent.occurredTime);
      expect(event.sourceDevice).assertEqual(multimodalEvent.sourceDevice);
      expect(event.inputDeviceId).assertEqual(multimodalEvent.inputDeviceId);
      expect(event.type).assertEqual(multimodalEvent.type);
    }

    const registerResult = inputEventClient.on(WINDOW_ID, 2423, eventHandle);
    expect(registerResult).assertEqual(REGISTERED_FAILED);
  })

  it('inputEventClient::answer_test-04', 0, function () {
    const multimodalEvent = {
      uuid: EVENT_UUID,
      occurredTime: Date.now(),
      sourceDevice: EVENT_SOURCE_TYPE,
      inputDeviceId: EVENT_DEVICE_ID,
      type: EventCallback.ON_ANSWER,
    }

    const eventHandle = (event) => {
      expect(event.uuid).assertEqual(multimodalEvent.uuid);
      expect(event.occurredTime).assertEqual(multimodalEvent.occurredTime);
      expect(event.sourceDevice).assertEqual(multimodalEvent.sourceDevice);
      expect(event.inputDeviceId).assertEqual(multimodalEvent.inputDeviceId);
      expect(event.type).assertNotEqual(EventCallback.ON_BACK);
    }

    const registerResult = inputEventClient.on(WINDOW_ID, 'answer', eventHandle);
    expect(registerResult).assertEqual(REGISTERED_SUCCESS);
    if (registerResult == REGISTERED_SUCCESS) {
      let ret = inputEventClient.unitTest(WINDOW_ID, multimodalEvent);
      expect(ret).assertEqual(UNIT_TEST_SUCCESS);
      const unregisterResult = inputEventClient.off(WINDOW_ID, 'answer', eventHandle);
      expect(unregisterResult).assertEqual(REGISTERED_SUCCESS);
    }
  })

  it('inputEventClient::answer_test-05', 0, function () {
    const multimodalEvent = {
      uuid: EVENT_UUID,
      occurredTime: Date.now(),
      sourceDevice: EVENT_SOURCE_TYPE,
      inputDeviceId: EVENT_DEVICE_ID,
      type: EventCallback.ON_ANSWER,
    }

    const eventHandle = (event) => {
      expect(event.uuid).assertEqual(multimodalEvent.uuid);
      expect(event.occurredTime).assertEqual(multimodalEvent.occurredTime);
      expect(event.sourceDevice).assertEqual(multimodalEvent.sourceDevice);
      expect(event.inputDeviceId).assertEqual(multimodalEvent.inputDeviceId);
      expect(event.type).assertEqual(multimodalEvent.type);
    }

    const registerResult = inputEventClient.on(WINDOW_ID, 'answer', eventHandle);
    expect(registerResult).assertEqual(REGISTERED_SUCCESS);
    if (registerResult == REGISTERED_SUCCESS) {
      let ret = inputEventClient.unitTest(WINDOW_ID, multimodalEvent);
      expect(ret).assertEqual(UNIT_TEST_SUCCESS);
      const unregisterResult = inputEventClient.off(WINDOW_ID, 12323, eventHandle);
      expect(unregisterResult).assertEqual(REGISTERED_FAILED);
    }
  })

  it('inputEventClient::answer_test-06', 0, function () {
    const multimodalEvent = {
      uuid: EVENT_UUID,
      occurredTime: Date.now(),
      sourceDevice: EVENT_SOURCE_TYPE,
      inputDeviceId: EVENT_DEVICE_ID,
      type: EventCallback.ON_ANSWER,
    }

    const eventHandle = (event) => {
      expect(event.uuid).assertEqual(multimodalEvent.uuid);
      expect(event.occurredTime).assertEqual(multimodalEvent.occurredTime);
      expect(event.sourceDevice).assertEqual(multimodalEvent.sourceDevice);
      expect(event.inputDeviceId).assertEqual(multimodalEvent.inputDeviceId);
      expect(event.type).assertEqual(multimodalEvent.type);
    }

    const registerResult = inputEventClient.on(WINDOW_ID, 'answer', eventHandle);
    expect(registerResult).assertEqual(REGISTERED_SUCCESS);
    if (registerResult == REGISTERED_SUCCESS) {
      let ret = inputEventClient.unitTest(WINDOW_ID, multimodalEvent);
      expect(ret).assertEqual(UNIT_TEST_SUCCESS);
      const unregisterResult = inputEventClient.off(WINDOW_ID, 'answer', 12321);
      expect(unregisterResult).assertEqual(REGISTERED_FAILED);
    }
  })

  it('inputEventClient::answer_test-07', 0, function () {
    const multimodalEvent = {
      uuid: EVENT_UUID,
      occurredTime: Date.now(),
      sourceDevice: EVENT_SOURCE_TYPE,
      inputDeviceId: EVENT_DEVICE_ID,
      type: EventCallback.ON_ANSWER,
    }

    const eventHandle = (event) => {
      expect(event.uuid).assertEqual(multimodalEvent.uuid);
      expect(event.occurredTime).assertEqual(multimodalEvent.occurredTime);
      expect(event.sourceDevice).assertEqual(multimodalEvent.sourceDevice);
      expect(event.inputDeviceId).assertEqual(multimodalEvent.inputDeviceId);
      expect(event.type).assertEqual(multimodalEvent.type);
    }

    const registerResult = inputEventClient.on(WINDOW_ID, 'answer', eventHandle,'aaa');
    expect(registerResult).assertEqual(REGISTERED_FAILED);
  })

  it('inputEventClient::answer_test-08', 0, function () {
    const multimodalEvent = {
      uuid: EVENT_UUID,
      occurredTime: Date.now(),
      sourceDevice: EVENT_SOURCE_TYPE,
      inputDeviceId: EVENT_DEVICE_ID,
      type: EventCallback.ON_ANSWER,
    }

    const eventHandle = (event) => {
      expect(event.uuid).assertEqual(multimodalEvent.uuid);
      expect(event.occurredTime).assertEqual(multimodalEvent.occurredTime);
      expect(event.sourceDevice).assertEqual(multimodalEvent.sourceDevice);
      expect(event.inputDeviceId).assertEqual(multimodalEvent.inputDeviceId);
      expect(event.type).assertEqual(multimodalEvent.type);
    }

    const registerResult = inputEventClient.on(WINDOW_ID, 'answer');
    expect(registerResult).assertEqual(REGISTERED_FAILED);
  })

  it('inputEventClient::answer_test-09', 0, function () {
    const multimodalEvent = {
      uuid: EVENT_UUID,
      occurredTime: Date.now(),
      sourceDevice: EVENT_SOURCE_TYPE,
      inputDeviceId: EVENT_DEVICE_ID,
      type: EventCallback.ON_ANSWER,
    }

    const eventHandle = (event) => {
      expect(event.uuid).assertEqual(multimodalEvent.uuid);
      expect(event.occurredTime).assertEqual(multimodalEvent.occurredTime);
      expect(event.sourceDevice).assertEqual(multimodalEvent.sourceDevice);
      expect(event.inputDeviceId).assertEqual(multimodalEvent.inputDeviceId);
      expect(event.type).assertEqual(multimodalEvent.type);
    }

    const registerResult = inputEventClient.on(WINDOW_ID, 'answer', eventHandle);
    expect(registerResult).assertEqual(REGISTERED_SUCCESS);
    if (registerResult == REGISTERED_SUCCESS) {
      let ret = inputEventClient.unitTest(WINDOW_ID, multimodalEvent);
      expect(ret).assertEqual(UNIT_TEST_SUCCESS);
      const unregisterResult = inputEventClient.off(WINDOW_ID, 'answer', eventHandle,'aaa');
      expect(unregisterResult).assertEqual(REGISTERED_FAILED);
    }
  })

  it('inputEventClient::answer_test-10', 0, function () {
    const multimodalEvent = {
      uuid: EVENT_UUID,
      occurredTime: Date.now(),
      sourceDevice: EVENT_SOURCE_TYPE,
      inputDeviceId: EVENT_DEVICE_ID,
      type: EventCallback.ON_ANSWER,
    }

    const eventHandle = (event) => {
      expect(event.uuid).assertEqual(multimodalEvent.uuid);
      expect(event.occurredTime).assertEqual(multimodalEvent.occurredTime);
      expect(event.sourceDevice).assertEqual(multimodalEvent.sourceDevice);
      expect(event.inputDeviceId).assertEqual(multimodalEvent.inputDeviceId);
      expect(event.type).assertEqual(multimodalEvent.type);
    }

    const registerResult = inputEventClient.on(WINDOW_ID, 'answer', eventHandle);
    expect(registerResult).assertEqual(REGISTERED_SUCCESS);
    if (registerResult == REGISTERED_SUCCESS) {
      let ret = inputEventClient.unitTest(WINDOW_ID, multimodalEvent);
      expect(ret).assertEqual(UNIT_TEST_SUCCESS);
      const unregisterResult = inputEventClient.off(WINDOW_ID, 'answer');
      expect(unregisterResult).assertEqual(REGISTERED_FAILED);
    }
  })



  // 成功测试
  it('inputEventClient::answer_test-01', 0, function () {
    const multimodalEvent = {
      uuid: EVENT_UUID,
      occurredTime: Date.now(),
      sourceDevice: EVENT_SOURCE_TYPE,
      inputDeviceId: EVENT_DEVICE_ID,
      type: EventCallback.ON_ANSWER,
    }

    const eventHandle = (event) => {
      expect(event.uuid).assertEqual(multimodalEvent.uuid);
      expect(event.occurredTime).assertEqual(multimodalEvent.occurredTime);
      expect(event.sourceDevice).assertEqual(multimodalEvent.sourceDevice);
      expect(event.inputDeviceId).assertEqual(multimodalEvent.inputDeviceId);
      expect(event.type).assertEqual(multimodalEvent.type);
    }

    const registerResult = inputEventClient.on(WINDOW_ID, 'answer', eventHandle);
    expect(registerResult).assertEqual(REGISTERED_SUCCESS);
    if (registerResult == REGISTERED_SUCCESS) {
      let ret = inputEventClient.unitTest(WINDOW_ID, multimodalEvent);
      expect(ret).assertEqual(UNIT_TEST_SUCCESS);
      const unregisterResult = inputEventClient.off(WINDOW_ID, 'answer', eventHandle);
      expect(unregisterResult).assertEqual(REGISTERED_SUCCESS);
    }
  })

  it('inputEventClient::showMenu_test-01', 0, function () {
    const multimodalEvent = {
      uuid: EVENT_UUID,
      occurredTime: Date.now(),
      sourceDevice: EVENT_SOURCE_TYPE,
      inputDeviceId: EVENT_DEVICE_ID,
      type: EventCallback.ON_SHOW_MENU,
    }

    const eventHandle = (event) => {
      expect(event.uuid).assertEqual(multimodalEvent.uuid);
      expect(event.occurredTime).assertEqual(multimodalEvent.occurredTime);
      expect(event.sourceDevice).assertEqual(multimodalEvent.sourceDevice);
      expect(event.inputDeviceId).assertEqual(multimodalEvent.inputDeviceId);
      expect(event.type).assertEqual(multimodalEvent.type);
    }

    const registerResult = inputEventClient.on(WINDOW_ID, 'showMenu', eventHandle);
    expect(registerResult).assertEqual(REGISTERED_SUCCESS);
    if (registerResult == REGISTERED_SUCCESS) {
      let ret = inputEventClient.unitTest(WINDOW_ID, multimodalEvent);
      expect(ret).assertEqual(UNIT_TEST_SUCCESS);
      const unregisterResult = inputEventClient.off(WINDOW_ID, 'showMenu', eventHandle);
      expect(unregisterResult).assertEqual(REGISTERED_SUCCESS);
    }
  })

  it('inputEventClient::send_test-01', 0, function () {
    const multimodalEvent = {
      uuid: EVENT_UUID,
      occurredTime: Date.now(),
      sourceDevice: EVENT_SOURCE_TYPE,
      inputDeviceId: EVENT_DEVICE_ID,
      type: EventCallback.ON_SEND,
    }

    const eventHandle = (event) => {
      expect(event.uuid).assertEqual(multimodalEvent.uuid);
      expect(event.occurredTime).assertEqual(multimodalEvent.occurredTime);
      expect(event.sourceDevice).assertEqual(multimodalEvent.sourceDevice);
      expect(event.inputDeviceId).assertEqual(multimodalEvent.inputDeviceId);
      expect(event.type).assertEqual(multimodalEvent.type);
    }

    const registerResult = inputEventClient.on(WINDOW_ID, 'send', eventHandle);
    expect(registerResult).assertEqual(REGISTERED_SUCCESS);
    if (registerResult == REGISTERED_SUCCESS) {
      let ret = inputEventClient.unitTest(WINDOW_ID, multimodalEvent);
      expect(ret).assertEqual(UNIT_TEST_SUCCESS);
      const unregisterResult = inputEventClient.off(WINDOW_ID, 'send', eventHandle);
      expect(unregisterResult).assertEqual(REGISTERED_SUCCESS);
    }
  })

  it('inputEventClient::copy_test-01', 0, function () {
    const multimodalEvent = {
      uuid: EVENT_UUID,
      occurredTime: Date.now(),
      sourceDevice: EVENT_SOURCE_TYPE,
      inputDeviceId: EVENT_DEVICE_ID,
      type: EventCallback.ON_COPY,
    }

    const eventHandle = (event) => {
      expect(event.uuid).assertEqual(multimodalEvent.uuid);
      expect(event.occurredTime).assertEqual(multimodalEvent.occurredTime);
      expect(event.sourceDevice).assertEqual(multimodalEvent.sourceDevice);
      expect(event.inputDeviceId).assertEqual(multimodalEvent.inputDeviceId);
      expect(event.type).assertEqual(multimodalEvent.type);
    }

    const registerResult = inputEventClient.on(WINDOW_ID, 'copy', eventHandle);
    expect(registerResult).assertEqual(REGISTERED_SUCCESS);
    if (registerResult == REGISTERED_SUCCESS) {
      let ret = inputEventClient.unitTest(WINDOW_ID, multimodalEvent);
      expect(ret).assertEqual(UNIT_TEST_SUCCESS);
      const unregisterResult = inputEventClient.off(WINDOW_ID, 'copy', eventHandle);
      expect(unregisterResult).assertEqual(REGISTERED_SUCCESS);
    }
  })

  it('inputEventClient::paste_test-01', 0, function () {
    const multimodalEvent = {
      uuid: EVENT_UUID,
      occurredTime: Date.now(),
      sourceDevice: EVENT_SOURCE_TYPE,
      inputDeviceId: EVENT_DEVICE_ID,
      type: EventCallback.ON_PASTE,
    }

    const eventHandle = (event) => {
      expect(event.uuid).assertEqual(multimodalEvent.uuid);
      expect(event.occurredTime).assertEqual(multimodalEvent.occurredTime);
      expect(event.sourceDevice).assertEqual(multimodalEvent.sourceDevice);
      expect(event.inputDeviceId).assertEqual(multimodalEvent.inputDeviceId);
      expect(event.type).assertEqual(multimodalEvent.type);
    }

    const registerResult = inputEventClient.on(WINDOW_ID, 'paste', eventHandle);
    expect(registerResult).assertEqual(REGISTERED_SUCCESS);
    if (registerResult == REGISTERED_SUCCESS) {
      let ret = inputEventClient.unitTest(WINDOW_ID, multimodalEvent);
      expect(ret).assertEqual(UNIT_TEST_SUCCESS);
      const unregisterResult = inputEventClient.off(WINDOW_ID, 'paste', eventHandle);
      expect(unregisterResult).assertEqual(REGISTERED_SUCCESS);
    }
  })

  it('inputEventClient::cut_test-01', 0, function () {
    const multimodalEvent = {
      uuid: EVENT_UUID,
      occurredTime: Date.now(),
      sourceDevice: EVENT_SOURCE_TYPE,
      inputDeviceId: EVENT_DEVICE_ID,
      type: EventCallback.ON_CUT,
    }

    const eventHandle = (event) => {
      expect(event.uuid).assertEqual(multimodalEvent.uuid);
      expect(event.occurredTime).assertEqual(multimodalEvent.occurredTime);
      expect(event.sourceDevice).assertEqual(multimodalEvent.sourceDevice);
      expect(event.inputDeviceId).assertEqual(multimodalEvent.inputDeviceId);
      expect(event.type).assertEqual(multimodalEvent.type);
    }

    const registerResult = inputEventClient.on(WINDOW_ID, 'cut', eventHandle);
    expect(registerResult).assertEqual(REGISTERED_SUCCESS);
    if (registerResult == REGISTERED_SUCCESS) {
      let ret = inputEventClient.unitTest(WINDOW_ID, multimodalEvent);
      expect(ret).assertEqual(UNIT_TEST_SUCCESS);
      const unregisterResult = inputEventClient.off(WINDOW_ID, 'cut', eventHandle);
      expect(unregisterResult).assertEqual(REGISTERED_SUCCESS);
    }
  })

  it('inputEventClient::undo_test-01', 0, function () {
    const multimodalEvent = {
      uuid: EVENT_UUID,
      occurredTime: Date.now(),
      sourceDevice: EVENT_SOURCE_TYPE,
      inputDeviceId: EVENT_DEVICE_ID,
      type: EventCallback.ON_UNDO,
    }

    const eventHandle = (event) => {
      expect(event.uuid).assertEqual(multimodalEvent.uuid);
      expect(event.occurredTime).assertEqual(multimodalEvent.occurredTime);
      expect(event.sourceDevice).assertEqual(multimodalEvent.sourceDevice);
      expect(event.inputDeviceId).assertEqual(multimodalEvent.inputDeviceId);
      expect(event.type).assertEqual(multimodalEvent.type);
    }

    const registerResult = inputEventClient.on(WINDOW_ID, 'undo', eventHandle);
    expect(registerResult).assertEqual(REGISTERED_SUCCESS);
    if (registerResult == REGISTERED_SUCCESS) {
      let ret = inputEventClient.unitTest(WINDOW_ID, multimodalEvent);
      expect(ret).assertEqual(UNIT_TEST_SUCCESS);
      const unregisterResult = inputEventClient.off(WINDOW_ID, 'undo', eventHandle);
      expect(unregisterResult).assertEqual(REGISTERED_SUCCESS);
    }
  })

  it('inputEventClient::refresh_test-01', 0, function () {
    const multimodalEvent = {
      uuid: EVENT_UUID,
      occurredTime: Date.now(),
      sourceDevice: EVENT_SOURCE_TYPE,
      inputDeviceId: EVENT_DEVICE_ID,
      type: EventCallback.ON_REFRESH,
    }

    const eventHandle = (event) => {
      expect(event.uuid).assertEqual(multimodalEvent.uuid);
      expect(event.occurredTime).assertEqual(multimodalEvent.occurredTime);
      expect(event.sourceDevice).assertEqual(multimodalEvent.sourceDevice);
      expect(event.inputDeviceId).assertEqual(multimodalEvent.inputDeviceId);
      expect(event.type).assertEqual(multimodalEvent.type);
    }

    const registerResult = inputEventClient.on(WINDOW_ID, 'refresh', eventHandle);
    expect(registerResult).assertEqual(REGISTERED_SUCCESS);
    if (registerResult == REGISTERED_SUCCESS) {
      let ret = inputEventClient.unitTest(WINDOW_ID, multimodalEvent);
      expect(ret).assertEqual(UNIT_TEST_SUCCESS);
      const unregisterResult = inputEventClient.off(WINDOW_ID, 'refresh', eventHandle);
      expect(unregisterResult).assertEqual(REGISTERED_SUCCESS);
    }
  })

  it('inputEventClient::cancel_test-01', 0, function () {
    const multimodalEvent = {
      uuid: EVENT_UUID,
      occurredTime: Date.now(),
      sourceDevice: EVENT_SOURCE_TYPE,
      inputDeviceId: EVENT_DEVICE_ID,
      type: EventCallback.ON_CANCEL,
    }

    const eventHandle = (event) => {
      expect(event.uuid).assertEqual(multimodalEvent.uuid);
      expect(event.occurredTime).assertEqual(multimodalEvent.occurredTime);
      expect(event.sourceDevice).assertEqual(multimodalEvent.sourceDevice);
      expect(event.inputDeviceId).assertEqual(multimodalEvent.inputDeviceId);
      expect(event.type).assertEqual(multimodalEvent.type);
    }

    const registerResult = inputEventClient.on(WINDOW_ID, 'cancel', eventHandle);
    expect(registerResult).assertEqual(REGISTERED_SUCCESS);
    if (registerResult == REGISTERED_SUCCESS) {
      let ret = inputEventClient.unitTest(WINDOW_ID, multimodalEvent);
      expect(ret).assertEqual(UNIT_TEST_SUCCESS);
      const unregisterResult = inputEventClient.off(WINDOW_ID, 'cancel', eventHandle);
      expect(unregisterResult).assertEqual(REGISTERED_SUCCESS);
    }
  })

  it('inputEventClient::enter_test-01', 0, function () {
    const multimodalEvent = {
      uuid: EVENT_UUID,
      occurredTime: Date.now(),
      sourceDevice: EVENT_SOURCE_TYPE,
      inputDeviceId: EVENT_DEVICE_ID,
      type: EventCallback.ON_ENTER,
    }

    const eventHandle = (event) => {
      expect(event.uuid).assertEqual(multimodalEvent.uuid);
      expect(event.occurredTime).assertEqual(multimodalEvent.occurredTime);
      expect(event.sourceDevice).assertEqual(multimodalEvent.sourceDevice);
      expect(event.inputDeviceId).assertEqual(multimodalEvent.inputDeviceId);
      expect(event.type).assertEqual(multimodalEvent.type);
    }

    const registerResult = inputEventClient.on(WINDOW_ID, 'enter', eventHandle);
    expect(registerResult).assertEqual(REGISTERED_SUCCESS);
    if (registerResult == REGISTERED_SUCCESS) {
      let ret = inputEventClient.unitTest(WINDOW_ID, multimodalEvent);
      expect(ret).assertEqual(UNIT_TEST_SUCCESS);
      const unregisterResult = inputEventClient.off(WINDOW_ID, 'enter', eventHandle);
      expect(unregisterResult).assertEqual(REGISTERED_SUCCESS);
    }
  })

  it('inputEventClient::previous_test-01', 0, function () {
    const multimodalEvent = {
      uuid: EVENT_UUID,
      occurredTime: Date.now(),
      sourceDevice: EVENT_SOURCE_TYPE,
      inputDeviceId: EVENT_DEVICE_ID,
      type: EventCallback.ON_PREVIOUS,
    }

    const eventHandle = (event) => {
      expect(event.uuid).assertEqual(multimodalEvent.uuid);
      expect(event.occurredTime).assertEqual(multimodalEvent.occurredTime);
      expect(event.sourceDevice).assertEqual(multimodalEvent.sourceDevice);
      expect(event.inputDeviceId).assertEqual(multimodalEvent.inputDeviceId);
      expect(event.type).assertEqual(multimodalEvent.type);
    }

    const registerResult = inputEventClient.on(WINDOW_ID, 'previous', eventHandle);
    expect(registerResult).assertEqual(REGISTERED_SUCCESS);
    if (registerResult == REGISTERED_SUCCESS) {
      let ret = inputEventClient.unitTest(WINDOW_ID, multimodalEvent);
      expect(ret).assertEqual(UNIT_TEST_SUCCESS);
      const unregisterResult = inputEventClient.off(WINDOW_ID, 'previous', eventHandle);
      expect(unregisterResult).assertEqual(REGISTERED_SUCCESS);
    }
  })

  it('inputEventClient::next_test-01', 0, function () {
    const multimodalEvent = {
      uuid: EVENT_UUID,
      occurredTime: Date.now(),
      sourceDevice: EVENT_SOURCE_TYPE,
      inputDeviceId: EVENT_DEVICE_ID,
      type: EventCallback.ON_NEXT,
    }

    const eventHandle = (event) => {
      expect(event.uuid).assertEqual(multimodalEvent.uuid);
      expect(event.occurredTime).assertEqual(multimodalEvent.occurredTime);
      expect(event.sourceDevice).assertEqual(multimodalEvent.sourceDevice);
      expect(event.inputDeviceId).assertEqual(multimodalEvent.inputDeviceId);
      expect(event.type).assertEqual(multimodalEvent.type);
    }

    const registerResult = inputEventClient.on(WINDOW_ID, 'next', eventHandle);
    expect(registerResult).assertEqual(REGISTERED_SUCCESS);
    if (registerResult == REGISTERED_SUCCESS) {
      let ret = inputEventClient.unitTest(WINDOW_ID, multimodalEvent);
      expect(ret).assertEqual(UNIT_TEST_SUCCESS);
      const unregisterResult = inputEventClient.off(WINDOW_ID, 'next', eventHandle);
      expect(unregisterResult).assertEqual(REGISTERED_SUCCESS);
    }
  })

  it('inputEventClient::back_test-01', 0, function () {
    const multimodalEvent = {
      uuid: EVENT_UUID,
      occurredTime: Date.now(),
      sourceDevice: EVENT_SOURCE_TYPE,
      inputDeviceId: EVENT_DEVICE_ID,
      type: EventCallback.ON_BACK,
    }

    const eventHandle = (event) => {
      expect(event.uuid).assertEqual(multimodalEvent.uuid);
      expect(event.occurredTime).assertEqual(multimodalEvent.occurredTime);
      expect(event.sourceDevice).assertEqual(multimodalEvent.sourceDevice);
      expect(event.inputDeviceId).assertEqual(multimodalEvent.inputDeviceId);
      expect(event.type).assertEqual(multimodalEvent.type);
    }

    const registerResult = inputEventClient.on(WINDOW_ID, 'back', eventHandle);
    expect(registerResult).assertEqual(REGISTERED_SUCCESS);
    if (registerResult == REGISTERED_SUCCESS) {
      let ret = inputEventClient.unitTest(WINDOW_ID, multimodalEvent);
      expect(ret).assertEqual(UNIT_TEST_SUCCESS);
      const unregisterResult = inputEventClient.off(WINDOW_ID, 'back', eventHandle);
      expect(unregisterResult).assertEqual(REGISTERED_SUCCESS);
    }
  })

  it('inputEventClient::print_test-01', 0, function () {
    const multimodalEvent = {
      uuid: EVENT_UUID,
      occurredTime: Date.now(),
      sourceDevice: EVENT_SOURCE_TYPE,
      inputDeviceId: EVENT_DEVICE_ID,
      type: EventCallback.ON_PRINT,
    }

    const eventHandle = (event) => {
      expect(event.uuid).assertEqual(multimodalEvent.uuid);
      expect(event.occurredTime).assertEqual(multimodalEvent.occurredTime);
      expect(event.sourceDevice).assertEqual(multimodalEvent.sourceDevice);
      expect(event.inputDeviceId).assertEqual(multimodalEvent.inputDeviceId);
      expect(event.type).assertEqual(multimodalEvent.type);
    }

    const registerResult = inputEventClient.on(WINDOW_ID, 'print', eventHandle);
    expect(registerResult).assertEqual(REGISTERED_SUCCESS);
    if (registerResult == REGISTERED_SUCCESS) {
      let ret = inputEventClient.unitTest(WINDOW_ID, multimodalEvent);
      expect(ret).assertEqual(UNIT_TEST_SUCCESS);
      const unregisterResult = inputEventClient.off(WINDOW_ID, 'print', eventHandle);
      expect(unregisterResult).assertEqual(REGISTERED_SUCCESS);
    }
  })

  it('inputEventClient::refuse_test-01', 0, function () {
    const multimodalEvent = {
      uuid: EVENT_UUID,
      occurredTime: Date.now(),
      sourceDevice: EVENT_SOURCE_TYPE,
      inputDeviceId: EVENT_DEVICE_ID,
      type: EventCallback.ON_REFUSE,
    }

    const eventHandle = (event) => {
      expect(event.uuid).assertEqual(multimodalEvent.uuid);
      expect(event.occurredTime).assertEqual(multimodalEvent.occurredTime);
      expect(event.sourceDevice).assertEqual(multimodalEvent.sourceDevice);
      expect(event.inputDeviceId).assertEqual(multimodalEvent.inputDeviceId);
      expect(event.type).assertEqual(multimodalEvent.type);
    }

    const registerResult = inputEventClient.on(WINDOW_ID, 'refuse', eventHandle);
    expect(registerResult).assertEqual(REGISTERED_SUCCESS);
    if (registerResult == REGISTERED_SUCCESS) {
      let ret = inputEventClient.unitTest(WINDOW_ID, multimodalEvent);
      expect(ret).assertEqual(UNIT_TEST_SUCCESS);
      const unregisterResult = inputEventClient.off(WINDOW_ID, 'refuse', eventHandle);
      expect(unregisterResult).assertEqual(REGISTERED_SUCCESS);
    }
  })

  it('inputEventClient::hangup_test-01', 0, function () {
    const multimodalEvent = {
      uuid: EVENT_UUID,
      occurredTime: Date.now(),
      sourceDevice: EVENT_SOURCE_TYPE,
      inputDeviceId: EVENT_DEVICE_ID,
      type: EventCallback.ON_HANGUP,
    }

    const eventHandle = (event) => {
      expect(event.uuid).assertEqual(multimodalEvent.uuid);
      expect(event.occurredTime).assertEqual(multimodalEvent.occurredTime);
      expect(event.sourceDevice).assertEqual(multimodalEvent.sourceDevice);
      expect(event.inputDeviceId).assertEqual(multimodalEvent.inputDeviceId);
      expect(event.type).assertEqual(multimodalEvent.type);
    }

    const registerResult = inputEventClient.on(WINDOW_ID, 'hangup', eventHandle);
    expect(registerResult).assertEqual(REGISTERED_SUCCESS);
    if (registerResult == REGISTERED_SUCCESS) {
      let ret = inputEventClient.unitTest(WINDOW_ID, multimodalEvent);
      expect(ret).assertEqual(UNIT_TEST_SUCCESS);
      const unregisterResult = inputEventClient.off(WINDOW_ID, 'hangup', eventHandle);
      expect(unregisterResult).assertEqual(REGISTERED_SUCCESS);
    }
  })

  it('inputEventClient::telephoneControl_test-01', 0, function () {
    const multimodalEvent = {
      uuid: EVENT_UUID,
      occurredTime: Date.now(),
      sourceDevice: EVENT_SOURCE_TYPE,
      inputDeviceId: EVENT_DEVICE_ID,
      type: EventCallback.ON_TELEPHONE_CONTROL,
    }

    const eventHandle = (event) => {
      expect(event.uuid).assertEqual(multimodalEvent.uuid);
      expect(event.occurredTime).assertEqual(multimodalEvent.occurredTime);
      expect(event.sourceDevice).assertEqual(multimodalEvent.sourceDevice);
      expect(event.inputDeviceId).assertEqual(multimodalEvent.inputDeviceId);
      expect(event.type).assertEqual(multimodalEvent.type);
    }

    const registerResult = inputEventClient.on(WINDOW_ID, 'telephoneControl', eventHandle);
    expect(registerResult).assertEqual(REGISTERED_SUCCESS);
    if (registerResult == REGISTERED_SUCCESS) {
      let ret = inputEventClient.unitTest(WINDOW_ID, multimodalEvent);
      expect(ret).assertEqual(UNIT_TEST_SUCCESS);
      const unregisterResult = inputEventClient.off(WINDOW_ID, 'telephoneControl', eventHandle);
      expect(unregisterResult).assertEqual(REGISTERED_SUCCESS);
    }
  })

  it('inputEventClient::play_test-01', 0, function () {
    const multimodalEvent = {
      uuid: EVENT_UUID,
      occurredTime: Date.now(),
      sourceDevice: EVENT_SOURCE_TYPE,
      inputDeviceId: EVENT_DEVICE_ID,
      type: EventCallback.ON_PLAY,
    }

    const eventHandle = (event) => {
      expect(event.uuid).assertEqual(multimodalEvent.uuid);
      expect(event.occurredTime).assertEqual(multimodalEvent.occurredTime);
      expect(event.sourceDevice).assertEqual(multimodalEvent.sourceDevice);
      expect(event.inputDeviceId).assertEqual(multimodalEvent.inputDeviceId);
      expect(event.type).assertEqual(multimodalEvent.type);
    }

    const registerResult = inputEventClient.on(WINDOW_ID, 'play', eventHandle);
    expect(registerResult).assertEqual(REGISTERED_SUCCESS);
    if (registerResult == REGISTERED_SUCCESS) {
      let ret = inputEventClient.unitTest(WINDOW_ID, multimodalEvent);
      expect(ret).assertEqual(UNIT_TEST_SUCCESS);
      const unregisterResult = inputEventClient.off(WINDOW_ID, 'play', eventHandle);
      expect(unregisterResult).assertEqual(REGISTERED_SUCCESS);
    }
  })

  it('inputEventClient::pause_test-01', 0, function () {
    const multimodalEvent = {
      uuid: EVENT_UUID,
      occurredTime: Date.now(),
      sourceDevice: EVENT_SOURCE_TYPE,
      inputDeviceId: EVENT_DEVICE_ID,
      type: EventCallback.ON_PAUSE,
    }

    const eventHandle = (event) => {
      expect(event.uuid).assertEqual(multimodalEvent.uuid);
      expect(event.occurredTime).assertEqual(multimodalEvent.occurredTime);
      expect(event.sourceDevice).assertEqual(multimodalEvent.sourceDevice);
      expect(event.inputDeviceId).assertEqual(multimodalEvent.inputDeviceId);
      expect(event.type).assertEqual(multimodalEvent.type);
    }

    const registerResult = inputEventClient.on(WINDOW_ID, 'pause', eventHandle);
    expect(registerResult).assertEqual(REGISTERED_SUCCESS);
    if (registerResult == REGISTERED_SUCCESS) {
      let ret = inputEventClient.unitTest(WINDOW_ID, multimodalEvent);
      expect(ret).assertEqual(UNIT_TEST_SUCCESS);
      const unregisterResult = inputEventClient.off(WINDOW_ID, 'pause', eventHandle);
      expect(unregisterResult).assertEqual(REGISTERED_SUCCESS);
    }
  })

  it('inputEventClient::mediaControl_test-01', 0, function () {
    const multimodalEvent = {
      uuid: EVENT_UUID,
      occurredTime: Date.now(),
      sourceDevice: EVENT_SOURCE_TYPE,
      inputDeviceId: EVENT_DEVICE_ID,
      type: EventCallback.ON_MEDIA_CONTROL,
    }

    const eventHandle = (event) => {
      expect(event.uuid).assertEqual(multimodalEvent.uuid);
      expect(event.occurredTime).assertEqual(multimodalEvent.occurredTime);
      expect(event.sourceDevice).assertEqual(multimodalEvent.sourceDevice);
      expect(event.inputDeviceId).assertEqual(multimodalEvent.inputDeviceId);
      expect(event.type).assertEqual(multimodalEvent.type);
    }

    const registerResult = inputEventClient.on(WINDOW_ID, 'mediaControl', eventHandle);
    expect(registerResult).assertEqual(REGISTERED_SUCCESS);
    if (registerResult == REGISTERED_SUCCESS) {
      let ret = inputEventClient.unitTest(WINDOW_ID, multimodalEvent);
      expect(ret).assertEqual(UNIT_TEST_SUCCESS);
      const unregisterResult = inputEventClient.off(WINDOW_ID, 'mediaControl', eventHandle);
      expect(unregisterResult).assertEqual(REGISTERED_SUCCESS);
    }
  })

})
