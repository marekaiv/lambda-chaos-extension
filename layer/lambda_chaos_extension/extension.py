#!/usr/bin/env python3

import json
import os
import time
import random
import logging
import requests
import threading
from flask import Flask, request
import boto3

app = Flask('lambda-chaos-extension')
AWS_LAMBDA_RUNTIME_API = os.getenv('AWS_LAMBDA_RUNTIME_API')
EXTENSION_NEXT_URL = f"http://{AWS_LAMBDA_RUNTIME_API}/2020-01-01/extension/event/next"
EXTENSION_REGISTER_URL = f"http://{AWS_LAMBDA_RUNTIME_API}/2020-01-01/extension/register"

s3 = boto3.client('s3')

faults = {}

app.logger.setLevel(logging.DEBUG)
app.logger.info(f"AWS_LAMBDA_RUNTIME_API = {AWS_LAMBDA_RUNTIME_API}")

def register_extension():
    register_res = requests.post(EXTENSION_REGISTER_URL,
                                 headers={'Lambda-Extension-Name': 'lambda_chaos_extension'},
                                 json={'events': []})
    extension_id = register_res.headers['Lambda-Extension-Identifier']
    print(f"[extension] extension '{extension_id}' registered.")
    print(f"[extension] enter event loop for extension id: '{extension_id}'")
    requests.get(EXTENSION_NEXT_URL, headers={'Lambda-Extension-Identifier': extension_id})

@app.before_request
def log_request_info():
    app.logger.info('Request Headers: %s', request.headers)
    app.logger.info('Request Body: %s', request.get_data())

@app.route("/2018-06-01/runtime/invocation/next", methods=['GET'])
def get_next_invocation():
    app.logger.info(f'chaos get_next_invocation {request.full_path}')
    resp = requests.get(f"http://{AWS_LAMBDA_RUNTIME_API}{request.full_path}")
    app.logger.info(f'chaos got resp headers {resp.headers}, content {resp.content}')
    # Chaos!!!
    # if random.random() > 0.9:
    #     app.logger.info(f'CHAOS STRIKES -- timeout')
    #     time.sleep(300) # sleep 5 minutes, causing the function to timeout.

    # example of how to short-circuit response
    requestId = resp.headers.get('Lambda-Runtime-Aws-Request-Id', None)
    traceId = resp.headers.get('Lambda-Runtime-Trace-Id', None)

    if traceId is not None and traceId[:5] == 'Root=':
        endIdx = traceId.index(';') if ';' in traceId else len(traceId)
        traceId = traceId[5:endIdx]
        app.logger.info(f'using traceid {traceId}')
        try:
            instructions = s3.get_object(Bucket='fault-injection-data', Key=traceId)['Body'].read()
            app.logger.info(f'Got fault instructions {instructions}')
            if instructions == b'tmout':
                app.logger.info(f'Will go to sleep')
                time.sleep(30) # todo be smarter about the time based on header value
            faults[requestId] = instructions
        except Exception as exc:
            app.logger.info(f'Did not get fault instructions for {traceId}: {exc}')

    resp.headers['Transfer-Encoding'] = None
    return resp.json(), resp.status_code, resp.headers.items()


@app.route("/2018-06-01/runtime/invocation/<path:request_id>/response", methods=['post'])
def post_invoke_response(request_id):
    app.logger.info(f'chaos post_invoke_response id {request_id}')
    app.logger.info(f'chaos response {request}')
    app.logger.info(f'chaos response headers {request.headers}')
    # Chaos!!!
    # if random.random() > 0.5:
    #     data = request.get_json()
    # else:
    #     # modify the response data
    #     app.logger.info(f'CHAOS STRIKES -- changing response to 500')
    #     data = {
    #         "statusCode": 500,
    #         "body": json.dumps({
    #             "message": "hello, Chaos!!!",
    #         }),
    #     }

    resp_url = f"http://{AWS_LAMBDA_RUNTIME_API}{request.full_path}"
    if request_id in faults:
        app.logger.info(f'CHAOS STRIKES -- instruction: {faults[request_id]})')
        instr = faults[request_id]
        if instr == b'500':
            data = {
                "statusCode": 500,
                "body": json.dumps({
                    "message": "hello, Chaos!!!",
                }),
            }
        elif instr == b'div0':
            # swap out '..../response' for '..../error' in url
            resp_url = resp_url[:-8] + 'error'
            data = {
                "errorMessage": "division by zero", 
                "errorType": "ZeroDivisionError", 
                "requestId": request_id, 
            }
    else:
        data = request.get_json()

    resp = requests.post(resp_url,
                         headers=request.headers,
                         json=data)

    return resp.json(), resp.status_code, resp.headers.items()


@app.route("/2018-06-01/runtime/init/error", methods=['post'])
def post_initialization_error():
    app.logger.info(f'chaos post_initialization_error')
    resp = requests.post(f"http://{AWS_LAMBDA_RUNTIME_API}{request.full_path}",
                         headers=request.headers,
                         json=request.get_json())
    return resp.json(), resp.status_code, resp.headers.items()


@app.route("/2018-06-01/runtime/invocation/<path:request_id>/error", methods=['post'])
def post_invoke_error(request_id):
    app.logger.info(f'chaos post_invoke_error id {request_id}')
    resp = requests.post(f"http://{AWS_LAMBDA_RUNTIME_API}{request.full_path}",
                         headers=request.headers,
                         json=request.get_json())
    return resp.json(), resp.status_code, resp.headers.items()


def main():
    # start rapid proxy
    threading.Thread(target=app.run, args=('127.0.0.1', 9100, False)).start()
    # start extension
    register_extension()


if __name__ == "__main__":
    main()
