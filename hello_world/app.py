import json
from datetime import datetime


def lambda_handler(event, context):
    return {
        "statusCode": 200,
        "body": json.dumps({
            "message": f'hello world {datetime.now()}',
        }),
    }
