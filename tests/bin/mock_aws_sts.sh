#!/bin/sh
ACCOUNT_ID="${MOCK_STS_ACCOUNT_ID:-123456789012}"
echo "{\"Account\": \"$ACCOUNT_ID\", \"UserId\": \"MOCKUSERID\", \"Arn\": \"arn:aws:iam::$ACCOUNT_ID:user/mock\"}"
exit "${MOCK_STS_EXIT_CODE:-0}"
