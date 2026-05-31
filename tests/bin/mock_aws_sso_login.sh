#!/bin/sh
echo "Browser will not be automatically opened."
echo "Please visit the following URL:"
echo ""
echo "https://device.sso.fake.example.com/activate"
echo ""
echo "Then enter the code:"
echo ""
echo "FAKE-CODE"
echo ""
echo "Alternatively, you may visit the following URL which will autofill the code upon loading:"
echo "https://device.sso.fake.example.com/activate?user_code=FAKE-CODE"
if [ -n "$MOCK_SSO_FIFO" ]; then
    read -r < "$MOCK_SSO_FIFO"
fi
exit "${MOCK_SSO_EXIT_CODE:-0}"
