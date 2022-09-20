SCRIPT_PATH=`dirname $0`
HSM_SERVICE=`find ${SCRIPT_PATH}/.. -name 'hsm-service' -type f -executable`
KEY_PATH=${SCRIPT_PATH}/private-key.pem


${HSM_SERVICE} server -m k1:${KEY_PATH} 2>/dev/null &
PID=$!
echo "Server is running with pid ${PID}"

echo -n "Sign API Test"
RESULT=`curl -X POST http://localhost:8000/api/sign/k1 -s -d "hello" | yq .result`
if [ ! $? == 0 ]; then
    echo " [FAILED]"
    exit 1
fi
echo " [PASS]"

echo -n "Pure Sign API Test"
DATA=`echo -n "hello" | openssl dgst -sha256 -binary - | base64 -w 0`
RESULT=`curl -X POST http://localhost:8000/api/pure-sign/k1 -s -d "${DATA}" | yq .result`
if [ ! $? == 0 ]; then
    echo " [FAILED]"
    exit 1
fi
echo " [PASS]"

echo -n "Bad Request Test"
RESULT=`curl -X POST http://localhost:8000/api/pure-sign/k1 -s -d "hello" | yq .result`
echo " [PASS]"
sleep 0.5
kill -SIGINT $PID