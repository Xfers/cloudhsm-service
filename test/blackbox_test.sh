SCRIPT_PATH=`dirname $0`
HSM_SERVICE=${SCRIPT_PATH}/../build/hsm-service
KEY_PATH=${SCRIPT_PATH}/private-key.pem

sign_test() {
    RAND=`echo $RANDOM | sha512sum | cut -f 1 -d" "`
    RESULT=`${HSM_SERVICE} sign -k ${KEY_PATH} -s $RAND 2>/dev/null`
    GROUND_TRUTH=`echo -n $RAND | openssl dgst -sign ${KEY_PATH} -sha256 | base64 -w 0`
    if [ "${RESULT}" == "${GROUND_TRUTH}" ]; then
        return 0
    else
        return 1
    fi
}

echo -n Sign Test
for i in {0..20}
do
    if ! sign_test ; then
        echo " [FAILED]"
        exit 1
    fi
done

echo " [PASS]"

pure_sign_test() {
    RAND=`echo $RANDOM | sha512sum | cut -f 1 -d" "`
    RESULT=`echo -n $RAND | openssl dgst -sha256 -binary | ${HSM_SERVICE} pure-sign -k ${KEY_PATH} - 2>/dev/null`
    GROUND_TRUTH=`echo -n $RAND | openssl dgst -sign ${KEY_PATH} -sha256 | base64 -w 0`
    if [ "${RESULT}" == "${GROUND_TRUTH}" ]; then
        return 0
    else
        return 1
    fi
}

echo -n Pure Sign Test
for i in {0..20}
do
    if ! pure_sign_test ; then
        echo " [FAILED]"
        exit 1
    fi
done

echo " [PASS]"
