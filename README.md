hsm-service
====
Sign program with CloudHSM.

## Run
### sign
`sign` is for signing signature with commandline
```bash
# immediate string
./hsm-service sign -k $YOUR_KEY_FILE -s "hello"
# from file
./hsm-service sign -k $YOUR_KEY_FILE -f $INPUT_FILE
# from stdin
echo -n hello | ./hsm-service sign -k $YOUR_KEY_FILE -
```

### pure-sign
`pure-sign` is to sign an already digested value. Usage is similiar with `sign` the only difference is it takes `sha256` digest value. 
```bash
echo -n "hello" | openssl dgst -sha256 -binary - | base64 -w 0 | ./hsm-service pure-sign -k $YOUR_KEY_FILE -
```

### server
Host a restful API server with mongoose. It spins up for two functionalities `sign` and `pure-sign`. You can refer to `test/server_test.sh` to see the usage.

```bash
./hsm-service server -m "k1:$YOUR_KEY_FILE"
# it is possible to host multiple keys
./hsm-service server -m "k1:$YOUR_KEY_FILE" -m "k2:$YOUR_KEY_FILE2"
```


## Schedule
- [TODO] Sign with other digest method like `sha512`