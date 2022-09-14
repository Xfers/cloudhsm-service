hsm-service
====
Sign program with CloudHSM

## Run
### sign
```bash
# immediate string
./hsm-service sign -k $YOUR_KEY_FILE -s "hello"
# from file
./hsm-service sign -k $YOUR_KEY_FILE -f $INPUT_FILE
# from stdin
echo -n hello | ./hsm-service sign -k $YOUR_KEY_FILE -
```

### pure-sign
