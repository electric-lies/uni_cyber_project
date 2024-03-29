# mmn15
This is the final project, although i know the project will be checked with windows computer, i had access to no such computer during the development of the project, so i just hope everything will work the same.

## Build the client
in client folder:
```
g++ -march=native -Wall -Wextra -o main main.cpp Base64Wrapper.cpp Base64Wrapper.h RSAWrapper.cpp RSAWrapper.h AESWrapper.cpp AESWrapper.h -l:libcryptopp.a
```

## Run the client
in client folder:
```
./main
```

## Clean the client for next run
```
rm me.info
```

## Run the server
in server folder
```
python main.py
```

## Clean the server for next run
```
rm defensive.db
rm -rf files/
mkdir files
```

## Inspect the DB (in Nushell)
```
open defensive.db | get files
```
