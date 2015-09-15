# aes_http_service
It is a AES service based on HTTP with python. You could send the action "enc/dec" and text/ciper by http request, then get the result from the payload of http response.
The result is encoded by base64.

## Usage  
[fgao@ubuntu py_aes_http_service]#./aes_server.py  -h  
-h: Show the help  
-l: Specify listen port  
-k: Specify AES key  
-e: Specify AES encrypt mode. default is cbc  
-s: Specify AES block size  
-v: Specify AES IV. default is random string  
-o: Use openssl to encrypt or decrypt. Must specify password too  
-p: Specify password. Only used with openssl  
-m: Specify openssl enc mode. Only used with openssl  
-t: Save the encrypt count and record  
-d: Debug mode  

## Example
### Start service
[fgao@ubuntu py_aes_http_service]#./aes_server.py -l 8080 -d  
Only support aes-128. Please use -o option to use openssl if you want to use other bits  
The AES server is listenning the 8080 port now  
The AES key is 1234567890abcdef 31323334353637383930616263646566  
The AES mode is cbc  
The AES block size is 16  
The AES iv uses random string  

### Encrypt  
1. send the enc request  
[fgao@ubuntu test]#wget "192.168.3.89:8080/?action=enc&text=123"   
2. check the result  
[fgao@ubuntu test]#cat index.html\?action\=enc\&text\=123  
{"ciper": "YqmA92pVCejurnrmcn1SWuBNvFf/IyGXWNX46bKxu3M=", "text": "123"}  
The ciper is the result  

### Decrypt  
1. send the dec request  
[fgao@ubuntu test]#wget "192.168.3.89:8080/?action=dec&ciper=YqmA92pVCejurnrmcn1SWuBNvFf/IyGXWNX46bKxu3M="  
2. check the result  
[fgao@ubuntu test]#cat index.html\?action\=dec\&ciper\=YqmA92pVCejurnrmcn1SWuBNvFf%2FIyGXWNX46bKxu3M\=  
{"ciper": "YqmA92pVCejurnrmcn1SWuBNvFf/IyGXWNX46bKxu3M=", "text": "123"}  
