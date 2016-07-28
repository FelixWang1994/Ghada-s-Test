# Ghada-s-Test
There are the server end and client end.
In the client end, you can choose a file, set an arbitrary key and use the key to encrypt the file(in AES_CBC mode, provided by openssl).
You also get the md5 of the file. After that, you can send the key, the correct md5 and the encrypted file to the server.

In the server end, you can receive the above staffs. The server will decrpty the received file with the key provided by the client. Then, the server will calculate the md5 of the newly created file and compare it with the received md5 to make sure the file is correct.

To run it, follow the following steps:
1, open the command line, go to the directory where server.exe is in.
2, run "Server.exe arg1, arg2" where arg1 means IP Address, arg2 means Port number
3, open another command line, go to the directory where client.exe is in.
3, run "Client.exe arg1, arg2" where arg1 means IP Address, arg2 means Port number
4, after that, following the tints to finish the transmission!

What need to do next:
Due to time limited, I set the file size limited. In the future, it should support arbitrary size.
