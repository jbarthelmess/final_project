Cryptography final project by JOSH BARTHELMESS and BILLY CULVER

To run our project, pull the files from github and run "make" from the local directory. this should work as long as you have the GNU C++ compiler

From there, you need at least two instances of the project to have a meaningful connection.

Run the resulting file as "./simple.exe" on the command line. The node will output a listening port. You can either have wait for a connection from
another user, or type "CONNECT <IP_ADDRESS> <PORT>" where ip address and port define another active user. Once you've connected you should be able to
send messages from one user to the other securely. The default encryption type is DES, but you can change it to RSA or a semantically secure RSA by typing
in the command SET <ENCRYPTION_CODE> where the encryption codes are "DES", "RSA", and "SEM".  

If you would like to disconnect from the person you are talking to and find someone else, simply type "DISCONNECT", and it should automatically bring you back 
to the waiting state.


