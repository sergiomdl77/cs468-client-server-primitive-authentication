# cs468-client-server-primitive-authentication

Project Overview:

I was  asked  to  improve  the  client  and  server  scheleton code by implementing  a  primitive  authentication based
on   user   ID   and   password.   Specifically, I was required to develop   two   C   programs: RShellClient1.c  and
RShellServer1.c  (scheleton code was provided as SimpleRShellClient.c  and SimpleRShellServer.c as starting point).
My implementation would have to accomplish two goals:

1. The command "RShellServer1  Port_number   Password_file"  will  listen  on  the  specified Port_number  and  authenticate the  
remote  shell  command  by comparing  the  SHA1 hash  of  the password  provided  by  the  client  with  that in  the  
Password_file.  If  the  authentication  is successful,  execute  the  shell  command  and  return  the execution result  
back  to  client.  The Password_file should contain one or more line: ID_string ; hex_of_SHA1(PW) 

2. The command "RShellClient1 Server_IP  Server_port_number  ID  Password" will read  shell  command  from  the  standard  
input  (i.e.,  the  keyboard)  and  send  the  shell  command  to the server listening at the Server_port_number on Server_IP.
It will provide the ID and the SHA1 hash of Passwor to the server for authentication.
