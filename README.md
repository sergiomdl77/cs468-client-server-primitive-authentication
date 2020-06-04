# cs468-client-server-primitive-authentication

Project Overview:

You  are  asked  to  improve  the  above  client  and  server  by  implementing  a  primitive  authentication based
on   user   ID   and   password.   Specifically,   you   need   to develop   two   C   programs: RShellClient1.c  and
RShellServer1.c  (you  can  use SimpleRShellClient.c  and SimpleRShellServer.c as starting point) such that  

•RShellServer1 <port number>   <password file>
will  listen  on  the  specified <port  number>  and  authenticate the  remote  shell  command  by comparing  the  SHA1  
hash  of  the password  provided  by  the  client  with  that in  the  <password  file>.  If  the  authentication  is 
successful,  execute  the  shell  command  and  return  the execution result  back  to  client.  
The <password file> should contain one or more line: <ID string>; <hex of SHA1(PW)> 

•RShellClient1 <server IP> <server port number> <ID> <password> 
will read  shell  command  from  the  standard  input  (i.e.,  the  keyboard)  and  send  the  shell  command  to the 
server listening at the <server port number> on <server IP>. It will provide the <ID> and the SHA1 hash of <password> to 
the server for authentication.
