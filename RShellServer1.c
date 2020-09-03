/* 

  RShellServer.c

  Created by Xinyuan Wang for CS 468

  All rights reserved.

*/

#include <openssl/sha.h>
#include <sys/time.h>
#include <ctype.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/errno.h>

#define TYPE_SIZE		1
#define LENGTH_SIZE     2
#define ID_SIZE			16
#define PASSWORD_SIZE	40
#define MR_SIZE         1

#define MAX_PAYLOAD_SIZE 65536 
#define MAX_COMMAND_SIZE (MAX_PAYLOAD_SIZE - ID_SIZE)
//#define resultSz		 (MAX_PAYLOAD_SIZE - ID_SIZE - MR_SIZE)
#define resultSz		 4096
#define	LINELEN			 128

#define RSHELL_REQ 		0x01
#define AUTH_REQ 		0x02
#define AUTH_RESP 		0x03
#define AUTH_SUCCESS 	0x04
#define AUTH_FAIL 		0x05
#define RSHELL_RESULT 	0x06

//#define DEBUG

// Components of message to send
char s_msgType;
short s_msgPayLength;
char s_msgId[ID_SIZE];
char *s_msgPayload;

// Components of message received
char r_msgType;
short r_msgPayLength;
char r_msgId[ID_SIZE];
char *r_msgPayload;

char userId[ID_SIZE];

int
serversock(int UDPorTCP, int portN, int qlen)
{
	struct sockaddr_in svr_addr;	/* my server endpoint address		*/
	int    sock;			/* socket descriptor to be allocated	*/

	if (portN<0 || portN>65535 || qlen<0)	/* sanity test of parameters */
		return -2;

	bzero((char *)&svr_addr, sizeof(svr_addr));
	svr_addr.sin_family = AF_INET;
	svr_addr.sin_addr.s_addr = INADDR_ANY;

    /* Set destination port number */
	svr_addr.sin_port = htons(portN);

    /* Allocate a socket */
	sock = socket(PF_INET, UDPorTCP, 0);
	if (sock < 0)
		return -3;

    /* Bind the socket */
	if (bind(sock, (struct sockaddr *)&svr_addr, sizeof(svr_addr)) < 0)
		return -4;

	if (UDPorTCP == SOCK_STREAM && listen(sock, qlen) < 0)
		return -5;

	return sock;
}

int 
serverTCPsock(int portN, int qlen) 
{
  return serversock(SOCK_STREAM, portN, qlen);
}

int 
serverUDPsock(int portN) 
{
  return serversock(SOCK_DGRAM, portN, 0);
}

void 
usage(char *self)
{
	fprintf(stderr, "Usage: %s port\n", self);
	exit(1);
}

void 
errmesg(char *msg)
{
	fprintf(stderr, "**** %s\n", msg);
	exit(1);

}

/*------------------------------------------------------------------------
 * reaper - clean up zombie children
 *------------------------------------------------------------------------
 */
void
reaper(int signum)
{
/*
	union wait	status;
*/

	int status;

	while (wait3(&status, WNOHANG, (struct rusage *)0) >= 0)
		/* empty */;
}

/*------------------------------------------------------------------------
 *  This is a very simplified remote shell, there are some shell command it 
	can not handle properly:

	cd
 *------------------------------------------------------------------------
 */
int
RemoteShellD(int sock)
{
#define	BUFSZ		128
#define resultSz	4096
	char cmd[BUFSZ+20];
	char result[resultSz];
	int	cc, len;
	int rc=0;
	FILE *fp;

#ifdef DEBUG
	printf("***** RemoteShellD(sock=%d) called\n", sock);
#endif

	while ((cc = read(sock, cmd, BUFSZ)) > 0)	/* received something */
	{	
		
		if (cmd[cc-1]=='\n')
			cmd[cc-1]=0;
		else cmd[cc] = 0;

#ifdef DEBUG
		printf("***** RemoteShellD(%d): received %d bytes: `%s`\n", sock, cc, cmd);
#endif

		strcat(cmd, " 2>&1");
#ifdef DEBUG
	printf("***** cmd: `%s`\n", cmd); 
#endif 
		if ((fp=popen(cmd, "r"))==NULL)	/* stream open failed */
			return -1;

		/* stream open successful */

		while ((fgets(result, resultSz, fp)) != NULL)	/* got execution result */
		{
			len = strlen(result);
			printf("***** sending %d bytes result to client: \n`%s` \n", len, result);

			if (write(sock, result, len) < 0)
			{ rc=-1;
			  break;
			}
		}
		fclose(fp);

	}

	if (cc < 0)
		return -1;

	return rc;
}


void cleanComponents(char option)
{
	if (option == 'r')
	{
		r_msgType = 0;
		r_msgPayLength = 0;
		r_msgId[0] = '\0';
		r_msgPayload = NULL;
	}
	else if( option == 's')
	{
		s_msgType = 0;
		s_msgPayLength = 0;
		s_msgId[0] = '\0';
		s_msgPayload = NULL;
	}
}


int sendToSocket(int socket)
{
	int bytesSent;

	bytesSent = write(socket, &s_msgType, TYPE_SIZE);
	if (bytesSent != TYPE_SIZE)
	{
		close(socket);
		return 0;
	}

	bytesSent = write(socket, &s_msgPayLength, LENGTH_SIZE);
	if (bytesSent != LENGTH_SIZE)
	{
		close(socket);
		return 0;
	}

	bytesSent = write(socket, &s_msgId, ID_SIZE);
	if (bytesSent != ID_SIZE)
	{
		close(socket);
		return 0;
	}

	bytesSent = write(socket, s_msgPayload, s_msgPayLength - ID_SIZE);
	if (bytesSent != (s_msgPayLength - ID_SIZE) )
	{
		close(socket);
		return 0;
	}

	cleanComponents('s');
	return 1;
}


int receiveFromSocket(int socket)
{
	cleanComponents('r');
	int bytesReceived;

	bytesReceived = recv(socket, &r_msgType, TYPE_SIZE, 0);
	if (bytesReceived != TYPE_SIZE)
	{
		close(socket);
		return 0;
	}

	bytesReceived = recv(socket, &r_msgPayLength, LENGTH_SIZE, 0);
	if (bytesReceived != LENGTH_SIZE)
	{
		close(socket);
		return 0;
	}

	bytesReceived = recv(socket, &r_msgId, ID_SIZE, 0);
	if (bytesReceived != ID_SIZE)
	{
		close(socket);
		return 0;
	}


	if (r_msgPayLength > ID_SIZE)
	{
      r_msgPayload = (char*)malloc( r_msgPayLength - ID_SIZE + 1); // +1 is for '\0'
		bytesReceived = recv(socket, r_msgPayload, (r_msgPayLength - ID_SIZE), 0);
		*(r_msgPayload + r_msgPayLength - ID_SIZE) = '\0';
		if (bytesReceived != (r_msgPayLength - ID_SIZE) )
		{
			close(socket);
			free(r_msgPayload);
			return 0;
		}
	}

	return 1;
}


int isAuthenticated(char *fileName, char userId[], unsigned char password[])
{	
	FILE *file;
	char *fileLine; 
	char *userFromFile;
	unsigned char *passwordFromFile;
	size_t lineLength;

	if (file = fopen(fileName, "r"))
	{

		getline(&fileLine, &lineLength, file);
		fclose(file);

		userFromFile = strtok(fileLine, "; \n");
		passwordFromFile = strtok(NULL, "; \n");


		if (strcmp(userId, userFromFile) == 0)
		{
			if(strcmp(password, passwordFromFile) == 0)
			{
				printf("User %s has been authenticated.\n", userId);
				return 1;
			}
			else
			{
				printf("Autenthication FAILED for user %s.\n", userId);
				return 0;
			}
		}
    }


	else
	{
		printf("Failed to open the file in server containing the passwords.");
		exit(1);
	}

	return 0;

}


void createResultMessage(char *command)
{

	FILE *resultFile;
	char cmdResult[resultSz];

	memset(cmdResult, 0, resultSz);

	resultFile = popen(command, "r");
	strcat(command, "2>&1");
	fread(cmdResult, resultSz, 1, resultFile);
	pclose(resultFile);

	cmdResult[strlen(cmdResult) - 1] = '\0';

	s_msgType = RSHELL_RESULT;

	s_msgPayLength = ID_SIZE + strlen(cmdResult);
	memcpy(s_msgId, userId, (ID_SIZE - 1));
	s_msgId[strlen(userId)] = '\0';

	if (resultFile != NULL)
	{
		s_msgPayload = cmdResult;
	}
	else
	{
		s_msgPayload = NULL;
//
		printf("Results where NULL");
	}
}






/*------------------------------------------------------------------------
 * main - Concurrent TCP server 
 *------------------------------------------------------------------------
 */
int
main(int argc, char *argv[])
{
	int	 msock;			/* master server socket		*/
	int	 ssock;			/* slave server socket		*/
	int  portN;			/* port number to listen */
	struct sockaddr_in fromAddr;	/* the from address of a client	*/
	unsigned int  fromAddrLen;		/* from-address length          */


	char *pwdFileName;
	int authenticated = 0;
	unsigned char *password;
	char *command;

	struct timeval timeOfAuth;
    struct timeval timeOfCmd;


	if (argc != 3)
		usage(argv[0]);
	else
	{
		portN = atoi(argv[1]);
		pwdFileName = argv[2];
	}

	msock = serverTCPsock(portN, 5);

	(void) signal(SIGCHLD, reaper);

	while (1) 
	{
		fromAddrLen = sizeof(fromAddr);
		ssock = accept(msock, (struct sockaddr *)&fromAddr, &fromAddrLen);
		if (ssock < 0) {
			if (errno == EINTR)
				continue;
			errmesg("accept error\n");
		}


		printf("\nConnection was made with client.\n");

		switch (fork()) 
		{
			case 0:		/* child */
				close(msock);


				while(receiveFromSocket(ssock))
				{
							
                    gettimeofday(&timeOfCmd, NULL);

							int elapsedTime = timeOfCmd.tv_sec - timeOfAuth.tv_sec;	

							if (elapsedTime > 1000)	// to correct for very first time being authenticated
								elapsedTime = 0;     		
					
                    	if( elapsedTime > 60)
							{
                        authenticated = 0;
								printf("\nClient's authentication has expired (%d seconds signed on).\n\n", elapsedTime);
							}

                    if(!authenticated)
                    {
	                    if (r_msgType == RSHELL_REQ)
	                    {

//								printf("Got RSHELL_REQ\n");
	       					
								memcpy(userId, r_msgId, (ID_SIZE));
							   userId[strlen(userId)] = '\0';

	                    	command = (char*)malloc( (r_msgPayLength - ID_SIZE) + 1);
	                    	memcpy(command, r_msgPayload, (r_msgPayLength - ID_SIZE));
	                    	command[r_msgPayLength - ID_SIZE] = '\0';

	                    	s_msgType = AUTH_REQ;
	                    	s_msgPayLength = ID_SIZE;
	                    	memcpy(s_msgId, userId, ID_SIZE-1);
	                    	s_msgId[strlen(userId)] = '\0';
	                    	s_msgPayload = '\0';
	                    	sendToSocket(ssock);

//								printf("We now are sending an AUTH_REQ\n");

	                    	receiveFromSocket(ssock);
	                    	if(r_msgType == AUTH_RESP)
	                    	{
//									printf("We got a AUTH_RESP\n");

		                    	password = (char*)malloc( (r_msgPayLength - ID_SIZE) +1);
		                    	memcpy(password, r_msgPayload, strlen(r_msgPayload));
		                    	*(password + r_msgPayLength - ID_SIZE) = '\0';

//									printf("Got password: %s\n", password);

		                    	if (authenticated = isAuthenticated(pwdFileName, userId, password))
		                    	{
		                    		gettimeofday(&timeOfAuth, NULL);

		                    		s_msgType = AUTH_SUCCESS;
	                    			s_msgPayLength = ID_SIZE;
	                    			memcpy(s_msgId, userId, ID_SIZE-1);
			                    	s_msgId[strlen(userId)] = '\0';
	                    			s_msgId[strlen(userId)] = '\0';
	                    			s_msgPayload = '\0';
	                    			sendToSocket(ssock);

	                    			createResultMessage(command);
	                    			sendToSocket(ssock);
		                    	}
		                    	else
		                    	{
		                    		s_msgType = AUTH_FAIL;
	                    			s_msgPayLength = ID_SIZE;
	                    			memcpy(s_msgId, userId, ID_SIZE-1);
			                    	s_msgId[strlen(userId)] = '\0';
	                    			s_msgId[strlen(userId)] = '\0';
	                    			s_msgPayload = '\0';
	                    			sendToSocket(ssock);
		                    	}
	                    	}
	                    }    
	                } // end of (if not authenticated yet)

	                else  // else (if already authenticated)
	                {
	                    	command = (char*)malloc( (r_msgPayLength - ID_SIZE) + 1);
	                    	memcpy(command, r_msgPayload, (r_msgPayLength - ID_SIZE));

	                    	*(command + r_msgPayLength - ID_SIZE) = '\0';
   	                 
	                    	createResultMessage(command);
								sendToSocket(ssock);
	                }
				}
                close(ssock);


			default:	/* parent */
				(void) close(ssock);
				break;
			case -1:
				errmesg("fork error\n");
		}
	}
	close(msock);
}


