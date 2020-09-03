/* 

  RShellClient.c

  Created by Xinyuan Wang for CS 468
 
  All rights reserved.
*/
#include <openssl/sha.h>
#include <time.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/errno.h>
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

int
clientsock(int UDPorTCP, const char *destination, int portN)
{
	struct hostent	*phe;		/* pointer to host information entry	*/
	struct sockaddr_in dest_addr;	/* destination endpoint address		*/
	int    sock;			/* socket descriptor to be allocated	*/

	printf("\n");
	printf("destination: %s\n", destination);
	printf("portN: %d\n", portN);


	bzero((char *)&dest_addr, sizeof(dest_addr));
	dest_addr.sin_family = AF_INET;

    /* Set destination port number */
	dest_addr.sin_port = htons(portN);

    /* Map host name to IPv4 address, does not work well for IPv6 */
	if ( (phe = gethostbyname(destination)) != 0 )
		bcopy(phe->h_addr, (char *)&dest_addr.sin_addr, phe->h_length);
	else if (inet_aton(destination, &(dest_addr.sin_addr))==0) /* invalid destination address */
		return -2;

/* version that support IPv6 
	else if (inet_pton(AF_INET, destination, &(dest_addr.sin_addr)) != 1) 
*/

    /* Allocate a socket */
	sock = socket(PF_INET, UDPorTCP, 0);
	if (sock < 0)
		return -3;

    /* Connect the socket */
	if (connect(sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0)
		return -4;


	return sock;
}
int 
clientTCPsock(const char *destination, int portN) 
{
  return clientsock(SOCK_STREAM, destination, portN);
}


int 
clientUDPsock(const char *destination, int portN) 
{
  return clientsock(SOCK_DGRAM, destination, portN);
}


void usage(char *self)
{
	fprintf(stderr, "Usage: %s destination port\n", self);
	exit(1);
}

void errmesg(char *msg)
{
	fprintf(stderr, "**** %s\n", msg);
	exit(1);

}

/*------------------------------------------------------------------------------
 * TCPrecv - read TCP socket sock w/ flag for up to buflen bytes into buf

 * return:
	>=0: number of bytes read
	<0: error
 *------------------------------------------------------------------------------
 */
int
TCPrecv(int sock, char *buf, int buflen, int flag)
{
	int inbytes, n;

	if (buflen <= 0) return 0;

  /* first recv could be blocking */
	inbytes = 0; 
	n=recv(sock, &buf[inbytes], buflen - inbytes, flag);
	if (n<=0 && n != EINTR)
		return n;

	buf[n] = 0;

#ifdef DEBUG
	printf("\tTCPrecv(sock=%d, buflen=%d, flag=%d): first read %d bytes : `%s`\n", 
			   sock, buflen, flag, n, buf);
#endif /* DEBUG */

  /* subsequent tries for for anything left available */

	for (inbytes += n; inbytes < buflen; inbytes += n)
	{ 
	 	if (recv(sock, &buf[inbytes], buflen - inbytes, MSG_PEEK|MSG_DONTWAIT)<=0) /* no more to recv */
			break;
	 	n=recv(sock, &buf[inbytes], buflen - inbytes, MSG_DONTWAIT);
		buf[n] = 0;
		
#ifdef DEBUG
		printf("\tTCPrecv(sock=%d, buflen=%d, flag=%d): subsequent read %d bytes : `%s`\n", 
			   sock, buflen, flag, n, &buf[inbytes]);
#endif /* DEBUG */

	  if (n<=0) /* no more bytes to receive */
		break;
	};

#ifdef DEBUG
		printf("\tTCPrecv(sock=%d, buflen=%d): read totally %d bytes : `%s`\n", 
			   sock, buflen, inbytes, buf);
#endif /* DEBUG */

	return inbytes;
}

int
RemoteShell(char *destination, int portN)
{
	char	buf[LINELEN+1];		/* buffer for one line of text	*/
	char	result[resultSz+1];
	int	sock;				/* socket descriptor, read count*/

	int	outchars, inchars;	/* characters sent and received	*/
	int n;

	if ((sock = clientTCPsock(destination, portN)) < 0)
		errmesg("fail to obtain TCP socket");

	while (fgets(buf, sizeof(buf), stdin)) 
	{
		buf[LINELEN] = '\0';	/* insure line null-terminated	*/
		outchars = strlen(buf);
		if ((n=write(sock, buf, outchars))!=outchars)	/* send error */
		{
#ifdef DEBUG
			printf("RemoteShell(%s, %d): has %d byte send when trying to send %d bytes to RemoteShell: `%s`\n", 
			   destination, portN, n, outchars, buf);
#endif /* DEBUG */
			close(sock);
			return -1;
		}
#ifdef DEBUG
		printf("RemoteShell(%s, %d): sent %d bytes to RemoteShell: `%s`\n", 
			   destination, portN, n, buf);
#endif /* DEBUG */

		/* Get the result */

		if ((inchars=recv(sock, result, resultSz, 0))>0) /* got some result */
		{
			result[inchars]=0;	
			fputs(result, stdout);			
		}
		if (inchars < 0)
				errmesg("socket read failed\n");
	}

	close(sock);
	return 0;
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
      r_msgPayload = (char*)malloc( r_msgPayLength - ID_SIZE + 1);
		bytesReceived = recv(socket, r_msgPayload, (r_msgPayLength - ID_SIZE), 0);
		*(r_msgPayload + r_msgPayLength - ID_SIZE) = '\0';
		if (bytesReceived != (r_msgPayLength - ID_SIZE) )
		{
			close(socket);
			return 0;
		}

	}

	return 1;
}




/*------------------------------------------------------------------------
 * main  *------------------------------------------------------------------------
 */
int
main(int argc, char *argv[])
{
	char *destination;
	int  portN;
	unsigned char password[(SHA_DIGEST_LENGTH * 2)+1];
	unsigned char prePassword[SHA_DIGEST_LENGTH];
    char *rawPassword;
    char *userId;


	if (argc==5)
	{ 
		destination = argv[1];
		portN = atoi(argv[2]);
		userId = argv[3];
		rawPassword = argv[4];  
	}
	else 
		usage(argv[0]);


	//******  Encrypting Password with SHA1 encryption *****************
	SHA_CTX ctx;
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, rawPassword, strlen(rawPassword));
	SHA1_Final(prePassword, &ctx);

	int counter;
	for(counter=0; counter<SHA_DIGEST_LENGTH; counter++)
	{
        sprintf( ((unsigned char*) &(password[ counter * 2 ])), "%02x", prePassword[ counter ] );

	}

	password[SHA_DIGEST_LENGTH * 2] = '\0';

	//******************************************************************



	int socket  = clientTCPsock(destination, portN);	 

	printf("socket: %d\n", socket);

	if (socket < 0)
	{
		printf("\nProgram couln't obtain a socket.\n");
		exit(1);
	}
	
	cleanComponents('r');
	cleanComponents('s');

	char cmdStr[MAX_COMMAND_SIZE];
	cmdStr[0] = '\0';

	printf("\nConnection was established with Remote Shell.\n");

	printf("\nclient-remote-shell-prompt> ");
	// while the user/client typed in a new command
	while(fgets(cmdStr, sizeof(cmdStr), stdin))
	{
		// if user typed in a new command
		if(strlen(cmdStr) > 1)
		{

			cmdStr[strlen(cmdStr) -	1] = '\0';   // getting rid of change of line character

			// Setting up components for RSHELL_REQ message
			s_msgType = RSHELL_REQ;
			s_msgPayLength = ID_SIZE + strlen(cmdStr);
			memcpy(s_msgId, userId, (ID_SIZE - 1));
			s_msgId[strlen(userId)] = '\0';
			s_msgPayload = cmdStr;
			// And now sending RSHELL_REQ to server
			sendToSocket(socket);

			receiveFromSocket(socket);

			if (r_msgType == AUTH_REQ)
			{
//				printf("We got an AUTH_REQ\n");

				// Setting up componenets for AUTH_RESP message
				s_msgType = AUTH_RESP;
				s_msgPayLength = ID_SIZE + strlen(password);
				memcpy(s_msgId, userId, (ID_SIZE - 1));
				s_msgId[strlen(userId)] = '\0';
				password[strlen(password)] = '\0';
				s_msgPayload = password;
//				s_msgPayload = (char*)malloc(strlen(password) + 1); // +1 for '\0'
//				memcpy(s_msgPayload, password, strlen(password));
//				*(s_msgPayload + strlen(password)) = '\0'; 
				sendToSocket(socket);

				receiveFromSocket(socket);

				if (r_msgType == AUTH_SUCCESS)
				{
//					printf("We got an AUTH_SUCCESS\n");
	
					receiveFromSocket(socket);
					if (r_msgType == RSHELL_RESULT)
					{
//						printf("We got a RSHELL_RESULT\n");

						if (r_msgPayload != NULL)
							printf("\nCommand's Results: \n%s \n", r_msgPayload);
						else
							printf("\nThere was no results for your command.\n");
					}	
				}
				else if (r_msgType == AUTH_FAIL)
				{
					printf("Server could not authenticate client %s.\n", userId);
					exit(1);
				}
			}

			else if (r_msgType == RSHELL_RESULT)
			{
				if (r_msgPayload != NULL)
					printf("Command's Results: \n%s \n", r_msgPayload);
				else
					printf("\nThere was no results for your command.\n");

			}

			printf("\nclient-remote-shell-prompt> ");
			cmdStr[0] = '\0';

		}
		else
			exit(0);

	}

	exit(0);
}






























