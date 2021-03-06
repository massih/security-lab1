/* $Header: https://svn.ita.chalmers.se/repos/security/edu/course/computer_security/trunk/lab/login_linux/login_linux.c 585 2013-01-19 10:31:04Z pk@CHALMERS.SE $ */

/* gcc -Wall -g -o mylogin login.linux.c -lcrypt */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <sys/types.h>
#include <crypt.h>
#include "pwent.h"

#define TRUE 1
#define FALSE 0
#define LENGTH 16

void sighandler() {
	signal(SIGINT,SIG_IGN);
	signal(SIGKILL,SIG_IGN);
	signal(SIGTSTP,SIG_IGN);
}

int main(int argc, char *argv[]) {

	mypwent *passwddata;

	char important[LENGTH] = "***IMPORTANT***";

	char user[LENGTH];
	char prompt[] = "password: ";
	char *user_pass;

	sighandler();

	while (TRUE) {
		/* check what important variable contains - do not remove, part of buffer overflow test */
		printf("Value of variable 'important' before input of login name: %s\n",
				important);

		printf("login: ");
		fflush(NULL); /* Flush all  output buffers */
		__fpurge(stdin); /* Purge any data in stdin buffer */

		if (fgets(user,16,stdin) == NULL) /* gets() is vulnerable to buffer */
			exit(0); /*  overflow attacks.  */

		/* check to see if important variable is intact after input of login name - do not remove */
		printf("Value of variable 'important' after input of login name: %*.*s\n",
				LENGTH - 1, LENGTH - 1, important);
		user[strlen(user)-1] = '\0';
		user_pass = getpass(prompt);
		passwddata = mygetpwnam(user);

		if (passwddata != NULL && user_pass != NULL) {
			char *encrypted_pass = crypt(user_pass,passwddata->passwd_salt);
			if(encrypted_pass == NULL){
				printf("Unsuccessful encryption \n");
				exit(0);
			}

			if (!strcmp(encrypted_pass, passwddata->passwd)) {

				printf("********Welcome %s !\n",user);
				passwddata->pwage++;
				printf("********Number of failed attempts: %d\n",passwddata->pwfailed);
				passwddata->pwfailed=0;
				if(mysetpwent(user,passwddata) == -1){
					printf("Something went wrong\n");
					exit(0);
				}
				if(passwddata->pwage > 10){
					printf("********You use your password more than 10 times, please change your password\n");
				}
				if(setuid(passwddata->uid) == -1){
					exit(0);
				}
				char *argvv[] = {"/bin/sh",NULL};
				char *envpp[] = {NULL};

				if(execve("/bin/sh", argvv , envpp) == -1)
					exit(0);

			}else{
				if(passwddata-> pwfailed == 3){
					printf("********Too many fail attempts! Try again later. \n");
					passwddata->pwfailed = 0;
					if(mysetpwent(user,passwddata) == -1){
						printf("Something went wrong\n");
						exit(0);
					}
					exit(0);
				}else{
					passwddata-> pwfailed++;
					if(mysetpwent(user,passwddata) == -1){
						printf("Something went wrong\n");
						exit(0);
					}
					printf("********Incorrect username or password, Try again \n");
				}

			}
		}else{
			printf("********Login Incorrect \n");
		}
	}
	return 0;
}