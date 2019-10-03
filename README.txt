Programming assignment #1

Language Used/Environment Tested: C (gcc version 8.1.1)

Contents:
	README.txt, makefile, proc_parse.c, shell.c, job_helper.c, job_helper.h

Source files:
	Part I: Observing the OS through the /proc file system 
		proc_parse.c
	Part II: Building a shell
		shell.c, job_helper.c, job_helper.h
		For this part I have referred the code from "/u/cs256/src/sh-skeleton.c"
		
Compilation:
	Run 'make'
	
Output:
	proc_parse, shell
	
Testing:
	Part I:
		1st Version:
			- Run './proc_parse'
		2nd Version:
			- Run './proc_parse <read_rate> <printout_rate>'
			- Ensure that 'printout_rate' >= 'read_rate' and are in seconds
			eg. './proc_parse 2 60'
	Part II:
		Run './shell'
		The shell prompt will be 'CSC456Shell$'
		Internal Commands:
			- exit -> Exit terminal shell 
			- cd -> Change current working directory (eg. 'cd ..')
			- fg -> [jid] Bring job #jid to foreground else bring the most recent job if jid is not given (eg. 'fg')
			- bg -> [jid] Continue job #jid in background else continue the most recent job if jid is not given (eg. 'bg 5')
			- jobs -> List all the active jobs associated with the terminal session
		General Commands:
			- Should be of the form  <program1> <arglist1> | <program2> <arglist2> | ... | <programN> <arglistN> [&]
			- Multiple commands should be seperated with the token "|"
			eg. 'ls -l', 'who', 'clear', 'make', 'man proc', 'sleep 10s &', 'ls -l | grep shell',
				'cat shell.c | gzip -c | gunzip -c | tail -n 10 &', 'ls -al | grep ^d', 'kill -CONT [pid]' etc.
			- Don't put quotes around any command/argument, it will not work
			- The '&' after the commandline will put the process in the background and give control to the terminal
			- Pressing ctrl-d will exit terminal shell
			- Pressing ctrl-c, ctrl-z, ctrl-\ when no foreground job is running will have no effect on the terminal
			- If a foreground job is running then:
				- Pressing ctrl-c will sent the SIGINT signal to the foreground job, probably exiting the job and
					bringing control to the terminal
				- Pressing ctrl-z will sent the SIGTSTP signal to the foreground job, stopping the job and 
					bringing control to the terminal
				- Pressing ctrl-\ will sent the SIGQUIT signal to the foreground job, probably quiting the job
					bringing control to the terminal

Please refer to the comments in the code for other details.
