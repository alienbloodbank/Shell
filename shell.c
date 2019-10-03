/* Part II: Building a shell */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <unistd.h>
#include <dirent.h>

#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>

#include "job_helper.h"

/* Misc manifest constants */
#define MAXARGS	128   				/* max args on a command line */

#define MAXCMDS	128					/* max number of commands in a pipe */

#define READ_END 0
#define WRITE_END 1

const char shell_prompt[] = "CSC456Shell$ ";				/* Shell prompt */
int shell_terminal = STDIN_FILENO;							/* File descriptor associated with terminal */
JOB_T jobs[MAXJOBS]; 										/* The job list per shell terminal session */
bool is_shell_fg = true;									/* flag for shell is foreground or not */
int shell_pid = -1;											/* Shell process ID */

typedef struct command_desc COMMAND_DESC;					
typedef struct input_desc INPUT_DESC;						
typedef void handler_t(int);								/* typedef for signal handler prototype */

/* Command Description */
struct command_desc
{
	char *parameters[MAXARGS];								/* Command/Program name and arguments */
	int num_parameters;										/* Number of arguments + 1 (Program name) */
};

/* Command Line Input Description */
struct input_desc
{
	char cmdline[MAXLINE];									/* Command line */
	COMMAND_DESC commands[MAXCMDS];							/* List of Commands */
	int num_commands;										/* Number of Commands */
};

/* Parsing each command on spaces/tabs/newlines to get command name and arguments */
bool get_cmd_desc(char *cmd, COMMAND_DESC *cmd_desc, bool checkbgsym)
{						
	bool is_bg = false;
	char *tokens = strtok(cmd, " \t\n");
	int num_tokens = 0;
	while(tokens)
	{
		cmd_desc->parameters[num_tokens] = (char *)malloc(sizeof(char) * strlen(tokens));
		strcpy(cmd_desc->parameters[num_tokens], tokens);
		num_tokens++;
		tokens = strtok(NULL, " \t\n");
	}
	cmd_desc->num_parameters = num_tokens;
	if(checkbgsym && num_tokens && (strcmp(cmd_desc->parameters[num_tokens - 1], "&") == 0))
	{
		num_tokens--;
		is_bg = true;
	}
	/* The array of pointers must be terminated by a null pointer for execvp */
	cmd_desc->parameters[num_tokens] = NULL;
	return is_bg;
}

/* Parsing command line input on '|' to get commands */
bool get_parsed_input_info(INPUT_DESC *inp_desc)
{
	bool is_bg = false;
	int num_commands = 0;
	char *cmd = strtok(inp_desc->cmdline, "|");

	char cmd_t[MAXCMDS][MAXARGS];	
	while(cmd)
	{
		strcpy(cmd_t[num_commands], cmd);
		cmd = strtok(NULL, "|");
		num_commands++;
	}
	for(int i = 0;i < num_commands - 1;i++)
	{
		get_cmd_desc(cmd_t[i], &(inp_desc->commands[i]), false);
	}	
	/* check if last command terminates with '&' for checking background status */
	is_bg = get_cmd_desc(cmd_t[num_commands - 1], &(inp_desc->commands[num_commands - 1]), true);
	inp_desc->num_commands = num_commands;
	return is_bg;
}

/* Wait for all processes in gpid to exit/stop/continue */
void synchronous_waitfg(int gpid)
{
	JOB_T *fg_job = getjobgpid(jobs, gpid);
	int *pids = (int*)calloc(fg_job->num_pids, sizeof(int));
	
	PROCESS *next_process = fg_job->first_process;
	int i = 0;
	/* Get list of all active processes in the job */
	while(next_process)
	{
		pids[i] = next_process->pid;
		i++;
		next_process = next_process->next;
	}
	
	for(i = 0;i < fg_job->num_pids;i++)
	{
		int child_status;
		if((pids[i] = waitpid(pids[i], &child_status, WUNTRACED | WCONTINUED)) > 0)
		{		
			/* Update job attributes associated with process: pids[i] accordingly */
			if (WIFEXITED(child_status)) {
				removejob(jobs, pids[i]);
			} else if (WIFSIGNALED(child_status)) {
				removejob(jobs, pids[i]);
			} else if (WIFSTOPPED(child_status)) {
				JOB_T *recent_job = getjobgpid(jobs, gpid);
				if(recent_job){
					recent_job->state = ST;
					printjob(recent_job);
				}
			} else if (WIFCONTINUED(child_status)) {
				JOB_T *recent_job = getjobgpid(jobs, gpid);
				if(recent_job)recent_job->state = BG;
			}
		}
	}
	free(pids);
}

/* Continue a stopped job in the background */
bool apply_bg(INPUT_DESC *inp_desc)
{
	/* Detect if first command starts with bg */
	if(strcmp(inp_desc->commands[0].parameters[0], "bg") == 0)
	{
		JOB_T *recent_job = NULL;
		
		/* Apply bg on the most recent job */
		if(inp_desc->commands[0].num_parameters == 1)
		{
			int mj = maxjid(jobs);
			recent_job = getjobjid(jobs, mj);
		}
		else /* Apply bg on a specific job */
		{
			recent_job = getjobjid(jobs, atoi(inp_desc->commands[0].parameters[1]));
		}
		
		if(recent_job && (recent_job->state == ST))
		{
			/* continuing stopped job in the background */
			kill(-(recent_job->gpid), SIGCONT);
			recent_job->state = BG;
			printjob(recent_job);
		}
		else printf("No stopped background job available\n");
		return true;
	}
	return false;
}

/* Bring a background job to foreground and continue if its stopped */
bool apply_fg(INPUT_DESC *inp_desc)
{
	/* Detect if first command starts with fg */
	if(strcmp(inp_desc->commands[0].parameters[0], "fg") == 0)
	{
		JOB_T *recent_job = NULL;
		/* Apply fg on the most recent job */
		if(inp_desc->commands[0].num_parameters == 1)
		{
			int mj = maxjid(jobs);
			recent_job = getjobjid(jobs, mj);
		}
		else /* Apply fg on a specific job */
		{
			recent_job = getjobjid(jobs, atoi(inp_desc->commands[0].parameters[1]));
		}
		
		if(recent_job)
		{
			int fg_pid = recent_job->gpid;
			/* continuing stopped job in the background */
			if(recent_job->state == ST)
			{
				kill(-fg_pid, SIGCONT);
				synchronous_waitfg(fg_pid); /* Calling this to use up wait call for recieiving continue signal */
			}
			recent_job->state = FG;
			/* Give foreground access to the job with PGID fg_pid */
			if(tcsetpgrp(shell_terminal, fg_pid) == -1)
			{
				fprintf(stderr, "tcsetpgrp failed: %s\n", strerror(errno));
				kill(-fg_pid, SIGKILL);
				return true;
			}
			printf("%s", recent_job->cmdline);
			synchronous_waitfg(fg_pid);
		}
		else printf("No background job available\n");
		return true;
	}
	return false;
}

/* Close all file descriptors associated with pipes created by a process */
void close_open_file_descriptors(int pid)
{
	char file_descriptor_path[64];
	sprintf(file_descriptor_path, "/proc/%d/fd", pid);
	struct dirent *de; 
  
    DIR *dr = opendir(file_descriptor_path); 
  
    if (dr == NULL)  /* opendir returns NULL if couldn't open directory */
    { 
        printf("Could not open current directory: %s\n", file_descriptor_path); 
        exit(EXIT_FAILURE); 
    } 
  
	/* Iterate over all file descriptors */
	while ((de = readdir(dr)) != NULL){
		/* Close symbolic links that could be file descriptors for pipes */
		/* 0, 1, 2 are the stdin, stdout and stderr.
		   3 is the file descriptor currently opened for the /proc/%d/fd directory */
		/* All the others will be coming from the pipes */
		if(de->d_type == DT_LNK && isdigit(de->d_name[0]) && atoi(de->d_name) > 3)
			close(atoi(de->d_name));
	}
    closedir(dr); 
}

/* Task performed when shell process exits */
void exit_cleanup()
{
	/* Close leaking open file descriptors */
	close_open_file_descriptors(shell_pid);
    /* Kill all jobs associated with the shell session */
	for (int i = 0; i < MAXJOBS; i++) {
		if (jobs[i].gpid != 0) {
			kill(-(jobs[i].gpid), SIGKILL);
		}
    }
}

/* Check for builtin commands */
bool builtin_command(INPUT_DESC *inp_desc)
{
	/* No command */
	if(inp_desc->commands[0].num_parameters == 0)
		return true;
		
	/* If user typed at least 'exit' then terminate the shell */
	if(strcmp(inp_desc->commands[0].parameters[0], "exit") == 0)
	{
		exit_cleanup();
		exit(EXIT_SUCCESS);
	}
	
	/* If user typed at least 'cd' */
	if(strcmp(inp_desc->commands[0].parameters[0], "cd") == 0)
	{
		if(chdir(inp_desc->commands[0].parameters[1]) == -1)
		{
			fprintf(stderr, "/usr/bin/cd: %s\n", strerror(errno));
		}
		return true;
	}
	
	/* If user typed at least 'jobs' */
	if(strcmp(inp_desc->commands[0].parameters[0], "jobs") == 0)
	{
		listjobs(jobs);
		return true;
	}

	/* If user typed at least 'bg' */	
	if(apply_bg(inp_desc))
		return true;
		
	/* If user typed at least 'fg' */
	if(apply_fg(inp_desc))
		return true;
	
	return false;
}

/* SIGCHLD handler for shell process */
void sigchld_handler() 
{
	int child_status;
	pid_t child_id;
	
	/* Reaping asychronously for any child process (background/zombie) that exited/stopped/continued */
	while((child_id = waitpid(-1, &child_status, WNOHANG | WUNTRACED | WCONTINUED)) > 0){
		/* Update job attributes associated with process: child_id accordingly */
		if (WIFEXITED(child_status)) {
			removejob(jobs, child_id);
		} else if (WIFSIGNALED(child_status)) {
			removejob(jobs, child_id);
		} else if (WIFSTOPPED(child_status)) {
			JOB_T *recent_job = getjobgpid(jobs, getpgid(child_id));
			if(recent_job)
			{
				recent_job->state = ST;
				printjob(recent_job);				
			}
		} else if (WIFCONTINUED(child_status)) {
			JOB_T *recent_job = getjobgpid(jobs, getpgid(child_id));
			if(recent_job)recent_job->state = BG;
		}
	}
}

/* Wrapper for the sigaction function */
handler_t *Signal(int signum, handler_t *handler) 
{
    struct sigaction action, old_action;

    action.sa_handler = handler;  
    sigemptyset(&action.sa_mask);   /* block sigs of type being handled */
    action.sa_flags = SA_RESTART;	/* restart syscalls if possible */
	
    if (sigaction(signum, &action, &old_action) < 0)
	{
		fprintf(stderr, "sigaction failed: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
    return (old_action.sa_handler);
}

/* Handler for ignoring ctrl-c, ctrl-z and ctrl-\*/
void sig_handler() 
{
	printf("\n%s", shell_prompt);
	fflush(stdout);
}

/* Spawning child processes for each command recursively */
void spawn_piped_processes(int *pipes, int *pids, int command_num, int num_pipes, INPUT_DESC *inp_desc)
{
	if(command_num < inp_desc->num_commands)
	{		
		if((pids[command_num] = fork()) == -1)
		{
			fprintf(stderr, "fork failed: %s\n", strerror(errno));
			return;
		}
		
		if(pids[command_num] == 0) /* Inside a child process */
		{
			/* First process in the pipeline reads stdin */
			if(command_num > 0){
				/* replace stdin with read end of pipe */
				if(dup2(pipes[2 * command_num - 2], READ_END) == -1)
				{
					fprintf(stderr, "dup2 failed for %s: %s\n", inp_desc->commands[command_num].parameters[0], 
						strerror(errno));
					close_open_file_descriptors(getpid());
					exit(EXIT_FAILURE);		
				}
			}

			/* Last process in the pipeline writes stdout */			
			if(command_num < (inp_desc->num_commands - 1)){
				/* replace stdout with write end of pipe */
				if(dup2(pipes[2 * command_num + 1], WRITE_END) == -1)
				{
					fprintf(stderr, "dup2 failed for %s: %s\n", inp_desc->commands[command_num].parameters[0], 
						strerror(errno));
					close_open_file_descriptors(getpid());
					exit(EXIT_FAILURE);		
				}
			}
			
			/* Close all pipes */
			for(int i = 0;i < num_pipes;i++)
				close(pipes[i]);

			/* Overlaying child process with command */
			execvp(inp_desc->commands[command_num].parameters[0], inp_desc->commands[command_num].parameters);
			
			/* If this 2-line code runs then execvp has failed */
			fprintf(stderr, "execvp failed for %s: %s\n", inp_desc->commands[command_num].parameters[0], 
				strerror(errno));
			/* exiting the child process if it failed to create another image */
			exit(EXIT_FAILURE);	
		}
		else /* Inside the parent shell process */
		{
			/* Assigning every child process's process group id 
			with process id of the first child in the pipeline */
			if(setpgid(pids[command_num], pids[0]) == -1)
			{
				fprintf(stderr, "setpgid failed for %s: %s\n", inp_desc->commands[command_num].parameters[0], 
					strerror(errno));
				return;	
			}

			/* Add the child process to the job */
			addjob(jobs, pids[0], (is_shell_fg ? BG : FG), pids[command_num], inp_desc->cmdline);
			
			spawn_piped_processes(pipes, pids, command_num + 1, num_pipes, inp_desc);
		}
	}
}

/* Reset the command line input data structures */
void reset_command_desc(INPUT_DESC *inp_desc)
{
	for(int i = 0;i < inp_desc->num_commands;i++)
	{
		for(int j = 0;j < inp_desc->commands[i].num_parameters;j++)
		{
			free(inp_desc->commands[i].parameters[j]);
			inp_desc->commands[i].parameters[j] = NULL;
		}
	}
	inp_desc->num_commands = 0;
}

/* Set up pipes for multiple commands */
bool init_pipes(int *pipes, INPUT_DESC *inp_desc)
{
	for(int i = 0;i < inp_desc->num_commands - 1;i++)
	{
		if(pipe(pipes + (i << 1)) == -1)
		{
			fprintf(stderr, "pipe failed: %s\n", strerror(errno));
			return false;			
		}
	}
	return true;
}

/* Driver code for shell process */
int main()
{	
	INPUT_DESC inp_desc = {.num_commands = 0};
	shell_pid = getpid();
	int *pipes = NULL;
	int *pids = NULL;
	printf("\nA minimalist shell!\n\n");

	/* Install the signal handlers */
	
	/* Signals sent to the foreground shell terminal */
    Signal(SIGINT,  sig_handler);   /* ctrl-c */
    Signal(SIGTSTP, sig_handler);  	/* ctrl-z */
    Signal(SIGQUIT, sig_handler);  	/* ctrl-\ */

	Signal(SIGCHLD, sigchld_handler);  /* For reaping background/zombie processes asychronously */
	
	sigset_t signal_set;

	/* errno is not set - https://linux.die.net/man/3/sigemptyset */
	if(sigemptyset(&signal_set) == -1)
	{
		fprintf(stderr, "sigemptyset failed\n");
		exit(EXIT_FAILURE);
	}
	
	/* errno is not set - https://linux.die.net/man/3/sigaddset */
	if(sigaddset(&signal_set, SIGTTOU) == -1) 	/* background shell process can't write to terminal */
	{
		fprintf(stderr, "sigaddset (SIGTTOU) failed\n");
		exit(EXIT_FAILURE);
	}		
	if(sigaddset(&signal_set, SIGTTIN) == -1)	/* background shell process can't read from terminal */
	{
 		fprintf(stderr, "sigaddset (SIGTTIN) failed\n");
		exit(EXIT_FAILURE);		
	}
	
	/* Blocking SIGTTOU and SIGTTIN signals to prevent shell process from stopping 
	   after giving foreground access to a foreground job */
	if(sigprocmask(SIG_BLOCK, &signal_set, NULL) == -1)
	{
		fprintf(stderr, "sigprocmask failed: %s\n", strerror(errno));
		exit(EXIT_FAILURE);				
	}
	
	/* Initialize the job list data structures */
	initjobs(jobs);
	
	/* Test whether shell_terminal is a valid terminal file descriptor */
	if(!isatty(shell_terminal))
	{
		fprintf(stderr, "isatty failed: %s\n", strerror(errno));	
		exit(EXIT_FAILURE);
	}
	
	/* Run shell instance */
	while(true)
	{
		free(pipes);
		free(pids);
		pipes = pids = NULL;
		reset_command_desc(&inp_desc);
		close_open_file_descriptors(shell_pid);
		
		printf("%s", shell_prompt);
		fflush(stdout);
		
		/* Give foreground access to shell terminal process */
		if(tcsetpgrp(shell_terminal, shell_pid) == -1)
		{
			fprintf(stderr, "tcsetpgrp failed: %s\n", strerror(errno));
			continue;
		}
		
		/* Read the command line input */
		if ((fgets(inp_desc.cmdline, MAXLINE, stdin) == NULL) && ferror(stdin))
		{
			fprintf(stderr, "fgets failed\n");
			continue;
		}
		
		/* Exit when pressing ctrl-d */ 
		if (feof(stdin)) { 
			fflush(stdout);
			exit_cleanup();
			exit(EXIT_SUCCESS);
		}
	
		is_shell_fg = get_parsed_input_info(&inp_desc);

		/* Check if command is builtin: exit, jobs, cd, fg, bg */
		if(builtin_command(&inp_desc))
			continue;

		/* Initialize list of process pids */
		pids = (int*)calloc(inp_desc.num_commands, sizeof(int));

		/* Initialize list of pipes for multiple processes */		
		int num_pipes = (inp_desc.num_commands - 1) << 1;
		if(num_pipes)
			pipes = (int*)calloc(num_pipes, sizeof(int));
	
		/* Set up the pipes */
		if(!init_pipes(pipes, &inp_desc))
			continue;

		/* Spawn child processes */
		spawn_piped_processes(pipes, pids, 0, num_pipes, &inp_desc);
			
		/* The first process PID is the process group ID for every process in the job */ 
		int fg_pid = pids[0];
		
		for(int i = 0;i < num_pipes;i++)
			close(pipes[i]);
		
		if(is_shell_fg) /* If background job/shell is foreground */
		{
			printf("[%d]: %d\n", gpid2jid(jobs, fg_pid), fg_pid);
		}
		else /* If foreground job */
		{	
			/* Give foreground access to the job with PGID fg_pid */
			if(tcsetpgrp(shell_terminal, fg_pid) == -1)
			{
				fprintf(stderr, "tcsetpgrp failed: %s\n", strerror(errno));
				kill(-fg_pid, SIGKILL);
				continue;
			}				
			synchronous_waitfg(fg_pid);		
		}
		fflush(stdout);
	}
	return EXIT_SUCCESS;
}
