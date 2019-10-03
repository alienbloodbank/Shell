#ifndef JOB_HELPER_H
#define JOB_HELPER_H

#define MAXJOBS 32   /* max jobs at any point in time */
#define MAXLINE	4096   				/* max line size */

/* Job states */
#define UNDEF 0 /* undefined */
#define FG 1    /* running in foreground */
#define BG 2    /* running in background */
#define ST 3    /* stopped */

typedef struct job_t JOB_T; 
typedef struct process PROCESS;

struct process
{
	PROCESS *next;       		/* next process in pipeline */
	pid_t pid;              	/* process ID */
};

struct job_t 					/* The job struct */
{              
    pid_t gpid;              	/* job Porcess Group ID */
    int jid;                	/* job ID [1, 2, ...] */
	PROCESS *first_process;  	/* linked list of jobs */
	int num_pids;				/* Count of processes in the job*/
    int state;              	/* UNDEF, BG, FG, or ST */
    char cmdline[MAXLINE];  	/* command line input */
};

void clearjob(JOB_T *job);
void printjob(JOB_T *job);
void initjobs(JOB_T *jobs);
int maxjid(JOB_T *jobs); 
int addjob(JOB_T *jobs, pid_t gpid, int state, int pid, char *cmdline);
int removejob(JOB_T *jobs, pid_t pid);
JOB_T *getjobgpid(JOB_T *jobs, pid_t gpid);
JOB_T *getjobjid(JOB_T *jobs, int jid); 
int gpid2jid(JOB_T *jobs, pid_t gpid); 
void listjobs(JOB_T *jobs);

#endif