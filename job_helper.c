#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "job_helper.h"

/***********************************************
 * Helper routines that manipulate the job list
 **********************************************/
 
static int nextjid = 1;            	/* next job ID to allocate */
static int verbose = 0;

/* Clear the entries in a job struct */
void clearjob(JOB_T *job) {
    job->gpid = 0;
    job->jid = 0;
    job->state = UNDEF;
    job->cmdline[0] = '\0';
	job->num_pids = 0;
	while(job->first_process)
	{
		PROCESS *next_process = job->first_process->next;
		free(job->first_process);
		job->first_process = next_process;
	}
	job->first_process = NULL;
}

/* Print the job state and command  */
void printjob(JOB_T *job)
{
	if(job){
		printf("[%d]: ", job->jid);
		switch (job->state) {
		case BG: 
			printf("bg: ");
			break;
		case FG: 
			printf("fg: ");
			break;
		case ST: 
			printf("stopped: ");
			break;
		default:
			printf("listjobs: Internal error: job[%d].state=%d ", 
			   job->jid, job->state);
		}
		printf("%s", job->cmdline);
	}
}

/* Initialize the job list */
void initjobs(JOB_T *jobs) 
{
    for (int i = 0; i < MAXJOBS; i++){
		jobs[i].first_process = NULL;
		clearjob(&jobs[i]);
	}
}

/* Returns largest allocated job ID */
int maxjid(JOB_T *jobs) 
{
    int max = 0;
    for (int i = 0; i < MAXJOBS; i++){
		if (jobs[i].jid > max)
			max = jobs[i].jid;
	}
    return max;
}

/* Add a job/process to the job list */
int addjob(JOB_T *jobs, pid_t gpid, int state, int pid, char *cmdline) 
{
    int i;
    
    if (gpid < 1 || pid < 1)
	return 0;

    for (i = 0; i < MAXJOBS; i++) {
		if (jobs[i].gpid == gpid)
		{
			
			PROCESS *first_process = (PROCESS*)malloc(sizeof(PROCESS));
			first_process->pid = pid;
			first_process->next = jobs[i].first_process;
			jobs[i].first_process = first_process;
			jobs[i].num_pids++;
			return 1;
		}
    }
	for(i = 0;i < MAXJOBS; i++)
	{
		if (jobs[i].gpid == 0) {
			jobs[i].gpid = gpid;
			jobs[i].state = state;
			jobs[i].jid = nextjid++;
			if (nextjid > MAXJOBS)
			nextjid = 1;
			strcpy(jobs[i].cmdline, cmdline);
			jobs[i].first_process = (PROCESS*)malloc(sizeof(PROCESS));
			jobs[i].first_process->pid = pid;
			jobs[i].first_process->next = NULL;
			jobs[i].num_pids = 1;
			if(verbose){
				printf("Added job [%d] %d %s\n", jobs[i].jid, jobs[i].gpid, jobs[i].cmdline);
			}
			return 1;
		}
	}
    printf("Tried to create too many jobs\n");
    return 0;
}

/* remove a job/process from the job list */
int removejob(JOB_T *jobs, pid_t pid)
{
	if (pid < 1)
	return 0;

    for (int i = 0; i < MAXJOBS; i++) {
		if (jobs[i].gpid != 0) {
			PROCESS *next_process = jobs[i].first_process;
			PROCESS *last_process = NULL;
			while(next_process)
			{
				if(next_process->pid == pid)
				{
					if(last_process == NULL)
					{
						jobs[i].first_process = next_process->next;
					}
					else
					{
						last_process->next = next_process->next;
					}
					free(next_process);
					jobs[i].num_pids--;
					if(jobs[i].num_pids == 0)
					{
						clearjob(&jobs[i]);
						nextjid = maxjid(jobs)+1;
					}
					return 1;			
				}
				last_process = next_process;
				next_process = next_process->next;
			}
		}
    }
    return 0;
}

/* Find a job (by GPID) on the job list */
JOB_T *getjobgpid(JOB_T *jobs, pid_t gpid) 
{
    if (gpid < 1)
		return NULL;
    for (int i = 0; i < MAXJOBS; i++)
	{
		if (jobs[i].gpid == gpid)
			return &jobs[i];
	}
    return NULL;
}

/* Find a job (by JID) on the job list */
JOB_T *getjobjid(JOB_T *jobs, int jid) 
{
    if (jid < 1)
		return NULL;
    for (int i = 0; i < MAXJOBS; i++)
	{
		if (jobs[i].jid == jid)
			return &jobs[i];
    }
	return NULL;
}

/* Map job process group ID to job ID */
int gpid2jid(JOB_T *jobs, pid_t gpid) 
{
    if (gpid < 1)
		return 0;
    for (int i = 0; i < MAXJOBS; i++)
	{
		if (jobs[i].gpid == gpid)
			return jobs[i].jid;
    }
    return 0;
}

/* Print the job list */
void listjobs(JOB_T *jobs) 
{  
    for (int i = 0; i < MAXJOBS; i++) {
		if (jobs[i].gpid != 0) {
			printjob(&jobs[i]);
		}
    }
}
/******************************
 * end job list helper routines
 ******************************/