/* Part I: Observing the OS through the /proc file system */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>

#define MAX_ARRAY_SIZE (1<<8)
#define MAX_FILE_SIZE (1<<16)
#define MAX_CPU_LINES (1<<8)
#define MAX_DISKS	  (1<<8)

/* Run: man proc */
const char processor_types_file[] = "/proc/cpuinfo";			/* CPU and system architecture dependent items */
const char kernel_version_file[] = "/proc/version";				/* kernel version */
const char memory_configured_file[] = "/proc/meminfo";			/* Statistics about memory usage on the system */
const char time_since_booted_file[] = "/proc/uptime";			/* the uptime of the system (seconds) */

const char cpu_stat_file[] = "/proc/stat";						/* kernel/system statistics */
const char disk_stat_file[] = "/proc/diskstats";				/* disk I/O statistics for each disk device. */

typedef struct kernel_info_1 KERNEL_INFO_1;
typedef struct kernel_info_2 KERNEL_INFO_2;
typedef struct cpu_times_info CPU_TIMES_INFO;

struct kernel_info_1
{
	char processor_type[MAX_ARRAY_SIZE];						/* model name -> /proc/cpuinfo */
	char kernel_version[MAX_ARRAY_SIZE];						/* Linux version -> /proc/version */
	char memory_configured[MAX_ARRAY_SIZE];						/* MemTotal -> /proc/meminfo */
	char time_since_booted[MAX_ARRAY_SIZE];						/* uptime(seconds) -> /proc/uptime */
};

/* /proc/stat */
struct cpu_times_info
{
	double percent_cpu_user_mode;								/* Percent of time spent in user mode */
	double percent_cpu_system_mode;								/* Percent of time spent in system mode */
	double percent_cpu_idle_task;								/* Percent of time spent in idle task */
};

struct kernel_info_2
{
	size_t num_cpu_lines : 8;									/* number of cpu lines */
	size_t num_disks : 8;										/* number of disk devices */
	
	CPU_TIMES_INFO total_cpu_time;								/* /proc/stat */
	CPU_TIMES_INFO cpu_time[MAX_CPU_LINES];
	
	double amount_available_memory;								/* MemAvailable -> /proc/meminfo */
	double percent_available_memory;							/* Percent of MemAvailable */
		
	/* https://www.kernel.org/doc/Documentation/iostats.txt */
	double total_rate_disk_read;								/* Rate of sectors read successfully -> /proc/diskstats */
	double rate_disk_read[MAX_DISKS];
	
	double total_rate_disk_write;								/* Rate of sectors written successfully -> /proc/diskstats */
	double rate_disk_write[MAX_DISKS];							
	
	double rate_context_switches;								/* Rate of ctxt -> /proc/stat */
	double rate_process_creations;								/* Rate of processes -> /proc/stat */
};

/* Reset KERNEL_INFO_2 */
void kernel_info_reset(KERNEL_INFO_2 *ki)
{
	ki->total_cpu_time = (CPU_TIMES_INFO){0};
	ki->amount_available_memory = 0;
	ki->percent_available_memory = 0;
	
	memset(ki->cpu_time, 0, MAX_CPU_LINES * sizeof(CPU_TIMES_INFO));
	
	ki->total_rate_disk_read = 0;
	
	memset(ki->rate_disk_read, 0.0, MAX_DISKS * sizeof(double));
	
	ki->total_rate_disk_write = 0;
	
	memset(ki->rate_disk_write, 0.0, MAX_DISKS * sizeof(double));
	
	ki->rate_context_switches = 0;
	ki->rate_process_creations = 0;
}

/* update c_ki by adding ki */
void kernel_info_update(KERNEL_INFO_2 *c_ki, KERNEL_INFO_2 *ki)
{
	c_ki->total_cpu_time.percent_cpu_user_mode += ki->total_cpu_time.percent_cpu_user_mode;
	c_ki->total_cpu_time.percent_cpu_system_mode += ki->total_cpu_time.percent_cpu_system_mode;
	c_ki->total_cpu_time.percent_cpu_idle_task += ki->total_cpu_time.percent_cpu_idle_task;
	c_ki->num_cpu_lines = ki->num_cpu_lines;
	
	for(size_t i = 0;i < c_ki->num_cpu_lines; i++)
	{
		c_ki->cpu_time[i].percent_cpu_user_mode += ki->cpu_time[i].percent_cpu_user_mode;
		c_ki->cpu_time[i].percent_cpu_system_mode += ki->cpu_time[i].percent_cpu_system_mode;
		c_ki->cpu_time[i].percent_cpu_idle_task += ki->cpu_time[i].percent_cpu_idle_task;
	}
	
	c_ki->amount_available_memory += ki->amount_available_memory;
	c_ki->percent_available_memory += ki->percent_available_memory;
	
	c_ki->total_rate_disk_read += ki->total_rate_disk_read;
	c_ki->total_rate_disk_write += ki->total_rate_disk_write;
	c_ki->num_disks = ki->num_disks;
	
	for(size_t i = 0;i < c_ki->num_disks; i++)
	{
		c_ki->rate_disk_read[i] += ki->rate_disk_read[i];
		c_ki->rate_disk_write[i] += ki->rate_disk_write[i];
	}
	
	c_ki->rate_context_switches += ki->rate_context_switches;
	c_ki->rate_process_creations += ki->rate_process_creations;
}	

/* Return file contents from file name */
char *get_file_contents(const char *file_name)
{
	static char file_contents[MAX_FILE_SIZE];
	FILE* file_pointer = fopen(file_name, "r");
	
	if(file_pointer == NULL)
	{
		fprintf(stderr, "fopen failed for %s: %s\n", file_name, strerror(errno));
		exit(EXIT_FAILURE);
	}
	
	int num_read = fread(file_contents, sizeof(char), MAX_FILE_SIZE - 1, file_pointer);   
	file_contents[num_read] = '\0';
	
	fclose(file_pointer);
	
	return file_contents;
}

/* Read model name for processor type */
void get_processor_model_name(KERNEL_INFO_1 *kernel_info)
{
	char *file_contents = get_file_contents(processor_types_file);
	char *reader = file_contents;
	reader = strstr(reader, "model name\t:");
	reader += strlen("model name\t:");
	sscanf(reader, "%[^\n]s", kernel_info->processor_type);
}

/* Read Linux version for version */
void get_kernel_version(KERNEL_INFO_1 *kernel_info)
{
	char *file_contents = get_file_contents(kernel_version_file);
	sscanf(file_contents, "Linux version %s", kernel_info->kernel_version);
}

/* Read Linux version for version */
void get_memory_configured(KERNEL_INFO_1 *kernel_info)
{
	char *file_contents = get_file_contents(memory_configured_file);
	sscanf(file_contents, "MemTotal: %[^\n]s", kernel_info->memory_configured);
}

/* Read uptime(second) for time since booted */
void get_time_since_booted(KERNEL_INFO_1 *kernel_info)
{
	char *file_contents = get_file_contents(time_since_booted_file);
	sscanf(file_contents, "%s", kernel_info->time_since_booted);
}

/* Get percent of cpu times in user mode, system mode and idle task since boot */
/* Get number of context switches and process creations per second */
void get_cpu_stat(KERNEL_INFO_2 *kernel_info, double uptime)
{
	char *file_contents = get_file_contents(cpu_stat_file);
	char *reader = file_contents;
	reader = strstr(reader, "cpu");
	reader += strlen("cpu");
	double user, nice, system, idle, iowait, irq, softirq, steal, guest, guest_nice;
	sscanf(reader, "%lf %lf %lf %lf %lf %lf %lf %lf %lf %lf", &user, &nice, &system, 
		&idle, &iowait, &irq, &softirq, &steal, &guest, &guest_nice);
	
	double total_cpu_time = user + nice + system + idle + iowait + irq + softirq + steal + guest + guest_nice;
	
	/* Ignored the time spent in user mode with low priority (nice) */
	kernel_info->total_cpu_time.percent_cpu_user_mode = user * 100 / total_cpu_time;
	kernel_info->total_cpu_time.percent_cpu_system_mode = system * 100 / total_cpu_time;
	kernel_info->total_cpu_time.percent_cpu_idle_task = idle * 100 / total_cpu_time;
	
	size_t i = 0;	
	/* Counting different cpu lines */
	while((reader = strstr(reader, "cpu")))
	{
		sscanf(reader, "%*s %lf %lf %lf %lf %lf %lf %lf %lf %lf %lf", &user, &nice, &system, 
		&idle, &iowait, &irq, &softirq, &steal, &guest, &guest_nice);
		reader += strlen("cpu");
		total_cpu_time = user + nice + system + idle + iowait + irq + softirq + steal + guest + guest_nice;
	
		kernel_info->cpu_time[i].percent_cpu_user_mode = user * 100 / total_cpu_time;
		kernel_info->cpu_time[i].percent_cpu_system_mode = system * 100 / total_cpu_time;
		kernel_info->cpu_time[i].percent_cpu_idle_task = idle * 100 / total_cpu_time;
		i++;
	}
	kernel_info->num_cpu_lines = i;

	/* Get number of context switches since boot */
	reader = strstr(file_contents, "ctxt");
	reader += strlen("ctxt");
	sscanf(reader, "%lf", &(kernel_info->rate_context_switches));

	/* Get number of process creations since boot */
	reader = strstr(reader, "processes");
	reader += strlen("processes");
	sscanf(reader, "%lf", &(kernel_info->rate_process_creations));
	
	kernel_info->rate_context_switches /= uptime;
	kernel_info->rate_process_creations /= uptime;
}

/* Get number of sector read/writes per second */
void get_disk_stat(KERNEL_INFO_2 *kernel_info, double uptime)
{
	// https://www.kernel.org/doc/Documentation/iostats.txt
	char *file_contents = get_file_contents(disk_stat_file);
	double sector_reads = 0.0, sector_writes = 0.0;
	kernel_info->total_rate_disk_read = 0.0;
	kernel_info->total_rate_disk_write = 0.0;
	char *disk_devices = strtok (file_contents, "\r\n");
	size_t i = 0;
	/* Counting different disk devices */
	while (disk_devices)
	{
		sscanf(disk_devices, "%*s %*s %*s %*s %*s %lf %*s %*s %*s %lf", &sector_reads, &sector_writes);
		
		kernel_info->total_rate_disk_read += sector_reads;
		kernel_info->total_rate_disk_write += sector_writes;
		kernel_info->rate_disk_read[i] = sector_reads / uptime;
		kernel_info->rate_disk_write[i] = sector_writes / uptime;
		
		disk_devices = strtok(NULL, "\r\n");
		i++;
	}
	kernel_info->num_disks = i;
	
	kernel_info->total_rate_disk_read /= uptime;
	kernel_info->total_rate_disk_write /= uptime;
}

/* Get amount and precent of available memory */
/* This is an estimate of how much memory is available for starting new applications, without swapping. */
void get_available_memory_stat(KERNEL_INFO_2 *kernel_info)
{
	char *file_contents = get_file_contents(memory_configured_file);
	double total_memory, available_memory;
	char *reader = strstr(file_contents, "MemTotal:");
	reader += strlen("MemTotal:");
	sscanf(reader, "%lf", &total_memory);
	reader = strstr(reader, "MemAvailable:");
	reader += strlen("MemAvailable:");
	sscanf(reader, "%lf", &available_memory);
	
	kernel_info->amount_available_memory = available_memory;
	kernel_info->percent_available_memory = available_memory * 100 / total_memory;
}

int main(int argc, char *argv[])
{	
	if (argc == 1) /* No command line arguments */
	{ 
		KERNEL_INFO_1 kernel_info;

		/* Processor type */
		get_processor_model_name(&kernel_info);

		printf("Processor type: %s\n", kernel_info.processor_type);

		/* Kernel Version */
		get_kernel_version(&kernel_info);

		printf("Kernel version: %s\n", kernel_info.kernel_version);

		/* Configured Memory */
		get_memory_configured(&kernel_info);

		printf("The amount of memory configured into this computer: %s\n", kernel_info.memory_configured);

		/* Up Time */
		get_time_since_booted(&kernel_info);

		printf("Amount of time since the system was last booted: %s Seconds\n", kernel_info.time_since_booted);

	}
	else if(argc == 3) /* Passed read_rate and printout_rate in seconds */
	{
		/* Assuming printout_rate >= read_rate and both are integers */
		int read_rate = atoi(argv[1]);
		int printout_rate = atoi(argv[2]);
		if(read_rate > printout_rate)
		{
			fprintf(stderr, "Read rate cannot be greater than printout rate.\nExiting\n");
			exit(EXIT_FAILURE);
		}
		
		KERNEL_INFO_2 kernel_info, cumulative_kernel_info;
		
		/* Get system uptime */
		char *file_contents = get_file_contents(time_since_booted_file);
		double uptime;
		sscanf(file_contents, "%lf", &uptime);

		/* Start timer */
		clock_t time_begin = clock();
		int old_duration = 0;
		kernel_info_reset(&cumulative_kernel_info);
		int instances = 0;
		while(true)
		{
			/* Track every second */
			int new_duration = (clock() - time_begin) / CLOCKS_PER_SEC;
			if(new_duration != old_duration)
			{
				old_duration = new_duration;
				/* Read statistics every read_rate seconds */
				if(old_duration % read_rate == 0)
				{
					/* Get the statistics */
					get_cpu_stat(&kernel_info, uptime);
		
					get_disk_stat(&kernel_info, uptime);
		
					get_available_memory_stat(&kernel_info);
					
					/* Update add statistics every read_rate seconds */
					kernel_info_update(&cumulative_kernel_info, &kernel_info);
					instances++;					
				}
				
				/* Write statistics every printout_rate seconds */
				if(old_duration % printout_rate == 0)
				{
					printf("\n%d Seconds Passed!\n\n", old_duration);
					
					/* Calculate the average every printout_rate seconds */
					cumulative_kernel_info.total_cpu_time.percent_cpu_user_mode /= instances;
					cumulative_kernel_info.total_cpu_time.percent_cpu_system_mode /= instances;
					cumulative_kernel_info.total_cpu_time.percent_cpu_idle_task /= instances;

					for(size_t i = 0;i < cumulative_kernel_info.num_cpu_lines; i++)
					{
						cumulative_kernel_info.cpu_time[i].percent_cpu_user_mode /= instances;
						cumulative_kernel_info.cpu_time[i].percent_cpu_system_mode /= instances;
						cumulative_kernel_info.cpu_time[i].percent_cpu_idle_task /= instances;
					}

					cumulative_kernel_info.amount_available_memory /= instances;
					cumulative_kernel_info.percent_available_memory /= instances;
						
					cumulative_kernel_info.total_rate_disk_read /= instances;
					cumulative_kernel_info.total_rate_disk_write /= instances;
					
					for(size_t i = 0;i < cumulative_kernel_info.num_disks; i++)
					{
						cumulative_kernel_info.rate_disk_read[i] /= instances;
						cumulative_kernel_info.rate_disk_write[i] /= instances;
					}
					
					cumulative_kernel_info.rate_context_switches /= instances;
					cumulative_kernel_info.rate_process_creations /= instances;
					
					/* Print the calulated average */
					printf("%%Cpu: %lf%%, %lf%%, %lf%%\n",
						cumulative_kernel_info.total_cpu_time.percent_cpu_user_mode, cumulative_kernel_info.total_cpu_time.percent_cpu_system_mode, 
						cumulative_kernel_info.total_cpu_time.percent_cpu_idle_task);

					for(size_t i = 0;i < cumulative_kernel_info.num_cpu_lines; i++)
					{
						printf("%%Cpu%lu: %lf%%, %lf%%, %lf%%\n", i,
							cumulative_kernel_info.cpu_time[i].percent_cpu_user_mode, cumulative_kernel_info.cpu_time[i].percent_cpu_system_mode, 
							cumulative_kernel_info.cpu_time[i].percent_cpu_idle_task);
					}
						
		 			printf("Mem: %.0lf KB, %lf%%\n", 
						cumulative_kernel_info.amount_available_memory, cumulative_kernel_info.percent_available_memory);

					printf("Sectors: %lf, %lf\n",
						cumulative_kernel_info.total_rate_disk_read, cumulative_kernel_info.total_rate_disk_write);

					for(size_t i = 0;i < cumulative_kernel_info.num_disks; i++)
					{
						printf("Sectors%lu: %lf, %lf\n", i, 
							cumulative_kernel_info.rate_disk_read[i], cumulative_kernel_info.rate_disk_write[i]);
					}
						
					printf("Context switches/s: %lf\n", cumulative_kernel_info.rate_context_switches);

					printf("Process creations/s: %lf\n", cumulative_kernel_info.rate_process_creations);
				
					/* Reset statistics to zero */
					kernel_info_reset(&cumulative_kernel_info);
					instances = 0;
				}
			}
		}

	}
	else
	{
		fprintf(stderr, "Wrong number of arguments\n");
		exit(EXIT_FAILURE);
	}
	return EXIT_SUCCESS;
}
