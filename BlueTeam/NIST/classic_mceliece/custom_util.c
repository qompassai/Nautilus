#include <sys/time.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <errno.h>
#include "gf.h"

void get_event_time(struct timeval *start, struct timeval *end, double *event_sum, int *event_times){

	long seconds, microseconds;
	double elapsed;

	seconds = end->tv_sec - start->tv_sec;
	microseconds = end->tv_usec - start->tv_usec;
	elapsed = seconds + microseconds*0.000001;
	*event_sum += elapsed*1000.0;
	*event_times += 1;
#ifdef ITERATION_PRINT
	printf("Time elapsed is %0.3f milliseconds\n", elapsed);
#endif


	return;

}


void print_event_execution_time(double *sum_list, int *times){

	printf("Avg Execution time is: %0.3f miliseconds \n", *sum_list/(*times));

	return;
}


/* msleep(): Sleep for the requested number of milliseconds. */
int msleep(long msec)
{
    struct timespec ts;
    int res;

    if (msec < 0)
    {
        errno = EINVAL;
        return -1;
    }

    ts.tv_sec = msec / 1000;
    ts.tv_nsec = (msec % 1000) * 1000000;

    do {
        res = nanosleep(&ts, &ts);
    } while (res && errno == EINTR);

    return res;
}



