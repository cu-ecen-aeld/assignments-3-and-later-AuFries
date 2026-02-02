#include "threading.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

// Optional: use these functions to add debug or error prints to your application
// #define DEBUG_LOG(msg,...)
#define DEBUG_LOG(msg,...) printf("threading: " msg "\n" , ##__VA_ARGS__)
#define ERROR_LOG(msg,...) printf("threading ERROR: " msg "\n" , ##__VA_ARGS__)
#define SLEEP_MULTIPLIER 1000

void* threadfunc(void* thread_param)
{
    // TODO: wait, obtain mutex, wait, release mutex as described by thread_data structure
    // hint: use a cast like the one below to obtain thread arguments from your parameter
    struct thread_data* thread_data = (struct thread_data *) thread_param;

    // wait wait_to_obtain_ms
    DEBUG_LOG("Waiting to obtain");
    usleep(thread_data->wait_to_obtain_ms*SLEEP_MULTIPLIER);

    // obtain mutex
    DEBUG_LOG("Obtaining mutex");
    int ret;
    ret = pthread_mutex_lock(thread_data->thread_mutex);
    if (ret != 0) {
        perror("pthread_mutex_lock");
        return false;
    }

    // wait wait_to_release_ms
    DEBUG_LOG("Waiting to release");
    usleep(thread_data->wait_to_release_ms*SLEEP_MULTIPLIER);

    // release mutex
    DEBUG_LOG("Releasing mutex");
    ret = pthread_mutex_unlock(thread_data->thread_mutex);
    if (ret != 0) {
        perror("pthread_mutex_unlock");
        return false;
    }

    thread_data->thread_complete_success = true;
    DEBUG_LOG("Thread return");
    return thread_param;
}


bool start_thread_obtaining_mutex(pthread_t *thread, pthread_mutex_t *mutex,int wait_to_obtain_ms, int wait_to_release_ms)
{
    /**
     * TODO: allocate memory for thread_data, setup mutex and wait arguments, pass thread_data to created thread
     * using threadfunc() as entry point.
     *
     * return true if successful.
     *
     * See implementation details in threading.h file comment block
     */


    // allocate memory for thread_data
    struct thread_data* thread_data = malloc(sizeof(*thread_data));

    // setup thread_data
    thread_data->thread_mutex = mutex;
    thread_data->wait_to_obtain_ms = wait_to_obtain_ms;
    thread_data->wait_to_release_ms = wait_to_release_ms;

    // create thread and pass thread_data
    DEBUG_LOG("Creating thread");
    int ret = pthread_create(thread, NULL, threadfunc, thread_data);
    if (ret != 0) {
        perror("pthread_create");
        return false;
    }

    DEBUG_LOG("Function return");
    return true;
}

