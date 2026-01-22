#include "systemcalls.h"

#include <stdlib.h> // system()
#include <sys/types.h> // pid_t
#include <unistd.h> // fork()
#include <sys/wait.h> // waitpid()
#include <signal.h> // kill()
#include <stdio.h> 
#include <sys/stat.h>
#include <fcntl.h>


#define SYSCALL_FAIL (-1)

/**
 * @param cmd the command to execute with system()
 * @return true if the command in @param cmd was executed
 *   successfully using the system() call, false if an error occurred,
 *   either in invocation of the system() call, or if a non-zero return
 *   value was returned by the command issued in @param cmd.
*/
bool do_system(const char *cmd)
{
    /*
    *  Call the system() function with the command set in the cmd
    *   and return a boolean true if the system() call completed with success
    *   or false() if it returned a failure
    */
    int ret = system(cmd);

    return (ret != SYSCALL_FAIL);
}

/**
* @param count -The numbers of variables passed to the function. The variables are command to execute.
*   followed by arguments to pass to the command
*   Since exec() does not perform path expansion, the command to execute needs
*   to be an absolute path.
* @param ... - A list of 1 or more arguments after the @param count argument.
*   The first is always the full path to the command to execute with execv()
*   The remaining arguments are a list of arguments to pass to the command in execv()
* @return true if the command @param ... with arguments @param arguments were executed successfully
*   using the execv() call, false if an error occurred, either in invocation of the
*   fork, waitpid, or execv() command, or if a non-zero return value was returned
*   by the command issued in @param arguments with the specified arguments.
*/

bool do_exec(int count, ...)
{
    va_list args;
    va_start(args, count);
    char * command[count+1];
    int i;
    for(i=0; i<count; i++)
    {
        command[i] = va_arg(args, char *);
    }
    va_end(args);
    command[count] = NULL;

    /*
    *   Execute a system command by calling fork, execv(),
    *   and wait instead of system (see LSP page 161).
    *   Use the command[0] as the full path to the command to execute
    *   (first argument to execv), and use the remaining arguments
    *   as second argument to the execv() command.
    */

    pid_t pid = fork();
    if (pid == SYSCALL_FAIL) {
        perror("fork");
        return false;
    }

    if (pid == 0) { // child process

        int ret = execv(command[0],command);
        perror("execv");
        _exit(ret);

    } else { // parent process

        int status;
        pid_t w;
        for(;;) { // loops until child process exits
            w = waitpid(pid, &status, 0);
            if (w == pid) break;
            if (w == SYSCALL_FAIL) {
                perror("waitpid");
                return false;
            }
        }

        if (WIFEXITED(status)) {
            int exitcode = WEXITSTATUS(status);
            return (exitcode == 0);
        } else if (WIFSIGNALED(status)) {
            // child terminated by signal
            return false;
        } else {
            // all other cases treated as fail
            return false;
        }
    }
}

/**
* @param outputfile - The full path to the file to write with command output.
*   This file will be closed at completion of the function call.
* All other parameters, see do_exec above
*/
bool do_exec_redirect(const char *outputfile, int count, ...)
{
    va_list args;
    va_start(args, count);
    char * command[count+1];
    int i;
    for (i=0; i<count; i++)
    {
        command[i] = va_arg(args, char *);
    }
    va_end(args);
    command[count] = NULL;
    
    /*
    *   Call execv, but first using https://stackoverflow.com/a/13784315/1446624 as a refernce,
    *   redirect standard out to a file specified by outputfile.
    *   The rest of the behaviour is same as do_exec()
    */

    int fd = open(outputfile, O_CREAT|O_RDWR|O_TRUNC, 0644);
    if (fd == SYSCALL_FAIL) {
        perror("open");
        return false;
    }

    pid_t pid = fork();
    if (pid == SYSCALL_FAIL) {
        perror("fork");
        return false;
    }

    if (pid == 0) { // child process
        dup2(fd, STDOUT_FILENO); // redirect stdout to file

        int ret = execv(command[0],command);
        perror("execv");
        close(fd);
        _exit(ret);

    } else { // parent process

        int status;
        pid_t w;
        for(;;) { // loops until child process exits
            w = waitpid(pid, &status, 0);
            if (w == pid) break;
            if (w == SYSCALL_FAIL) {
                perror("waitpid");
                return false;
            }
        }

        if (WIFEXITED(status)) {
            int exitcode = WEXITSTATUS(status);
            return (exitcode == 0);
        } else if (WIFSIGNALED(status)) {
            // child terminated by signal
            return false;
        } else {
            // all other cases treated as fail
            return false;
        }
    }

    return true;
}
