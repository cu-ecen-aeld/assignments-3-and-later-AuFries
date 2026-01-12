/* Writes a string to a file
   Parameters:
   writefile - file to write to
   writestr - string to write
   Logs what occurs in script to syslog. Exits with value 0 if successful.
   Exits with value 1 error if parameters not specified.
 */

#include <syslog.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

 int main(int argc, char *argv[]) {
    openlog("writer", LOG_PID|LOG_CONS, LOG_USER);
    if (argc != 3) {
        syslog(LOG_ERR, "Incorrect script paramters. Usage: writer <writefile> <writestr>");
        closelog();
        return 1;
    }

    const char *writefile = argv[1];
    const char *writestr = argv[2];

    FILE *file = fopen(writefile, "w");
    if (file == NULL) {
        syslog(LOG_ERR, "Error opening file");
        closelog();
        return 1;
    }

    syslog(LOG_DEBUG, "Writing %s to %s", writestr, writefile);
    int ret = fprintf(file, "%s", writestr);
    if (ret < 0) {
        syslog(LOG_ERR, "Error writing to file: %s", strerror(errno));
        fclose(file);
        closelog();
        return 1;
    }
    fclose(file);
    closelog();
    return 0;
 }