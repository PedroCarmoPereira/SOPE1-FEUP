#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>

typedef struct
{
    bool r, v, o, h, sha1, sha256, md5;
    char *filename;
    char *logfilename;
    char *outputfilename;
    clock_t start, end;
} arg;

void writeLog(double inst, int pid, char* act, arg args){
  FILE *logfile = fopen(args.logfilename, "a");

  fprintf(logfile, "%0.2f - %08d - %s\n", inst, pid, act);

  fclose(logfile);
}

void logger(int i, arg args, char *cmd){
  args.end = clock();
  double inst = args.end-args.start;
  int pid = getpid();
  char act[25];
  char final[1000];
  switch(i){
    case 0:
      strcpy(act, "ANALYZED: ");
      strcpy(final, act);
      strcat(final, args.filename);
      break;
    case 1:
      strcpy(act, "COMMAND: ");
      strcpy(final, act);
      strcat(final, cmd);
      break;
    case 2:
      strcpy(act, "SIGNAL: ");
      strcpy(final, act);
      strcat(final, cmd);
      break;
    default:
      break;

  }


  writeLog(inst, pid, final, args);
}


void hashCalculator(arg args)
{

    char *filename = args.filename;

    char tempFileName[1000];

    FILE * out;
    if (args.o) out = fopen(args.outputfilename, "a");
    else out = stdout;

    strcpy(tempFileName, filename);
    strcat(tempFileName, "_info");

    if (args.md5)
    {

        char command[1000];
        char sum[25];

        sprintf(command, "md5sum %s >> %s", filename, tempFileName);

        system(command);
        if(args.v) logger(1, args, command);

        FILE *tempFile = fopen(tempFileName, "r");

        fgets(sum, 25, tempFile);

        sum[24] = '\0';

        fclose(tempFile);

        unlink(tempFileName);

        fprintf(out, ",%s", sum);
    }
    if (args.sha1)
    {
        char command[1000];
        char sum[33];

        sprintf(command, "sha1sum %s >> %s", filename, tempFileName);

        system(command);
        if(args.v) logger(1, args, command );

        FILE *tempFile = fopen(tempFileName, "r");

        fgets(sum, 33, tempFile);
        sum[32] = '\0';

        fclose(tempFile);

        unlink(tempFileName);

        fprintf(out,",%s", sum);
    }

    if (args.sha256)
    {
        char command[1000];
        char sum[65];

        sprintf(command, "sha256sum %s >> %s", filename, tempFileName);

        system(command);
        if(args.v) logger(1, args, command);

        FILE *tempFile = fopen(tempFileName, "r");

        fgets(sum, 65, tempFile);

        sum[64] = '\0';

        fclose(tempFile);

        unlink(tempFileName);

        fprintf(out,",%s", sum);
    }

    fprintf(out,"\n");
    if(args.o) fclose(out);

}

void getFileInfo(arg args){



    char *filename = args.filename;
    char tempFileName[1000];
    struct stat fileInfo;
    char date[20];
    strcpy(tempFileName, filename);
    strcat(tempFileName, "_info");

    FILE * out;
    if (args.o) out = fopen(args.outputfilename, "a");
    else out = stdout;
    int a = stat(filename, &fileInfo);
    if ( a < 0)
        printf("%s\n", strerror(errno));

    else if (a == 0 && S_ISDIR(fileInfo.st_mode)){
      fprintf(out, "%s is a directory;", args.filename);
      //if(args.r) analyseDirR(argc)

    }
    else{

        fprintf(out, "%s", filename);

        char command[1000];
        char sum[100];

        sprintf(command, "file %s >> %s", filename, tempFileName);

        system(command);
        if(args.v) logger(1, args, command);

        FILE *tempFile = fopen(tempFileName, "r");


        size_t pos = ftell(tempFile);
        fseek(tempFile, 0, SEEK_END);
        size_t length = ftell(tempFile);
        fseek(tempFile, pos, SEEK_SET);

        fgets(sum, length, tempFile);

        const char s[2] = ":";
        char *token;

        token = strtok(sum, s);
        token = strtok(NULL, s);

        fclose(tempFile);

        unlink(tempFileName);

        fprintf(out, ",%s", token);

        fprintf(out, ",%ld,", fileInfo.st_size);

        if(fileInfo.st_mode & S_IRUSR){
            fprintf(out, "r");
        }
        if(fileInfo.st_mode & S_IWUSR){
            fprintf(out, "w");
        }
        if(fileInfo.st_mode & S_IXUSR){
            fprintf(out, "x");
        }

        strftime(date, 20, "%G-%m-%dT%H:%M:%S", localtime(&(fileInfo.st_atime)));
        fprintf(out, ",%s",date);

        strftime(date, 20, "%G-%m-%dT%H:%M:%S", localtime(&(fileInfo.st_mtime)));
        fprintf(out, ",%s",date);

    }

    if(!args.h || (stat(args.filename, &fileInfo) == 0 && S_ISDIR(fileInfo.st_mode))){
        fprintf(out,"\n");
    }

    if(args.o){
      if (a == 0 && S_ISDIR(fileInfo.st_mode)){
        kill(getpid(),SIGUSR1);
        char act[25];
        strcpy(act, "SIGUSR1");
        if(args.v) logger(2,args,act);
      }
      else{
        kill(getpid(),SIGUSR2);
        char act[25];
        strcpy(act, "SIGUSR2");
        if(args.v) logger(2,args,act);
      }
        printf("Data saved on file %s\n", args.outputfilename);
        fclose(out);
    }

}

arg analyseArgs(int argc, char *argv[])
{

    arg args;
    args.r = false;
    args.h = false;
    args.o = false;
    args.v = false;
    args.filename = argv[argc - 1];

    if(argc < 3){

        return args;
    }


    for (int i = 0; i < argc; i++)
    {

        if (strcmp(argv[i], "-h") == 0)
        {
            if(argc < 4){
                return args;
            }

            args.h = true;
            if (strstr(argv[i + 1], "sha1") != NULL)
            {
                args.sha1 = true;
            }
            if (strstr(argv[i + 1], "sha256") != NULL)
            {
                args.sha256 = true;
            }
            if (strstr(argv[i + 1], "md5") != NULL)
            {
                args.md5 = true;
            }

        }

        if (strcmp(argv[i], "-r") == 0)
        {
            args.r = true;

        }

        if (strcmp(argv[i], "-v") == 0)
        {
            args.v = true;
            args.logfilename = getenv("LOGFILENAME");
        }

        if (strcmp(argv[i], "-o") == 0)
        {
            args.outputfilename = getenv("PWD");
            if(argv[i+1] == args.filename) strcat(args.outputfilename , "/forensicOut.txt");
            else {
                strcat(args.outputfilename, "/");
                strcat(args.outputfilename,  argv[i+1]);
            }
            args.o = true;
            unlink(args.outputfilename);
        }
    }

    return args;
}


void options(arg args)
{

    struct stat fileInfo;
    if(stat(args.filename, &fileInfo) == 0 && S_ISDIR(fileInfo.st_mode)){
        return;
    }
    if (args.h == true)
    {
        hashCalculator(args);
    }


    return;
}


void analyseDirNR(arg args){
    DIR * dp = opendir(args.filename);
    struct dirent *direntity;
    pid_t pid;
    while((direntity = readdir(dp)) != NULL){
        if (strcmp(direntity->d_name, ".") != 0 && strcmp(direntity->d_name, "..") != 0){
            if ((pid = fork()) < 0) fprintf(stderr, "Fork Error\n");
            if (pid == 0){
                strcat(args.filename, "/");
                strcat(args.filename, direntity->d_name);
                //printf("%s\n", args.filename);
                getFileInfo(args);
                options(args);
                if(args.v) logger(0, args, NULL);
                return;
            }

            else wait(NULL);
        }
    }

    closedir(dp);
}

void analyseDirR(int argc, char *argv[], char *envp[]){

    arg args = analyseArgs(argc, argv);
    DIR * dp = opendir(args.filename);
    struct dirent *direntity;
    pid_t pid;
    while((direntity = readdir(dp)) != NULL){
        if (strcmp(direntity->d_name, ".") != 0 && strcmp(direntity->d_name, "..") != 0){
            if ((pid = fork()) < 0) fprintf(stderr, "Fork Error\n");
            if (pid == 0){
                strcat(args.filename, "/");
                strcat(args.filename, direntity->d_name);
                struct stat fileInfo;
                if (stat(args.filename, &fileInfo) == 0 && !S_ISDIR(fileInfo.st_mode)){
                    getFileInfo(args);
                    options(args);
                    if(args.v) logger(0, args, NULL);
                }
                else execve(argv[0], argv, envp);
            }
            else wait(NULL);
        }
    }

    closedir(dp);
}

void int_handler(){
  printf("Program terminated!\n");
  waitpid(-1, NULL, 0);
  exit(0);
}

void usr_handler(int signo)
{
  if (signo == SIGUSR1){
    FILE *f;
    //char dirnum[32];
    int intdirnum;
    f = fopen("dirnum.txt","r+");
    fscanf(f, "%d", &intdirnum);
    //intdirnum = atoi(dirnum);
    intdirnum++;
    printf("New directory: %d directories at this time.\n", intdirnum);
    fprintf(f, "%d", intdirnum);
    fclose(f);
  }
  else if (signo == SIGUSR2){
    FILE *f;
    char filenum[32];
    int intfilenum;
    f = fopen("filenum.txt","rw");
    fscanf(f, "%s", filenum);
    intfilenum = atoi(filenum);
    intfilenum++;
    printf("New file: %d files at this time.\n", intfilenum);
    fprintf(f, "%d", intfilenum);
    fclose(f);
  }

}

void instalHandlers(){
  struct sigaction usr1_act;
  usr1_act.sa_handler = usr_handler;
  usr1_act.sa_flags = 0;
  sigemptyset(&(usr1_act.sa_mask));
  sigaction(SIGUSR1, &usr1_act, NULL);

  struct sigaction usr2_act;
  usr2_act.sa_handler = usr_handler;
  usr2_act.sa_flags = 0;
  sigemptyset(&(usr2_act.sa_mask));
  sigaction(SIGUSR2, &usr2_act, NULL);

  struct sigaction int_act;
  int_act.sa_handler = int_handler;
  int_act.sa_flags = 0;
  sigemptyset(&(int_act.sa_mask));
  sigaddset(&(int_act.sa_mask), SIGINT);
  sigaddset(&(int_act.sa_mask), SIGUSR1);
  sigaddset(&(int_act.sa_mask), SIGUSR2);
  sigaddset(&(int_act.sa_mask), SIGTSTP);
  sigaddset(&(int_act.sa_mask), SIGCONT);
  sigaction(SIGINT, &int_act, NULL);
}

int main(int argc, char *argv[], char *envp[])
{
    arg args;

    args.start = clock();

    instalHandlers();
    setenv("LOGFILENAME", "Logfile.txt", 1);


    if (argc < 2)
    {
        printf("forensic: forensic  [-r] [-h [md5[,sha1[,sha256]]] [-o <outfile>] [-v] <file|dir> \n");
        return 1;
    }

    args = analyseArgs(argc, argv);

    char cmd[1000];
    strcpy(cmd, argv[0]);
    for(int i = 1; i < argc; i++){
      strcat(cmd, " ");
      strcat(cmd, argv[i]);
    }

    if (args.v) logger(1, args, cmd);

    struct stat fileInfo;
    if(stat(args.filename, &fileInfo) == 0 && S_ISDIR(fileInfo.st_mode) && !args.r) analyseDirNR(args);

    else if (args.r) analyseDirR(argc, argv, envp);

    else {
        getFileInfo(args);
        options(args);
    }
}
