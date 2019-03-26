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
} arg;

arg args;

void getFileInfo(){

    char *filename = args.filename;
    char tempFileName[100];
    struct stat fileInfo;
    char date[20];
    strcpy(tempFileName, filename);
    strcat(tempFileName, "_info");
    
    if (stat(filename, &fileInfo) < 0)
        printf("%s\n", strerror(errno));
    else{

        printf("%s", filename);
        
        char command[100];
        char sum[100]; 

        sprintf(command, "file %s >> %s", filename, tempFileName);

        system(command);

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

        printf(",%s", token);

        printf(",%ld,", fileInfo.st_size);

        if(fileInfo.st_mode & S_IRUSR){
            printf("r");
        }
        if(fileInfo.st_mode & S_IWUSR){
            printf("w");
        }
        if(fileInfo.st_mode & S_IXUSR){
            printf("x");
        }

        strftime(date, 20, "%G-%m-%dT%H:%M:%S", localtime(&(fileInfo.st_atime)));
        printf(",%s",date);

        strftime(date, 20, "%G-%m-%dT%H:%M:%S", localtime(&(fileInfo.st_mtime)));
        printf(",%s",date);

    }

    if(!args.h){
        printf("\n");
    }
        
}

int analyseArgs(int argc, char *argv[])
{

    args.r = false;
    args.h = false;
    args.o = false;
    args.v = false;
    args.filename = argv[argc - 1];

    if(argc < 3){
        return 1;
    }

    for (int i = 0; i < argc; i++)
    {

        if (strcmp(argv[i], "-h") == 0)
        {
            if(argc < 4){
                return 1;
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

            
            break;
        }

        if (strcmp(argv[i], "-r") == 0)
        {
            args.r = true;
            break;
        }

        if (strcmp(argv[i], "-v") == 0)
        {
            args.v = true;
            break;
        }

        if (strcmp(argv[i], "-o") == 0)
        {
            args.outputfilename = argv[4];
            args.o = true;
            break;
        }
    }

    getFileInfo();

    return 0;
}


void hashCalculator()
{

    char *filename = args.filename;

    char tempFileName[100];

    strcpy(tempFileName, filename);
    strcat(tempFileName, "_info");

    if (args.md5)
    {

        char command[100];
        char sum[25];

        sprintf(command, "md5sum %s >> %s", filename, tempFileName);

        system(command);

        FILE *tempFile = fopen(tempFileName, "r");

        fgets(sum, 25, tempFile);

        sum[24] = '\0';

        fclose(tempFile);

        unlink(tempFileName);

        printf(",%s", sum);
    }
    if (args.sha1)
    {
        char command[100];
        char sum[33];

        sprintf(command, "sha1sum %s >> %s", filename, tempFileName);

        system(command);

        FILE *tempFile = fopen(tempFileName, "r");

        fgets(sum, 33, tempFile);
        sum[32] = '\0';

        fclose(tempFile);

        unlink(tempFileName);

        printf(",%s", sum);
    }

    if (args.sha256)
    {
        char command[100];
        char sum[65];

        sprintf(command, "sha256sum %s >> %s", filename, tempFileName);

        system(command);

        FILE *tempFile = fopen(tempFileName, "r");

        fgets(sum, 65, tempFile);

        sum[64] = '\0';

        fclose(tempFile);

        unlink(tempFileName);

        printf(",%s", sum);
    }

    printf("\n");

}


void options()
{

    if (args.h == true)
    {
        hashCalculator();
    }
    if (args.r == true)
    {
        printf("opt2\n");
    }
    if (args.v == true)
    {
        printf("opt3\n");
    }
    if (args.o == true)
    {
       printf("opt4\n");
    }
    
    if( (args.h == false) && (args.r == false) && (args.v == false) && (args.o == false)){
        getFileInfo();
    }
}

int main(int argc, char *argv[])
{

    if (argc < 2)
    {
        printf("USE THIS PLEASE: ./forensic  [-r] [-h [md5[,sha1[,sha256]]] [-o <outfile>] [-v] <file|dir> \n");
        return 1;
    }

    analyseArgs(argc, argv);
    options();
    
}