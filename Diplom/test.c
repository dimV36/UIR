#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
     char *range = "s1-s3:c0,c2.c5,c10";
     char delim[] = "-:.,";
     char* token;
     
     int min_level = 0;
     int max_level = 0;

//     for (token = strtok(range, delim); token; token = strtok(NULL, delim)) { 
//	printf("%s\n", token);
//        scanf("s%d", &min_level, token);
	sscanf(range, "s%d%*cs%d", &min_level, &max_level);
	printf("%d, %d\n", min_level, max_level);
//     }
     return 0;
}
 
