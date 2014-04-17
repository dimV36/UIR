#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
     char range[] = "s1-s5:c0,c2.c5,c10";
     char *level_range = NULL;
     char *category_range = NULL;
     char* token = NULL;
     
     int min_level = -1;
     int max_level = -1;

     level_range = strtok(range, ":");
     category_range = strtok(NULL, ":");
     
     printf("level: %s\n", level_range);
     printf("category: %s\n", category_range);
     
     sscanf(level_range, "s%d%*cs%d", &min_level, &max_level);
     if (-1 == max_level)
	max_level = min_level;
     
     int i, j;
     for (i = min_level; i < max_level + 1; i++) {
	for (j = i; j < max_level + 1; j++)
	 printf("s%d-s%d\n", i, j);
     }
     
     	const char *	delim = ";,";
	char *		save;
	char *		p;

	char *test = "s1-s5:c0,c2.c5,c10";
	for (p = strtok_r(&test, delim, &save); p; p = strtok_r(NULL, delim, &save))
	{
			printf("chunk=%s\n", *p);
		}
     
//     for (token = strtok(range, delim); token; token = strtok(NULL, delim)) 
//	printf("%s\n", token);
//        scanf("s%d", &min_level, token);
//     }

     return 0;
}
 
