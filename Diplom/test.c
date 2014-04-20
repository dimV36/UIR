#define _GNU_SOURCE 
#include <stdio.h>

int main()
{
  char *my_string;

  asprintf (&my_string, "Hello World.");
  puts (my_string);

  return 0;
}