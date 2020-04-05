#include "includes.h"
#include "lsh.h"

/**
 * https://brennan.io/2015/01/16/write-a-shell-in-c/
 */

#define LSH_TOK_BUFSIZE 64
#define LSH_TOK_DELIM " \t\r\n\a"


char *builtin_str[] = {
    "login",
    "put",
    "del",
    "get",
    "ls",
    "mkdir",
    "rmdir",
    "cd",
    "help",
    "exit"
};

int lsh_num_builtins() {
  return sizeof(builtin_str) / sizeof(char *);
}

char *lsh_read_line(void)
{
  char *line = NULL;
  ssize_t bufsize = 0; // 利用 getline 帮助我们分配缓冲区
  getline(&line, &bufsize, stdin);
  return line;
}
char **lsh_split_line(char *line)
{
  int bufsize = LSH_TOK_BUFSIZE, position = 0;
  char **tokens = malloc(bufsize * sizeof(char*));
  char *token;

  if (!tokens) {
    fprintf(stderr, "lsh: allocation error\n");
    exit(EXIT_FAILURE);
  }

  token = strtok(line, LSH_TOK_DELIM);
  while (token != NULL) {
    tokens[position] = token;
    position++;

    if (position >= bufsize) {
      bufsize += LSH_TOK_BUFSIZE;
      tokens = realloc(tokens, bufsize * sizeof(char*));
      if (!tokens) {
        fprintf(stderr, "lsh: allocation error\n");
        exit(EXIT_FAILURE);
      }
    }

    token = strtok(NULL, LSH_TOK_DELIM);
  }
  tokens[position] = NULL;
  return tokens;
}
