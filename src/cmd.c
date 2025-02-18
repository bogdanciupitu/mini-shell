// SPDX-License-Identifier: BSD-3-Clause

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "cmd.h"
#include "utils.h"

#define READ		0
#define WRITE		1

static bool shell_cd(word_t *dir)
{
	if (!dir || dir->next_part)
		return false;

	char *path = get_word(dir);

	if (chdir(path) != 0) {
		perror("cd");
		free(path);
		return false;
	}

	free(path);
	return true;
}

static int shell_exit(void)
{
	exit(0);
	return SHELL_EXIT;
}

static int parse_simple(simple_command_t *s, int level, command_t *father)
{
	if (!s || !s->verb)
		return -1;

	char *cmd = get_word(s->verb);

	char *equal_sign = strchr(cmd, '=');

	if (equal_sign) {
		*equal_sign = '\0';
		char *name = cmd;
		char *value = equal_sign + 1;

		setenv(name, value, 1);
		free(cmd);
		return 0;
	}

	if (strcmp(cmd, "cd") == 0) {
		free(cmd);
		return !shell_cd(s->params);
	} else if (strcmp(cmd, "exit") == 0 || strcmp(cmd, "quit") == 0) {
		free(cmd);
		return shell_exit();
	}

	free(cmd);

	int argc;
	char **argv = get_argv(s, &argc);
	pid_t pid = fork();
	int status;

	if (pid == 0) {
		if (s->in) {
			char *file = get_word(s->in);
			int fd = open(file, O_RDONLY);

			if (fd < 0) {
				free(file);
				exit(EXIT_FAILURE);
			}

			dup2(fd, STDIN_FILENO);
			close(fd);
			free(file);
		}

		if (s->out) {
			int fd;
			char *file = get_word(s->out);

			if (s->io_flags == IO_OUT_APPEND)
				fd = open(file, O_CREAT | O_WRONLY | O_APPEND, 0644);
			else
				fd = open(file, O_CREAT | O_WRONLY | O_TRUNC, 0644);


			if (fd < 0) {
				free(file);
				exit(EXIT_FAILURE);
			}

			dup2(fd, STDOUT_FILENO);
			close(fd);
			free(file);
		}

		if (s->err) {
			int fd;
			char *file = get_word(s->err);

			if (s->io_flags == IO_ERR_APPEND)
				fd = open(file, O_CREAT | O_WRONLY | O_APPEND, 0644);
			else
				fd = open(file, O_CREAT | O_WRONLY | O_TRUNC, 0644);

			if (fd < 0) {
				free(file);
				exit(EXIT_FAILURE);
			}

			dup2(fd, STDERR_FILENO);
			close(fd);
			free(file);
		}

		if (strcmp(cmd, "pwd") == 0) {
			char cwd[1024];

			if (getcwd(cwd, sizeof(cwd)) != NULL)
				printf("%s\n", cwd);
		} else {
			if (execvp(argv[0], argv) == -1)
				printf("Execution failed for '%s'\n", argv[0]);
		}
		exit(EXIT_FAILURE);
	} else if (pid > 0) {
		waitpid(pid, &status, 0);

		for (int i = 0; i < argc; i++)
			free(argv[i]);
		free(argv);

		return WEXITSTATUS(status);
	} else {
		return -1;
	}
}

static bool run_in_parallel(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	pid_t pid1, pid2;
	int status1, status2;

	pid1 = fork();
	if (pid1 == 0)
		exit(parse_command(cmd1, level + 1, father));

	pid2 = fork();
	if (pid2 == 0)
		exit(parse_command(cmd2, level + 1, father));

	waitpid(pid1, &status1, 0);
	waitpid(pid2, &status2, 0);

	if (WIFEXITED(status1) && WIFEXITED(status2))
		return true;
	return false;
}

static bool run_on_pipe(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	int pipefd[2];
	pid_t pid1, pid2;
	int status1, status2;

	if (pipe(pipefd) == -1)
		return false;

	pid1 = fork();
	if (pid1 < 0) {
		return false;
	} else if (pid1 == 0) {
		close(pipefd[READ]);
		dup2(pipefd[WRITE], STDOUT_FILENO);
		close(pipefd[WRITE]);

		exit(parse_command(cmd1, level + 1, father));
	}

	pid2 = fork();
	if (pid2 < 0) {
		return false;
	} else if (pid2 == 0) {
		close(pipefd[WRITE]);
		dup2(pipefd[READ], STDIN_FILENO);
		close(pipefd[READ]);

		exit(parse_command(cmd2, level + 1, father));
	}

	close(pipefd[READ]);
	close(pipefd[WRITE]);
	waitpid(pid1, &status1, 0);
	waitpid(pid2, &status2, 0);

	if (WIFEXITED(status1) && WIFEXITED(status2))
		return true;
	return false;
}

int parse_command(command_t *c, int level, command_t *father)
{
	if (!c)
		return -1;

	if (c->op == OP_NONE)
		return parse_simple(c->scmd, level, father);

	switch (c->op) {
	case OP_SEQUENTIAL:
		parse_command(c->cmd1, level + 1, c);
		return parse_command(c->cmd2, level + 1, c);

	case OP_PARALLEL:
		if (run_in_parallel(c->cmd1, c->cmd2, level, c))
			return 0;
		return 1;

	case OP_CONDITIONAL_NZERO:
		if (parse_command(c->cmd1, level + 1, c))
			return parse_command(c->cmd2, level + 1, c);
		return 0;

	case OP_CONDITIONAL_ZERO:
		if (!parse_command(c->cmd1, level + 1, c))
			return parse_command(c->cmd2, level + 1, c);
		return 0;

	case OP_PIPE:
		if (run_on_pipe(c->cmd1, c->cmd2, level, c))
			return 0;
		return 1;

	default:
		return SHELL_EXIT;
	}
}
