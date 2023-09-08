# C Execution methods

 Summary
| Method                             | Advantages                                                                                       |
|------------------------------------|--------------------------------------------------------------------------------------------------|
| `system` Function                  | - Simplicity: It's straightforward to use.<br>- No need to manage child processes manually.      |
| `exec` Family of Functions         | - Control: Allows fine-grained control over the command execution.<br>- No need for a shell.     |
| - `execl` Subtype                  | - Specify the command and its arguments as separate parameters.<br>- Explicit argument list.     |
| - `execv` Subtype                  | - Pass the command and its arguments as an array.<br>- Flexibility for variable arguments.       |
| - `execve` Subtype                 | - Pass the command and its arguments as an array.<br>- Also specify the env variables            |
| - `execvp` Subtype                 | - Pass the command and its arguments as an array.<br>- Search for program in PATH                |
| - `execvpe` Subtype                | - Pass the command and its arguments as an array.<br>- Search for program in PATH, and specify the env variables<br>- Not part of the C standard library but is available on Unix like systems      |
| `popen` Function                   | - Bidirectional: Can capture both the output and input of the command.<br>- Streamlined I/O.     |
| `fork` and `exec`                  | - Customization: Provides control over the child process.<br>- Suitable for complex scenarios.   |
| `posix_spawn` Function             | - Efficiency: More efficient for spawning processes in POSIX systems.<br>- Fine-grained control. |

## System
```c
#include <stdlib.h>

int main() {
    system("ls -l");
    return 0;
}
```

## Exec Familly

### Execl
```c
#include <unistd.h>

int main() {
    execl("/bin/ls", "ls", "-l", NULL);
    return 0;
}

```

### Execv
```c
#include <unistd.h>

int main() {
    char *args[] = {"/bin/ls", "-l", NULL};
    execv(args[0], args);
    return 0;
}
```

### Execve
```c
#include <unistd.h>

int main() {
    char *args[] = {"/bin/ls", "-l", NULL};
    char *env[] = {"PATH=/usr/bin", "USER=john", NULL};
    execve(args[0], args, env);
    return 0;
}
```

### Execvp
```c
#include <stdio.h>
#include <unistd.h>

int main() {
    char *args[] = {"ls", "-l", NULL};
    execvp(args[0], args);
    return 0;
}
```

### Execvpe
```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    char *args[] = {"ls", "-l", NULL};
    char *envp[] = {"PATH=/bin:/usr/bin", NULL};
    execvpe(args[0], args, envp);
    return 0;
}
```

## Popen
```c
#include <stdio.h>

int main() {
    FILE *fp = popen("ls -l", "r");
    if (fp) {
        char buffer[256];
        while (fgets(buffer, sizeof(buffer), fp) != NULL) {
            printf("%s", buffer);
        }
        pclose(fp);
    }
    return 0;
}
```

## Fork
```c
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>

int main() {
    pid_t pid = fork();
    if (pid == 0) { // Child process
        execl("/bin/ls", "ls", "-l", NULL);
    } else if (pid > 0) { // Parent process
        wait(NULL); // Wait for the child to complete
    } else {
        perror("fork");
        return 1;
    }
    return 0;
}
```

## Posix Spawn
```c
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <spawn.h>
#include <unistd.h>
#include <sys/wait.h>

int main() {
    char *const cmd[] = {"ls", "-l", NULL};
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);

    pid_t pid;
    if (posix_spawn(&pid, "/bin/ls", &actions, NULL, cmd, NULL) == 0) {
        wait(NULL); // Wait for the child to complete
    } else {
        perror("posix_spawn");
        return 1;
    }

    return 0;
}
