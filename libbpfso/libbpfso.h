#define TASK_COMM_LEN 16

struct event {
    int pid;
    char comm[TASK_COMM_LEN];
    char filename[256];
};
