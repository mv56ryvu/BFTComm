#ifndef UCX_CLIENT_H
#define UCX_CLIENT_H

#include <ucp/api/ucp.h>

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <unistd.h>
#include <thread>
#include <cstring>
#include <vector>
#include <mutex>

/**
 * Stream request context. Holds a value to indicate whether or not the
 * request is completed.
 */
typedef struct test_req {
    int complete;
} test_req_t;

class ucx_client {
public:
    int init_conn(int sendPort);
    void send(void* data, size_t size, int messageId);
    void register_callback(ucp_am_recv_callback_t callback, int messageId);
    static void progress_worker();
    void cleanup();
private:
    static ucs_status_t request_progress(void *request, test_req_t* req);
    static void err_cb(void *arg, ucp_ep_h ep, ucs_status_t status);
    static void conn_handle_cb(ucp_conn_request_h conn_request, void *arg);
};

#endif
