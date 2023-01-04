#include "ucxclient.h"

ucp_context_h myContext;
ucp_worker_h myWorker;
ucp_ep_h myEndpoint;

ucp_listener_h myListener;

std::vector<char> dataVector;

std::mutex sendMutex;

bool stop = false;

// Error handling callback.
void ucx_client::err_cb(void *arg, ucp_ep_h ep, ucs_status_t status)
{
	printf("error handling callback was invoked with status %d (%s)\n",status, ucs_status_string(status));
	stop = true;
}


// The callback on the sending side, which is invoked after finishing sending the message.
static void send_cb(void *request, ucs_status_t status, void *user_data)
{
    test_req_t *ctx;
    ctx           = (test_req_t*) user_data;
    ctx->complete = 1;
}

// Progress the request until it completes.
ucs_status_t ucx_client::request_progress(void *request, test_req_t* req)
{
	ucs_status_t status;

    /* if operation was completed immediately */
    if (request == NULL) {
        return UCS_OK;
    }

    if (UCS_PTR_IS_ERR(request)) {
        return UCS_PTR_STATUS(request);
    }


    while (!req->complete) {
		ucp_worker_progress(myWorker);
        usleep(10);
    }
    
	status = UCS_PTR_STATUS(request);

	free(req);
    ucp_request_free(request);

    return status;
}

void ucx_client::progress_worker() {
    while(!stop) {
		sendMutex.lock();
		ucp_worker_progress(myWorker);
		sendMutex.unlock();
	}
}

/**
 * The callback invoked upon receiving a connection request from the host.
 */
void ucx_client::conn_handle_cb(ucp_conn_request_h conn_request, void *arg)
{
    printf("Got connection request.\n");

    ucp_ep_h endPoint;
    ucp_ep_params_t ep_params;
    ep_params.field_mask =  UCP_EP_PARAM_FIELD_ERR_HANDLER |
                            UCP_EP_PARAM_FIELD_CONN_REQUEST;
    ep_params.err_handler.cb = err_cb;
    ep_params.err_handler.arg  = NULL;
    ep_params.conn_request = conn_request;
    ucp_ep_create(myWorker, &ep_params, &endPoint);

    myEndpoint = endPoint;

    printf("Finished handling connection request.\n");
}

int ucx_client::init_conn(int receivePort)
{
	//UCP objects
	ucp_params_t ucp_params;
	ucs_status_t status;

	memset(&ucp_params, 0, sizeof(ucp_params));

	// UCP initialization
	ucp_params.field_mask = UCP_PARAM_FIELD_FEATURES;
	ucp_params.features = UCP_FEATURE_AM;

	status = ucp_init(&ucp_params, NULL, &myContext);
	if (status != UCS_OK) {
		fprintf(stderr, "failed to ucp_init (%s)\n", ucs_status_string(status));
		return -1;
	}

	ucp_worker_params_t worker_params;
    memset(&worker_params, 0, sizeof(worker_params));
    worker_params.field_mask  = UCP_WORKER_PARAM_FIELD_THREAD_MODE;
    worker_params.thread_mode = UCS_THREAD_MODE_SINGLE;

    status = ucp_worker_create(myContext, &worker_params, &myWorker);
	if (status != UCS_OK) {
		fprintf(stderr, "failed to init_worker (%s)\n", ucs_status_string(status));
		ucp_cleanup(myContext);
		return -1;
	}

	struct sockaddr_storage listen_addr;
	ucp_listener_params_t params;

	struct sockaddr_in *sa_in = (struct sockaddr_in*) &listen_addr;
	sa_in->sin_addr.s_addr = INADDR_ANY;
	sa_in->sin_family = AF_INET;
	sa_in->sin_port   = htons(receivePort);

	params.field_mask         = UCP_LISTENER_PARAM_FIELD_SOCK_ADDR |
								UCP_LISTENER_PARAM_FIELD_CONN_HANDLER;
	params.sockaddr.addr      = (const struct sockaddr*)&listen_addr;
	params.sockaddr.addrlen   = sizeof(listen_addr);
	params.conn_handler.cb    = conn_handle_cb;
	params.conn_handler.arg   = NULL;

	/* Create a listener on the server side to listen on the given address.*/
	status = ucp_listener_create(myWorker, &params, &myListener);
	if (status != UCS_OK) {
		fprintf(stderr, "failed to listen (%s)\n", ucs_status_string(status));
		return status;
	}

	return 0;
}

void ucx_client::send(void* data, size_t size, int messageId) {
	ucs_status_t status;
	ucs_status_ptr_t request;
    ucp_request_param_t params;

	sendMutex.lock();

	test_req_t* req = (test_req_t*) malloc(sizeof(test_req_t));
	req->complete = 0;

	params.op_attr_mask = 	UCP_OP_ATTR_FIELD_CALLBACK |
							UCP_OP_ATTR_FIELD_DATATYPE |
                          	UCP_OP_ATTR_FIELD_USER_DATA |
							UCP_OP_ATTR_FIELD_FLAGS;
	params.datatype = ucp_dt_make_contig(1);
	params.cb.send = (ucp_send_nbx_callback_t) send_cb;
	params.user_data = req;
	params.flags = UCP_AM_SEND_FLAG_EAGER;

	request = ucp_am_send_nbx(myEndpoint, messageId, NULL, 0, data, size, &params);
	
	status = request_progress(request, req);
	if (status != UCS_OK) {
	    fprintf(stderr, "unable to send UCX message: %d (%s)\n", status, ucs_status_string(status));
    }
	sendMutex.unlock();
}

void ucx_client::register_callback(ucp_am_recv_callback_t callback, int messageId) {
	ucs_status_t status;

	ucp_am_handler_param_t handler_params;
    handler_params.field_mask = UCP_AM_HANDLER_PARAM_FIELD_ID |
                                UCP_AM_HANDLER_PARAM_FIELD_CB ;
    handler_params.id = messageId;
    handler_params.cb = callback;

    status = ucp_worker_set_am_recv_handler(myWorker, &handler_params);
	if (status != UCS_OK) {
		printf("Error registering callback (%s)", ucs_status_string(status));
	}
}

void ucx_client::cleanup() {
	stop =  true;

	printf("Stopping UCX execution\n");

	ucs_status_ptr_t close_status_pointer;
    ucp_request_param_t params;
    params.op_attr_mask = 0;

	close_status_pointer = ucp_ep_close_nbx(myEndpoint, &params);

    ucs_status_t status;
    if(UCS_PTR_IS_PTR(close_status_pointer)) {
		do {
			ucp_worker_progress(myWorker);
			status = ucp_request_check_status(close_status_pointer);
		} while (status == UCS_INPROGRESS);
		ucp_request_free(close_status_pointer);
	} else {
		status = UCS_PTR_STATUS(close_status_pointer);
	}

	if (status != UCS_OK) {
		fprintf(stderr, "failed to close ep %p: %s\n", (void*)myEndpoint, ucs_status_string(status));
	}

    ucp_worker_destroy(myWorker);
	ucp_cleanup(myContext);
}
