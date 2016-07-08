#include <thread>
#include <mutex>
#include <atomic>
#include <condition_variable>
#include <mongoose.h>
#include "../server/server.h"
#include "../client/client.h"

#define HTTPSRV_STDPORT 18200
#define POLL_MSEC 100

static void NET_HTTP_StartPolling();
static void NET_HTTP_StopPolling();
static size_t mgstr2str(char *out, size_t outlen, const struct mg_str *in);

static std::thread worker_thread;

/*
==============================================
Shared variables
==============================================
*/
static std::mutex m_event;

static std::atomic<bool> end_poll_loop;
static struct mg_mgr http_mgr;
static struct mg_connection *http_srv;

typedef enum {
	HTTPEVT_NONE,
	HTTPEVT_FILE_REQUEST,
	HTTPEVT_DLSTATUS,
} httpEventType_t;

typedef struct {
	char reqPath[MAX_OSPATH];
	char rootPath[MAX_OSPATH];
	bool allowed;
} httpFileRequest_t;

typedef struct {
	size_t bytesWritten;
	size_t fileSize;
	bool ended;
	bool error;
	char err_msg[256];
} httpDLStatus_t;

typedef struct {
	httpEventType_t evtType;
	bool inuse;
	std::condition_variable cv_processed;
	bool processed;
	void *evt;
} httpEvent_t;

static httpEvent_t event;

#ifndef DEDICATED
static struct mg_connection *http_dl;
static httpDLStatus_t dlstatus;
static FILE *dl_file;
static std::atomic<bool> dl_abortFlag;
static size_t dl_bytesWritten;
static size_t dl_fileSize;
#endif

/*
==============================================
HTTP Worker Thread
==============================================
*/
#ifndef DEDICATED
char err_msg[256];
bool internal_error;

static void NET_HTTP_RecvData(struct mbuf *io, struct mg_connection *nc) {
	if (dl_abortFlag.load()) {
		nc->flags |= MG_F_CLOSE_IMMEDIATELY;
		return;
	}

	size_t bytesAvailable = io->len;
	if (dl_bytesWritten + bytesAvailable > dl_fileSize) {
		bytesAvailable = dl_fileSize - dl_bytesWritten;
	}

	if (bytesAvailable > 0) {
		size_t wrote = 0;
		size_t total = 0;

		// Handle short writes
		while ((wrote = fwrite(io->buf + total, 1, bytesAvailable - total, dl_file)) > 0) {
			total += wrote;
		}

		if (total < bytesAvailable) {
			strcpy(err_msg, "HTTP Error: 0 bytes written to file\n");
			internal_error = true;
			nc->flags |= MG_F_CLOSE_IMMEDIATELY;
			return;
		}

		dl_bytesWritten += bytesAvailable;

		{
			std::lock_guard<std::mutex> lk(m_event);
			dlstatus.bytesWritten = dl_bytesWritten;
			dlstatus.fileSize = dl_fileSize;
			event.evtType = HTTPEVT_DLSTATUS;
			event.evt = (httpDLStatus_t *)(&dlstatus);
			event.inuse = true;
			event.processed = false;
		}

		mbuf_remove(io, bytesAvailable);
	}

	if (dl_bytesWritten == dl_fileSize) {
		nc->flags |= MG_F_CLOSE_IMMEDIATELY;
	}
}
#endif

static void NET_HTTP_Event(struct mg_connection *nc, int ev, void *ev_data) {
	assert(http_srv);
	if (http_srv && nc->listener == http_srv) {
		if (ev == MG_EV_HTTP_REQUEST) {
			struct http_message *hm = (struct http_message *)ev_data;

			httpFileRequest_t filereq_evt;
			mgstr2str(filereq_evt.reqPath, sizeof(filereq_evt.reqPath), &hm->uri);
			memmove(filereq_evt.reqPath, filereq_evt.reqPath + 1, strlen(filereq_evt.reqPath));

			// wait for free event, set event, wait for result, free event and notify another worker thread
			{
				std::unique_lock<std::mutex> lk(m_event);

				event.evtType = HTTPEVT_FILE_REQUEST;
				event.inuse = true;
				event.processed = false;
				event.evt = (void *)(&filereq_evt);

				event.cv_processed.wait(lk, [] { return event.processed; });

				event.evt = NULL;
				event.inuse = false;
				lk.unlock();
			}

			if (filereq_evt.allowed) {
				struct mg_serve_http_opts opts = {
					filereq_evt.rootPath
				};

				mg_serve_http(nc, hm, opts);
			} else {
				mg_printf(nc, "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\n\r\n"
					"<html><body><h1>403 Forbidden</h1></body></html>");
				nc->flags |= MG_F_SEND_AND_CLOSE;
			}
		}
	}
#ifndef DEDICATED
	else if (http_dl && nc == http_dl) {
		switch (ev) {
		case MG_EV_CONNECT: {
			if (*(int *)ev_data != 0) {
				sprintf(err_msg, "connecting failed: %s", strerror(*(int *)ev_data));
				internal_error = true;
				nc->flags |= MG_F_CLOSE_IMMEDIATELY;
				return;
			}
			break;
		} case MG_EV_RECV: {
			struct mbuf *io = &nc->recv_mbuf;

			struct http_message msg;
			if (!dl_fileSize && mg_parse_http(io->buf, (int)io->len, &msg, 0)) {
				if (msg.resp_code != 200) {
					char tmp[128];

					mgstr2str(tmp, sizeof(tmp), &msg.resp_status_msg);
					sprintf(err_msg, "HTTP Error: %i %s", msg.resp_code, tmp);
					internal_error = true;
					nc->flags |= MG_F_CLOSE_IMMEDIATELY;
					return;
				}

				if (msg.body.len && io->buf + io->len >= msg.body.p) {
					dl_fileSize = msg.body.len;

					mbuf_remove(io, msg.body.p - io->buf);
					NET_HTTP_RecvData(io, nc);
				}
			} else {
				NET_HTTP_RecvData(io, nc);
			}
			break;
		} case MG_EV_CLOSE: {
			std::lock_guard<std::mutex> lk(m_event);
			event.evtType = HTTPEVT_DLSTATUS;
			event.evt = (httpDLStatus_t *)(&dlstatus);
			event.inuse = true;
			event.processed = false;
			dlstatus.ended = true;

			if (!dl_fileSize || dl_bytesWritten != dl_fileSize) {
				if (internal_error) {
					dlstatus.error = true;
					Q_strncpyz(dlstatus.err_msg, err_msg, sizeof(dlstatus.err_msg));
				} else if (!dl_abortFlag.load()) {
					dlstatus.error = true;
					Q_strncpyz(dlstatus.err_msg, "HTTP connection closed by remote host", sizeof(dlstatus.err_msg));
				}

				return;
			}
			break;
		} default:
			break;
		}
	}
	assert(http_dl);
#endif
}

static void NET_HTTP_PollLoop() {
	for (;;) {
		mg_mgr_poll(&http_mgr, POLL_MSEC);

		if (end_poll_loop.load()) {
			return;
		}
	}
}

/*
====================
NET_HTTP_ProgressEvents
====================
*/
void NET_HTTP_ProgressEvents() {
	std::unique_lock<std::mutex> lk(m_event);

	if (event.inuse && !event.processed) {
		if (event.evtType == HTTPEVT_FILE_REQUEST) {
			httpFileRequest_t *filereq = (httpFileRequest_t *)event.evt;

			const char *rootPath = FS_MV_VerifyDownloadPath(filereq->reqPath);
			if (rootPath) {
				filereq->allowed = true;
				Q_strncpyz(filereq->rootPath, rootPath, sizeof(filereq->reqPath));
			} else {
				filereq->allowed = false;
			}
		}
#ifndef DEDICATED
		else if (event.evtType == HTTPEVT_DLSTATUS) {
			httpDLStatus_t *dlstatus = (httpDLStatus_t *)event.evt;

			if (dlstatus->ended) {
				NET_HTTP_StopDownload();

				if (dlstatus->error) {
					Com_Error(ERR_DROP, dlstatus->err_msg);
				}
			} else {
				CL_ProgressHTTPDownload(dlstatus->fileSize, dlstatus->bytesWritten);
			}
		}
#endif

		// notify thread about processed event
		event.processed = true;
		lk.unlock();
		event.cv_processed.notify_one();
	}
}

/*
====================
NET_HTTP_StartPolling
====================
*/
static void NET_HTTP_StartPolling() {
	if (worker_thread.joinable())
		return;

	end_poll_loop = false;
	worker_thread = std::thread(NET_HTTP_PollLoop);
}

/*
====================
NET_HTTP_StopPolling
====================
*/
static void NET_HTTP_StopPolling() {
	if (!worker_thread.joinable())
		return;

	end_poll_loop = true;
	worker_thread.join();
}

/*
====================
NET_HTTP_Init
====================
*/
void NET_HTTP_Init() {
	mg_mgr_init(&http_mgr, NULL);
	Com_Printf("HTTP Engine initialized\n");
}

/*
====================
NET_HTTP_Shutdown
====================
*/
void NET_HTTP_Shutdown() {
	NET_HTTP_StopServer();

	Com_Printf("HTTP Engine: shutting down...\n");
	mg_mgr_free(&http_mgr);
}

/*
====================
NET_HTTP_StartServer
====================
*/
int NET_HTTP_StartServer(int port) {
	NET_HTTP_StopPolling();

	if (http_srv) {
		NET_HTTP_StartPolling();
		return 0;
	}

	if (port) {
		http_srv = mg_bind(&http_mgr, va("%i", port), NET_HTTP_Event);
	} else {
		for (port = HTTPSRV_STDPORT; port <= HTTPSRV_STDPORT + 15; port++) {
			http_srv = mg_bind(&http_mgr, va("%i", port), NET_HTTP_Event);
			if (http_srv) break;
		}
	}

	if (http_srv) {
		mg_set_protocol_http_websocket(http_srv);
		NET_HTTP_StartPolling();

		Com_Printf("HTTP Downloads: webserver running on port %i...\n", port);
		return port;
	} else {
		Com_Error(ERR_DROP, "HTTP Downloads: webserver startup failed.");
		return 0;
	}
}

/*
====================
NET_HTTP_StopServer
====================
*/
void NET_HTTP_StopServer() {
	NET_HTTP_StopPolling();

	if (!http_srv) {
		return;
	}

	Com_Printf("HTTP Downloads: shutting down webserver...\n");

	mg_mgr_free(&http_mgr);
	http_srv = NULL;
}

#ifndef DEDICATED
/*
====================
NET_HTTP_StartDownload
====================
*/
void NET_HTTP_StartDownload(const char *url, const char *toPath, const char *userAgent, const char *referer) {
	if (dl_file) {
		return;
	}

	dl_bytesWritten = dl_fileSize = 0;
	dl_abortFlag = false; internal_error = false;
	memset(&dlstatus, 0, sizeof(dlstatus));

	dl_file = fopen(toPath, "wb");
	if (!dl_file) {
		Com_Error(ERR_DROP, "could not open file %s for writing.", toPath);
		return;
	}

	char headers[1024];
	Com_sprintf(headers, sizeof(headers), "User-Agent: %s\r\nReferer: %s\r\n", userAgent, referer);

	http_dl = mg_connect_http(&http_mgr, NET_HTTP_Event, url, headers, NULL);
	NET_HTTP_StartPolling();
}

/*
====================
NET_HTTP_StopDownload
====================
*/
void NET_HTTP_StopDownload() {
	if (!dl_file) {
		return;
	}

	dl_abortFlag = true;
	NET_HTTP_StopPolling();
	http_dl = NULL;
	event.inuse = false;

	fclose(dl_file); dl_file = NULL;
	CL_EndHTTPDownload((qboolean)!(dl_fileSize && dl_bytesWritten == dl_fileSize));
}
#endif

static size_t mgstr2str(char *out, size_t outlen, const struct mg_str *in) {
	size_t cpylen = in->len;
	if (cpylen > outlen - 1) cpylen = outlen - 1;

	memcpy(out, in->p, cpylen);
	out[cpylen] = '\0';

	return cpylen;
}
