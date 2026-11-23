# One process per CPU core; threads give I/O concurrency inside each process.
import multiprocessing
bind = "127.0.0.1:8080"
workers = multiprocessing.cpu_count()
threads = 4
timeout = 15
graceful_timeout = 10
limit_request_line = 2048
limit_request_fields = 100
limit_request_field_size = 8190
max_requests = 10000          # recycle workers to cap memory growth
max_requests_jitter = 1000
accesslog = None              # Warden writes its own JSON access log
