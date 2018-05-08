# -*- coding: utf-8 -*-
from datetime import datetime

import re

HAPROXY_HTTPCLF_LINE_REGEX = re.compile(
    # Client IP, literal '- -'
    # 127.0.0.1 - -
    r'(?P<client_ip>\d+\.\d+\.\d+\.\d+) - -\s'
    # Connection accept time, UTC.
    # [03/Mar/2017:08:43:15 +0000]
    r'\[(?P<accept_date>.*) \+\d{4}\]\s'
    # HTTP request string
    # "GET /my/awesome/object HTTP/1.1"
    r'"(?P<http_request>.*)"\s'
    # HTTP Status bytes read, literal '"" ""'
    # 200 8221 "" ""
    r'(?P<status_code>\d{3})\s(?P<bytes_read>\d+)\s""\s""\s'
    # Client port, accept time milliseconds (discarded).
    # 45788 506
    r'(?P<client_port>\d+)\s\d+\s'
    # Frontend (~ = ssl) / Backend / Server names
    # "main-fe~" "main-be" "best-server01"
    r'"(?P<frontend_name>.*)"\s"(?P<backend_name>.*)"\s"(?P<server_name>.*)"\s'
    # Timing info
    # Tq - Time waiting for client to send full HTTP request not counting data.
    # Tw - Time waiting in various queues
    # Tc - Time waiting for connection to establish to backend server.
    # Tr - Time waiting for be_srv to send full HTTP resp, not counting data.
    # Tt - Total time between initial accept, and last conn close.
    # 2 0 0 1 3
    r'(?P<tq>\d+)\s(?P<tw>\d+)\s(?P<tc>\d+)\s(?P<tr>\d+)\s(?P<tt>\d+)\s'
    # Disconnection state - Not currently supported by upstream
    # LR--
    r'(?P<disconnection_state>.{4})\s'
    # Connection/retry stats
    # actual conns, frontend conns, backend conns, server conns, retries
    # 1 1 0 0 0
    r'(?P<act>\d+)\s(?P<fe>\d+)\s(?P<be>\d+)\s(?P<srv>\d+)\s(?P<retries>\d+)\s'
    # Queue status
    # server queue, backend queue
    # 0 0
    r'(?P<queue_server>\d+)\s(?P<queue_backend>\d+)\s'
    # captured req/resp cookies - I don't think this is used right now.
    r'"(?P<request_cookies>.*)"\s"(?P<response_cookies>.*)"\s'
    # captured req/resp headers - Not sure if used or not right now.
    r'"(?P<request_headers>.*)"\s"(?P<response_headers>.*)"'
    # Other captured headers
    r'(?P<headers>.*)\Z',
)
