#!/usr/bin/env python3
import logging


def hook(bindAddr, hookPath, secret, callback):
    _str = lambda obj: "" if obj is None else str(obj)
    from urllib.parse import urlencode, urlparse, parse_qs
    from http.server import BaseHTTPRequestHandler, HTTPServer
    import hmac, hashlib

    class HTTPHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            session = urlparse(self.path)
            self.process(session.path, parse_qs(session.query), None)

        def do_POST(self):
            session = urlparse(self.path)
            cLength = int(self.headers['Content-Length'])
            if cLength > 0:
                if _str(self.headers['content-type']) == 'application/x-www-form-urlencoded':
                    self.process(session.path, parse_qs('&'.join([session.query, self.rfile.read(cLength).decode()])), None)
                else:
                    self.process(session.path, parse_qs(session.query), self.rfile.read(cLength))
            else:
                self.process(session.path, parse_qs(session.query), None)

        def process(http, path, query, data):
            if path == hookPath:
                logging.info('EventID:' + " ".join([_str(http.headers['X-GitHub-Delivery']), _str(http.headers['X-GitHub-Event'])]))
                payload = _str(query['payload'][0]) if data is None else data.decode()
                localSig = 'sha1=' + hmac.new(_str(secret).encode(), (urlencode({'payload': payload}) if data is None else payload).encode(), hashlib.sha1).hexdigest()
                remoteSig = _str(http.headers['X-Hub-Signature'])
                logging.info('Local-Signature:' + localSig)
                logging.info('X-Hub-Signature:' + remoteSig)
                if (_str(secret) == '' and remoteSig == '') or (remoteSig == localSig):
                    http.send_response(200)
                    http.send_header('Content-type', 'text/plain')
                    http.end_headers()
                    http.wfile.write(callback(payload))
                else:
                    logging.error('Signature not match')
                    http.send_response_only(401)
                    http.end_headers()
            else:
                http.send_response_only(404)
                http.end_headers()

    HTTPServer(bindAddr, HTTPHandler).serve_forever()


if __name__ == '__main__':
    import argparse, subprocess
    parser = argparse.ArgumentParser(description='Another webhook for GitHub')
    parser.add_argument("-p", "--port", type=int, default=8000, help='Port to bind')
    parser.add_argument("-b", "--bind", default="", help='Address to bind')
    parser.add_argument("-a", "--path", default="/webhook", help='Path to bind')
    parser.add_argument("-s", "--sig", default="", help='X-Hub-Signature')
    parser.add_argument("program", help='Program to execute, json passes as stdin')
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    hook((args.bind, args.port), args.path, args.sig, lambda data: subprocess.run(args.program.split(), input=data.encode(), stdout=subprocess.PIPE).stdout)
