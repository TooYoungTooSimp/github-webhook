from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
from subprocess import run, PIPE
import logging, argparse

args = None


def _str(obj): return "" if obj is None else str(obj)


class HTTPHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        session = urlparse(self.path)
        self.process(session.path, parse_qs(session.query), None)

    def do_POST(self):
        session = urlparse(self.path)
        cLength = int(self.headers['Content-Length'])
        if cLength > 0:
            if _str(self.headers['content-type']) == 'application/x-www-form-urlencoded':
                self.process(session.path,
                             parse_qs('&'.join([session.query, self.rfile.read(cLength).decode('utf-8')])), None)
            else:
                self.process(session.path, parse_qs(session.query), self.rfile.read(cLength))
        else:
            self.process(session.path, parse_qs(session.query), None)

    def process(http, path, query, data):
        if path == '/webhook':
            logging.info('X-GitHub-Event:' + _str(http.headers['X-GitHub-Event']))
            logging.info('X-Hub-Signature:' + _str(http.headers['X-Hub-Signature']))
            logging.info('X-GitHub-Delivery:' + _str(http.headers['X-GitHub-Delivery']))
            http.send_response(200)
            http.send_header('Content-type', 'text/html')
            http.end_headers()
            http.wfile.write(run(args.program, input=query['payload'][0].encode('UTF-8'), stdout=PIPE).stdout)
        else:
            http.send_response_only(404)
            http.end_headers()


def main():
    parser = argparse.ArgumentParser(description='Another webhook for GitHub')
    parser.add_argument("-p", "--port", type=int, default=8000, help='Port to bind')
    parser.add_argument("-b", "--bind", default="", help='Address to bind')
    parser.add_argument("-s", "--sig", default="", help='X-Hub-Signature')
    parser.add_argument("program", help='Program to execute, json passes as stdin')
    global args
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    HTTPServer((args.bind, args.port), HTTPHandler).serve_forever()


main()
