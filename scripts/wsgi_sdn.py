# Minimal WSGI replacement for OS-Ken/Ryu
import eventlet
from eventlet import wsgi
from webob.dec import wsgify
from os_ken.lib import hub

class WSGIApplication(object):
    def __init__(self, **kwargs):
        super(WSGIApplication, self).__init__()
        self.app_mgr = kwargs.get('app_mgr')
        self.reg_apps = {}

    @wsgify
    def __call__(self, req):
        # Very simple dispatcher for Sentinel dashboard checks
        if req.path == '/stats/switches':
            return '[]' # Return empty list if no switches connected
        return '{"status": "ok", "app": "sentinel-sdn-compat"}'

def start_service(app_mgr):
    # This is what osken_manager_compat.py expects
    instance = WSGIApplication(app_mgr=app_mgr)
    
    def _run():
        # Port 8080 is the standard Ryu/OS-Ken REST port
        sock = eventlet.listen(('0.0.0.0', 8080))
        wsgi.server(sock, instance)
        
    return _run
