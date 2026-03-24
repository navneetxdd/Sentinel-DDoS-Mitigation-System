# REST API bridge for Sentinel (Compatible with OS-Ken/Ryu)
from os_ken.app.ofctl import service
from os_ken.base import app_manager

class OfctlRest(app_manager.OSKenApp):
    _CONTEXTS = {
        'ofp_service': service.OfctlService
    }
    def __init__(self, *args, **kwargs):
        super(OfctlRest, self).__init__(*args, **kwargs)
