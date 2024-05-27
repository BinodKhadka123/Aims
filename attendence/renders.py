from rest_framework import renderers
import json
class UserRenderer(renderers.JSONRenderer):
    charset='utf-8'
    def render(self,data,accepted_media_type=None,renderer_context=None):
        respone=""
        if 'ErrorDetails' in str(data):
            respone =json.dumps({'errors':data})
        else:
            respone =json.dumps(data)
        return respone
    