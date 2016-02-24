import json
import datetime
import time


class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, datetime.datetime):
            return int(time.mktime(o.timetuple()))
        return json.JSONEncoder(self, o)