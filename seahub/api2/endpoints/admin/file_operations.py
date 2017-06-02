import datetime
import time
import logging
import copy

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAdminUser
from django.utils.translation import ugettext as _
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status

from seahub.utils import get_file_audit_stats
from seahub.api2.authentication import TokenAuthentication
from seahub.api2.throttling import UserRateThrottle
from seahub.api2.utils import api_error

logger = logging.getLogger(__name__)


class FileOperations(APIView):
    """
    The  File Operations Record .
        Permission checking:
        1. only admin can perform this action.
    """
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    throttle_classes = (UserRateThrottle,)
    permission_classes = (IsAdminUser,)

    def get(self, request):
        """
        Get a record of the specified time
            param:
                start: the start time of the query.
                end: the end time of the query.
            return:
                the list of file operations record.
        """
        request_get = request.GET
        get_start = request_get.get("start", "")
        get_end = request_get.get("end", "")
        error_msg = ""
        if not get_start or not get_end:
            error_msg = _("The start or end time parameter can not be empty")
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)
        try:
            start_time = datetime.datetime.strptime(get_start,
                    "%Y-%m-%d %H:%M:%S")
            end_time = datetime.datetime.strptime(get_end, "%Y-%m-%d %H:%M:%S")
        except:
            error_msg = _("The start or end time parameter is invalid")
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)
        data = get_file_audit_stats(start_time, end_time)
        print data
        res_data = []
        dict_data = {}
        data = copy.deepcopy(data)
        for i in data:
            timestamp = str(int(time.mktime(i[0].timetuple())))
            if not dict_data.get(timestamp, None):
                dict_data[timestamp] = {}
            dict_data[timestamp][i[1]] = i[2]
        for x, y in dict_data.items():
            timeArray = time.localtime(int(x))
            x = time.strftime("%Y-%m-%d %H:%M:%S", timeArray)
            added = y.get('Added', '0')
            deleted = y.get('Deleted', '0')
            visited = y.get('Visited', '0')
            res_data.append(dict(zip(['datetime', 'added', 'deleted',
                    'visited'], [x, added, deleted, visited])))
        return Response(sorted(res_data, key=lambda x: x['datetime']))
