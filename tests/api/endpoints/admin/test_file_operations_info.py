import datetime
import json
from mock import patch
from django.core.urlresolvers import reverse
from seahub.test_utils import BaseTestCase


class FileOperationsInfoText(BaseTestCase):
    @patch("seahub.api2.endpoints.admin.file_operations.get_file_audit_stats")
    def test_can_get(self, mock_class):
        self.login_as(self.admin)
        mock_class.return_value = [
            (datetime.datetime(2017, 6, 2, 7, 0), u'Added', 2L),
            (datetime.datetime(2017, 6, 2, 7, 0), u'Deleted', 2L),
            (datetime.datetime(2017, 6, 2, 7, 0), u'Visited', 2L),
            (datetime.datetime(2017, 6, 2, 8, 0), u'Added', 3L),
            (datetime.datetime(2017, 6, 2, 8, 0), u'Deleted', 4L),
            (datetime.datetime(2017, 6, 2, 8, 0), u'Visited', 5L)]
        url = reverse('api-v2.1-admin-file-operations')
        url += "?start=2017-06-01 07:00:00&end=2017-06-03 07:00:00"
        resp = self.client.get(url)
        json_resp = json.loads(resp.content)
        self.assertEqual(json_resp[0]['datetime'], "2017-06-02 07:00:00")
        self.assertEqual(json_resp[0]['added'], 2)
        self.assertEqual(json_resp[0]['deleted'], 2)
        self.assertEqual(json_resp[0]['visited'], 2)
        self.assertEqual(json_resp[1]['datetime'], "2017-06-02 08:00:00")
        self.assertEqual(json_resp[1]['added'], 3)
        self.assertEqual(json_resp[1]['deleted'], 4)
        self.assertEqual(json_resp[1]['visited'], 5)
