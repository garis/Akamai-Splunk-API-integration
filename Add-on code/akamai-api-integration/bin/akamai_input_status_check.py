
# encoding = utf-8
# Always put this line at the beginning of this file
import akamai_api_integration_declare

import os
import sys

from alert_actions_base import ModularAlertBase
import modalert_akamai_input_status_check_helper

class AlertActionWorkerakamai_input_status_check(ModularAlertBase):

    def __init__(self, ta_name, alert_name):
        super(AlertActionWorkerakamai_input_status_check, self).__init__(ta_name, alert_name)

    def validate_params(self):

        if not self.get_param("username"):
            self.log_error('username is a mandatory parameter, but its value is None.')
            return False

        if not self.get_param("base_url"):
            self.log_error('base_url is a mandatory parameter, but its value is None.')
            return False

        if not self.get_param("input_type"):
            self.log_error('input_type is a mandatory parameter, but its value is None.')
            return False

        if not self.get_param("input_name"):
            self.log_error('input_name is a mandatory parameter, but its value is None.')
            return False
        return True

    def process_event(self, *args, **kwargs):
        status = 0
        try:
            if not self.validate_params():
                return 3
            status = modalert_akamai_input_status_check_helper.process_event(self, *args, **kwargs)
        except (AttributeError, TypeError) as ae:
            self.log_error("Error: {}. Please double check spelling and also verify that a compatible version of Splunk_SA_CIM is installed.".format(str(ae)))
            return 4
        except Exception as e:
            msg = "Unexpected error: {}."
            if e:
                self.log_error(msg.format(str(e)))
            else:
                import traceback
                self.log_error(msg.format(traceback.format_exc()))
            return 5
        return status

if __name__ == "__main__":
    exitcode = AlertActionWorkerakamai_input_status_check("akamai-api-integration", "akamai_input_status_check").run(sys.argv)
    sys.exit(exitcode)
