#!/usr/bin/python3
# -*- coding: utf-8 -*-
# ---------------------------------------------------------------
# COREX check HPE MSA 2050 storage plugin for Icinga 2
# Copyright (C) 2019-2023, Gabor Borsos <bg@corex.bg>
# 
# v1.1 built on 2024.01.01.
# usage: check_hpe_msa_storage.py --help
#
# For bugs and feature requests mailto bg@corex.bg
# 
# ---------------------------------------------------------------
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# ---------------------------------------------------------------

import sys

try:
    from enum import Enum
    import argparse
    import hashlib
    import re
    import requests
    import textwrap
    import urllib3
    import xml.etree.ElementTree as ET

except ImportError as e:
    print("Missing python module: {}".format(str(e)))
    sys.exit(255)



class CheckState(Enum):
    OK = 0
    WARNING = 1
    CRITICAL = 2
    UNKNOWN = 3



class CheckMSA:

    def __init__(self):
        self.pluginname = "check_hpe_msa_storage.py"
        self.help = f"Run {self.pluginname} --help for more information!"
        self.error_codes_description = {}
        self.result_list = []
        self.result_dict = {}
        self.parse_args()



    def parse_args(self):
        parser = argparse.ArgumentParser(
            prog=self.pluginname, 
            add_help=True, 
            formatter_class=argparse.RawTextHelpFormatter,
            description = textwrap.dedent("""
            PLUGIN DESCRIPTION: HP MSA Storage check plugin for ICINGA 2."""),
            epilog = textwrap.dedent(f"""
            Examples:
            {self.pluginname} --hostname mystorage.mydomain.com --username monitor --password monitorpassword --subcommand system
            {self.pluginname} --hostname mystorage.mydomain.com --username monitor --password monitorpassword --subcommand controllers
            {self.pluginname} --hostname mystorage.mydomain.com --username monitor --password monitorpassword --subcommand disks --disk-life-left-limit 85 --disk-poh-limit 40000 --disk-temp-warning 40 --disk-temp-critical 50 --media-errors-1-limit 1 --media-errors-2-limit 1 --nonmedia-errors-1-limit 2 --nonmedia-errors-2-limit 2
            {self.pluginname} --hostname mystorage.mydomain.com --username monitor --password monitorpassword --subcommand ports --ignore-fc-port a3 --ignore-fc-port a4
            {self.pluginname} --hostname mystorage.mydomain.com --username monitor --password monitorpassword --subcommand sensor-status --sensor-temp-warning 50 --sensor-temp-critical 60
            """))

        check_options = parser.add_argument_group('SHA256 arguments for authentication', 'hostname, username, password')
        check_options.add_argument('--hostname', dest='hostname', metavar='MDA HOSTNAME', type=str, required=True,
                                        help='MDA hostname or FQDN')
        check_options.add_argument('--username', dest='username', metavar='MDA USERNAME', type=str, required=True,
                                        help='MDA username to create SHA256 string, --username monitoruser')
        check_options.add_argument('--password', dest='password', metavar='MDA PASSWORD', type=str, required=True,
                                        help='MDA password to create SHA256 string, --password monitorpasswordword')

        check_procedure = parser.add_argument_group('check arguments', 'controllers, disk-groups, disks, fans, frus, network-parameters, pools, ports, power-supplies, sensor-status, system, volumes, volume-statistics')

        check_procedure.add_argument("--subcommand",
                                        choices=(
                                            'controllers', 'disk-groups', 'disks', 'fans', 'frus', 'network-parameters', 'pools', 'ports', 'power-supplies', 'sensor-status', 'system', 'volumes', 'volume-statistics'),
                                        required=True,
                                        help="Select subcommand to use. Some subcommands need warning and critical or limit arguments.")
        
        check_procedure.add_argument('--ignore-controller', dest='ignore_controller_list', action='append', metavar='IGNORE_CONTROLLER',
                                        help='Ignore controller from "controllers" checking, --ignore-controller B', default=[])
        check_procedure.add_argument('--ignore-disk', dest='ignore_disks_list', action='append', metavar='IGNORE_DISK',
                                        help='Ignore disk(s) from "disks" checking, --ignore-disk disk_01.11 --ignore-disk disk_01.15 ...etc', default=[])
        check_procedure.add_argument('--ignore-fan', dest='ignore_fan_list', action='append', metavar='IGNORE-FAN',
                                        help='Ignore fan(s) from "fans" checking, --ignore-fan "Fan 2" ...etc', default=[])
        check_procedure.add_argument('--ignore-fru', dest='ignore_fru_list', action='append', metavar='IGNORE-FRU',
                                        help='Ignore fru(s) from "frus" checking, --ignore-fru "MEMORY CARD" --ignore-fru "RAID_IOM" ...etc', default=[])
        check_procedure.add_argument('--ignore-fc-port', dest='ignore_fc_ports_list', action='append', metavar='IGNORE-FC-PORT',
                                        help='Ignore FC port(s) from "port" checking, --ignore-fc-port a1 --ignore-fc-port b2 ...etc', default=[])
        check_procedure.add_argument('--ignore-mgmt-port', dest='ignore_mgmt_ports_list', action='append', metavar='IGNORE-MGMT-PORT',
                                        help='Ignore management port(s) from "network-parameters" checking, --ignore-mgmt-port mgmtport_b ...etc', default=[])
        check_procedure.add_argument('--ignore-pool', dest='ignore_pool_list', action='append', metavar='IGNORE-POOL',
                                        help='Ignore pool(s) from "pool" checking, --ignore-pool B --ignore-pool C ...etc', default=[])
        check_procedure.add_argument('--ignore-psu', dest='ignore_psu_list', action='append', metavar='IGNORE-PSU',
                                        help='Ignore psu from "psu" checking, use exact device name in argument, e.g. --ignore-psu "PSU 2, Right" ', default=[])
        check_procedure.add_argument('--ignore-sensor', dest='ignore_sensor_list', action='append', metavar='IGNORE-SENSOR',
                                        help='Ignore sensor from "sensors" checking, use exact device name in argument, e.g. --ignore-psu "PSU 2, Right" ', default=[])
        check_procedure.add_argument('--ignore-volume', dest='ignore_volume_list', action='append', metavar='IGNORE-VOLUME',
                                        help='Ignore volume from "volumes" checking, e.g. --ignore-volume "myvol2" ', default=[])
        check_procedure.add_argument('--disk-life-left-limit', dest='disk_life_left_limit', type=int,
                                        help='Warning limit threshold for disk life left checking in percent. --disk-life-left-limit 50')
        check_procedure.add_argument('--disk-poh-limit', dest='disk_poh_limit', type=int,
                                        help='Warning limit threshold for disk power on hours checking, --disk-poh-limit 45000')
        check_procedure.add_argument('--sensor-temp-warning', dest='sensor_temp_warning', type=int,
                                        help='Warning threshold for controller/cpu temperature in "sensor-status" checking, --sensor-temp-warning 70')
        check_procedure.add_argument('--sensor-temp-critical', dest='sensor_temp_critical', type=int,
                                        help='Critical threshold for controller/cpu temperature in "sensor-status" checking, --sensor-temp-critical 80')
        check_procedure.add_argument('--disk-temp-warning', dest='disk_temp_warning', type=int,
                                        help='Warning threshold for disk temperature on hours checking, --disk-temp-warning 50')
        check_procedure.add_argument('--disk-temp-critical', dest='disk_temp_critical', type=int,
                                        help='Critical threshold for disk temperature on hours checking, --disk-temp-critical 60')
        check_procedure.add_argument('--fan-speed-low-limit', dest='fan_speed_low_limit', type=int,
                                        help='Warning lower speed limit threshold for fan checking, --fan-speed-low-limit 500')
        check_procedure.add_argument('--pool-size-warning', dest='pool_size_warning', type=int,
                                        help='Warning threshold for pool usage checking in percent. --pool-size-warning 85')
        check_procedure.add_argument('--pool-size-critical', dest='pool_size_critical', type=int,
                                        help='Critical threshold for pool usage checking in percent. --pool-size-critical 95')
        check_procedure.add_argument('--volume-size-warning', dest='volume_size_warning', type=int,
                                        help='Warning threshold for volume usage checking in percent. --volume-size-warning 85')
        check_procedure.add_argument('--volume-size-critical', dest='volume_size_critical', type=int,
                                        help='Critical threshold for volume usage checking in percent. --volume-size-critical 95')
        check_procedure.add_argument('--media-errors-1-limit', dest='media_errors_1_limit', type=int,
                                        help='Number of Media Errors Port 1 warning threshold for "disk" checking, --media-errors-1-limit 5')
        check_procedure.add_argument('--media-errors-2-limit', dest='media_errors_2_limit', type=int,
                                        help='Number of Media Errors Port 2 warning threshold for "disk" checking, --media-errors-2-limit 5')
        check_procedure.add_argument('--nonmedia-errors-1-limit', dest='nonmedia_errors_1_limit', type=int,
                                        help='Number of Non-media Errors Port 1 warning threshold for "disk" checking, --nonmedia-errors-1-limit 5')
        check_procedure.add_argument('--nonmedia-errors-2-limit', dest='nonmedia_errors_2_limit', type=int,
                                        help='Number of Non-media Errors Port 2 warning threshold for "disk" checking, --nonmedia-errors-2-limit 5')
        check_procedure.add_argument('--block-reassigns-1-limit', dest='block_reassigns_1_limit', type=int,
                                        help='Number of Block Reassignments Port 1 warning threshold for "disk" checking, --block-reassigns-1-limit 5')
        check_procedure.add_argument('--block-reassigns-2-limit', dest='block_reassigns_2_limit', type=int,
                                        help='Number of Block Reassignments Port 2 warning threshold for "disk" checking, --block-reassigns-2-limit 5')
        check_procedure.add_argument('--bad-blocks-1-limit', dest='bad_blocks_1_limit', type=int,
                                        help='Number of Bad Blocks Port 1 warning threshold for "disk" checking, --bad-blocks-1-limit 5')
        check_procedure.add_argument('--bad-blocks-2-limit', dest='bad_blocks_2_limit', type=int,
                                        help='Number of Bad Blocks Port 2 warning threshold for "disk" checking, --bad-blocks-2-limit 5')

        self.options = parser.parse_args()
        
        

    def main(self):
        self.check_thresholds_scale()
        login_sha256 = self.create_sha256(self.options.username, self.options.password)
        session_key = self.get_session_key(self.options.hostname, login_sha256)
        subcommand_function = (self.options.subcommand).replace("-", "_")
        eval(f"self.check_{subcommand_function}" + "(self.options.subcommand, self.options.hostname, session_key)")
        self.check_exitcodes(self.result_list, self.result_dict)



    @staticmethod
    def output(state, message):
        prefix = state.name
        message = '{} - {}'.format(prefix, message)
        print(message)
        sys.exit(state.value)



    def check_thresholds_scale(self):
        
        def check_scale(increase_dict):
            for device_performance_name, warning_critical_list in increase_dict.items():
                if warning_critical_list[0] > warning_critical_list[1]:
                    self.output(CheckState.WARNING, f"{device_performance_name} warning threshold must be lower then critical threshold! {self.help}")
        
        
        if self.options.disk_temp_warning or self.options.disk_temp_critical:
            
            increase_dict = {
                "disk temperature" : [self.options.disk_temp_warning, self.options.disk_temp_critical]
            }
            check_scale(increase_dict)
            
            
        if self.options.pool_size_warning or self.options.pool_size_critical:
            
            increase_dict = {
                "pool size" : [self.options.pool_size_warning, self.options.pool_size_critical]
            }
            check_scale(increase_dict)

        if self.options.sensor_temp_warning or self.options.sensor_temp_critical:
            
            increase_dict = {
                "sensor temperature" : [self.options.sensor_temp_warning, self.options.sensor_temp_critical]
            }
            check_scale(increase_dict)
            
        if self.options.volume_size_warning or self.options.volume_size_critical:
            
            increase_dict = {
                "volume size" : [self.options.volume_size_warning, self.options.volume_size_critical]
            }
            check_scale(increase_dict)
        


    def get_response_code(self, url, headers=""):
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        try:
            response = requests.get(url, headers=headers, verify=False, timeout=5)
            if response.status_code == 200:
                return response.text
            else:
                self.output(CheckState.WARNING, f"Request ({url}) failed with status code: {response.status_code}")
        except:
            self.output(CheckState.WARNING, f"Connection timed out to {self.options.hostname}. Please check your connection!")



    def analyze_device_parameters(self, device_parameters_dict, device_name_string, ignore_list=""):
        for device_dict in self.device_part_list:
            device_name = device_dict[device_name_string]
            if device_name not in ignore_list:
                for device_property_name, device_status_codes in device_parameters_dict.items():
                    device_property_value = device_dict[device_property_name]
                    self.check_device_parameter(device_name, device_property_name, device_property_value, device_status_codes[0], device_status_codes[1], device_status_codes[2])



    def analyze_device_performances(self, device_check_performances_dict, device_name_string, ignore_list=""):
        for device_dict in self.device_part_list:
            device_name = device_dict[device_name_string]
            if device_name not in ignore_list:
                for device_property_name, performance_warn_crit_list in device_check_performances_dict.items():
                    device_property_value = device_dict[device_property_name]
                    if None not in performance_warn_crit_list:
                        self.check_device_performances(device_name, performance_warn_crit_list, device_property_name, device_property_value)
                    


    def analyze_performance_difference(self, device_difference_dict, device_name_string, ignore_list=""):
        for device_dict in self.device_part_list:
            device_name = device_dict[device_name_string]
            if device_name not in ignore_list:
                for performance_name, performance_difference_list in device_difference_dict.items():
                    device_property_value_list = [device_dict[performance_difference_list[0]], device_dict[performance_difference_list[1]]]
                    performance_warn_crit_list = [performance_difference_list[2], performance_difference_list[3]]
                    self.check_device_performances(device_name, performance_warn_crit_list, performance_name, device_property_value_list)



    def create_sha256(self, username, password):
        user_and_pass = f"{username}_{password}"
        sha_signature = hashlib.sha256(user_and_pass.encode()).hexdigest()
        return sha_signature



    def get_session_key(self, hostname, login_sha256):
        url = f"https://{hostname}/api/login/{login_sha256}"
        xml_response = self.get_response_code(url)
        return self.get_property_value_from_xml(xml_response, ".//PROPERTY[@name='response']")


    
    def get_property_value_from_xml(self, xml_response, xml_property_name):
        root = ET.fromstring(xml_response)
        response_property = root.find(xml_property_name)

        if response_property is not None:
            response_value = response_property.text
            return response_value
        else:
            print("Response property not found.")



    def get_xml_data_from_api(self, hostname, session_key, device_part, property_dict):
        device_part_list = []
        url_prefix = f"https://{hostname}/api/show/"
        headers = {
            "sessionKey": session_key,
            "dataType": "ipa"
        }
        
        if "basetype" in property_dict:
            check_url = property_dict["basetype"]
            property_code_prefix = f".//OBJECT[@basetype='{check_url}']"
        else:
            check_url = device_part
            property_code_prefix = f".//OBJECT[@basetype='{check_url}']"
        
        api_url = f"{url_prefix}{device_part}"
        xml_response = self.get_response_code(api_url, headers=headers)
        root = ET.fromstring(xml_response)
        
        for xml_object in root.findall(property_code_prefix):
            device_part_dict_name = f"{check_url}_part"
            locals()[device_part_dict_name] = {}
            device_part_dict = locals()[device_part_dict_name]
            
            for property_name, property_code in property_dict.items():
                device_part_dict["device_part"] = check_url
                if property_name != "basetype":
                    try:
                        property_value = xml_object.find(property_code).text
                        device_part_dict[property_name] = property_value
                    except:
                        self.output(CheckState.WARNING, f"{property_name} error. Please check xml output!")

            device_part_list.append(device_part_dict)
        
        return device_part_list


    
    def result_dict_append(self, device_name, status, output):
        if not device_name in self.result_dict:
            self.result_dict[device_name] = []
            [self.result_dict[device_name].append(f"{status} - {output}.")]
        else:
            [self.result_dict[device_name].append(f"{status} - {output}.")]



    def check_device_parameter(self, device_name, device_property_name, device_property_value, ok_status="", warning_status="", critical_status=""):
        output = f"{device_name} {device_property_name} is {device_property_value}"
        
        if not isinstance(critical_status, list):
            critical_status = [critical_status]
        if not isinstance(warning_status, list):
            critical_status = [warning_status]

        if device_property_value in critical_status:
            if self.error_codes_description:
                if device_property_value in self.error_codes_description:
                    self.result_list.append(f"CRITICAL - {output}. {self.error_codes_description[device_property_value]}!")
            else:
                self.result_list.append(f"CRITICAL - {output}!")
        elif device_property_value in warning_status:
            if self.error_codes_description:
                if device_property_value in self.error_codes_description:
                    self.result_list.append(f"WARNING - {output}. {self.error_codes_description[device_property_value]}!")
            else:
                self.result_list.append(f"WARNING - {output}!")
        elif device_property_value == ok_status:
            if self.error_codes_description:
                if device_property_value in self.error_codes_description:
                    self.result_list.append(f"OK - {output}. {self.error_codes_description[device_property_value]}")
            else:
                self.result_dict_append(device_name, "OK", output)
        else:
            self.result_list.append (f"UNKNOWN - {output}.")



    def check_device_performances(self, device_name, performance_warn_crit_list, device_property_name, device_property_value):
        
        if "life left" in device_property_name:
            device_property_value = int(device_property_value.replace("%", ""))
            device_performance_warning = performance_warn_crit_list[0]

            output = f"{device_name} life left is {device_property_value} %"
            print(f"|{device_name} life left={device_property_value}%;{device_performance_warning};;100;0")

            if device_performance_warning >= device_property_value:
                self.result_dict_append(device_name, "WARNING", output)
            elif device_property_value > device_performance_warning:
                self.result_dict_append(device_name, "OK", output)


        elif "power on hours" in device_property_name:
            device_property_value = int(device_property_value)
            device_performance_warning = performance_warn_crit_list[0]

            output = f"{device_name} power on hours are {device_property_value} hours"

            if device_performance_warning <= device_property_value:
                self.result_dict_append(device_name, "WARNING", output)
            elif device_property_value < device_performance_warning:
                self.result_dict_append(device_name, "OK", output)


        elif "temperature" in device_property_name or "CPU Temperature" in device_name or "Disk Controller Temperature" in device_name:
            device_property_value = int(device_property_value.replace(" C", ""))
            device_performance_warning = performance_warn_crit_list[0]
            device_performance_critical = performance_warn_crit_list[1]

            output = f"{device_name} temperature {device_property_value} C"
            print(f"|{device_name} temperature={device_property_value};{device_performance_warning};{device_performance_critical};0;;")

            if device_performance_critical <= device_property_value:
                self.result_dict_append(device_name, "CRITICAL", output)
            elif device_performance_warning <= device_property_value < device_performance_critical:
                self.result_dict_append(device_name, "WARNING", output)
            elif device_property_value < device_performance_warning:
                self.result_dict_append(device_name, "OK", output)


        elif "pool usage" in device_property_name:
            warning_percent = performance_warn_crit_list[0]
            critical_percent = performance_warn_crit_list[1]
            total_size = float(device_property_value[0].replace("GB", ""))
            available_size = float(device_property_value[1].replace("GB", ""))
            used_size = round((total_size-available_size),1)
            device_performance_warning = round(((total_size/100)*warning_percent), 1)
            device_performance_critical = round(((total_size/100)*critical_percent), 1)
            used_percent = round(((used_size/total_size)*100),1)

            output = f"{device_name} usage is {used_percent}% ({used_size} GB/{total_size} GB)"
            print(f"|{device_name} GB={used_size};{device_performance_warning};{device_performance_critical};0;{total_size};")

            if device_performance_critical <= used_size:
                self.result_dict_append(device_name, "CRITICAL", output)
            elif device_performance_warning <= used_size < device_performance_critical:
                self.result_dict_append(device_name, "WARNING", output)
            elif used_size < device_performance_warning:
                self.result_dict_append(device_name, "OK", output)


        elif "Media Errors Port 1" in device_property_name or "Media Errors Port 2" in device_property_name or "Non-media Errors Port 1" in device_property_name or "Non-media Errors Port 2" in device_property_name\
            or "Block Reassignments Port 1" in device_property_name or "Block Reassignments Port 2" in device_property_name or "Bad Blocks Port 1" in device_property_name or "Bad Blocks Port 2" in device_property_name:
            self.check_disk_error_numbers(device_name, device_property_name, device_property_value, performance_warn_crit_list)


        elif "fan speed" in device_property_name:
            device_property_value = int(device_property_value)
            device_performance_warning = performance_warn_crit_list[0]

            output = f"{device_name} speed {device_property_value} rpm"
            print(f"|{device_name} speed={device_property_value};{device_performance_warning};;0;")

            if device_performance_warning >= device_property_value:
                self.result_dict_append(device_name, "WARNING", output)
            elif device_property_value > device_performance_warning:
                self.result_dict_append(device_name, "OK", output)


        elif "volume usage" in device_property_name:
            warning_percent = performance_warn_crit_list[0]
            critical_percent = performance_warn_crit_list[1]
            total_size = float(device_property_value[0].replace("GB", ""))
            used_size = float(device_property_value[1].replace("GB", ""))
            device_performance_warning = round(((total_size/100)*warning_percent), 1)
            device_performance_critical = round(((total_size/100)*critical_percent), 1)
            used_percent = round(((used_size/total_size)*100),1)

            output = f"{device_name} usage is {used_percent}% ({used_size} GB/{total_size} GB)"
            print(f"|{device_name} GB={used_size};{device_performance_warning};{device_performance_critical};0;{total_size};")

            if device_performance_critical <= used_size:
                self.result_dict_append(device_name, "CRITICAL", output)
            elif device_performance_warning <= used_size < device_performance_critical:
                self.result_dict_append(device_name, "WARNING", output)
            elif used_size < device_performance_warning:
                self.result_dict_append(device_name, "OK", output)



        elif "iops usage" in device_property_name:
            iops = int(device_property_value[0])
            transfer_match = re.search(r'(\d+\.\d+)(.*)', device_property_value[1])
            transfer_speed = float(transfer_match.group(1))
            transfer_unit = transfer_match.group(2)

            if transfer_unit == "KB":
                transfer_speed = round((transfer_speed/1024),2)
            
            print(f"|{device_name} iops={iops};;;0;; {device_name} transfer speed={transfer_speed}MB;;;0;;")



    def check_system(self, subcommand, hostname, session_key):
        property_dict = {
            "product id" : "./PROPERTY[@name='product-id']",
            "system name" : "./PROPERTY[@name='system-name']",
            "midplane serial number" : "./PROPERTY[@name='midplane-serial-number']",
            "system health" : "./PROPERTY[@name='health']",
            "system health reason" : "./PROPERTY[@name='health-reason']",
            "other MC status" : "./PROPERTY[@name='other-MC-status']"
            }

        device_parameters_dict = {
            "system health" : ["OK", "Degraded", "Fault"],
            "other MC status" : ["Operational", "Not Communicating", "Not Operational"]
            }

        self.device_part_list = self.get_xml_data_from_api(hostname, session_key, subcommand, property_dict)
        self.analyze_device_parameters(device_parameters_dict, device_name_string=next(iter(property_dict)))
        


    def check_controllers(self, subcommand, hostname, session_key):
        ignore_list = [x.upper() for x in self.options.ignore_controller_list]

        property_dict = {
            "controller id" : "./PROPERTY[@name='controller-id']",
            "controller model" : "./PROPERTY[@name='model']",
            "controller status" : "./PROPERTY[@name='status']",
            "controller health" : "./PROPERTY[@name='health']",
            "controller redundancy status" : "./PROPERTY[@name='redundancy-status']",
            "controller redundancy mode" : "./PROPERTY[@name='redundancy-mode']",
            "controller failed" : "./PROPERTY[@name='failed-over']",
            "controller failed reason" : "./PROPERTY[@name='fail-over-reason']",
            "controller serial" : "./PROPERTY[@name='serial-number']",
            "disk number" : "./PROPERTY[@name='disks']",
            "ip address" : "./PROPERTY[@name='ip-address']",
            "mac address" : "./PROPERTY[@name='mac-address']",
            "controller health reason" : "./PROPERTY[@name='health-reason']",
            "controller health recommendation" : "./PROPERTY[@name='health-recommendation']"
            }
        
        device_parameters_dict = {
            "controller health" : ["OK", "Degraded", "Fault"],
            "controller status" : ["Operational", "Not Installed", "Down"],
            "controller redundancy status" : ["Redundant", "Operational but not redundant", "Down"],
            "controller redundancy mode" : ["Active-Active ULP", ["Failed Over", "Single Controller"], "Down"],
            "controller failed" : ["No", "", "Yes"]
            }

        self.device_part_list = self.get_xml_data_from_api(hostname, session_key, subcommand, property_dict)
        self.analyze_device_parameters(device_parameters_dict, device_name_string=next(iter(property_dict)), ignore_list=ignore_list)



    def check_disk_error_numbers(self, device_name, device_property_name, device_property_value, performance_warn_crit_list):
        device_property_value = int(device_property_value)
        device_performance_warning = performance_warn_crit_list[0]

        output = f"{device_name} has '{device_property_name}' {device_property_value} errors. (limit: {device_performance_warning})"
        print(f"|{device_name} {device_property_name}={device_property_value};{device_performance_warning};;0;100")

        if device_property_value >= device_performance_warning:
            self.result_dict_append(device_name, "WARNING", output)
        else: 
            self.result_dict_append(device_name, "OK", output)



    def check_disk_groups(self, subcommand, hostname, session_key):
        property_dict = {
            "disk-group name" : "./PROPERTY[@name='name']",
            "disk-group health" : "./PROPERTY[@name='health']",
            "disk-group status" : "./PROPERTY[@name='status']",
            "disk-group raid type" : "./PROPERTY[@name='raidtype']",
            "disk-group related pool" : "./PROPERTY[@name='pool']",
            "disk-group disk count" : "./PROPERTY[@name='diskcount']",
            "disk-group size" : "./PROPERTY[@name='size']",
            "disk-group available" : "./PROPERTY[@name='freespace']",
            "disk-group current job" : "./PROPERTY[@name='current-job']",
            "disk-group health reason" : "./PROPERTY[@name='health-reason']",
            "disk-group health recomm." : "./PROPERTY[@name='health-recommendation']"
            }
        
        device_parameters_dict = {
            "disk-group health" : ["OK", "Degraded", "Fault"],
            "disk-group status" : ["FTOL", ["UP", "FTDN", "STOP", "MSNG"], ["CRIT", "DMGD", "OFFL", "QTCR", "QTDN", "QTOF", "QTUN"]]
                }

        self.error_codes_description = {
            "CRIT" : "Critical. The disk group is online but isn't fault tolerant because some of its disks are down.",
            "DMGD" : "Damaged. The disk group is online and fault tolerant, but some of its disks are damaged.",
            "FTDN" : "Fault tolerant with a down disk. The disk group is online and fault tolerant, but some of its disks are down.",
            "FTOL" : "Fault tolerant and online.",
            "MSNG" : "Missing. The disk group is online and fault tolerant, but some of its disks are missing.",
            "OFFL" : "Offline. Either the disk group is using offline initialization, or its disks are down and data may be lost.",
            "QTCR" : "Quarantined critical. The disk group is critical with at least one inaccessible disk. For example, two disks are inaccessible in a RAID-6 disk group or one disk is inaccessible for other fault-tolerant RAID levels. If the inaccessible disks come online or if after 60 seconds from being quarantined the disk group is QTCR or QTDN, the disk group is automatically dequarantined.",
            "QTDN" : "Quarantined with a down disk. The RAID-6 disk group has one inaccessible disk. The disk group is fault tolerant but degraded. If the inaccessible disks come online or if after 60 seconds from being quarantined the disk group is QTCR or QTDN, the disk group is automatically dequarantined.",
            "QTOF" : "Quarantined offline. The disk group is offline with multiple inaccessible disks causing user data to be incomplete, or is an NRAID or RAID-0 disk group.",
            "QTUN" : "Quarantined unsupported. The disk group contains data in a format that is not supported by this system. Forexample, this system does not support linear disk groups.",
            "STOP" : "The disk group is stopped.",
            "UNKN" : "Unknown.",
            "UP"   : "Up. The disk group is online and does not have fault-tolerant attributes"
        }

        self.device_part_list = self.get_xml_data_from_api(hostname, session_key, subcommand, property_dict)
        self.analyze_device_parameters(device_parameters_dict, device_name_string=next(iter(property_dict)))



    def check_disk_statistics(self, subcommand, hostname, session_key):
        property_dict = {
            "disk id" : "./PROPERTY[@name='durable-id']",
            "Media Errors Port 1" : "./PROPERTY[@name='number-of-media-errors-1']",
            "Media Errors Port 2" : "./PROPERTY[@name='number-of-media-errors-2']",
            "Non-media Errors Port 1" : "./PROPERTY[@name='number-of-nonmedia-errors-1']",
            "Non-media Errors Port 2" : "./PROPERTY[@name='number-of-nonmedia-errors-2']",
            "Block Reassignments Port 1" : "./PROPERTY[@name='number-of-block-reassigns-1']",
            "Block Reassignments Port 2" : "./PROPERTY[@name='number-of-block-reassigns-2']",
            "Bad Blocks Port 1" : "./PROPERTY[@name='number-of-bad-blocks-1']",
            "Bad Blocks Port 2" : "./PROPERTY[@name='number-of-bad-blocks-2']"
            }
        
        mylist = self.get_xml_data_from_api(hostname, session_key, "disk-statistics", property_dict)
        return mylist


    def check_disks(self, subcommand, hostname, session_key):
        ignore_list = [x.lower() for x in self.options.ignore_disks_list]
        
        property_dict = {
            "basetype" : "drives",
            "disk id" : "./PROPERTY[@name='durable-id']",
            "disk slot" : "./PROPERTY[@name='slot']",
            "disk status" : "./PROPERTY[@name='status']",
            "disk health" : "./PROPERTY[@name='health']",
            "disk life left" : "./PROPERTY[@name='ssd-life-left']",
            "disk power on hours" : "./PROPERTY[@name='power-on-hours']",
            "disk model" : "./PROPERTY[@name='model']",
            "disk serial" : "./PROPERTY[@name='serial-number']",
            "disk architecture" : "./PROPERTY[@name='architecture']",
            "disk interface" : "./PROPERTY[@name='interface']",
            "disk transfer rate" : "./PROPERTY[@name='transfer-rate']",
            "disk size" : "./PROPERTY[@name='size']",
            "disk temperature" : "./PROPERTY[@name='temperature']",
            "disk owner controller" : "./PROPERTY[@name='owner']",
            "disk pool usage" : "./PROPERTY[@name='usage']",
            "disk pool" : "./PROPERTY[@name='storage-pool-name']",
            "disk disk-group usage" : "./PROPERTY[@name='disk-group']"
            }
        
        device_parameters_dict = {
            "disk status" : ["Up", ["Warning", "Disconnected"], "Error"],
            "disk health" : ["OK", "Degraded", "Fault"]
            }

        device_check_performance_dict = {
            "disk life left" : [self.options.disk_life_left_limit, self.options.disk_life_left_limit],
            "disk power on hours" : [self.options.disk_poh_limit, self.options.disk_poh_limit],
            "disk temperature" : [self.options.disk_temp_warning, self.options.disk_temp_critical],
            "Media Errors Port 1" : [self.options.media_errors_1_limit, self.options.media_errors_1_limit],
            "Media Errors Port 2" : [self.options.media_errors_2_limit, self.options.media_errors_2_limit],
            "Non-media Errors Port 1" : [self.options.nonmedia_errors_1_limit, self.options.nonmedia_errors_1_limit],
            "Non-media Errors Port 2" : [self.options.nonmedia_errors_2_limit, self.options.nonmedia_errors_2_limit],
            "Block Reassignments Port 1" : [self.options.block_reassigns_1_limit, self.options.block_reassigns_1_limit],
            "Block Reassignments Port 2" : [self.options.block_reassigns_2_limit, self.options.block_reassigns_2_limit],
            "Bad Blocks Port 1" : [self.options.bad_blocks_1_limit, self.options.bad_blocks_1_limit],
            "Bad Blocks Port 2" : [self.options.bad_blocks_2_limit, self.options.bad_blocks_2_limit],
            }

        self.device_part_list = self.get_xml_data_from_api(hostname, session_key, subcommand, property_dict)
        disk_statistics_list = self.check_disk_statistics(subcommand, hostname, session_key)
        
        del property_dict["basetype"]
        
        merged_list = []
        
        if len(self.device_part_list) == len(disk_statistics_list):
            for i in range(len(self.device_part_list)):
                combined_dict = {**self.device_part_list[i], **disk_statistics_list[i]}
                merged_list.append(combined_dict)
        else:
            self.output(CheckState.WARNING, f"BUG, {subcommand} subcommand error. Please, get in touch with the developer!")

        self.device_part_list = merged_list

        self.analyze_device_parameters(device_parameters_dict, device_name_string=next(iter(property_dict)), ignore_list=ignore_list)
        self.analyze_device_performances(device_check_performance_dict, device_name_string=next(iter(property_dict)), ignore_list=ignore_list)



    def check_fans(self, subcommand, hostname, session_key):
        ignore_list = self.options.ignore_fan_list

        property_dict = {
            "basetype" : "fan",
            "fan name" : "./PROPERTY[@name='name']",
            "fan health" : "./PROPERTY[@name='health']",
            "fan status 1" : "./PROPERTY[@name='status']",
            "fan status 2" : "./PROPERTY[@name='status-ses']",
            "fan speed" : "./PROPERTY[@name='speed']",
            "fan location" : "./PROPERTY[@name='location']",
            "fan position" : "./PROPERTY[@name='position']",
            "fan health reason" : "./PROPERTY[@name='health-reason']",
            "fan health recomm." : "./PROPERTY[@name='health-recommendation']"
            }
        
        device_parameters_dict = {
            "fan health" : ["OK", "Degraded", "Fault"],
            "fan status 1" : ["Up", ["Off", "Missing"], "Error"],
            "fan status 2" : ["OK", ["Warning", "Unrecoverable"], "Critical"]
            }

        device_check_performance_dict = {
            "fan speed" : [self.options.fan_speed_low_limit, self.options.fan_speed_low_limit]
        }

        self.device_part_list = self.get_xml_data_from_api(hostname, session_key, subcommand, property_dict)
        del property_dict["basetype"]
        self.analyze_device_parameters(device_parameters_dict, device_name_string=next(iter(property_dict)), ignore_list=ignore_list)
        self.analyze_device_performances(device_check_performance_dict, device_name_string=next(iter(property_dict)), ignore_list=ignore_list)



    def check_frus(self, subcommand, hostname, session_key):
        ignore_list = self.options.ignore_fru_list

        property_dict = {
            "basetype" : "enclosure-fru",
            "fru name" : "./PROPERTY[@name='name']",
            "fru description" : "./PROPERTY[@name='description']",
            "fru part number" : "./PROPERTY[@name='part-number']",
            "fru serial number" : "./PROPERTY[@name='serial-number']",
            "fru manufacturing date" : "./PROPERTY[@name='mfg-date']",
            "fru location" : "./PROPERTY[@name='fru-location']",
            "fru status" : "./PROPERTY[@name='fru-status']"
            }
        
        device_parameters_dict = {
            "fru status" : ["OK", ["Invalid Data", "Absent"], "Fault"]
            }


        self.device_part_list = self.get_xml_data_from_api(hostname, session_key, subcommand, property_dict)
        del property_dict["basetype"]
        self.analyze_device_parameters(device_parameters_dict, device_name_string=next(iter(property_dict)), ignore_list=ignore_list)



    def check_network_parameters(self, subcommand, hostname, session_key):
        ignore_list = [x.lower() for x in self.options.ignore_mgmt_ports_list]

        property_dict = {
            "management port" : "./PROPERTY[@name='durable-id']",
            "management port ip address" : "./PROPERTY[@name='ip-address']",
            "management port health" : "./PROPERTY[@name='health']"
            }
        
        device_parameters_dict = {
            "management port health" : ["OK", "Degraded", "Fault"]
            }

        self.device_part_list = self.get_xml_data_from_api(hostname, session_key, subcommand, property_dict)
        self.analyze_device_parameters(device_parameters_dict, device_name_string=next(iter(property_dict)), ignore_list=ignore_list)
        


    def check_pools(self, subcommand, hostname, session_key):
        ignore_list = [x.upper() for x in self.options.ignore_controller_list]

        property_dict = {
            "pool name" : "./PROPERTY[@name='name']",
            "pool health" : "./PROPERTY[@name='health']",
            "pool serial" : "./PROPERTY[@name='serial-number']",
            "pool owner controller" : "./PROPERTY[@name='owner']",
            "pool type" : "./PROPERTY[@name='storage-type']",
            "pool size" : "./PROPERTY[@name='total-size']",
            "pool available" : "./PROPERTY[@name='total-avail']",
            "pool health reason" : "./PROPERTY[@name='health-reason']",
            "pool health recommendation" : "./PROPERTY[@name='health-recommendation']"
            }
        
        device_parameters_dict = {
            "pool health" : ["OK", "Degraded", "Fault"]
            }

        device_difference_dict = {
            "pool usage" : ["pool size", "pool available", self.options.pool_size_warning, self.options.pool_size_critical]
            }

        self.device_part_list = self.get_xml_data_from_api(hostname, session_key, subcommand, property_dict)
        self.analyze_device_parameters(device_parameters_dict, device_name_string=next(iter(property_dict)), ignore_list=ignore_list)
        if self.options.pool_size_warning or self.options.pool_size_critical is not None:
            self.analyze_performance_difference(device_difference_dict, device_name_string=next(iter(property_dict)), ignore_list=ignore_list)



    def check_ports(self, subcommand, hostname, session_key):
        ignore_list = [x.upper() for x in self.options.ignore_fc_ports_list]
        
        property_dict = {
            "basetype" : "port",
            "FC port name" : "./PROPERTY[@name='port']",
            "FC port type" : "./PROPERTY[@name='port-type']",
            "FC port status" : "./PROPERTY[@name='status']",
            "FC port health" : "./PROPERTY[@name='health']",
            "FC port actual speed" : "./PROPERTY[@name='actual-speed']"
            }
        
        device_parameters_dict = {
            "FC port status" : ["Up", ["Warning", "Disconnected"], ["Error"]],
            "FC port health" : ["OK", "Degraded", "Fault"]
            }

        self.device_part_list = self.get_xml_data_from_api(hostname, session_key, subcommand, property_dict)
        del property_dict["basetype"]
        self.analyze_device_parameters(device_parameters_dict, device_name_string=next(iter(property_dict)), ignore_list=ignore_list)
    


    def check_power_supplies(self, subcommand, hostname, session_key):
        ignore_list = self.options.ignore_psu_list

        property_dict = {
            "psu name" : "./PROPERTY[@name='name']",
            "psu description" : "./PROPERTY[@name='description']",
            "psu part number" : "./PROPERTY[@name='part-number']",
            "psu serial number" : "./PROPERTY[@name='serial-number']",
            "psu manufacturing date" : "./PROPERTY[@name='mfg-date']",
            "psu location" : "./PROPERTY[@name='location']",
            "psu status" : "./PROPERTY[@name='status']",
            "psu health" : "./PROPERTY[@name='health']",
            "psu health reason" : "./PROPERTY[@name='health-reason']",
            "psu health recommendation" : "./PROPERTY[@name='health-recommendation']"
            }
        
        device_parameters_dict = {
            "psu health" : ["OK", "Degraded", "Fault"],
            "psu status" : ["Up", ["Off", "Missing"], "Error"]
            }


        self.device_part_list = self.get_xml_data_from_api(hostname, session_key, subcommand, property_dict)
        self.analyze_device_parameters(device_parameters_dict, device_name_string=next(iter(property_dict)), ignore_list=ignore_list)



    def check_sensor_status(self, subcommand, hostname, session_key):
        ignore_list = self.options.ignore_sensor_list

        property_dict = {
            "basetype" : "sensors",
            "sensor name" : "./PROPERTY[@name='sensor-name']",
            "sensor value" : "./PROPERTY[@name='value']",
            "sensor status" : "./PROPERTY[@name='status']"
            }
        
        device_parameters_dict = {
            "sensor status" : ["OK", ["Warning", "Unrecoverable"], "Critical"]
            }

        device_check_performance_dict = {
            "sensor value" : [self.options.sensor_temp_warning, self.options.sensor_temp_critical]
        }

        self.device_part_list = self.get_xml_data_from_api(hostname, session_key, subcommand, property_dict)
        del property_dict["basetype"]
        self.analyze_device_parameters(device_parameters_dict, device_name_string=next(iter(property_dict)), ignore_list=ignore_list)
        self.analyze_device_performances(device_check_performance_dict, device_name_string=next(iter(property_dict)), ignore_list=ignore_list)



    def check_volumes(self, subcommand, hostname, session_key):
        ignore_list = [x.lower() for x in self.options.ignore_volume_list]

        property_dict = {
            "volume name" : "./PROPERTY[@name='volume-name']",
            "volume health" : "./PROPERTY[@name='health']",
            "volume size" : "./PROPERTY[@name='total-size']",
            "volume allocated size" : "./PROPERTY[@name='allocated-size']",
            "virtual disk name" : "./PROPERTY[@name='virtual-disk-name']",
            "storage pool name" : "./PROPERTY[@name='storage-pool-name']",
            "raid type" : "./PROPERTY[@name='raidtype']",
            "volume health reason" : "./PROPERTY[@name='health-reason']",
            "volume health recommendation" : "./PROPERTY[@name='health-recommendation']"
            }
        
        device_parameters_dict = {
            "volume health" : ["OK", "Degraded", "Fault"]
            }

        device_difference_dict = {
            "volume usage" : ["volume size", "volume allocated size", self.options.volume_size_warning, self.options.volume_size_critical]
            }

        self.device_part_list = self.get_xml_data_from_api(hostname, session_key, subcommand, property_dict)
        self.analyze_device_parameters(device_parameters_dict, device_name_string=next(iter(property_dict)), ignore_list=ignore_list)
        if self.options.volume_size_warning or self.options.volume_size_critical is not None:
            self.analyze_performance_difference(device_difference_dict, device_name_string=next(iter(property_dict)), ignore_list=ignore_list)



    def check_volume_statistics(self, subcommand, hostname, session_key):
        ignore_list = [x.lower() for x in self.options.ignore_volume_list]

        property_dict = {
            "volume name" : "./PROPERTY[@name='volume-name']",
            "bytes-per-second" : "./PROPERTY[@name='bytes-per-second']",
            "iops" : "./PROPERTY[@name='iops']"
            }
        
        device_difference_dict = {
            "iops usage" : ["iops", "bytes-per-second", self.options.volume_size_warning, self.options.volume_size_critical]
            }
        

        self.device_part_list = self.get_xml_data_from_api(hostname, session_key, subcommand, property_dict)
        self.analyze_performance_difference(device_difference_dict, device_name_string=next(iter(property_dict)), ignore_list=ignore_list)
        


    def check_exitcodes(self, result_list, result_dict):
        
        if any("CRITICAL" in x for x in result_list):
            [print(x) for x in result_list if re.search("CRITICAL", x)]
        if any("WARNING" in x for x in result_list):
            [print(x) for x in result_list if re.search("WARNING", x)]
        if any("UNKNOWN" in x for x in result_list):
            [print(x) for x in result_list if re.search("UNKNOWN", x)]
        if any("OK" in x for x in result_list):
            [print(x) for x in result_list if re.search("OK", x)]
        
        print("\n")
        
        final_result_list = []
        for device_name, device_details_list in result_dict.items():
            if len(device_details_list) != 0:
                if any("CRITICAL" in x for x in device_details_list):
                    [final_result_list.append(x) for x in device_details_list if re.search("CRITICAL", x)]
                elif any("WARNING" in x for x in device_details_list):
                    [final_result_list.append(x) for x in device_details_list if re.search("WARNING", x)]
                elif any("UNKNOWN" in x for x in device_details_list):
                    [final_result_list.append(x) for x in device_details_list if re.search("UNKNOWN", x)]
                else:
                    final_result_list.append(f"OK - {device_name} is OK.")

        if len(final_result_list) != 0:
            if len(final_result_list) != 0:
                if any("CRITICAL" in x for x in final_result_list):
                    [print(x) for x in final_result_list if re.search("CRITICAL", x)]
                    [print(x) for x in final_result_list if re.search("WARNING", x)]
                elif any("WARNING" in x for x in final_result_list):
                    [print(x) for x in final_result_list if re.search("WARNING", x)]
                elif any("UNKNOWN" in x for x in final_result_list):
                    [print(x) for x in final_result_list if re.search("UNKNOWN", x)]
                elif any("OK" in x for x in final_result_list):
                    [print(x) for x in final_result_list if re.search("OK", x)]

        print("\n")

        for device_dict in self.device_part_list:
            for property_name, property_value in device_dict.items():
                if property_name != "device_part":
                    print(f"{property_name}\t{property_value}".expandtabs(40))
            print("\n")

        if any("CRITICAL" in x for x in result_list) or any("CRITICAL" in x for x in final_result_list):
            sys.exit(2)
        if any("WARNING" in x for x in result_list) or any("WARNING" in x for x in final_result_list):
            sys.exit(1)
        if any("UNKNOWN" in x for x in result_list) or any("UNKNOWN" in x for x in final_result_list):
            sys.exit(3)

        sys.exit(0)
        


check_hp_msa = CheckMSA()
check_hp_msa.main()
