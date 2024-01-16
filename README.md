# check_hpe_msa_storage

COREX check HPE MSA 2050 storage plugin for Icinga 2 v1.1
 
### Features
 - checks HPE MSA 2050 Storage with username and password
 - prints performance data for Icinga 2 Graphite Module ( and other solutions like Graphite )
 - available subcommands: controllers, disk-groups, disks, fans, frus, network-parameters, pools, ports, power-supplies, sensor-status, system, volumes, volume-statistics
 - warning/critical thresholds for each separate subcommands
 - for more details run check_hpe_msa_storage.py --help

### Usage

<pre><code>
# cd /usr/lib/nagios/plugins
# ./check_hpe_msa_storage.py --hostname mystorage.mydomain.com --username monitor --password monitorpassword --subcommand system
OK - MSA 2050 SAN is OK.
product id                              MSA 2050 SAN
system name                             HUBUDMSA2050
midplane serial number                  00C0FF5002D4
system health                           OK
system health reason                    None
other MC status                         Operational
#
</code></pre>

<pre><code>
# cd /usr/lib/nagios/plugins
# ./check_hpe_msa_storage.py --hostname mystorage.mydomain.com --username monitor --password monitorpassword --subcommand controllers
OK - A is OK.
OK - B is OK.

controller id                           A
controller model                        MSA 2050 SAN
controller status                       Operational
controller health                       OK
controller redundancy status            Redundant
controller redundancy mode              Active-Active ULP
controller failed                       No
controller failed reason                Not applicable
controller serial                       ACM045T015
disk number                             17
ip address                              192.168.76.216
mac address                             00:BB:CC:DD:E0:FB
controller health reason                None
controller health recommendation        None


controller id                           B
controller model                        MSA 2050 SAN
controller status                       Operational
controller health                       OK
controller redundancy status            Redundant
controller redundancy mode              Active-Active ULP
controller failed                       No
controller failed reason                Not applicable
controller serial                       7CE923M492
disk number                             17
ip address                              192.168.76.217
mac address                             00:BB:CC:DD:A3:B1
controller health reason                None
controller health recommendation        None
#

</code></pre>



### Version

 - v1.1

### ToDo

 - waiting for bugs or feature requests (-:

## Changelog
 - [initial release] version 1.1
