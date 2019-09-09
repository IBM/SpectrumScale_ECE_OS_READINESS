This tool assesses the readiness of a single node to run IBM Spectrum Scale Erasure Code Edition (ECE). This tool only checks for requirement of a system that run ECE, no other software or middleware on top in the same server.

This tool is run when installing ECE with the Spectrum Scale toolkit, it is used by the toolkit to do a more comprehensive inter node checking from a cluster perspective, this tool does only check at node level. Each run it generates a JSON file with name IP_ADDRESS.json where some data is saved, on standalone mode this file is only for reference.

SW requirements:
 - RPM packages that are listed on on packages.json file.
 - needs python-dmidecode and python-ethtool RPM packages.
 - nvme-cli if NVME are drives are installed
 - storcli if SAS card[s] are installed.

The tool requires one parameter (--ip) to be passed, it has to be the local IP where RAID traffic is going to happen. It does not allow names of a node it must be an IPv4 address

```
# ./mor.py -h
usage: mor.py [-h] --ip IPv4_ADDRESS [--path PATH/] [--no-cpu-check]
              [--no-md5-check] [--no-mem-check] [--no-os-check]
              [--no-packages-check] [--no-net-check] [--no-storage-check]
              [--no-sysctl-check] [--toolkit] [-v]

optional arguments:
  -h, --help           show this help message and exit
  --ip IPv4_ADDRESS    Local IP address linked to device used for NSD
  --path PATH/         Path ending with / where JSON files are located.
                       Defaults to local directory
  --no-cpu-check       Does not run CPU checks
  --no-md5-check       Does not check MD5 of JSON files
  --no-mem-check       Does not run memory checks
  --no-os-check        Does not run OS checks
  --no-packages-check  Does not run packages checks
  --no-net-check       Does not run network checks
  --no-storage-check   Does not run storage checks
  --no-sysctl-check    Does not run sysctl checks
  --toolkit            To indicate this is being run from Spectrum Scale
                       install toolkit
  -v, --version        show program's version number and exit
```

  Additionally optional parameters to skip certain checks can be passed. To be able to install ECE your node must pass all the tests on all nodes. You can additionally gather the JSON output files and run [SpectrumScale_ECE_OS_OVERVIEW](https://github.com/IBM/SpectrumScale_ECE_OS_OVERVIEW)

  A "good enough" run is shown below:

  ```
  # ./mor.py --ip 10.168.2.17
  [ INFO  ] c72f4m5u17 IBM Spectrum Scale Erasure Code Edition OS readiness version 0.43
  [ INFO  ] c72f4m5u17 JSON files versions:
  [ INFO  ] c72f4m5u17 	supported OS:		0.2
  [ INFO  ] c72f4m5u17 	sysctl: 		0.2
  [ INFO  ] c72f4m5u17 	packages: 		0.4
  [ INFO  ] c72f4m5u17 	SAS adapters:		1.0
  [ INFO  ] c72f4m5u17 	NIC adapters:		1.0
  [ INFO  ] c72f4m5u17 	HW requirements:	1.0
  [ INFO  ] c72f4m5u17 checking processor compatibility
  [ INFO  ] c72f4m5u17 x86_64 processor is supported for ECE
  [ INFO  ] c72f4m5u17 checking socket count
  [ INFO  ] c72f4m5u17 this system has 2 sockets which complies with the minimum of 2 sockets required to support ECE
  [ INFO  ] c72f4m5u17 checking core count
  [ INFO  ] c72f4m5u17 socket 0x0048 has 10 core[s] that is more than 8 cores required to support ECE
  [ INFO  ] c72f4m5u17 socket 0x0044 has 10 core[s] that is more than 8 cores required to support ECE
  [ INFO  ] c72f4m5u17 Red Hat Enterprise Linux Server 7.5 is a supported OS for ECE
  [ INFO  ] c72f4m5u17 checking packages install status
  [ INFO  ] c72f4m5u17 installation status of dmidecode is as expected
  [ INFO  ] c72f4m5u17 installation status of pciutils is as expected
  [ INFO  ] c72f4m5u17 checking memory
  [ INFO  ] c72f4m5u17 total memory is 125 GB, which is sufficient to run ECE
  [ WARN  ] c72f4m5u17 not all DIMM slots are populated. This system has 20 empty DIMM slots. This is not recommended when using ECE
  [ INFO  ] c72f4m5u17 all populated DIMM slots have same memory size of 32767 MB
  [ INFO  ] c72f4m5u17 checking SAS adapters
  [ INFO  ] c72f4m5u17 has SAS3516 adapter which is supported by ECE. The disks under this SAS adapter can be used for ECE
  [ INFO  ] c72f4m5u17 has 3 HDD drive[s] on the SAS adapter the same size of 557.861 GBytes that ECE can use
  [ WARN  ] c72f4m5u17 no SSD disks usable for ECE found
  [ INFO  ] c72f4m5u17 checking NVMe devices
  [ INFO  ] c72f4m5u17 has 2 NVMe device[s] detected
  [ INFO  ] c72f4m5u17 all NVMe devices have the same size of 960.20 GBytes that ECE can use
  [ INFO  ] c72f4m5u17 has at least one SSD or NVMe device that ECE can use. This is required to run ECE
  [ INFO  ] c72f4m5u17 has 5 drives that ECE can use
  [ INFO  ] c72f4m5u17 checking NIC adapters
  [ INFO  ] c72f4m5u17 has ConnectX-4 adapter which is supported by ECE
  [ INFO  ] c72f4m5u17 checking 10.168.2.17 device and link speed
  [ INFO  ] c72f4m5u17 the ip address 10.168.2.17 is found on device ib0
  [ INFO  ] c72f4m5u17 interface ib0 has a link of 100000 Mb/s. Which is supported to run ECE
  [ INFO  ] c72f4m5u17 checking sysctl settings
  [ INFO  ] c72f4m5u17 vm.min_free_kbytes it is set to the recommended value of 512000
  [ INFO  ] c72f4m5u17 kernel.shmmax it is set to the recommended value of 13743895347
  [ INFO  ] c72f4m5u17 kernel.sysrq it is set to the recommended value of 1
  [ INFO  ] c72f4m5u17 kernel.numa_balancing it is set to the recommended value of 0
  ```

  A failed run is shown below:

  ```
  # ./mor.py --ip 10.10.12.92
  [ INFO  ] mestor01 IBM Spectrum Scale Erasure Code Edition OS readiness version 0.43
  [ INFO  ] mestor01 JSON files versions:
  [ INFO  ] mestor01 	supported OS:		0.2
  [ INFO  ] mestor01 	sysctl: 		0.2
  [ INFO  ] mestor01 	packages: 		0.5
  [ INFO  ] mestor01 	SAS adapters:		1.0
  [ INFO  ] mestor01 	NIC adapters:		1.0
  [ INFO  ] mestor01 	HW requirements:	1.0
  [ INFO  ] mestor01 checking processor compatibility
  [ INFO  ] mestor01 x86_64 processor is supported for ECE
  [ INFO  ] mestor01 checking socket count
  [ INFO  ] mestor01 this system has 4 sockets which complies with the minimum of 2 sockets required to support ECE
  [ INFO  ] mestor01 checking core count
  [ FATAL ] mestor01 socket 0x0006 has 1 core[s] which is less than 8 cores per socket required to run ECE
  [ FATAL ] mestor01 socket 0x0007 has 1 core[s] which is less than 8 cores per socket required to run ECE
  [ FATAL ] mestor01 socket 0x0004 has 1 core[s] which is less than 8 cores per socket required to run ECE
  [ FATAL ] mestor01 socket 0x0005 has 1 core[s] which is less than 8 cores per socket required to run ECE
  [ INFO  ] mestor01 Red Hat Enterprise Linux Server 7.6 is a supported OS for ECE
  [ INFO  ] mestor01 checking packages install status
  [ INFO  ] mestor01 installation status of dmidecode is as expected
  [ INFO  ] mestor01 installation status of pciutils is as expected
  [ INFO  ] mestor01 checking memory
  [ FATAL ] mestor01 total memory is less than 60 GB required to run ECE
  [ WARN  ] mestor01 not all DIMM slots are populated. This system has 127 empty DIMM slots. This is not recommended when using ECE
  [ INFO  ] mestor01 all populated DIMM slots have same memory size of 16384 MB
  [ INFO  ] mestor01 checking SAS adapters
  [ WARN  ] mestor01 does not have any SAS adapter supported by ECE. The disks under any SAS adapter in this system cannot be used for ECE
  [ INFO  ] mestor01 checking NVMe devices
  [ WARN  ] mestor01 no NVMe devices detected
  [ FATAL ] mestor01 has no SAS adapters nor NVMe supported devices in this system
  [ INFO  ] mestor01 checking NIC adapters
  [ FATAL ] mestor01 does not have NIC adapter supported by ECE
  [ INFO  ] mestor01 checking sysctl settings
  [ WARN  ] mestor01 vm.min_free_kbytes is 67584 and should be 512000
  [ WARN  ] mestor01 kernel.shmmax is 18446744073692774399 and should be 13743895347
  [ WARN  ] mestor01 kernel.sysrq is 16 and should be 1
  [ INFO  ] mestor01 kernel.numa_balancing it is set to the recommended value of 0
  [ FATAL ] mestor01 3 sysctl setting[s] need to be changed. Check information above this message
  [ FATAL ] mestor01 does not have a supported configuration to run ECE
  ```
