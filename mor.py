#!/usr/bin/python
import json
import os
import sys
import datetime
import subprocess
import platform
import argparse
import socket
import importlib
import hashlib
import re
import shlex

try:
    raw_input      # Python 2
    PYTHON3 = False
except NameError:  # Python 3
    raw_input = input
    PYTHON3 = True

if PYTHON3:
    import subprocess
else:
    import commands

# Start the clock
start_time_date = datetime.datetime.now()

# This script version, independent from the JSON versions
MOR_VERSION = "1.6"

# GIT URL
GITREPOURL = "https://github.com/IBM/SpectrumScale_ECE_OS_READINESS"

# Colorful constants
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
NOCOLOR = '\033[0m'

# Message labels
INFO = "[ " + GREEN + "INFO" + NOCOLOR + "  ] "
WARNING = "[ " + YELLOW + "WARN" + NOCOLOR + "  ] "
ERROR = "[ " + RED + "FATAL" + NOCOLOR + " ] "

# Get hostname for output on screen
LOCAL_HOSTNAME = platform.node().split('.', 1)[0]

# Regex patterns
SASPATT = re.compile('.*"SAS address"\s*:\s*"0x(?P<sasaddr>.*)"')
WWNPATT = re.compile('.*"WWN"\s*:\s*"(?P<wwn>.*)"')
OSVERPATT = re.compile('(?P<major>\d+)[\.](?P<minor>\d+)[\.].*')

# Next are python modules that need to be checked before import
try:
    import dmidecode
except ImportError:
    sys.exit(
        ERROR +
        LOCAL_HOSTNAME +
        " cannot import dmidecode, please check python-dmidecode is installed")
try:
    import ethtool
except ImportError:
    sys.exit(
        ERROR +
        LOCAL_HOSTNAME +
        " cannot import ethtool, please check python-ethtool is installed")

# devnull redirect destination
DEVNULL = open(os.devnull, 'w')

# Define expected MD5 hashes of JSON input files
HW_REQUIREMENTS_MD5 = "57518bc8a0d7a177ffa5cea8a61b1c72"
NIC_ADAPTERS_MD5 = "00412088e36bce959350caea5b490001"
PACKAGES_MD5 = "62a4d7bbc57d4ad0ee5fa3dcfdd3983f"
SAS_ADAPTERS_MD5 = "5a7dc0746cb1fe1b218b655800c0a0ee"
SUPPORTED_OS_MD5 = "d5ef1280707912298764c4c39c844fc6"
SYSCTL_MD5 = "5737397a77786735c9433006bed78cc4"


# Functions
def parse_arguments():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        '--ip',
        required=True,
        action='store',
        dest='ip_address',
        help='Local IP address linked to device used for NSD',
        metavar='IPv4_ADDRESS',
        type=str,
        default="NO IP")

    parser.add_argument(
        '--path',
        action='store',
        dest='path',
        help='Path where JSON files are located. Defaults to local directory',
        metavar='PATH/',
        type=str,
        default='./')

    parser.add_argument(
        '--no-cpu-check',
        action='store_false',
        dest='cpu_check',
        help='Does not run CPU checks',
        default=True)

    parser.add_argument(
        '--no-md5-check',
        action='store_false',
        dest='md5_check',
        help='Does not check MD5 of JSON files',
        default=True)

    parser.add_argument(
        '--no-mem-check',
        action='store_false',
        dest='mem_check',
        help='Does not run memory checks',
        default=True)

    parser.add_argument(
        '--no-os-check',
        action='store_false',
        dest='os_check',
        help='Does not run OS checks',
        default=True)

    parser.add_argument(
        '--no-packages-check',
        action='store_false',
        dest='packages_ch',
        help='Does not run packages checks',
        default=True)

    parser.add_argument(
        '--no-net-check',
        action='store_false',
        dest='net_check',
        help='Does not run network checks',
        default=True)

    parser.add_argument(
        '--no-storage-check',
        action='store_false',
        dest='storage_check',
        help='Does not run storage checks',
        default=True)

    parser.add_argument(
        '--no-sysctl-check',
        action='store_false',
        dest='sysctl_check',
        help='Does not run sysctl checks',
        default=True)

    parser.add_argument(
        '--toolkit',
        action='store_true',
        dest='toolkit_run',
        help='To indicate is being run from Spectrum Scale install toolkit',
        default=False)

    parser.add_argument(
        '-v',
        '--version',
        action='version',
        version='IBM Spectrum Scale Erasure Code Edition OS readiness ' +
        'version: ' + MOR_VERSION)

    args = parser.parse_args()

    return (args.ip_address,
            args.path,
            args.cpu_check,
            args.md5_check,
            args.mem_check,
            args.os_check,
            args.packages_ch,
            args.storage_check,
            args.net_check,
            args.sysctl_check,
            args.toolkit_run)


def load_json(json_file_str):
    # Loads  JSON into a dictionary or quits the program if it cannot.
    try:
        with open(json_file_str, "r") as json_file:
            json_dict = json.load(json_file)
            return json_dict
    except BaseException:
        sys.exit(
            ERROR +
            LOCAL_HOSTNAME +
            " cannot open or parse JSON file: '" +
            json_file_str +
            "'. Please check the file exists and has JSON format")


def md5_chksum(json_file_str):
    # Files are small not doing chunks
    try:
        md5_hash = (hashlib.md5(open(json_file_str, 'rb').read()).hexdigest())
        return md5_hash
    except BaseException:
        sys.exit(
            ERROR +
            LOCAL_HOSTNAME +
            " cannot create MD5 sum of file: " +
            json_file_str)


def md5_verify(md5_check, json_file_str, md5_hash_real, md5_hash_expected):
    # Compare expected MD5 with real one and print message if OK and message
    # plus exit if not OK
    if md5_hash_real == md5_hash_expected:
        # print(INFO + LOCAL_HOSTNAME +
        # " MD5 hash verified for " + json_file_str)
        return True
    elif md5_check:
        sys.exit(
            ERROR +
            LOCAL_HOSTNAME +
            " MD5 hash failed to verify file: " +
            json_file_str)
    else:
        print(
            WARNING +
            LOCAL_HOSTNAME +
            " MD5 hash failed to verify file: " +
            json_file_str)
        return False


def show_header(moh_version, json_version, toolkit_run):
    print(
        INFO +
        LOCAL_HOSTNAME +
        " IBM Spectrum Scale Erasure Code Edition OS readiness version " +
        moh_version)
    if not toolkit_run:
        print(
            INFO +
            LOCAL_HOSTNAME +
            " This tool comes with absolute not warranty")
        print(
            INFO +
            LOCAL_HOSTNAME +
            " Please check " + GITREPOURL + " for details")
    print(INFO + LOCAL_HOSTNAME + " JSON files versions:")
    print(
        INFO +
        LOCAL_HOSTNAME +
        " \tsupported OS:\t\t" +
        json_version['supported_OS'])
    print(INFO + LOCAL_HOSTNAME + " \tsysctl: \t\t" + json_version['sysctl'])
    print(
        INFO +
        LOCAL_HOSTNAME +
        " \tpackages: \t\t" +
        json_version['packages'])
    print(
        INFO +
        LOCAL_HOSTNAME +
        " \tSAS adapters:\t\t" +
        json_version['SAS_adapters'])
    print(
        INFO +
        LOCAL_HOSTNAME +
        " \tNIC adapters:\t\t" +
        json_version['NIC_adapters'])
    print(
        INFO +
        LOCAL_HOSTNAME +
        " \tHW requirements:\t" +
        json_version['HW_requirements'])


def rpm_is_installed(rpm_package):
    # returns the RC of rpm -q rpm_package or quits if it cannot run rpm
    errors = 0
    try:
        return_code = subprocess.call(
            ['rpm', '-q', rpm_package], stdout=DEVNULL, stderr=DEVNULL)
    except BaseException:
        sys.exit(ERROR + LOCAL_HOSTNAME + " cannot run rpm")
    return return_code


def is_IP_address(ip):
    # Lets check is a full ip by counting dots
    if ip.count('.') != 3:
        return False
    try:
        socket.inet_aton(ip)
        return True
    except Exception:
        return False


def list_net_devices():
    # This works on Linux only
    # net_devices = os.listdir('/sys/class/net/')
    net_devices = ethtool.get_active_devices()
    return net_devices


def what_interface_has_ip(net_devices, ip_address):
    fatal_error = True
    for device in net_devices:
        try:
            device_ip = ethtool.get_ipaddr(str(device))
        except BaseException:
            continue
        if device_ip != ip_address:
            fatal_error = True
        else:
            fatal_error = False
            print(
                INFO +
                LOCAL_HOSTNAME +
                " the IP address " +
                ip_address +
                " is found on device " +
                device)
            return fatal_error, device
    print(
        ERROR +
        LOCAL_HOSTNAME +
        " cannot find interface with IP address " +
        ip_address)
    return fatal_error, "NONE"


def check_NIC_speed(net_interface, min_link_speed):
    fatal_error = False
    device_speed = 0
    try:
        if PYTHON3:
            ethtool_out = subprocess.getoutput(
                'ethtool ' + net_interface + ' | grep "Speed:"').split()
        else:
            ethtool_out = commands.getoutput(
                'ethtool ' + net_interface + ' | grep "Speed:"').split()
        device_speed = ''.join(ethtool_out[1].split())
        device_speed = device_speed[:-4]
        device_speed = device_speed[-6:]
        if int(device_speed) > min_link_speed:
            print(
                INFO +
                LOCAL_HOSTNAME +
                " interface " +
                net_interface +
                " has a link of " +
                device_speed +
                " Mb/s. Which is supported to run ECE")
        else:
            print(
                ERROR +
                LOCAL_HOSTNAME +
                " interface " +
                net_interface +
                " has a link of " +
                device_speed +
                " Mb/s. Which is not supported to run ECE")
    except BaseException:
        fatal_error = True
        print(
            ERROR +
            LOCAL_HOSTNAME +
            " cannot determine link speed on " +
            net_interface +
            ". Is the link up?")
    return fatal_error, device_speed


def packages_check(packages_dictionary):

    # Checks if packages from JSON are installed or not based on the input
    # data ont eh JSON
    errors = 0
    print(INFO + LOCAL_HOSTNAME + " checking packages install status")
    for package in packages_dictionary.keys():
        if package != "json_version":
            current_package_rc = rpm_is_installed(package)
            expected_package_rc = packages_dictionary[package]
            if current_package_rc == expected_package_rc:
                print(
                    INFO +
                    LOCAL_HOSTNAME +
                    " installation status of " +
                    package +
                    " is as expected")
            else:
                print(
                    WARNING +
                    LOCAL_HOSTNAME +
                    " installation status of " +
                    package +
                    " is *NOT* as expected")
                errors = errors + 1
    return(errors)


def check_processor():
    fatal_error = False
    print(INFO + LOCAL_HOSTNAME + " checking processor compatibility")
    current_processor = platform.processor()
    # We go x86_64 only at this point
    if current_processor == 'x86_64':
        print(
            INFO +
            LOCAL_HOSTNAME +
            " " +
            current_processor +
            " processor is supported to run ECE")
    else:
        print(
            ERROR +
            LOCAL_HOSTNAME +
            " " +
            current_processor +
            " processor is not supported to run ECE")
        fatal_error = True
    return fatal_error, current_processor


def check_sockets_cores(min_socket, min_cores):
    fatal_error = False
    cores = []
    print(INFO + LOCAL_HOSTNAME + " checking socket count")
    sockets = dmidecode.processor()
    num_sockets = len(sockets)
    if num_sockets < min_socket:
        print(
            ERROR +
            LOCAL_HOSTNAME +
            " this system has " +
            str(num_sockets) +
            " socket[s] which is less than " +
            str(min_socket) +
            " sockets required to support ECE")
        fatal_error = True
    else:
        print(
            INFO +
            LOCAL_HOSTNAME +
            " this system has " +
            str(num_sockets) +
            " sockets which complies with the minimum of " +
            str(min_socket) +
            " sockets required to support ECE")

    print(INFO + LOCAL_HOSTNAME + " checking core count")
    for socket in sockets.keys():
        core_count = sockets[socket]['data']['Core Count']
        # For socket but no chip installed
        if core_count == "None":
            core_count = 0
        cores.append(core_count)
        if core_count < min_cores:
            print(
                ERROR +
                LOCAL_HOSTNAME +
                " socket " +
                str(socket) +
                " has " +
                str(core_count) +
                " core[s] which is less than " +
                str(min_cores) +
                " cores per socket required to run ECE")
            fatal_error = True
        else:
            print(
                INFO +
                LOCAL_HOSTNAME +
                " socket " +
                str(socket) +
                " has " +
                str(core_count) +
                " core[s] which copmplies with " +
                str(min_cores) +
                " cores per socket required to support ECE")
    return fatal_error, num_sockets, cores


def check_memory(min_gb_ram):
    fatal_error = False
    print(INFO + LOCAL_HOSTNAME + " checking memory")
    # Total memory
    mem_b = os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES')
    mem_gb = mem_b / 1024**3
    if mem_gb < min_gb_ram:
        print(
            ERROR +
            LOCAL_HOSTNAME +
            " total memory is less than " +
            str(min_gb_ram) +
            " GB required to run ECE")
        fatal_error = True
    else:
        print(
            INFO +
            LOCAL_HOSTNAME +
            " total memory is " +
            str(mem_gb) +
            " GB, which is sufficient to run ECE")
    # Memory DIMMs
    dimms = {}
    m_slots = dmidecode.memory()
    for slot in m_slots.keys():
        # Avoiding 'System Board Or Motherboard'. Need more data
        if m_slots[slot]['data']['Error Information Handle'] == 'Not Provided':
            continue
        dimms[m_slots[slot]['data']['Locator']
              ] = m_slots[slot]['data']['Size']
    empty_dimms = 0
    num_dimms = len(dimms)
    dimm_size = {}
    for dimm in dimms.keys():
        if dimms[dimm] is None:
            empty_dimms = empty_dimms + 1
        else:
            dimm_size[dimm] = dimms[dimm]
    if empty_dimms > 0:
        print(
            WARNING +
            LOCAL_HOSTNAME +
            " not all " +
            str(num_dimms) +
            " DIMM slot[s] are populated. This system has " +
            str(empty_dimms) +
            " empty DIMM slot[s]. This is not recommended to run ECE")
    else:
        print(INFO + LOCAL_HOSTNAME + " all " + str(num_dimms) +
              " DIMM slot[s] are populated. This is recommended to run ECE")
    dimm_memory_size = []
    for dimm in dimm_size.keys():
        dimm_memory_size.append(dimm_size[dimm])
    main_memory_size = unique_list(dimm_memory_size)
    if len(main_memory_size) == 1:
        print(
            INFO +
            LOCAL_HOSTNAME +
            " all populated DIMM slots have same memory size of " +
            main_memory_size[0])
    else:
        print(
            ERROR +
            LOCAL_HOSTNAME +
            " all populated DIMM slots do not have same memory sizes")
        fatal_error = True
    return fatal_error, mem_gb, dimms, num_dimms, empty_dimms, main_memory_size


def unique_list(inputlist):
    outputlist = []
    for item in inputlist:
        if item not in outputlist:
            outputlist.append(item)
    return outputlist


def check_os_redhat(os_dictionary):
    fatal_error = False
    # Check redhat-release vs dictionary list
    redhat_distribution = platform.linux_distribution()
    version_string = redhat_distribution[1]
    if platform.dist()[0] == "centos":
        try:
            matchobj = re.match(OSVERPATT, version_string)
            version_string = "{}.{}".format(matchobj.group('major'),
                                            matchobj.group('minor'))
        except AttributeError:
            pass

    redhat_distribution_str = redhat_distribution[0] + \
        " " + version_string

    error_message = ERROR + LOCAL_HOSTNAME + " " + \
        redhat_distribution_str + " is not a supported OS to run ECE"
    try:
        if os_dictionary[redhat_distribution_str] == 'OK':
            print(
                INFO +
                LOCAL_HOSTNAME +
                " " +
                redhat_distribution_str +
                " is a supported OS to run ECE")
        elif os_dictionary[redhat_distribution_str] == 'WARN':
            print(
                WARNING +
                LOCAL_HOSTNAME +
                " " +
                redhat_distribution_str +
                " is a clone OS that is not officially supported" +
                " to run ECE." +
                " See Spectrum Scale FAQ for restrictions.")
        else:
            print(error_message)
            fatal_error = True
    except BaseException:
        print(error_message)
        fatal_error = True

    return fatal_error, redhat_distribution_str


def get_json_versions(
        os_dictionary,
        sysctl_dictionary,
        packages_dictionary,
        SAS_dictionary,
        NIC_dictionary,
        HW_dictionary):

    # Gets the versions of the json files into a dictionary
    json_version = {}

    # Lets see if we can load version, if not quit
    try:
        json_version['supported_OS'] = os_dictionary['json_version']
    except BaseException:
        sys.exit(
            ERROR +
            LOCAL_HOSTNAME +
            " cannot load version from supported OS JSON")

    try:
        json_version['sysctl'] = sysctl_dictionary['json_version']
    except BaseException:
        sys.exit(
            ERROR +
            LOCAL_HOSTNAME +
            " cannot load version from sysctl JSON")

    try:
        json_version['packages'] = packages_dictionary['json_version']
    except BaseException:
        sys.exit(
            ERROR +
            LOCAL_HOSTNAME +
            " cannot load version from packages JSON")

    try:
        json_version['SAS_adapters'] = SAS_dictionary['json_version']
    except BaseException:
        sys.exit(ERROR + LOCAL_HOSTNAME + " cannot load version from SAS JSON")

    try:
        json_version['NIC_adapters'] = NIC_dictionary['json_version']
    except BaseException:
        sys.exit(ERROR + LOCAL_HOSTNAME + " cannot load version from SAS JSON")

    try:
        json_version['HW_requirements'] = HW_dictionary['json_version']
    except BaseException:
        sys.exit(ERROR + LOCAL_HOSTNAME + " cannot load version from HW JSON")

    # If we made it this far lets return the dictionary. This was being stored
    # in its own file before
    return json_version


def check_NVME():
    fatal_error = False
    print(INFO + LOCAL_HOSTNAME + " checking NVMe devices")
    try:
        nvme_devices = os.listdir('/sys/class/nvme/')
        num_nvme_devices = len(nvme_devices)
        if num_nvme_devices == 0:
            print(WARNING + LOCAL_HOSTNAME + " no NVMe devices detected")
            fatal_error = True
        else:
            print(
                INFO +
                LOCAL_HOSTNAME +
                " has " +
                str(num_nvme_devices) +
                " NVMe device[s] detected")

    except BaseException:
        num_nvme_devices = 0
        print(WARNING + LOCAL_HOSTNAME + " no NVMe devices detected")
        fatal_error = True

    return fatal_error, num_nvme_devices


def check_NVME_packages(packages_ch):
    fatal_error = False
    nvme_packages = {"nvme-cli": 0}
    if packages_ch:
        print(INFO +
        LOCAL_HOSTNAME +
        " checking that needed software for NVMe is installed")
        nvme_packages_errors = packages_check(nvme_packages)
        if nvme_packages_errors:
            fatal_error = True
    return fatal_error


def check_SAS_packages(packages_ch):
    fatal_error = False
    sas_packages = {"storcli": 0}
    if packages_ch:
        print(INFO +
        LOCAL_HOSTNAME +
        " checking that needed software for SAS is installed")
        sas_packages_errors = packages_check(sas_packages)
        if sas_packages_errors:
            fatal_error = True
    return fatal_error


def check_NVME_disks():
    # If we run this we already check elsewhere that there are NVme drives
    fatal_error = False
    try:
        if PYTHON3:
            drives = subprocess.getoutput("nvme list | grep nvme").split('\n')
        else:
            drives = commands.getoutput("nvme list | grep nvme").split('\n')
        drives_dict = {}
        drives_size_list = []
        for single_drive in drives:
            list_single_drive = single_drive.split()
            drives_dict[list_single_drive[1]] = [list_single_drive[0],
                                                 list_single_drive[2],
                                                 list_single_drive[4],
                                                 list_single_drive[5],
                                                 list_single_drive[14]]
            drives_size_list.append(list_single_drive[4])
        drives_unique_size = unique_list(drives_size_list)
        if len(drives_unique_size) == 1:
            print(
                INFO +
                LOCAL_HOSTNAME +
                " all NVMe devices have the same size")
        else:
            # fatal_error = True
            print(
                WARNING +
                LOCAL_HOSTNAME +
                "not all NVMe devices have the same size")
    except BaseException:
        fatal_error = True
        print(
            WARNING +
            LOCAL_HOSTNAME +
            " cannot query NVMe devices"
            )
    return fatal_error, drives_dict


def check_SAS(SAS_dictionary):
    fatal_error = False
    check_disks = False
    SAS_model = []
    # do a lspci check if it has at least one adpater from the dictionary
    found_SAS = False
    print(INFO + LOCAL_HOSTNAME + " checking SAS adapters")
    for SAS in SAS_dictionary:
        if SAS != "json_version":
            try:
                lspci_out = subprocess.Popen(['lspci'], stdout=subprocess.PIPE)
                grep_rc_lspci = subprocess.call(
                    ['grep', SAS],
                    stdin=lspci_out.stdout,
                    stdout=DEVNULL,
                    stderr=DEVNULL)
                lspci_out.wait()

                if grep_rc_lspci == 0:  # We have this SAS, 1 or more
                    if SAS_dictionary[SAS] == "OK":
                        print(
                            INFO +
                            LOCAL_HOSTNAME +
                            " has " +
                            SAS +
                            " adapter which is supported by ECE. The disks " +
                            "under this SAS adapter could be used by ECE")
                        found_SAS = True
                        check_disks = True
                        SAS_model.append(SAS)
                    elif SAS_dictionary[SAS] == "WARN":
                        print(
                            ERROR +
                            LOCAL_HOSTNAME +
                            " has " +
                            SAS +
                            " adapter which is NOT supported by ECE. The" +
                            " disks under this SAS adapter will still be " +
                            " checked for use by ECE")
                        found_SAS = False
                        check_disks = True
                        SAS_model.append(SAS)
                    else:
                        print(
                            ERROR +
                            LOCAL_HOSTNAME +
                            " has " +
                            SAS +
                            " adapter which is explicitly not supported by " +
                            "ECE. The disks under this SAS adapter cannot " +
                            "be used by ECE")
                        found_SAS = False
                        check_disks = False
                        SAS_model.append(SAS)
            except BaseException:
                sys.exit(
                    ERROR +
                    LOCAL_HOSTNAME +
                    " an undetermined error ocurred while " +
                    "determing SAS adapters")

    if not found_SAS:
        print(
            ERROR +
            LOCAL_HOSTNAME +
            " does not have any SAS adapter supported by ECE. The disks " +
            "under any SAS adapter in this system cannot be used by ECE")
        fatal_error = True

    return fatal_error, check_disks, SAS_model


def exec_cmd(command):
    # write command to JSON to have an idea of the system

    try:
        run_cmd = subprocess.Popen(shlex.split(command), stdout=subprocess.PIPE)
        run_cmd.wait()
        cmd_output = run_cmd.stdout.read()
        return cmd_output

    except BaseException:
        sys.exit(
            ERROR +
            LOCAL_HOSTNAME +
            " cannot run " + str(command))


def check_SAS_disks(device_type):
    fatal_error = False
    num_errors = 0
    number_of_drives = 0
    number_of_SATA_drives = 0
    SAS_drives_dict = {}
    try:
        if PYTHON3:
            drives = subprocess.getoutput(
                "/opt/MegaRAID/storcli/storcli64 /call show " +
                "| egrep \"JBOD|UGood\" | grep SAS | grep " +
                device_type).split('\n')
            SATA_drives = subprocess.getoutput(
                "/opt/MegaRAID/storcli/storcli64 /call show " +
                "| grep SATA | grep " +
                device_type).split('\n')
        else:
            drives = commands.getoutput(
                "/opt/MegaRAID/storcli/storcli64 /call show " +
                "| egrep \"JBOD|UGood\" | grep SAS | grep " +
                device_type).split('\n')
            SATA_drives = commands.getoutput(
                "/opt/MegaRAID/storcli/storcli64 /call show " +
                "| grep SATA | grep " +
                device_type).split('\n')
        number_of_drives = len(drives)
        number_of_SATA_drives = len(SATA_drives)

        if number_of_SATA_drives > 1:
            # Throw a warning about SATA drives
            print(
                WARNING +
                LOCAL_HOSTNAME +
                " has " +
                str(number_of_SATA_drives) +
                " SATA " +
                device_type +
                " drive[s] on the SAS adapter. SATA drives are not" +
                " supported by ECE. Do not use them for ECE")

        if number_of_drives > 0:
            drives_size_list = []
            for single_drive in drives:
                list_single_drive = single_drive.split()
                SAS_drives_dict[list_single_drive[0]] = [
                    list_single_drive[4],
                    list_single_drive[5],
                    list_single_drive[10],
                    list_single_drive[11]]
                drives_size_list.append(list_single_drive[4])

            drives_unique_size = unique_list(drives_size_list)
            if len(drives_unique_size) == 1:
                print(
                    INFO +
                    LOCAL_HOSTNAME +
                    " has " +
                    str(number_of_drives) +
                    " " +
                    device_type +
                    " drive[s] on the SAS adapter the same size " +
                    "that ECE can use")
            else:
                # num_errors = num_errors + 1
                print(
                    WARNING +
                    LOCAL_HOSTNAME +
                    " has " +
                    str(number_of_drives) +
                    " " +
                    device_type +
                    " drive[s] on the SAS adapter with different sizes " +
                    "that ECE can use")

    except BaseException:
        num_errors = num_errors + 1
        number_of_drives = 0
        print(
            WARNING +
            LOCAL_HOSTNAME +
            " no " +
            device_type +
            " disk[s] usable by ECE found. The drives under SAS controller " +
            "must be on JBOD mode and be SAS drives")

    if num_errors != 0:
        fatal_error = True

    return fatal_error, number_of_drives, SAS_drives_dict


def check_WCE_NVME(NVME_dict):
    num_errors = 0
    fatal_error = False
    for drive in NVME_dict.keys():
        os_device = NVME_dict[drive][0]
        wce_drive_enabled = False
        try:
            if PYTHON3:
                rc, write_cache_drive = subprocess.getstatusoutput(
                    '/usr/bin/sdparm -g WCE=1 -H ' + os_device)
            else:
                rc, write_cache_drive = commands.getstatusoutput(
                    '/usr/bin/sdparm -g WCE=1 -H ' + os_device)
        except BaseException:
            sys.exit(
                ERROR +
                LOCAL_HOSTNAME +
                " cannot read WCE status for NVMe devices")

        # if WCE is not supported on device the we expect nonzero rc
        if rc == 0:
            wce_drive_enabled = bool(int(write_cache_drive, 16))
            NVME_dict[drive].append(wce_drive_enabled)

        if wce_drive_enabled:
            print(
                ERROR +
                LOCAL_HOSTNAME +
                " " +
                str(os_device) +
                " has Write Cache Enabled. This is not supported by ECE")
            num_errors = num_errors + 1
    if num_errors != 0:
        fatal_error = True
    else:
        print(INFO + LOCAL_HOSTNAME + " all NVME drives have Volatile Write" +
              " Cache disabled")

    return fatal_error, NVME_dict


def check_WCE_SAS(SAS_drives_dict):
    # Check WCE is enabled, if so print an ERROR + return fatal_error True
    fatal_error = False
    num_errors = 0
    for drive in SAS_drives_dict.keys():
        enc_slot_list = drive.split(':')
        try:
            if PYTHON3:
                storcli_output = subprocess.getoutput(
                    '/opt/MegaRAID/storcli/storcli64 /call/e' +
                    enc_slot_list[0] + '/s' + enc_slot_list[1] + ' show all j ')
            else:
                storcli_output = commands.getoutput(
                    '/opt/MegaRAID/storcli/storcli64 /call/e' + enc_slot_list[0] +
                    '/s' + enc_slot_list[1] + ' show all j ')
            wwn = WWNPATT.search(storcli_output).group('wwn')
            sasaddr = SASPATT.search(storcli_output).group('sasaddr')
            if wwn == 'NA':
                # if wwn is not defined, use sasaddr - we truncate last
                # digit later
                wwn = sasaddr
        except BaseException as e:
            sys.exit(
                ERROR +
                LOCAL_HOSTNAME +
                " cannot parse WWN for SAS devices")
        SAS_drives_dict[drive].append(wwn.lower())
        map_error, os_device = map_WWN_to_OS_device(wwn.lower())
        SAS_drives_dict[drive].append(map_error)
        SAS_drives_dict[drive].append(os_device)
        wce_drive_enabled = False
        try:
            if PYTHON3:
                rc, write_cache_drive = subprocess.getstatusoutput(
                    '/usr/bin/sdparm -g WCE=1 -H /dev/' + os_device)
            else:
                rc, write_cache_drive = commands.getstatusoutput(
                    '/usr/bin/sdparm -g WCE=1 -H /dev/' + os_device)
        except BaseException:
            sys.exit(
                ERROR +
                LOCAL_HOSTNAME +
                " cannot read WCE status for SAS devices")

        # if WCE is not supported on device the we expect nonzero rc
        if rc == 0:
            wce_drive_enabled = bool(int(write_cache_drive, 16))
            SAS_drives_dict[drive].append(wce_drive_enabled)

        if wce_drive_enabled:
            print(
                ERROR +
                LOCAL_HOSTNAME +
                " " +
                str(os_device) +
                " has Write Cache Enabled. This is not supported by ECE")
            num_errors = num_errors + 1

        # why do we need to check again with storcli?
        try:
            if PYTHON3:
                write_cache_list = subprocess.getoutput(
                    '/opt/MegaRAID/storcli/storcli64 /call/e' +
                    enc_slot_list[0] +
                    '/s' + enc_slot_list[1] +
                    ' show all | grep -i "Write Cache"').split(' ')
            else:
                write_cache_list = commands.getoutput(
                    '/opt/MegaRAID/storcli/storcli64 /call/e' +
                    enc_slot_list[0] +
                    '/s' + enc_slot_list[1] +
                    ' show all | grep -i "Write Cache"').split(' ')
        except BaseException:
            sys.exit(
                ERROR +
                LOCAL_HOSTNAME +
                " cannot read WCE status for SAS card")

        # if write cache entry is returned by storcli, use it
        # otherwise ignore
        if len(write_cache_list) > 3:
            wc_status = write_cache_list[3]
            SAS_drives_dict[drive].append(write_cache_list[3])
        else:
            wc_status = 'Unsupported'

        SAS_drives_dict[drive].append(wc_status)
        if wc_status == "Enabled":
            print(
                ERROR +
                LOCAL_HOSTNAME +
                " " +
                str(drive) +
                " has Write Cache Enabled. This is not supported by ECE")
            num_errors = num_errors + 1
    if num_errors != 0:
        fatal_error = True
    else:
        print(INFO + LOCAL_HOSTNAME +
              " all SAS drives have Volatile Write Cache disabled")

    return fatal_error, SAS_drives_dict


def map_WWN_to_OS_device(drive_WWN):
    fatal_error = False
    num_errors = 0
    # ignore the least signicant digit - this is enough to uniquely ID
    # drives by WWN.  (but need all other digits - here is an example
    # where ignoring last 2 digits causes a problem:
    # # lsscsi -w | grep 0x50000397c82ac4
    # [1:0:20:0]   disk    0x50000397c82ac4b9                  /dev/sdt
    # [1:0:21:0]   disk    0x50000397c82ac461                  /dev/sdu
    # [1:0:23:0]   disk    0x50000397c82ac42d                  /dev/sdw
    truncated_WWN = drive_WWN[:-1]
    try:
        if PYTHON3:
            OS_drive_list = subprocess.getoutput(
                '/usr/bin/readlink /dev/disk/by-id/wwn-0x' + truncated_WWN +
                '? | /usr/bin/head -1').split('/')
        else:
            OS_drive_list = commands.getoutput(
                '/usr/bin/readlink /dev/disk/by-id/wwn-0x' + truncated_WWN +
                '? | /usr/bin/head -1').split('/')
    except BaseException:
        sys.exit(
            ERROR +
            LOCAL_HOSTNAME +
            " cannot parse WWN from SAS devices")
    try:
        os_device = OS_drive_list[2]
    except BaseException:
        os_device = "NONE"
        num_errors = num_errors + 1

    if num_errors != 0:
        fatal_error = True
    return fatal_error, os_device


def check_NIC(NIC_dictionary):
    fatal_error = False
    NIC_model = []
    # do a lspci check if it has at least one adpater from the dictionary
    found_NIC = False
    print(INFO + LOCAL_HOSTNAME + " checking NIC adapters")
    for NIC in NIC_dictionary:
        if NIC != "json_version":
            try:
                lspci_out = subprocess.Popen(['lspci'], stdout=subprocess.PIPE)
                grep_rc_lspci = subprocess.call(
                    ['grep', NIC],
                    stdin=lspci_out.stdout,
                    stdout=DEVNULL,
                    stderr=DEVNULL)
                lspci_out.wait()

                if grep_rc_lspci == 0:  # We have this NIC, 1 or more
                    if NIC_dictionary[NIC] == "OK":
                        print(INFO + LOCAL_HOSTNAME + " has " + NIC +
                             " adapter which is supported by ECE")
                        found_NIC = True
                        NIC_model.append(NIC)
                    else:
                        print(
                            ERROR +
                            LOCAL_HOSTNAME +
                            " has " +
                            NIC +
                            " adapter which is explicitly not supported by " +
                            "ECE")
                        found_NIC = False
                        fatal_error = True
                        NIC_model.append(NIC)

            except BaseException:
                sys.exit(
                    ERROR +
                    LOCAL_HOSTNAME +
                    " an undetermined error ocurred while " +
                    "determing NIC adapters")

    if not found_NIC:
        print(
            ERROR +
            LOCAL_HOSTNAME +
            " does not have NIC adapter supported by ECE")
        fatal_error = True

    return fatal_error, NIC_model


def check_sysctl(sysctl_dictionary):
    fatal_error = False
    sysctl_right = []
    sysctl_wrong = []
    # Runs checks versus values on sysctl on JSON file
    errors = 0
    print(INFO + LOCAL_HOSTNAME + " checking sysctl settings")
    for sysctl in sysctl_dictionary.keys():
        if sysctl != "json_version":
            recommended_value_str = str(sysctl_dictionary[sysctl])
            # Need to clean the entries that have spaces for integer
            # comparision
            recommended_value = int(recommended_value_str.replace(" ", ""))
            try:
                current_value_str = subprocess.check_output(
                    ['sysctl', '-n', sysctl], stderr=subprocess.STDOUT)
                current_value_str = current_value_str.replace(
                    "\t", " ").replace("\n", "")
                # Need to clean the entries that have spaces for integer
                # comparision
                current_value = int(current_value_str.replace(" ", ""))
                # This creates an possible colision issue, might fix this in
                # the future

                if recommended_value != current_value:
                    print(
                        WARNING +
                        LOCAL_HOSTNAME +
                        " " +
                        sysctl +
                        " is " +
                        current_value_str +
                        " and should be " +
                        recommended_value_str)
                    errors = errors + 1
                    fatal_error = True
                    sysctl_wrong.append(sysctl)
                else:
                    print(
                        INFO +
                        LOCAL_HOSTNAME +
                        " " +
                        sysctl +
                        " it is set to the recommended value of " +
                        recommended_value_str)
                    sysctl_right.append(sysctl)
            except BaseException:
                print(
                    WARNING +
                    LOCAL_HOSTNAME +
                    " " +
                    sysctl +
                    "current value does not exists")
                errors = errors + 1
                fatal_error = True
    return fatal_error, errors, sysctl_right, sysctl_wrong


def check_distribution():
    # Decide if this is a redhat or a suse
    what_dist = platform.dist()[0]
    if what_dist in ["redhat", "centos"]:
        return what_dist
    else:  # everything else we fail
        print(ERROR + LOCAL_HOSTNAME + " ECE is only supported on RedHat")
        return "UNSUPPORTED_DISTRIBUTION"


def print_summary_toolkit(sysctl_errors):
    # We are here so we need to raise an error RC to be catched by the toolkit
    if sysctl_errors > 0:
        print(
            ERROR +
            LOCAL_HOSTNAME +
            " " +
            str(sysctl_errors) +
            " sysctl setting[s] need to be changed. Check information " +
            "above this message")
    # Lets the overall script catch the errors
    print(
        ERROR +
        LOCAL_HOSTNAME +
        " does not have a supported configuration to run ECE")


def print_summary_standalone(
        nfatal_errors,
        sysctl_errors,
        outputfile_name,
        start_time_date,
        end_time_date,
        redhat_distribution_str,
        current_processor,
        num_sockets,
        core_count,
        mem_gb,
        num_dimms,
        empty_dimms,
        number_of_HDD_drives,
        number_of_SSD_drives,
        number_of_NVME_drives,
        device_speed,
        all_checks_on):
    # This is not being run from the toolkit so lets write a more human summary
    if sysctl_errors > 0:
        print(
            ERROR +
            LOCAL_HOSTNAME +
            " " +
            str(sysctl_errors) +
            " sysctl setting[s] need to be changed. Check " +
            "information above this message")

    print("")
    print("\tSummary of this standalone run:")
    print("\t\tRun started at " + str(start_time_date))
    print("\t\tECE Readiness version " + MOR_VERSION)
    print("\t\tHostname: " + LOCAL_HOSTNAME)
    print("\t\tOS: " + redhat_distribution_str)
    print("\t\tArchitecture: " + str(current_processor))
    print("\t\tSockets: " + str(num_sockets))
    print("\t\tCores per socket: " + str(core_count))
    print("\t\tMemory: " + str(mem_gb) + " GBytes")
    print("\t\tDIMM slots: " + str(num_dimms))
    print("\t\tDIMM slots in use: " + str(num_dimms - empty_dimms))
    print("\t\tJBOD SAS HDD drives: " + str(number_of_HDD_drives))
    print("\t\tJBOD SAS SSD drives: " + str(number_of_SSD_drives))
    print("\t\tNVMe drives: " + str(number_of_NVME_drives))
    print("\t\tLink speed: " + str(device_speed))
    print("\t\tRun ended at " + str(end_time_date))
    print("")
    print("\t\t" + outputfile_name + " contains information about this run")
    print("")

    if nfatal_errors > 0:
        sys.exit(
            ERROR +
            LOCAL_HOSTNAME +
            " system cannot run IBM Spectrum Scale Erasure Code Edition")
    elif all_checks_on:
        print(
            INFO +
            LOCAL_HOSTNAME +
            " system can run IBM Spectrum Scale Erasure Code Edition")
    else:
        print(
            WARNING +
            LOCAL_HOSTNAME +
            " Although the tests run were passed some tests were skipped so " +
            "this tool cannot assess if this system can run " +
            "IBM Spectrum Scale Erasure Code Edition")


def main():
    nfatal_errors = 0
    outputfile_dict = {}

    # Start time
    outputfile_dict['start_time'] = str(start_time_date)

    # Parse ArgumentParser
    (ip_address,
        path,
        cpu_check,
        md5_check,
        mem_check,
        os_check,
        packages_ch,
        storage_check,
        net_check,
        sysctl_check,
        toolkit_run) = parse_arguments()

    if (cpu_check and md5_check and mem_check and os_check and packages_ch
            and storage_check and net_check and sysctl_check):
        all_checks_on = True
    else:
        all_checks_on = False

    # JSON loads and store MD5
    os_dictionary = load_json(path + "supported_OS.json")
    supported_OS_md5 = md5_chksum(path + "supported_OS.json")
    outputfile_dict['supported_OS_md5'] = supported_OS_md5
    sysctl_dictionary = load_json(path + "sysctl.json")
    sysctl_md5 = md5_chksum(path + "sysctl.json")
    outputfile_dict['sysctl_md5'] = sysctl_md5
    packages_dictionary = load_json(path + "packages.json")
    packages_md5 = md5_chksum(path + "packages.json")
    outputfile_dict['packages_md5'] = packages_md5
    SAS_dictionary = load_json(path + "SAS_adapters.json")
    SAS_adapters_md5 = md5_chksum(path + "SAS_adapters.json")
    outputfile_dict['SAS_adapters_md5'] = SAS_adapters_md5
    NIC_dictionary = load_json(path + "NIC_adapters.json")
    NIC_adapters_md5 = md5_chksum(path + "NIC_adapters.json")
    outputfile_dict['NIC_adapters_md5'] = NIC_adapters_md5
    HW_dictionary = load_json(path + "HW_requirements.json")
    HW_requirements_md5 = md5_chksum(path + "HW_requirements.json")
    outputfile_dict['HW_requirements_md5'] = HW_requirements_md5

    # Check MD5 hashes. Files are already checked that exists and load JSON
    passed_md5_supported_os = md5_verify(
        md5_check,
        "supported_OS.json",
        supported_OS_md5,
        SUPPORTED_OS_MD5)
    outputfile_dict['passed_md5_supported_os'] = passed_md5_supported_os
    passed_md5_sysctl = md5_verify(
        md5_check, "sysctl.json", sysctl_md5, SYSCTL_MD5)
    outputfile_dict['passed_md5_sysctl'] = passed_md5_sysctl
    passed_md5_packages = md5_verify(
        md5_check,
        "packages.json",
        packages_md5,
        PACKAGES_MD5)
    outputfile_dict['passed_md5_packages'] = passed_md5_packages
    passed_md5_SAS_adapters = md5_verify(
        md5_check,
        "SAS_adapters.json",
        SAS_adapters_md5,
        SAS_ADAPTERS_MD5)
    outputfile_dict['passed_md5_SAS_adapters'] = passed_md5_SAS_adapters
    passed_md5_NIC_adapters = md5_verify(
        md5_check,
        "NIC_adapters.json",
        NIC_adapters_md5,
        NIC_ADAPTERS_MD5)
    outputfile_dict['passed_md5_NIC_adapters'] = passed_md5_NIC_adapters
    passed_md5_HW_requirements = md5_verify(
        md5_check,
        "HW_requirements.json",
        HW_requirements_md5,
        HW_REQUIREMENTS_MD5)
    outputfile_dict['passed_md5_HW_requirements'] = passed_md5_HW_requirements

    # Initial header and checks
    json_version = get_json_versions(
        os_dictionary,
        sysctl_dictionary,
        packages_dictionary,
        SAS_dictionary,
        NIC_dictionary,
        HW_dictionary)
    show_header(MOR_VERSION, json_version, toolkit_run)

    # Set HW constants
    min_socket = HW_dictionary['MIN_SOCKET']
    min_cores = HW_dictionary['MIN_CORES']
    min_gb_ram = HW_dictionary['MIN_GB_RAM']
    max_drives = HW_dictionary['MAX_DRIVES']
    min_link_speed = HW_dictionary['MIN_LINK_SPEED']

    outputfile_dict['parameters'] = [
        LOCAL_HOSTNAME,
        ip_address,
        path,
        cpu_check,
        md5_check,
        mem_check,
        os_check,
        packages_ch,
        storage_check,
        net_check,
        sysctl_check,
        min_socket,
        min_cores,
        min_gb_ram,
        max_drives,
        min_link_speed]

    # Check cpu
    current_processor = "NOT CHECKED"
    num_sockets = 0
    core_count = 0
    if cpu_check:
        fatal_error, current_processor = check_processor()
        outputfile_dict['current_processor'] = current_processor
        if fatal_error:
            nfatal_errors = nfatal_errors + 1
        fatal_error, num_sockets, core_count = check_sockets_cores(
            min_socket, min_cores)
        outputfile_dict['num_sockets'] = num_sockets
        outputfile_dict['cores_per_socket'] = core_count
        outputfile_dict['CPU_fatal_error'] = fatal_error
        if fatal_error:
            nfatal_errors = nfatal_errors + 1

    # Check linux_distribution
    redhat_distribution_str = "NOT CHECKED"
    if os_check:
        linux_distribution = check_distribution()
        outputfile_dict['linux_distribution'] = linux_distribution
        if linux_distribution in ["redhat", "centos"]:
            fatal_error, redhat_distribution_str = check_os_redhat(
                os_dictionary)
            if fatal_error:
                nfatal_errors = nfatal_errors + 1
            else:
                outputfile_dict['OS'] = redhat_distribution_str
        else:
            sys.exit(
                ERROR +
                LOCAL_HOSTNAME +
                " cannot determine Linux distribution\n")

    # Check packages
    if packages_ch:
        packages_errors = packages_check(packages_dictionary)
        if packages_errors > 0:
            sys.exit(
                ERROR +
                LOCAL_HOSTNAME +
                " has missing packages needed to run this tool\n")
        else:
            outputfile_dict['packages_checked'] = packages_dictionary

    # Check memory
    mem_gb = 0
    dimms = 0
    num_dimms = 0
    empty_dimms = 0
    if mem_check:
        (fatal_error,
            mem_gb,
            dimms,
            num_dimms,
            empty_dimms,
            main_memory_size) = check_memory(min_gb_ram)
        outputfile_dict['memory_all'] = [fatal_error, mem_gb,
                                         dimms, num_dimms, empty_dimms,
                                         main_memory_size]
        outputfile_dict['memory_error'] = fatal_error
        outputfile_dict['system_memory'] = mem_gb
        outputfile_dict['num_dimm_slots'] = num_dimms
        outputfile_dict['num_dimm_empty_slots'] = empty_dimms
        outputfile_dict['dimm_memory_size'] = main_memory_size
        if fatal_error:
            nfatal_errors = nfatal_errors + 1

    # Check SAS SAS_adapters
    n_mestor_drives = 0
    n_HDD_drives = 0
    n_SSD_drives = 0
    n_NVME_drives = 0
    HDD_error = False
    SSD_error = False
    NVME_error = False
    SAS_but_no_usable_drives = False
    NVME_dict = {}
    if storage_check:
        SAS_fatal_error, check_disks, SAS_model = check_SAS(SAS_dictionary)
        outputfile_dict['error_SAS_card'] = SAS_fatal_error
        outputfile_dict['SAS_model'] = SAS_model
        if check_disks:
            SAS_packages_errors = check_SAS_packages(packages_ch)
            outputfile_dict['SAS_packages_errors'] = SAS_packages_errors
            if SAS_packages_errors > 0:
                sys.exit(
                    ERROR +
                    LOCAL_HOSTNAME +
                    " has missing packages needed to run this tool\n")
            else:
                # Extra information to the JSON
                call_all = exec_cmd(
                    "/opt/MegaRAID/storcli/storcli64 /call show all j")
                outputfile_dict['storcli_call'] = call_all
                call_eall_all = exec_cmd(
                    "/opt/MegaRAID/storcli/storcli64 /call/eall show all j")
                outputfile_dict['storcli_call_eall'] = call_eall_all
                call_sall_all = exec_cmd(
                    "/opt/MegaRAID/storcli/storcli64 /call/eall/sall show all j")
                outputfile_dict['storcli_call_sall_all'] = call_sall_all
                # Checks start
                HDD_error, n_HDD_drives, HDD_dict = check_SAS_disks("HDD")
                outputfile_dict['HDD_fatal_error'] = HDD_error
                outputfile_dict['HDD_n_of_drives'] = n_HDD_drives
                outputfile_dict['HDD_drives'] = HDD_dict
                if n_HDD_drives > 0:
                    HDD_WCE_error, HDD_dict = check_WCE_SAS(HDD_dict)
                    outputfile_dict['HDD_WCE_error'] = HDD_WCE_error
                    if HDD_WCE_error:
                        nfatal_errors = nfatal_errors + 1
                SSD_error, n_SSD_drives, SSD_dict = check_SAS_disks("SSD")
                outputfile_dict['SSD_fatal_error'] = SSD_error
                outputfile_dict['SSD_n_of_drives'] = n_SSD_drives
                outputfile_dict['SSD_drives'] = SSD_dict
                if n_SSD_drives > 0:
                    SSD_WCE_error, SSD_dict = check_WCE_SAS(SSD_dict)
                    outputfile_dict['SSD_WCE_error'] = SSD_WCE_error
                    if SSD_WCE_error:
                        nfatal_errors = nfatal_errors + 1
                if not HDD_error:
                    n_mestor_drives = n_mestor_drives + n_HDD_drives
                if not SSD_error:
                    n_mestor_drives = n_mestor_drives + n_SSD_drives
                if HDD_error and SSD_error:
                    SAS_but_no_usable_drives = True
                    outputfile_dict['found_SAS_card_but_no_drives'] = True
        # NVME checks
        NVME_error, n_NVME_drives = check_NVME()
        outputfile_dict['NVME_fatal_error'] = NVME_error
        outputfile_dict['NVME_number_of_drives'] = n_NVME_drives
        if not NVME_error:
            NVME_packages_errors = check_NVME_packages(packages_ch)
            outputfile_dict['NVME_packages_errors'] = NVME_packages_errors
            if NVME_packages_errors > 0:
                sys.exit(
                    ERROR +
                    LOCAL_HOSTNAME +
                    " has missing packages needed to run this tool\n")
            else:
                n_mestor_drives = n_mestor_drives + n_NVME_drives
                NVME_error, NVME_dict = check_NVME_disks()
        if n_NVME_drives > 0:
            NVME_WCE_error, NVME_dict = check_WCE_NVME(NVME_dict)
            outputfile_dict['NVME_WCE_error'] = NVME_WCE_error
            if NVME_WCE_error:
                nfatal_errors = nfatal_errors + 1

        outputfile_dict['NVME_drives'] = NVME_dict

        outputfile_dict['ALL_number_of_drives'] = n_mestor_drives
        # Throw a warning if no drives
        if SAS_but_no_usable_drives:
            print(
                WARNING +
                LOCAL_HOSTNAME +
                " has a supported SAS adapter but no supported drives")
        # Lets check what we can use here
        if SAS_fatal_error and NVME_error:
            print(
                ERROR +
                LOCAL_HOSTNAME +
                " has no supported SAS adapter nor NVMe supported " +
                "devices in this system")
            nfatal_errors = nfatal_errors + 1
        elif SSD_error and NVME_error:
            print(
                ERROR +
                LOCAL_HOSTNAME +
                " has no SSD or NVMe device that ECE can use. At least " +
                "one device of those types is required to run ECE")
            nfatal_errors = nfatal_errors + 1
        else:
            print(
                INFO +
                LOCAL_HOSTNAME +
                " has at least one SSD or NVMe device that ECE can use. " +
                "This is required to run ECE")
            if n_mestor_drives > max_drives:
                print(
                    ERROR +
                    LOCAL_HOSTNAME +
                    " has more than " +
                    str(max_drives) +
                    " drives that ECE can use in one RG. " +
                    "This is not supported by ECE")
                nfatal_errors = nfatal_errors + 1
            else:
                print(
                    INFO +
                    LOCAL_HOSTNAME +
                    " has " +
                    str(n_mestor_drives) +
                    " drives that ECE can use")

    # Network checks
    device_speed = "NOT CHECKED"
    outputfile_dict['local_hostname'] = LOCAL_HOSTNAME
    ip_address_is_IP = is_IP_address(ip_address)
    outputfile_dict['IP_address_is_possible'] = ip_address_is_IP
    outputfile_dict['ip_address'] = ip_address
    if net_check:
        fatal_error, NIC_model = check_NIC(NIC_dictionary)
        outputfile_dict['error_NIC_card'] = fatal_error
        outputfile_dict['NIC_model'] = NIC_model
        if fatal_error:
            nfatal_errors = nfatal_errors + 1
        elif (ip_address_is_IP):
            print(
                INFO +
                LOCAL_HOSTNAME +
                " checking " +
                ip_address +
                " device and link speed")
            net_devices = list_net_devices()
            outputfile_dict['ALL_net_devices'] = net_devices
            fatal_error, net_interface = what_interface_has_ip(
                net_devices, ip_address)
            outputfile_dict['IP_not_found'] = fatal_error
            outputfile_dict['netdev_with_IP'] = net_interface
            if fatal_error:
                nfatal_errors = nfatal_errors + 1
            else:
                # It is a valid IP and there is an interface on this node with
                # this IP
                fatal_error, device_speed = check_NIC_speed(
                    net_interface, min_link_speed)
                outputfile_dict['netdev_speed_error'] = fatal_error
                outputfile_dict['netdev_speed'] = device_speed
                if fatal_error:
                    nfatal_errors = nfatal_errors + 1
        else:
            print(
                ERROR +
                LOCAL_HOSTNAME +
                " " +
                ip_address +
                " is not a valid IP address")
            nfatal_errors = nfatal_errors + 1

    # Check sysctl
    if sysctl_check:
        fatal_error, sysctl_errors, sysctl_right, sysctl_wrong = check_sysctl(
            sysctl_dictionary)
        outputfile_dict['sysctl_right'] = sysctl_right
        outputfile_dict['sysctl_wrong'] = sysctl_wrong
        if fatal_error:
            nfatal_errors = nfatal_errors + 1
    else:
        sysctl_errors = 0

    if nfatal_errors > 0:
        outputfile_dict['ECE_node_ready'] = False
    else:
        outputfile_dict['ECE_node_ready'] = True

    # Save lspci output to JSON
    lspci_output = exec_cmd("lspci")
    outputfile_dict['lspci'] = lspci_output

    # Exit protocol
    DEVNULL.close()

    outputfile_name = path + ip_address + ".json"
    outputfile = open(outputfile_name, "w")
    end_time_date = datetime.datetime.now()
    outputfile_dict['end_time'] = str(end_time_date)
    outputfile_json = json.dumps(outputfile_dict)
    outputfile.write(outputfile_json)
    outputfile.close()

    if toolkit_run and nfatal_errors > 0:
        print_summary_toolkit(sysctl_errors)
    if toolkit_run is False:
        print_summary_standalone(
            nfatal_errors,
            sysctl_errors,
            outputfile_name,
            start_time_date,
            end_time_date,
            redhat_distribution_str,
            current_processor,
            num_sockets,
            core_count,
            mem_gb,
            num_dimms,
            empty_dimms,
            n_HDD_drives,
            n_SSD_drives,
            n_NVME_drives,
            device_speed,
            all_checks_on)


if __name__ == '__main__':
    main()
