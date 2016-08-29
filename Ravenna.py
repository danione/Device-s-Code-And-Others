#! /usr/bin/python3
# Program for the device
# Started August
# Yordan
import subprocess
import os
import time
import csv
import signal
    # AP & Associated client=>
    # AP - BSSID, ESSID, PWR, ENC, CIPHER, AUTH
    # Associated client - Connected BSSID, STATION
class AccessPoint():
    """AccessPoint"""
    def __init__(self,BSSID, ESSID, PWR, ENC, CIPHER, AUTH):
        self.BSSID = BSSID
        self.ESSID = ESSID
        self.PWR = PWR
        self.ENC = ENC
        self.CIPHER = CIPHER
        self.AUTH = AUTH

    def get_BSSID(self):
        return self.BSSID

    def get_ESSID(self):
        return self.ESSID

    def get_ENC(self):
        return self.ENC

    def get_PWR(self):
        return self.PWR

class AssociatedClient():
    """AssociatedClient"""

    def __init__(self, CONNECTED_BSSID, STATION):
        self.CONNECTED_BSSID = CONNECTED_BSSID
        self.STATION = STATION

    def get_Connected_BSSID(self):
        return self.CONNECTED_BSSID

    def get_Station(self):
        return self.STATION

#Used to create and manage a subprocess command
def subprocess_command(command):
    command_process = subprocess.Popen(command,stdout=subprocess.PIPE, shell=True)
    output = command_process.communicate()[0].strip()
    return output.decode("utf-8")

#Used for shutting down the monitor mode when done
def shutting_down_monitor_mode(name):
    print("Shutting down monitor mode...")
    subprocess_command('airmon-ng stop ' + name)
    print("Goodbye, little fellow...")
    return

#We need the range to be closer
def check_range(power):
    return abs(power) <= 60

def csv_parser(file_pos):

    ap = []
    assoc_clients = []
    is_ap = False
    place = 0

    with open(file_pos, 'r') as csvfile:
        liner = csv.reader(csvfile, delimiter=',')
        for line in liner:
            if len(line) < 1:
                continue
            if line[0].strip() == 'BSSID':
                is_ap = True
                continue
            if line[0].strip() == 'Station MAC':
                place = 0
                is_ap = False
                continue
            if is_ap:
                accessP = AccessPoint(line[0].strip(),
                                      line[13].strip(),
                                      line[8].strip(),
                                      line[5].strip(),
                                      line[6].strip(),
                                      line[7].strip())
                if int(line[4].strip()) != -1:

                    if abs(int(accessP.get_PWR())) < 60:
                        if accessP.get_ENC() != 'OPN' or accessP.get_ENC() != '':
                            ap.append(accessP)
            else:
                assoc_cl = AssociatedClient(line[5].strip(),line[0].strip())
                assoc_clients.append(assoc_cl)

    return (ap, assoc_clients)


def airodump(monitor_mode, file_directory):
        process = subprocess.Popen('airodump-ng -a -w '+file_directory+'raven --output-format csv '+monitor_mode, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, preexec_fn=os.setsid)

        time.sleep(7)

        try:
            os.kill(process.pid, signal.SIGTERM)
        except OSError:
            pass
        except UnboundLocalError:
            pass

        (ap, assoc_clients) = csv_parser(file_directory + 'raven-01.csv')

        print("Stopped scanning, please wait while gathering information ...")

        is_WEP = False

        for point in ap:
            filtered_clients = []
            for client in assoc_clients:
                if point.get_ENC() == 'WEP':
                    is_WEP = True
                else:
                    if point.get_BSSID() == client.get_Connected_BSSID():
                        filtered_clients.append(client)
            if is_WEP:
                print("Algorithm for WEP")
            else:
                if not filtered_clients:
                    print("Cannot run the attack - no clients on the run")
                    return
                else:
                    print("Algorithm for WPA")
                    
            is_WEP = False


def checking_dir(directory):
    if not os.path.exists(directory):
        print("Creating dir...")
        os.makedirs(directory)
    else:
        print("You have one...")
    return directory

try:

    CWD = os.getcwd()
    #First stage - getting the name of the wlan card
    print ("Configuring your wlan card name... Please wait")
    wlan_name = subprocess_command('iwconfig 2>&1 | grep IEEE | awk \'{print $1}\'')
    print("Your wlan card name is " + wlan_name)

    #Second stage - setting it into monitor mode
    print("Setting up your device...")
    subprocess_command('ifconfig ' + wlan_name + ' up')
    print("All set up, now we will continue into monitor mode...")
    monitor_mode_wlan = subprocess_command('airmon-ng start ' + wlan_name + ' | grep \'monitor mode\' | cut -d \']\' -f 3 | cut -d \')\' -f 1')
    print("Monitor mode successfully put up - " + monitor_mode_wlan)

    #third stage - checking for directory and scanning
    print("Checking for existing directory...")

    file_directory = checking_dir(CWD + '/raven/')

    if  os.listdir(file_directory):
        subprocess_command('rm -rf ' + file_directory + 'raven*')

    print("Starting scanning...")
    airodump(monitor_mode_wlan,file_directory)

    shutting_down_monitor_mode(monitor_mode_wlan)
except KeyboardInterrupt:
    shutting_down_monitor_mode(monitor_mode_wlan)
