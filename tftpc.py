'''
$ tftp ip_address [-p port_mumber] <get|put> filename
'''

import socket
import argparse
import sys
#import validators
from struct import pack

DEFAULT_PORT = 69
BLOCK_SIZE = 512
DEFAULT_TRANSFER_MODE = 'netascii'

OPCODE = {'RRQ': 1, 'WRQ': 2, 'DATA': 3, 'ACK': 4, 'ERROR': 5}
MODE = {'netascii': 1,'octet': 2, 'mail': 3}

ERROR_CODE = {
    0: "Not defined, see error message (if any).",
    1: "File not found.",
    2: "Access violation.",
    3: "Disk full or allocation exceeded.",
    4: "Illegal TFTP operation.",
    5: "Unknown transfer ID.",
    6: "File already exists.",
    7: "No such user."
}

def send_wrq(filename, mode):
    format = f'>h{len(filename)}sB{len(mode)}sB'
    wrq_message = pack(format, OPCODE['WRQ'], bytes(filename, 'utf-8'), 0, bytes(mode, 'utf-8'), 0)
    sock.sendto(wrq_message, server_address)

def send_rrq(filename, mode):
    format = f'>h{len(filename)}sB{len(mode)}sB'
    rrq_message = pack(format, OPCODE['RRQ'], bytes(filename, 'utf-8'), 0, bytes(mode, 'utf-8'), 0)
    sock.sendto(rrq_message, server_address)
    #print(rrq_message)

def send_ack(seq_num, server):
    format = f'>hh'
    #print(seq_num)
    ack_message = pack(format, OPCODE['ACK'], seq_num)
    #print(ack_message)
    sock.sendto(ack_message, server)

def send_data(seq_num, server,data):
    format = f'>hh{len(data)}s'
    #print(seq_num)
    data_message = pack(format, OPCODE['DATA'], seq_num,data)
    #print(ack_message)
    sock.sendto(data_message, server)

def receivefile():
    # Open a file with the same name to save data  from server
    file = open(filename, "wb")
    seq_number = 0

    while True:

        # receive data from the server
        data, server = sock.recvfrom(516)
        # server uses a newly assigned port(not 69)to transfer data
        # so ACK should be sent to the new socket
        opcode = int.from_bytes(data[:2], 'big')

        # check message type
        if opcode == OPCODE['DATA']:
            seq_number = int.from_bytes(data[2:4], 'big')
            send_ack(seq_number, server)

        elif opcode == OPCODE['ERROR']:
            error_code = int.from_bytes(data[2:4], byteorder='big')
            print(ERROR_CODE[error_code])
            break
        else:
            break

        file_block = data[4:]
        print(file_block.decode())
        file.write(file_block)

        if len(file_block) < BLOCK_SIZE:
            print(len(file_block))
            file.close()
            break


def sendfile():
    try:
        file = open(filename, "rb")
        while True:
            data, server = sock.recvfrom(516)
            opcode = int.from_bytes(data[:2], 'big')
            line=file.read(512);
            if opcode == OPCODE['ACK']:
                seq_number = int.from_bytes(data[2:4], 'big')+1
                send_data(seq_number, server,line)
            if line==b'':
                break

        file.close()
    except FileNotFoundError:
        print("File not found.")
        sys.exit(1)

#203.250.133.88 get cat.txt

# parse command line arguments
parser = argparse.ArgumentParser(description='TFTP client program')
parser.add_argument(dest="host", help="Server IP address", type=str)
parser.add_argument(dest="action", help="get or put a file", type=str)
parser.add_argument(dest="filename", help="name of file to transfer", type=str)
parser.add_argument("-p", "--port", dest="port", action="store", type=int)
args = parser.parse_args()

'''
if validators.domain(args.host):
    serber_ip = gethostbyname(args.host) 
elif validators.ip_address.ipv4(args.host)
    server_ip = args.host
else:
    print("Invalid host address")
    exit(0)
        
if args.port == None:
    server_port = DEFAULT_PORT
else 
    server_port == args_port
'''

# Create a UDP socket
server_ip = args.host
server_port = DEFAULT_PORT
if args.port == None:
    server_port = DEFAULT_PORT
else :
    server_port == args.port
server_address = (server_ip, server_port)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Send RRQ_message
mode = DEFAULT_TRANSFER_MODE
filename = args.filename

if args.action =='get':
    send_rrq(filename, mode)
    receivefile()

elif args.action=='put':
    send_wrq(filename, mode)
    sendfile()
sock.close()
