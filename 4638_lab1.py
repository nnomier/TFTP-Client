# Don't forget to change this file's name before submission.
import sys
import os
import enum
import socket
import struct

class TftpProcessor(object):

    class TftpPacketType(enum.Enum):
    	RRQ = 1
    	WRQ = 2
    	DATA= 3
    	ACK = 4
    	ERROR = 5

    def __init__(self):
    	# self.packet_type =TftpPacketType()
    	self.received_packets=[]
    	self.packet_buffer = []
    	self.filepath=''
    	pass

    def process_udp_packet(self, packet_data, packet_source):
    	"""
    	Parse the input packet, execute your logic according to that packet.
    	packet data is a bytearray, packet source contains the address
    	information of the sender.
    	"""
    	# Add your logic here, after your logic is done,
    	# add the packet to be sent to self.packet_buffer
    	# feel free to remove this line
    	print(f"Received a packet from {packet_source}")
    	in_packet, block_number = self._parse_udp_packet(packet_data)
    	out_packet = self._do_some_logic(in_packet, block_number)

    	# This shouldn't change.
    	self.packet_buffer.append(out_packet)

    def _parse_udp_packet(self,packet_bytes):
    	type = struct.unpack('!b',packet_bytes[1:2])[0]
    	print( type )
    	if type == 3:
    		block_number = struct.unpack( '!h', packet_bytes[2:4])[0]
    		format_str = "!{}s".format( len(packet_bytes) - 4)
    		new_data = struct.unpack(format_str, packet_bytes[4::])[0]
    		received_packets.append(new_data)
    		print( new_data, 'block no ', block_number )
    		return self.TftpPacketType.DATA, block_number
    	elif type == 4:
    		block_number = struct.unpack( '!h', packet_bytes[2:4])[0]
    		return self.TftpPacketType.ACK, block_number
    	elif type == 5:
    		return self.TftpPacketType.ERROR,0




    def _do_some_logic(self, input_packet, block_number):
    	"""
    	hygilo eltype bt3 elpacket received
    	w b3den hy3ml elpacket elli elmafroud ttba3at
    	(data aw acknowledge 3ala 7asab elpacket elli wasalet)
    	w haraga3 elpacket dih b2a
    	"""
    	if input_packet == self.TftpPacketType.ACK:
    		return self._parse_file( block_number)
    	elif input_packet == self.TftpPacketType.DATA:
    	    return self._create_ack_packet( block_number)
    	elif input_packet == self.TftpPacketType.ERROR:
    		print('ana hena')
    		pass

    def get_next_output_packet(self):
    	"""
    	Returns the next packet that needs to be sent.
    	This function returns a byetarray representing
    	the next packet to be sent.
    	For example;
    	s_socket.send(tftp_processor.get_next_output_packet())
    	Leave this function as is.
    	"""
    	return self.packet_buffer.pop(0)

    def has_pending_packets_to_be_sent(self):
    	"""
    	Returns if any packets to be sent are available.
    	Leave this function as is.
    	"""
    	return len(self.packet_buffer) != 0

    def _process_chunk(self,chunk,block_no):
    	format_str = "!bbh{}s".format(len(chunk))
    	packet = struct.pack(format_str,0,self.TftpPacketType.DATA.value,block_no,chunk)
    	return packet

    def _create_ack_packet(self, block_no):
    	format_str = "!bbh"
    	packet = struct.pack(0, self.TftpPacketType.ACK, block_no)
    	return packet

    def _create_request_packet(self,type,file_name):
        format_str = "!bb{}sb5sb".format(
                len(file_name))
        packet = struct.pack( format_str,0,type.value,file_name.encode('utf-8'),0,'octet'.encode('utf-8'),0)
        return packet

    def _parse_file(self,block_no):
        chunk_len=512
        print("hello",self.filepath,"s")
        with open(self.filepath,'rb') as file:
            file.seek( block_no * 512)
            chunk=file.read(chunk_len)
            if not chunk:
                print("here i am ")
                return -1
            packet_chunk=self._process_chunk(chunk, block_no+1)
        return packet_chunk

    def upload_file(self, file_path_on_server):
        self.filepath=file_path_on_server
        packet=self._create_request_packet(self.TftpPacketType.WRQ,file_path_on_server)
        self.packet_buffer.append(packet)
        pass

    def request_file(self, file_path_on_server):
        self.filepath=file_path_on_server
        packet=self._create_request_packet(self.TftpPacketType.RRQ,file_path_on_server)
        self.packet_buffer.append(packet)
        pass


def check_file_name():
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
    	print(f"[WARN] File name is invalid [{script_name}]")
    pass


def setup_sockets(address):

    pass

def do_socket_logic():

    pass


def socket_connection( server_address, client_socket, file_name,processor):
    i=1
    while True:
        print("i",i)
        i+=1
        if processor.has_pending_packets_to_be_sent():
            packet = processor.get_next_output_packet()
            print("packet",packet)
            client_socket.sendto( packet, (server_address, 69))
            input_packet, input_address = client_socket.recvfrom(516)
            print( input_packet)
            processor.process_udp_packet( input_packet, input_address)
        else :
            break

def parse_user_input(address, operation, file_name=None):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    processor = TftpProcessor()
    if operation == "push":
    	processor.upload_file( file_name )
    	pass
    elif operation == "pull":
    	processor.request_file( file_name )
    	print(f"Attempting to download [{file_name}]...")
    	pass
    socket_connection( address, client_socket, file_name, processor)




def get_arg(param_index, default=None):
    """
    Gets a command line argument by index (note: index starts from 1)
    If the argument is not supplies, it tries to use a default value.
    If a default value isn't supplied, an error message is printed
    and terminates the program.
    """
    try:
    	return sys.argv[param_index]
    except IndexError as e:
    	if default:
    		return default
    	else:
    		print(e)
    		print(
    		    f"[FATAL] The comamnd-line argument #[{param_index}] is missing")
    		exit(-1)    # Program execution failed.


def main():
    """
    Write your code above this function.
    if you need the command line arguments
    """
    print("*" * 50)
    print("[LOG] Printing command line arguments\n", ",".join(sys.argv))
    check_file_name()
    print("*" * 50)

    # This argument is required.
    # For a server, this means the IP that the server socket
    # will use.
    # The IP of the server, some default values
    # are provided. Feel free to modify them.
    ip_address = get_arg(1, "127.0.0.1")
    operation = get_arg(2, "pull")
    file_name = get_arg(3, "test.txt")

    # Modify this as needed.
    parse_user_input(ip_address, operation, file_name)


if __name__ == "__main__":
    main()
