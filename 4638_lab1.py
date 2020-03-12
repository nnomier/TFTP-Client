# Don't forget to change this file's name before submission.
import sys
import os
import enum
import socket

class TftpProcessor(object):

    class TftpPacketType(enum.Enum):
        """
        Represents a TFTP packet type add the missing types here and
        modify the existing values as necessary.
        """
        RRQ = 1
        WRQ = 2
        DATA= 3
        ACK = 4
        ERROR = 5

    def __init__(self):
        self.received_packets=[]
        self.packet_buffer = []
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
        in_packet = self._parse_udp_packet(packet_data)
        out_packet = self._do_some_logic(in_packet)

        # This shouldn't change.
        self.packet_buffer.append(out_packet)

    def _parse_udp_packet(self, packet_bytes):
        """
        You'll use the struct module here to determine
        the type of the packet and extract other available
        information.
        returns type
        w ht3ml ay 7aga mohema l ba2it elpacket
        masaln hasave eldata elli gat
        """
        pass

    def _do_some_logic(self, input_packet):
        """
        hygilo eltype bt3 elpacket received
        w b3den hy3ml elpacket elli elmafroud ttba3at
        (data aw acknowledge 3ala 7asab elpacket elli wasalet)
        w haraga3 elpacket dih b2a
        """
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

    def _process_chunk(chunk,number):
        format_str = "!bbh{}s".format(
                    len(chunk))
        packet = struct.pack(format_str,0,DATA,number,chunk)
        return packet

    def _create_request_packet(type,file_name):
        format_str = "!bb{}sb5sb".format(
                    len(file_name))
        packet = struct.pack(0,type,file_name,0,'octet',0)
        return packet

    def _parse_file(self,file_path):
        chunk_len=512
        i=1
        with open(file_path,'rb') as file:
            while True:
                chunk=file.read(chunk_len)
                if not chunk: break
                """ check if we should convert to bytes"""
                packet_chunk=process_chunk(chunk,i)
                self.packet_buffer.append(packet)
                i++

    def upload_file(self, file_path_on_server):
        
        pass

    def request_file(self, file_path_on_server):
        """
        This method is only valid if you're implementing
        a TFTP client, since the client requests or uploads
        a file to/from a server, one of the inputs the client
        accept is the file name. Remove this function if you're
        implementing a server.
        """
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


def parse_user_input(address, operation, file_name=None):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = ("127.0.0.1", 69)

    if operation == "push":
        """
         send wrq packet
         wait for ack and make sure it's valid
         if error terminate , if ack is recieved
         start sending packet and wait for acknoledge
        """
        pass
    elif operation == "pull":
        r_bytes = bytearray([0, 1, 97, 46, 116, 120, 116, 0, 111, 99, 116, 101, 116, 0])
        client_socket.sendto(r_bytes, ("127.0.0.1", 69))
        print(f"Attempting to download [{file_name}]...")
        pass


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
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = (ip_address, 69)
    print(operation)
    # Modify this as needed.
    parse_user_input(ip_address, operation, file_name)


if __name__ == "__main__":
    main()
