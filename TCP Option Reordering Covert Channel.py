from scapy.all import *

"""
Secret Message

undr brdge@925p
01110101 01101110 01100100 01110010 00100000 01100010 01110010 01100100 01100111 01100101 01000000 00111001 00110010 00110101 01110000 
"""



def encoding_algorithm(msg):
    """
    Produces an array of arrays, of manipulated arrangement of TCP options for DNS keep-alive
    packets between a DNS server and client on port 53. Uses specific pre-defined options and
    port range. soon to have a port management feature.

    params:
    ------
    msg : String, secret message to be encoded

    returns:
    --------
    manipulated_options : list, several lists of 6 containing custom arrangements encoding a binary message
    """
    
    options = {'a00':"MSS NOP", 'a01':"NOP SACK", 'a02':"NOP Wscale",
               'a10':"NOP NSS", 'a11':"SACK NOP", 'a12':"Wscale NOP"}

    manipulated_options = list()
    
    bits = ""
    for char in msg:
        bits += bin(ord(char))[2:].zfill(8)

    # iterate over a set of each 3 bits of the message
    for i in range(0, len(bits), 3):
        bitset = bits[i:i+3]

      
        # iterate over each individual bit in the set
        order = 0
        
        for bit in bitset:
            manipulated_options.extend(tuple(options['a'+bit+str(order)].split())) if bit == '0' else None
            manipulated_options.extend(tuple(options['a'+bit+str(order)].split())) if bit == '1' else None; order += 1;

    manipulated_options = [manipulated_options[i:i+6] for i in range(0, len(manipulated_options), 6)]

    print(manipulated_options)
    return manipulated_options
            

#encoding_algorithm("undr brdge@925p")
encoding_algorithm("FF")

def test1():
    # Create a TCP options object with desired options
    tcp_options = [("MSS", 1460), ("NOP", None), ("WScale", 2)]

    # Create the TCP layer with options
    tcp = TCP(sport=25565, dport=2556, flags="A", seq=1000, dataofs=8, options=tcp_options)

    """
    the offset field determines the size of the header, dataofs = 5 means 20 bytes which means options
    will be removed, thats why if the offset is 5 the options field will disapear
    """

    #tcp = TCP(sport=25565 , dport=25565, flags="A", seq=1000, dataofs=5, options=tcp_options)

    # Set the desired source and destination ports
    src_port = 12345
    dst_port = 12345

    # Create the IP packet with TCP layer
    ip = IP(src="192.168.1.109", dst="192.168.1.1")
    packet = ip / tcp


    # Display the packet summary
    packet.summary()
    send(packet)



def test2():
    


    #when we set the data offset value to 5 in the TCP header,
    #it means that the TCP header is 5 words long.

    #Since each word is 4 bytes, a data offset value of 5
    #corresponds to a TCP header size of 5 * 4 bytes, which
    #is 20 bytes. The first 20 bytes of a TCP segment will
    #be dedicated to the TCP header.

    # 20 to 60 bytes header size

    # Creating TCP header
    ip = IP(src="192.168.1.109", dst="192.168.1.100")

    # Create TCP header with initial options
    tcp_options = [("NOP", None), ("NOP", None), ("EOL", None)]
    tcp = TCP(sport=25565, dport=25565, flags="A", seq=1000, options=tcp_options)

    # Calculate the length of the TCP header and options
    tcp_header_length = len(tcp)
    tcp_options_length = sum([len(opt) for opt in tcp.options])

    # Calculate the number of padding bytes needed
    padding_bytes = 32 - tcp_header_length - tcp_options_length

    # Add padding bytes


    # Recalculate TCP checksum

    #tcp.options += b'\x00' * padding_bytes

    tcp.options += [('NOP', None)] * padding_bytes

    del tcp[TCP].chksum

    print(len(tcp))
    
    # Combine IP and TCP headers
    packet = ip / tcp

    # Show the packet details
    packet.show2(dump=True)
    packet.show()

    # Send the packet
    send(packet)
    
    

#test1()
#test2()


"""
TCP OPTION SIZES


End of Options (EOO): The EOO option does not carry any data and is only one byte in size.

No-Operation (NOP): The NOP option also does not carry any data and is one byte in size.

Maximum Segment Size (MSS): The MSS option typically consists of the option kind field (1 byte),
option length field (1 byte), and the MSS value (2 bytes). So, the total size is 4 bytes.

Window Scale: The Window Scale option consists of the option kind field (1 byte), option length
field (1 byte), and the scale factor value (1 byte). So, the total size is 3 bytes.

Selective Acknowledgment (SACK): The size of the SACK option can vary depending on the number of blocks
being acknowledged. Each block typically consists of a left edge pointer (4 bytes) and a right edge
pointer (4 bytes). The total size of the SACK option is variable based on the number of blocks.

Timestamps: The Timestamps option consists of the option kind field (1 byte), option length field
(1 byte), the sender's timestamp value (4 bytes), and the echo reply timestamp value (4 bytes).
So, the total size is 10 bytes.

#if bit == '0':
            
                #manipulated_options.extend(tuple(options['a'+bit+str(order)].split()))
                #order += 1
            
            #elif bit == '1':
           
                #manipulated_options.extend(tuple(options['a'+bit+str(order)].split()))
                #order += 1

"""






