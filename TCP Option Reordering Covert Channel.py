"""
                      _______ _____ _____     _____ _____  
                     |__   __/ ____|  __ \   / ____/ ____| 
                        | | | |    | |__) | | |   | |      
                        | | | |    |  ___/  | |   | |      
                        | | | |____| |      | |___| |____  
                        |_|  \_____|_|       \_____\_____| 
                                                           

Description: Transmission Control Protocol covert channel through reordering
             options in Domain Name Service keep alive tcp packets

@author: Rashed Alnuman
@Email : Rashed123numan@gmail.com
@Language : Python 3
"""


from scapy.all import *


"""
Secret Message

string: undr brdge@925p
binary: 011101010110111001100100011100100010000001100010011100100110010001100111011001010100000000111001001100100011010101110000 
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
"""






