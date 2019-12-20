import struct

packet_parse_diapasons = { # -14
    'Header length' : (0, 1),     # packet parsing will be define from type of ICMP
    'Explicit Congestion Notification' : (1, 2),
    'Total length' : (2, 4),
    'IP Identification' : (4, 6),
    'Fragment offset' : (6, 8),      # 'bBhHHBBHBBBBBBBBbbHHh'
    'Time to live' : (8, 9),
    'Protocol' : (9, 10),
    'Header checksum' : (10, 12),
    'Source' : (12, 16),
    'Destination' : (16, 20),  #IP
    'Header icmp' : (20, 28)        # ICMP 11 duplicate packet that was send to hop               Data in 0 is after Header to end -10(Padding)
                                                                                            #11 no Data    and  8 Data to end 
}


def packet_parse(packet):
    (header_length, explicit_congestion_notification, total_length0,
     total_length1, ip_identification0,
    ip_identification1, fragment_offset, time_to_live, protocol,
    header_checksum, source0, source1, source2, source3,
    destination0, destination1, destination2, destination3,
    type_icmp, code_icmp, icmp_header_checksum, identifier,
    sequence_number) = struct.unpack('BBBBBBHBBHBBBBBBBBbbHHh',
                                     packet[:28])     # header length is wrong
    return f'''
Header length: {header_length}                                                   
Explicit Congestion Notification: {explicit_congestion_notification}
Total length: {total_length0*16 + total_length1}
IP Identification: {ip_identification0*16 + ip_identification1}
Fragment offset: {fragment_offset}
Time to live: {time_to_live}
Protocol: {protocol}
Checksum ip: {header_checksum}
Source: {source0}.{source1}.{source2}.{source3}
Destination: {destination0}.{destination1}.{destination2}.{destination3}
Version icmp: {type_icmp}
Code icmp: {code_icmp}
Checksum icmp: {icmp_header_checksum}
Identifier: {identifier}
Sequence number: {sequence_number}
''', type_icmp                # need to data 


def get_damp_packet(packet):
    packet_length = len(packet)
    print_border = 0
    damp = ''
    while print_border < packet_length:
        numeric = hex(print_border)[2:]
        damp +='0'*(4 - len(numeric)) + numeric + '  '
        byte_str = ''
        ascii_str = ''
        for i in range(print_border, print_border + 16):
            temp = packet[i: i + 1].hex()
            byte_str += (temp or '  ') + ' '
            if temp == '0a':
                ascii_str += ' '
                continue
            if temp != '':
                ascii_str += chr(int(temp, 16))
        damp += byte_str + ' ' + ascii_str + '\n'
        print_border += 16
    return damp


def get_parse_result(result):
    recieve_pack = result[2][1]
    parse_result = ''
    recieve_pack_parse = packet_parse(recieve_pack)
    if recieve_pack_parse[1] == 11:
        send_pack = result[2][1][28:48] + result[2][0]
        parse_result += f'''
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

{get_damp_packet(send_pack)}{packet_parse(send_pack)[0]}
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
'''
    parse_result += f'''
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

{get_damp_packet(recieve_pack)}{recieve_pack_parse[0]}
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
'''
    return parse_result