# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
import array

from ImpactPacket import Header, ImpactPacketException, PacketBuffer

class IP6_Extension_Header(Header):
# --------------------------------- - - - - - - -
# | Next Header | Header Ext Len | Options
# --------------------------------- - - - - - - -

    HEADER_TYPE_VALUE = -1
    EXTENSION_HEADER_FIELDS_SIZE = 2
    
    EXTENSION_HEADER_DECODER = None

    def __init__(self, buffer = None):
        Header.__init__(self, self.get_headers_field_size())
        self._option_list = []
        if buffer:
            self.load_header(buffer)
        else:
            self.reset()

    def __str__(self):
        header_type = self.get_header_type()
        next_header_value = self.get_next_header()
        header_ext_length = self.get_header_extension_length()

        s  = "Header Extension Name: " + self.__class__.HEADER_EXTENSION_DESCRIPTION + "\n"
        s += "Header Type Value: " + str(header_type) + "\n"
        s += "Next Header: " + str(next_header_value) + "\n"
        s += "Header Extension Length: " + str(header_ext_length) + "\n"
        s += "Options:\n"
        
        for option in self._option_list:
            option_str = str(option)
            option_str = option_str.split('\n')
            option_str = map(lambda s: (' ' * 4) + s, option_str)
            s += '\n'.join(option_str) + '\n'
        
        return s

    def load_header(self, buffer):
        self.set_bytes_from_string(buffer[:self.get_headers_field_size()])
        
        remaining_bytes = (self.get_header_extension_length() + 1) * 8
        remaining_bytes -= self.get_headers_field_size()

        buffer = array.array('B', buffer[self.get_headers_field_size():])
        if remaining_bytes > len(buffer):
            raise ImpactPacketException, "Cannot load options from truncated packet"

        while remaining_bytes > 0:
            option_type = buffer[0]
            if option_type == Option_PAD1.OPTION_TYPE_VALUE:
                # Pad1
                self._option_list.append(Option_PAD1())
                
                remaining_bytes -= 1
                buffer = buffer[1:]
            else:
                # PadN
                # From RFC 2460: For N octets of padding, the Opt Data Len
                # field contains the value N-2, and the Option Data consists
                # of N-2 zero-valued octets.
                option_length = buffer[1]
                option_length += 2
                
                self._option_list.append(Option_PADN(option_length))

                remaining_bytes -= option_length
                buffer = buffer[option_length:]
    
    def reset(self):
        pass

    @classmethod
    def get_header_type_value(cls):
        return cls.HEADER_TYPE_VALUE
    
    @classmethod
    def get_extension_headers(cls):
        header_types = {}
        for subclass in cls.__subclasses__():
            subclass_header_types = subclass.get_extension_headers()
            if not subclass_header_types:
                # If the subclass did not return anything it means
                # that it is a leaf subclass, so we take its header
                # type value
                header_types[subclass.get_header_type_value()] = subclass
            else:
                # Else we extend the list of the obtained types
                header_types.update(subclass_header_types)
        return header_types
    
    @classmethod
    def get_decoder(cls):
        raise RuntimeError("Class method %s.get_decoder must be overridden." % cls)

    def get_header_type(self):
        return self.__class__.get_header_type_value()

    def get_headers_field_size(self):
        return IP6_Extension_Header.EXTENSION_HEADER_FIELDS_SIZE

    def get_header_size(self):
        header_size = self.get_headers_field_size()
        for option in self._option_list:
            header_size += option.get_len()
        return header_size

    def get_next_header(self):
        return self.get_byte(0)

    def get_header_extension_length(self):
        return self.get_byte(1)

    def set_next_header(self, next_header):
        self.set_byte(0, next_header & 0xFF)

    def set_header_extension_length(self, header_extension_length):
        self.set_byte(1, header_extension_length & 0xFF)
    
    def add_option(self, option):
        self._option_list.append(option)
    
    def get_options(self):
        return self._option_list

    def get_packet(self):
        data = self.get_data_as_string()

        # Update the header length
        self.set_header_extension_length(self.get_header_size() / 8 - 1)

        # Build the entire extension header packet
        header_bytes = self.get_buffer_as_string()
        for option in self._option_list:
            header_bytes += option.get_buffer_as_string()
        
        if data:
            return header_bytes + data
        else:
            return header_bytes

    def contains(self, aHeader):
        Header.contains(self, aHeader)
        if isinstance(aHeader, IP6_Extension_Header):
            self.set_next_header(aHeader.get_header_type())
    
    def get_pseudo_header(self):
        # The pseudo-header only contains data from the IPv6 header.
        # So we pass the message to the parent until it reaches it.
        return self.parent().get_pseudo_header()

class Extension_Option(PacketBuffer):
    MAX_OPTION_LEN  = 256
    OPTION_TYPE_VALUE = -1

    def __init__(self, option_type, size):
        if size > Extension_Option.MAX_OPTION_LEN:
            raise ImpactPacketException, "Option size of % is greater than the maximum of %d" % (size, Extension_Option.MAX_OPTION_LEN)
        PacketBuffer.__init__(self, size)
        self.set_option_type(option_type)

    def __str__(self):
        option_type = self.get_option_type()
        option_length = self.get_option_length()

        s  = "Option Name: " + str(self.__class__.OPTION_DESCRIPTION) + "\n"
        s += "Option Type: " + str(option_type) + "\n"
        s += "Option Length: " + str(option_length) + "\n"
        
        return s

    def set_option_type(self, option_type):
        self.set_byte(0, option_type)

    def get_option_type(self):
        return self.get_byte(0)

    def set_option_length(self, length):
        self.set_byte(1, length)

    def get_option_length(self):
        return self.get_byte(1)

    def set_data(self, data):
        self.set_option_length(len(data))
        option_bytes = self.get_bytes()
        
        option_bytes = self.get_bytes()
        option_bytes[2:2+len(data)] = array.array('B', data)
        self.set_bytes(option_bytes)

    def get_len(self):
        return len(self.get_bytes())

class Option_PAD1(Extension_Option):
    OPTION_TYPE_VALUE = 0x00   # Pad1 (RFC 2460)
    OPTION_DESCRIPTION = "Pad1 Option"

    def __init__(self):
        Extension_Option.__init__(self, Option_PAD1.OPTION_TYPE_VALUE, 1)

    def get_len(self):
        return 1

class Option_PADN(Extension_Option):
    OPTION_TYPE_VALUE = 0x01   # Pad1 (RFC 2460)
    OPTION_DESCRIPTION = "PadN Option"

    def __init__(self, padding_size):
        if padding_size < 2:
            raise ImpactPacketException, "PadN Extension Option must be greater than 2 bytes"

        Extension_Option.__init__(self, Option_PADN.OPTION_TYPE_VALUE, padding_size)
        self.set_data('\x00' * (padding_size - 2))

class Basic_Extension_Header(IP6_Extension_Header):
    MAX_OPTIONS_LEN = 256 * 8
    MIN_HEADER_LEN  = 8
    MAX_HEADER_LEN  = MIN_HEADER_LEN + MAX_OPTIONS_LEN

    def __init__(self, buffer = None):
        self.padded = False
        IP6_Extension_Header.__init__(self, buffer)

    def reset(self):
        self.set_next_header(0)
        self.set_header_extension_length(0)
        self.add_padding()

    def add_option(self, option):
        if self.padded:
            self._option_list.pop()
            self.padded = False

        IP6_Extension_Header.add_option(self, option)

        self.add_padding()
        
    def add_padding(self):
        required_octets = 8 - (self.get_header_size() % 8)
        if self.get_header_size() + required_octets > Basic_Extension_Header.MAX_HEADER_LEN:
            raise Exception("Not enough space for the padding")

        # Insert Pad1 or PadN to fill the necessary octets
        if 0 < required_octets < 8:
            if required_octets == 1:
                self.add_option(Option_PAD1())
            else:
                self.add_option(Option_PADN(required_octets))
            self.padded = True
        else:
            self.padded = False

class Hop_By_Hop(Basic_Extension_Header):
    HEADER_TYPE_VALUE = 0x00
    HEADER_EXTENSION_DESCRIPTION = "Hop By Hop Options"
    
    @classmethod
    def get_decoder(self):
        import ImpactDecoder
        return ImpactDecoder.HopByHopDecoder

class Destination_Options(Basic_Extension_Header):
    HEADER_TYPE_VALUE = 0x3c
    HEADER_EXTENSION_DESCRIPTION = "Destination Options"
    
    @classmethod
    def get_decoder(self):
        import ImpactDecoder
        return ImpactDecoder.DestinationOptionsDecoder

class Routing_Options(IP6_Extension_Header):
    HEADER_TYPE_VALUE = 0x2b
    HEADER_EXTENSION_DESCRIPTION = "Routing Options"
    ROUTING_OPTIONS_HEADER_FIELDS_SIZE = 8
    
    def reset(self):
        self.set_next_header(0)
        self.set_header_extension_length(0)
        self.set_routing_type(0)
        self.set_segments_left(0)

    def __str__(self):
        header_type = self.get_header_type()
        next_header_value = self.get_next_header()
        header_ext_length = self.get_header_extension_length()
        routing_type = self.get_routing_type()
        segments_left = self.get_segments_left()

        s  = "Header Extension Name: " + self.__class__.HEADER_EXTENSION_DESCRIPTION + "\n"
        s += "Header Type Value: " + str(header_type) + "\n"
        s += "Next Header: " + str(next_header_value) + "\n"
        s += "Header Extension Length: " + str(header_ext_length) + "\n"
        s += "Routing Type: " + str(routing_type) + "\n"
        s += "Segments Left: " + str(segments_left) + "\n"

        return s
        
    @classmethod
    def get_decoder(self):
        import ImpactDecoder
        return ImpactDecoder.RoutingOptionsDecoder

    def get_headers_field_size(self):
        return Routing_Options.ROUTING_OPTIONS_HEADER_FIELDS_SIZE

    def set_routing_type(self, routing_type):
        self.set_byte(2, routing_type)

    def get_routing_type(self):
        return self.get_byte(2)

    def set_segments_left(self, segments_left):
        self.set_byte(3, segments_left)

    def get_segments_left(self):
        return self.get_byte(3)
