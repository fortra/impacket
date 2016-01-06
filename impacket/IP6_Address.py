# Copyright (c) 2003-2016 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#

import array

class IP6_Address():
    ADDRESS_BYTE_SIZE = 16
    #A Hex Group is a 16-bit unit of the address
    TOTAL_HEX_GROUPS = 8
    HEX_GROUP_SIZE = 4 #Size in characters
    TOTAL_SEPARATORS = TOTAL_HEX_GROUPS - 1
    ADDRESS_TEXT_SIZE = (TOTAL_HEX_GROUPS * HEX_GROUP_SIZE) + TOTAL_SEPARATORS
    SEPARATOR = ":"
    SCOPE_SEPARATOR = "%"
    
#############################################################################################################
# Constructor and construction helpers

    def __init__(self, address):
        #The internal representation of an IP6 address is a 16-byte array
        self.__bytes = array.array('B', '\0' * self.ADDRESS_BYTE_SIZE)
        self.__scope_id = ""
        
        #Invoke a constructor based on the type of the argument
        if type(address) is str or type(address) is unicode:
            self.__from_string(address)
        else:
            self.__from_bytes(address)

                                
    def __from_string(self, address):
        #Separate the Scope ID, if present
        if self.__is_a_scoped_address(address):
            split_parts = address.split(self.SCOPE_SEPARATOR)
            address = split_parts[0]
            if (split_parts[1] == ""):
                raise Exception("Empty scope ID")
            self.__scope_id = split_parts[1]
        
        #Expand address if it's in compressed form
        if self.__is_address_in_compressed_form(address):
            address = self.__expand_compressed_address(address)
            
        #Insert leading zeroes where needed        
        address = self.__insert_leading_zeroes(address)
        
        #Sanity check
        if len(address) != self.ADDRESS_TEXT_SIZE:
            raise Exception('IP6_Address - from_string - address size != ' + str(self.ADDRESS_TEXT_SIZE))
    
        #Split address into hex groups
        hex_groups = address.split(self.SEPARATOR)
        if len(hex_groups) != self.TOTAL_HEX_GROUPS:
            raise Exception('IP6_Address - parsed hex groups != ' + str(self.TOTAL_HEX_GROUPS))

        #For each hex group, convert it into integer words
        offset = 0
        for group in hex_groups:
            if len(group) != self.HEX_GROUP_SIZE:
                raise Exception('IP6_Address - parsed hex group length != ' + str(self.HEX_GROUP_SIZE))
            
            group_as_int = int(group, 16)
            self.__bytes[offset]     = (group_as_int & 0xFF00) >> 8
            self.__bytes[offset + 1] = (group_as_int & 0x00FF) 
            offset += 2            

    def __from_bytes(self, bytes):
        if len(bytes) != self.ADDRESS_BYTE_SIZE:
            raise Exception ("IP6_Address - from_bytes - array size != " + str(self.ADDRESS_BYTE_SIZE))
        self.__bytes = bytes

#############################################################################################################
# Projectors
    def as_string(self, compress_address = True, scoped_address = True):
        s = ""
        for i, v in enumerate(self.__bytes):
            s += hex(v)[2:].rjust(2, '0')
            if (i % 2 == 1):
                s += self.SEPARATOR
        s = s[:-1].upper()
        
        if (compress_address):
            s = self.__trim_leading_zeroes(s)
            s = self.__trim_longest_zero_chain(s)
            
        if (scoped_address and self.get_scope_id() != ""):
            s += self.SCOPE_SEPARATOR + self.__scope_id
        return s
                
    def as_bytes(self):
        return self.__bytes
    
    def __str__(self):
        return self.as_string()
    
    def get_scope_id(self):
        return self.__scope_id
    
    def get_unscoped_address(self):
        return self.as_string(True, False) #Compressed address = True, Scoped address = False
        
#############################################################################################################
# Semantic helpers
    def is_multicast(self):
        return self.__bytes[0] == 0xFF
    
    def is_unicast(self):
        return self.__bytes[0] == 0xFE
    
    def is_link_local_unicast(self):
        return self.is_unicast() and (self.__bytes[1] & 0xC0 == 0x80)
    
    def is_site_local_unicast(self):
        return self.is_unicast() and (self.__bytes[1] & 0xC0 == 0xC0)
    
    def is_unique_local_unicast(self):
        return (self.__bytes[0] == 0xFD)
                
    
    def get_human_readable_address_type(self):
        if (self.is_multicast()):
            return "multicast"
        elif (self.is_unicast()):
            if (self.is_link_local_unicast()):
                return "link-local unicast"
            elif (self.is_site_local_unicast()):
                return "site-local unicast"
            else:
                return "unicast"
        elif (self.is_unique_local_unicast()):
            return "unique-local unicast"
        else:
            return "unknown type"

#############################################################################################################
#Expansion helpers

    #Predicate - returns whether an address is in compressed form
    def __is_address_in_compressed_form(self, address):
        #Sanity check - triple colon detection (not detected by searches of double colon)        
        if address.count(self.SEPARATOR * 3) > 0:
            raise Exception('IP6_Address - found triple colon')
        
        #Count the double colon marker
        compression_marker_count = self.__count_compression_marker(address)        
        if compression_marker_count == 0:
            return False
        elif compression_marker_count == 1:
            return True
        else:
            raise Exception('IP6_Address - more than one compression marker (\"::\") found')
       
    #Returns how many hex groups are present, in a compressed address 
    def __count_compressed_groups(self, address):
        trimmed_address = address.replace(self.SEPARATOR * 2, self.SEPARATOR) #Replace "::" with ":"        
        return trimmed_address.count(self.SEPARATOR) + 1

    #Counts how many compression markers are present
    def __count_compression_marker(self, address):
        return address.count(self.SEPARATOR * 2) #Count occurrences of "::"

    #Inserts leading zeroes in every hex group
    def __insert_leading_zeroes(self, address):
        hex_groups = address.split(self.SEPARATOR)
        
        new_address = ""
        for hex_group in hex_groups:
            if len(hex_group) < 4:
                hex_group = hex_group.rjust(4, "0")
            new_address += hex_group + self.SEPARATOR
            
        return new_address[:-1] #Trim the last colon
            
            
    #Expands a compressed address
    def __expand_compressed_address(self, address):
        group_count = self.__count_compressed_groups(address)
        groups_to_insert = self.TOTAL_HEX_GROUPS - group_count
        
        pos = address.find(self.SEPARATOR * 2) + 1 
        while (groups_to_insert):
            address = address[:pos] + "0000" + self.SEPARATOR + address[pos:]
            pos += 5
            groups_to_insert -= 1

        #Replace the compression marker with a single colon            
        address = address.replace(self.SEPARATOR * 2, self.SEPARATOR)        
        return address


#############################################################################################################
#Compression helpers

    def __trim_longest_zero_chain(self, address):
        chain_size = 8
        
        while (chain_size > 0):
            groups = address.split(self.SEPARATOR)
            start_index = -1
            end_index = -1
                        
            for index, group in enumerate(groups):
                #Find the first zero
                if (group == "0"):                    
                    start_index = index
                    end_index = index
                    #Find the end of this chain of zeroes
                    while (end_index < 7 and groups[end_index + 1] == "0"):
                        end_index += 1
                        
                    #If the zero chain matches the current size, trim it
                    found_size = end_index - start_index + 1
                    if (found_size == chain_size):
                        address = self.SEPARATOR.join(groups[0:start_index]) + self.SEPARATOR * 2 + self.SEPARATOR.join(groups[(end_index+1):])
                        return address
                    
            #No chain of this size found, try with a lower size    
            chain_size -= 1
        return address

                                
    #Trims all leading zeroes from every hex group
    def __trim_leading_zeroes(self, str):
        groups = str.split(self.SEPARATOR)
        str = ""
        
        for group in groups:
            group = group.lstrip("0") + self.SEPARATOR
            if (group == self.SEPARATOR):
                group = "0" + self.SEPARATOR
            str += group
        return str[:-1]
                

#############################################################################################################
    @classmethod
    def is_a_valid_text_representation(cls, text_representation):
        try:
            #Capitalize on the constructor's ability to detect invalid text representations of an IP6 address            
            ip6_address = IP6_Address(text_representation)
            return True
        except Exception, e:
            return False
                
    def __is_a_scoped_address(self, text_representation):
        return text_representation.count(self.SCOPE_SEPARATOR) == 1
    
#############################################################################################################
# Informal tests
if __name__ == '__main__':
    print IP6_Address("A:B:C:D:E:F:1:2").as_string()
#    print IP6_Address("A:B:C:D:E:F:0:2").as_bytes()
    print IP6_Address("A:B:0:D:E:F:0:2").as_string()
#    print IP6_Address("A::BC:E:D").as_string(False)
    print IP6_Address("A::BC:E:D").as_string()
    print IP6_Address("A::BCD:EFFF:D").as_string()
    print IP6_Address("FE80:0000:0000:0000:020C:29FF:FE26:E251").as_string()

#    print IP6_Address("A::BCD:EFFF:D").as_bytes()
    print IP6_Address("::").as_string()
    print IP6_Address("1::").as_string()
    print IP6_Address("::2").as_string()
#    bin = [
#           0x01, 0x02, 0x03, 0x04,
#           0x01, 0x02, 0x03, 0x04,
#           0x01, 0x02, 0x03, 0x04,
#           0x01, 0x02, 0x03, 0x04]
#    a = IP6_Address(bin)
#    print a.as_string()
#    print a
    
#    Malformed addresses
#    print IP6_Address("ABCD:EFAB:1234:1234:1234:1234:1234:12345").as_string()
#    print IP6_Address(":::").as_string()
#    print IP6_Address("::::").as_string()
                    
