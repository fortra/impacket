import argparse
import getpass
import sys

from impacket.acl import Permissions
from impacket.examples.utils import parse_target


def main():
    parser = argparse.ArgumentParser( add_help=True,
                                      description="Utility for view and set windows file acls. It allows you to add or "
                                                  "delete permissions to user or group. much like the Windows icacls "
                                                  "binary or like the samba smbcacls." )

    parser.add_argument( 'target', action='store', help='[[domain/]username[:password]@]<targetName>' )
    parser.add_argument( '-target-ip', action='store', metavar="ip address",
                         help='IP Address of the target host you want to attack. If omitted it will use the targetName '
                              'parameter' )

    parser.add_argument( '-share', action='store', help='share name to connect to', default=None )
    parser.add_argument( '-file-path', action='store', help='file path to view / change permissions', required=True )

    parser.add_argument( '-target-user', action='store', help='target user to change permission for (empty for view)',
                         default=None )
    parser.add_argument( '-permissions', action='store', help='permissions to change in the format of <permission '
                                                               'char>,<permission char>. example: R,W (empty for view)',
                         default=None )

    if len( sys.argv ) == 1:
        parser.print_help()
        print("\nExample:")

        print("\tThis will view the permissions of the file MyFile.txt in the share MyShare")
        print("\tpython smbcacls.py -share MyShare -file-path MyFile.txt domain.net/user:mypwd@domain-host\n")

        print("\tThis will add read, write and execute permissions to the user Guest")
        print("\tpython smbcacls.py -share MyShare -file-path MyFile.txt -target-user Guest -permissions R,W,X domain.net/user:mypwd@domain-host\n")

        print("\tThis will remove all permissions to the user Guest")
        print("\tpython smbcacls.py -share MyShare -file-path MyFile.txt -target-user Guest domain.net/user:mypwd@domain-host\n")

    options = parser.parse_args()
    domain, username, password, address = parse_target( options.target )

    if domain is None:
        domain = '.WORKGROUP'

    # interactive typing
    if password is None:
        password = getpass.getpass()

    if options.target_ip:
        target_ip = options.target_ip
    else:
        target_ip = address

    permission = Permissions( target_ip, address, username, password, domain )

    # set operation
    if options.target_user:
        permission.set_permissions( options.share, options.file_path, options.target_user, options.permissions )
        print( 'Successfully processed {}'.format( options.file_path ) )
    # get operation
    else:
        print( permission.get_permissions( options.share, options.file_path ) )


if __name__ == '__main__':
    main()
