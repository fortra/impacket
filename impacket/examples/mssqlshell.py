#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies 
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   [MS-TDS] & [MC-SQLR] example.
#
# Author:
#   Alberto Solino (@agsolino)
#
# Reference for:
#   Structure
#

import os
import cmd
import sys

# for "do_upload"
import hashlib
import base64
import shlex
import json

class SQLSHELL(cmd.Cmd):
    def __init__(self, SQL, show_queries=False, tcpShell=None):
        if tcpShell is not None:
            cmd.Cmd.__init__(self, stdin=tcpShell.stdin, stdout=tcpShell.stdout)
            sys.stdout = tcpShell.stdout
            sys.stdin = tcpShell.stdin
            sys.stderr = tcpShell.stdout
            self.use_rawinput = False
            self.shell = tcpShell
        else:
            cmd.Cmd.__init__(self)
            self.shell = None

        self.sql = SQL
        self.show_queries = show_queries
        self.at = []
        self.crawled_servers = set()  # Track crawled servers to avoid loops
        self.discovered_paths = []  # Store all discovered link paths for automatic execution
        self.server_to_paths = {}  # Map server instance names to their paths
        self.set_prompt()
        self.intro = '[!] Press help for extra shell commands'

    def print_replies(self):
        # to condense all calls to sql.printReplies with right logger in this context
        self.sql.printReplies(error_logger=print, info_logger=print)

    def do_help(self, line):
        print("""
    lcd {path}                 - changes the current local directory to {path}
    exit                       - terminates the server process (and this session)
    enable_xp_cmdshell         - you know what it means
    disable_xp_cmdshell        - you know what it means
    enum_db                    - enum databases
    enum_links                 - enum linked servers
    enum_impersonate           - check logins that can be impersonated
    enum_logins                - enum login users
    enum_users                 - enum current db users
    enum_owner                 - enum db owner
    exec_as_user {user}        - impersonate with execute as user
    exec_as_login {login}      - impersonate with execute as login
    xp_cmdshell {cmd}          - executes cmd using xp_cmdshell
    xp_dirtree {path}          - executes xp_dirtree on the path
    sp_start_job {cmd}         - executes cmd using the sql server agent (blind)
    use_link {link}            - linked server to use (set use_link localhost to go back to local or use_link .. to get back one step)
    crawl_links                - recursively crawl all linked servers and display their info
    query_link [path|server] {query}  - execute query through all discovered paths, specific path, or server instance
    xp_cmdshell_link [path|server] {cmd} - execute xp_cmdshell through all discovered paths, specific path, or server instance
    ! {cmd}                    - executes a local shell cmd
    upload {from} {to}         - uploads file {from} to the SQLServer host {to}
    download {from} {to}       - downloads file from the SQLServer host {from} to {to}
    show_query                 - show query
    mask_query                 - mask query
    """)

    def postcmd(self, stop, line):
        self.set_prompt()
        return stop

    def set_prompt(self):
        try:
            row = self.sql_query('select system_user + SPACE(2) + current_user as "username"', False)
            username_prompt = row[0]['username']
        except:
            username_prompt = '-'
        if self.at is not None and len(self.at) > 0:
            at_prompt = ''
            for (at, prefix) in self.at:
                at_prompt += '>' + at
            self.prompt = 'SQL %s (%s@%s)> ' % (at_prompt, username_prompt, self.sql.currentDB)
        else:
            self.prompt = 'SQL (%s@%s)> ' % (username_prompt, self.sql.currentDB)

    def do_show_query(self, s):
        self.show_queries = True

    def do_mask_query(self, s):
        self.show_queries = False

    def execute_as(self, exec_as):
        if self.at is not None and len(self.at) > 0:
            (at, prefix) = self.at[-1:][0]
            self.at = self.at[:-1]
            self.at.append((at, exec_as))
        else:
            self.sql_query(exec_as)
            self.print_replies()

    def do_exec_as_login(self, s):
        exec_as = "execute as login='%s';" % s
        self.execute_as(exec_as)

    def do_exec_as_user(self, s):
        exec_as = "execute as user='%s';" % s
        self.execute_as(exec_as)

    def do_use_link(self, s):
        if s == 'localhost':
            self.at = []
        elif s == '..':
            self.at = self.at[:-1]
        else:
            self.at.append((s, ''))
            row = self.sql_query('select system_user as "username"')
            self.print_replies()
            if len(row) < 1:
                self.at = self.at[:-1]

    def sql_query(self, query, show=True):
        if self.at is not None and len(self.at) > 0:
            for (linked_server, prefix) in self.at[::-1]:
                query = "EXEC ('" + prefix.replace("'", "''") + query.replace("'", "''") + "') AT " + linked_server
        if self.show_queries and show:
            print('[%%] %s' % query)
        return self.sql.sql_query(query)

    def do_shell(self, s):
        os.system(s)

    def do_download(self, line):
        try:
            args = shlex.split(line, posix=False)
            remote_path = args[0]
            local_path = args[1]

            # check permission
            result = self.sql_query("SELECT HAS_PERMS_BY_NAME(NULL, NULL, 'ADMINISTER BULK OPERATIONS') AS HasBulkAdminPermission")
            if result[0].get('HasBulkAdminPermission') != 1:
                print("[-] Current user does not have 'ADMINISTER BULK OPERATIONS' permission")
                return

            # download file
            result = self.sql_query("SELECT * FROM sys.dm_os_file_exists('" + remote_path + "')")
            # This iters through the dict returned by MSSQL and gets the first key which stores if the file exists or not
            first_key = next(iter(result[0]))
            # If the value is not 1, the file doesn't exist
            if result[0].get(first_key) != 1:
                print("[-] File does not exist")
                return
            print("[+] File exists, downloading...")
            result = self.sql_query("SELECT * FROM OPENROWSET(BULK N'" + remote_path + "', SINGLE_BLOB) AS HexContent")
            if len(result) == 0:
                print("[-] Error downloading file. File is either empty or access is denied")
                return

            # write to disk
            print("[+] Writing file to disk...")
            with open(local_path, 'wb') as f:
                data = bytes.fromhex(result[0].get('BulkColumn').decode())
                f.write(data)
            print("[+] Downloaded")
        except Exception as e:
            print("[-] Unhandled Exception:", e)

    def do_upload(self, line):
        BUFFER_SIZE = 5 * 1024
        try:
            # validate "xp_cmdshell" is enabled
            self.sql_query("exec master.dbo.sp_configure 'show advanced options', 1; RECONFIGURE;")
            result = self.sql_query("exec master.dbo.sp_configure 'xp_cmdshell'")
            self.sql_query("exec master.dbo.sp_configure 'show advanced options', 0; RECONFIGURE;")
            if result[0].get('run_value') != 1:
                print("[-] xp_cmdshell not enabled. Try running 'enable_xp_cmdshell' first")
                return

            args = shlex.split(line, posix=False)
            local_path = args[0]
            remote_path = args[1]

            # upload file
            with open(local_path, 'rb') as f:
                data = f.read()
                md5sum = hashlib.md5(data).hexdigest()
                b64enc_data = b"".join(base64.b64encode(data).split()).decode()
            print("[+] Data length (b64-encoded): %.2f KB with MD5: %s" % (len(b64enc_data) / 1024, str(md5sum)))
            print("[+] Uploading...")
            for i in range(0, len(b64enc_data), BUFFER_SIZE):
                cmd = 'echo ' + b64enc_data[i:i+BUFFER_SIZE] + ' >> "' + remote_path + '.b64"'
                self.sql_query("EXEC xp_cmdshell '" + cmd + "'")
            result = self.sql_query("EXEC xp_fileexist '" + remote_path + ".b64'")
            # This iters through the dict returned by MSSQL and gets the first key which stores if the file exists or not
            first_key = next(iter(result[0]))
            # If the value is not 1, the file doesn't exist
            if result[0].get(first_key) != 1:
                print("[-] Error uploading file. Check permissions in the configured remote path")
                return
            print("[+] Uploaded")

            # decode
            cmd = 'certutil -decode "' + remote_path + '.b64" "' + remote_path + '"'
            self.sql_query("EXEC xp_cmdshell '" + cmd + "'")
            print("[+] " + cmd)

            # remove encoded
            cmd = 'del "' + remote_path + '.b64"'
            self.sql_query("EXEC xp_cmdshell '" + cmd + "'")
            print("[+] " + cmd)

            # validate hash
            cmd = 'certutil -hashfile "' + remote_path + '" MD5'
            result = self.sql_query("EXEC xp_cmdshell '" + cmd + "'")
            print("[+] " + cmd)
            md5sum_uploaded = result[1].get('output').replace(" ", "")
            if md5sum == md5sum_uploaded:
                print("[+] MD5 hashes match")
            else:
                print("[-] ERROR! MD5 hashes do NOT match!")
                print("[+] Uploaded file MD5: %s" % md5sum_uploaded)
        except Exception as e:
            print("[-] Unhandled Exception:", e)

    def do_xp_dirtree(self, s):
        try:
            self.sql_query("exec master.sys.xp_dirtree '%s',1,1" % s)
            self.print_replies()
            self.sql.printRows()
        except:
            pass

    def do_xp_cmdshell(self, s):
        try:
            self.sql_query("exec master..xp_cmdshell '%s'" % s)
            self.print_replies()
            self.sql.colMeta[0]['TypeData'] = 80*2
            self.sql.printRows()
        except:
            pass

    def do_xp_cmdshell_link(self, line):
        """
        Execute xp_cmdshell through all discovered link paths (or a specific path/server if provided).
        Usage: xp_cmdshell_link "whoami"  (tries all discovered paths)
        Usage: xp_cmdshell_link link1->link2 "whoami"  (tries specific path)
        Usage: xp_cmdshell_link DB-SQLSRV "whoami"  (tries paths to server instance DB-SQLSRV)
        """
        try:
            args = shlex.split(line, posix=False)
            if len(args) < 1:
                print("[-] Usage: xp_cmdshell_link [link_path|server_name] <command>")
                print("    Example: xp_cmdshell_link \"whoami\"  (tries all paths)")
                print("    Example: xp_cmdshell_link link1->link2 \"whoami\"  (specific path)")
                print("    Example: xp_cmdshell_link DB-SQLSRV \"whoami\"  (server instance name)")
                return
            
            # Check if first arg is a path (contains ->) or is the command
            paths_to_try = []
            cmd = None
            
            if len(args) == 1:
                # Only command provided, use all discovered paths
                cmd = args[0]
                if not self.discovered_paths:
                    print("[*] No paths discovered yet. Running crawl_links first...")
                    self.do_crawl_links("")
                paths_to_try = self.discovered_paths.copy()
            elif '->' in args[0] or args[0] == 'LOCAL':
                # First arg is a path
                link_path_str = args[0]
                cmd = ' '.join(args[1:])
                
                # Parse link path
                if link_path_str == 'LOCAL' or link_path_str == '':
                    link_path = []
                else:
                    link_path = [link.strip() for link in link_path_str.split('->')]
                paths_to_try = [link_path]
            elif args[0] in self.server_to_paths:
                # First arg is a server instance name
                server_name = args[0]
                cmd = ' '.join(args[1:])
                paths_to_try = self.server_to_paths[server_name].copy()
                print(f"[*] Found {len(paths_to_try)} path(s) to server '{server_name}'")
            else:
                # Check if it might be a server name but we need to crawl first
                if not self.discovered_paths:
                    print("[*] No paths discovered yet. Running crawl_links first...")
                    self.do_crawl_links("")
                    # Check again after crawling
                    if args[0] in self.server_to_paths:
                        server_name = args[0]
                        cmd = ' '.join(args[1:])
                        paths_to_try = self.server_to_paths[server_name].copy()
                        print(f"[*] Found {len(paths_to_try)} path(s) to server '{server_name}'")
                    else:
                        # No path indicator, treat all as command and use all paths
                        cmd = ' '.join(args)
                        paths_to_try = self.discovered_paths.copy()
                else:
                    # No path indicator, treat all as command and use all paths
                    cmd = ' '.join(args)
                    paths_to_try = self.discovered_paths.copy()
            
            if not cmd:
                print("[-] No command provided")
                return
            
            # Try xp_cmdshell on each path
            success_count = 0
            for link_path in paths_to_try:
                try:
                    path_display = '->'.join(link_path) if link_path else 'LOCAL'
                    print(f"\n[*] Trying path: {path_display}")
                    
                    # Build xp_cmdshell query through link path
                    # Escape single quotes in the command
                    escaped_cmd = cmd.replace("'", "''")
                    # Add WITH RESULT SETS for xp_cmdshell (like PowerUpSQL) to properly handle output
                    query = f"exec master..xp_cmdshell '{escaped_cmd}' WITH RESULT SETS ((output VARCHAR(8000)))"
                    if link_path:
                        final_query = self.build_link_query(link_path, query)
                    else:
                        final_query = query
                    
                    if self.show_queries:
                        print(f"[%] {final_query}")
                    
                    result = self.sql_query(final_query, show=False)
                    self.print_replies()
                    if result:
                        print(f"[+] Success on path: {path_display}")
                        # Clean up and display xp_cmdshell output nicely
                        output_lines = []
                        for row in result:
                            # Get the output column (could be 'output' or first column)
                            output_value = None
                            if 'output' in row:
                                output_value = row['output']
                            elif len(row) > 0:
                                # Get first column value
                                output_value = list(row.values())[0]
                            
                            # Skip NULL values
                            if output_value is None:
                                continue
                            
                            # Convert to string and clean up
                            if isinstance(output_value, bytes):
                                output_value = output_value.decode('utf-8', errors='ignore')
                            else:
                                output_value = str(output_value)
                            
                            # Remove b' prefix if present (string representation of bytes)
                            # This handles cases where bytes are displayed as "b'text'"
                            if output_value.startswith("b'") and output_value.endswith("'"):
                                output_value = output_value[2:-1]
                                # Unescape common escape sequences
                                output_value = output_value.replace("\\n", "\n").replace("\\t", "\t").replace("\\\\", "\\")
                            elif output_value.startswith("b'") and len(output_value) > 2:
                                # Handle case where b' is at start but no closing quote
                                output_value = output_value[2:]
                            
                            # Strip whitespace and skip empty lines
                            output_value = output_value.strip()
                            if output_value and output_value.lower() != 'null':
                                output_lines.append(output_value)
                        
                        # Display cleaned output
                        if output_lines:
                            print()  # Empty line for readability
                            print("\n".join(output_lines))
                        else:
                            print("(No output)")
                        success_count += 1
                    else:
                        print(f"[-] No results on path: {path_display}")
                except Exception as e:
                    print(f"[-] Error on path {path_display}: {e}")
            
            print(f"\n[+] xp_cmdshell execution complete. Success on {success_count}/{len(paths_to_try)} paths.")
        except Exception as e:
            print(f"[-] Error executing xp_cmdshell: {e}")

    def do_sp_start_job(self, s):
        try:
            self.sql_query("DECLARE @job NVARCHAR(100);"
                                "SET @job='IdxDefrag'+CONVERT(NVARCHAR(36),NEWID());"
                                "EXEC msdb..sp_add_job @job_name=@job,@description='INDEXDEFRAG',"
                                "@owner_login_name='sa',@delete_level=3;"
                                "EXEC msdb..sp_add_jobstep @job_name=@job,@step_id=1,@step_name='Defragmentation',"
                                "@subsystem='CMDEXEC',@command='%s',@on_success_action=1;"
                                "EXEC msdb..sp_add_jobserver @job_name=@job;"
                                "EXEC msdb..sp_start_job @job_name=@job;" % s)
            self.print_replies()
            self.sql.printRows()
        except:
            pass

    def do_lcd(self, s):
        if s == '':
            print(os.getcwd())
        else:
            os.chdir(s)

    def do_enable_xp_cmdshell(self, line):
        try:
            self.sql_query("exec master.dbo.sp_configure 'show advanced options',1;RECONFIGURE;"
                                "exec master.dbo.sp_configure 'xp_cmdshell', 1;RECONFIGURE;")
            self.print_replies()
            self.sql.printRows()
        except:
            pass

    def do_disable_xp_cmdshell(self, line):
        try:
            self.sql_query("exec sp_configure 'xp_cmdshell', 0 ;RECONFIGURE;exec sp_configure "
                            "'show advanced options', 0 ;RECONFIGURE;")
            self.print_replies()
            self.sql.printRows()
        except:
            pass

    def do_enum_links(self, line):
        self.sql_query("EXEC sp_linkedservers")
        self.print_replies()
        self.sql.printRows()
        self.sql_query("EXEC sp_helplinkedsrvlogin")
        self.print_replies()
        self.sql.printRows()

    def build_link_query(self, link_path, query, depth=0):
        """
        Build a nested query through a link path (recursive, like PowerUpSQL).
        For SELECT queries, uses OPENQUERY (like PowerUpSQL).
        For EXEC queries, uses EXEC AT.
        For path ['link1', 'link2'], builds nested queries with proper quote escaping.
        Quote escaping: at depth N, quotes are escaped 2^N times (matching PowerUpSQL logic).
        """
        if len(link_path) <= 0:
            # Base case: escape quotes in the original query based on depth
            num_escapes = int(2 ** depth)
            if num_escapes == 1:
                escaped_query = query.replace("'", "''")
            else:
                # Replace each ' with ' repeated num_escapes times
                escaped_query = query.replace("'", "'" * num_escapes)
            return escaped_query
        
        # Recursively build query for the rest of the path
        remaining_path = link_path[1:]
        current_link = link_path[0]
        inner_query = self.build_link_query(remaining_path, query, depth + 1)
        
        # Add quotes around the inner query (2^depth quotes on each side)
        # The inner query already has proper escaping from the recursive call
        num_quotes = int(2 ** depth)
        quote_str = "'" * num_quotes
        
        # Always use OPENQUERY (like PowerUpSQL) - it works for both SELECT and EXEC statements
        # OPENQUERY doesn't require RPC to be enabled, unlike EXEC AT
        # Quote link name with double quotes (OPENQUERY requires this)
        return f'SELECT * FROM OPENQUERY("{current_link}", {quote_str}{inner_query}{quote_str})'

    def get_server_info(self, link_path=None):
        """
        Get server information (servername, version, user, sysadmin) through a link path.
        Returns dict with server info or None on error.
        """
        try:
            # Build query to get server info
            info_query = "SELECT @@servername as servername, @@version as version, system_user as linkuser, is_srvrolemember('sysadmin') as issysadmin"
            
            if link_path:
                query = self.build_link_query(link_path, info_query)
            else:
                query = info_query
            
            result = self.sql_query(query, show=False)
            if result and len(result) > 0:
                return {
                    'servername': result[0].get('servername', 'Unknown'),
                    'version': result[0].get('version', 'Unknown'),
                    'linkuser': result[0].get('linkuser', 'Unknown'),
                    'issysadmin': result[0].get('issysadmin', 0)
                }
        except Exception as e:
            print(f"[-] Error getting server info: {e}")
        return None

    def get_linked_servers(self, link_path=None):
        """
        Get list of linked servers through a link path.
        Returns list of linked server names or empty list on error.
        """
        try:
            links_query = "SELECT srvname FROM master..sysservers WHERE dataaccess=1"
            
            if link_path:
                query = self.build_link_query(link_path, links_query)
            else:
                query = links_query
            
            result = self.sql_query(query, show=False)
            if result:
                return [row.get('srvname', '') for row in result if row.get('srvname')]
        except Exception as e:
            print(f"[-] Error getting linked servers: {e}")
        return []

    def crawl_links_recursive(self, current_path=None, max_depth=10, depth=0):
        """
        Recursively crawl linked servers.
        current_path: list of link names representing the path to current server
        max_depth: maximum recursion depth to prevent infinite loops
        depth: current recursion depth
        """
        if depth > max_depth:
            return []
        
        if current_path is None:
            current_path = []
        
        # Create path identifier to avoid loops
        path_key = '->'.join(current_path) if current_path else 'LOCAL'
        if path_key in self.crawled_servers:
            return []
        
        self.crawled_servers.add(path_key)
        
        results = []
        
        # Get server info
        server_info = self.get_server_info(current_path)
        if not server_info:
            print(f"[-] Could not get server info for path: {path_key}")
            return results
        
        # Get linked servers
        linked_servers = self.get_linked_servers(current_path)
        
        # Display current server info
        path_display = path_key if path_key != 'LOCAL' else 'LOCAL'
        print(f"\n[+] Server: {server_info['servername']}")
        print(f"    Path: {path_display}")
        print(f"    Version: {server_info['version'][:50]}...")  # Truncate long version strings
        print(f"    User: {server_info['linkuser']}")
        print(f"    IsSysAdmin: {bool(server_info['issysadmin'])}")
        print(f"    Linked Servers: {', '.join(linked_servers) if linked_servers else 'None'}")
        
        # Store result
        results.append({
            'path': current_path.copy(),
            'servername': server_info['servername'],
            'version': server_info['version'],
            'linkuser': server_info['linkuser'],
            'issysadmin': server_info['issysadmin'],
            'linked_servers': linked_servers
        })
        
        # Recursively crawl each linked server
        for link in linked_servers:
            # Avoid loops: don't crawl if this link is already in the path
            if link not in current_path:
                new_path = current_path + [link]
                sub_results = self.crawl_links_recursive(new_path, max_depth, depth + 1)
                results.extend(sub_results)
        
        return results

    def do_crawl_links(self, line):
        """
        Recursively crawl all linked servers.
        Usage: crawl_links [max_depth]
        """
        try:
            max_depth = 10
            if line.strip():
                max_depth = int(line.strip())
            
            print(f"[*] Starting link crawl (max depth: {max_depth})...")
            self.crawled_servers = set()  # Reset crawled servers
            results = self.crawl_links_recursive(max_depth=max_depth)
            
            # Store all discovered paths for later use
            self.discovered_paths = [result['path'] for result in results]
            # Also include LOCAL (empty path)
            if [] not in self.discovered_paths:
                self.discovered_paths.insert(0, [])
            
            # Build mapping of server instance names to paths
            self.server_to_paths = {}
            for result in results:
                servername = result['servername']
                path = result['path']
                if servername not in self.server_to_paths:
                    self.server_to_paths[servername] = []
                self.server_to_paths[servername].append(path)
            
            # Also map LOCAL server
            local_info = self.get_server_info([])
            if local_info:
                local_servername = local_info['servername']
                if local_servername not in self.server_to_paths:
                    self.server_to_paths[local_servername] = []
                if [] not in self.server_to_paths[local_servername]:
                    self.server_to_paths[local_servername].append([])
            
            print(f"\n[+] Crawl complete. Found {len(results)} servers.")
            print(f"[+] Discovered {len(self.discovered_paths)} paths for query execution.")
        except ValueError:
            print("[-] Invalid max_depth. Usage: crawl_links [max_depth]")
        except Exception as e:
            print(f"[-] Error during crawl: {e}")

    def do_query_link(self, line):
        """
        Execute a query through all discovered link paths (or a specific path/server if provided).
        Usage: query_link "SELECT @@version"  (tries all discovered paths)
        Usage: query_link link1->link2 "SELECT @@version"  (tries specific path)
        Usage: query_link DB-SQLSRV "SELECT @@version"  (tries paths to server instance DB-SQLSRV)
        """
        try:
            args = shlex.split(line, posix=False)
            if len(args) < 1:
                print("[-] Usage: query_link [link_path|server_name] <query>")
                print("    Example: query_link \"SELECT @@version\"  (tries all paths)")
                print("    Example: query_link link1->link2 \"SELECT @@version\"  (specific path)")
                print("    Example: query_link DB-SQLSRV \"SELECT @@version\"  (server instance name)")
                return
            
            # Check if first arg is a path (contains ->) or is the query
            paths_to_try = []
            query = None
            
            if len(args) == 1:
                # Only query provided, use all discovered paths
                query = args[0]
                if not self.discovered_paths:
                    print("[*] No paths discovered yet. Running crawl_links first...")
                    self.do_crawl_links("")
                paths_to_try = self.discovered_paths.copy()
            elif '->' in args[0] or args[0] == 'LOCAL':
                # First arg is a path
                link_path_str = args[0]
                query = ' '.join(args[1:])
                
                # Parse link path
                if link_path_str == 'LOCAL' or link_path_str == '':
                    link_path = []
                else:
                    link_path = [link.strip() for link in link_path_str.split('->')]
                paths_to_try = [link_path]
            elif args[0] in self.server_to_paths:
                # First arg is a server instance name
                server_name = args[0]
                query = ' '.join(args[1:])
                paths_to_try = self.server_to_paths[server_name].copy()
                print(f"[*] Found {len(paths_to_try)} path(s) to server '{server_name}'")
            else:
                # Check if it might be a server name but we need to crawl first
                if not self.discovered_paths:
                    print("[*] No paths discovered yet. Running crawl_links first...")
                    self.do_crawl_links("")
                    # Check again after crawling
                    if args[0] in self.server_to_paths:
                        server_name = args[0]
                        query = ' '.join(args[1:])
                        paths_to_try = self.server_to_paths[server_name].copy()
                        print(f"[*] Found {len(paths_to_try)} path(s) to server '{server_name}'")
                    else:
                        # No path indicator, treat all as query and use all paths
                        query = ' '.join(args)
                        paths_to_try = self.discovered_paths.copy()
                else:
                    # No path indicator, treat all as query and use all paths
                    query = ' '.join(args)
                    paths_to_try = self.discovered_paths.copy()
            
            if not query:
                print("[-] No query provided")
                return
            
            # Try query on each path
            success_count = 0
            for link_path in paths_to_try:
                try:
                    path_display = '->'.join(link_path) if link_path else 'LOCAL'
                    print(f"\n[*] Trying path: {path_display}")
                    
                    # Build query through link path
                    if link_path:
                        final_query = self.build_link_query(link_path, query)
                    else:
                        final_query = query
                    
                    if self.show_queries:
                        print(f"[%] {final_query}")
                    
                    result = self.sql_query(final_query, show=False)
                    self.print_replies()
                    if result:
                        print(f"[+] Success on path: {path_display}")
                        self.sql.rows = result
                        self.sql.printRows()
                        success_count += 1
                    else:
                        print(f"[-] No results on path: {path_display}")
                except Exception as e:
                    print(f"[-] Error on path {path_display}: {e}")
            
            print(f"\n[+] Query execution complete. Success on {success_count}/{len(paths_to_try)} paths.")
        except Exception as e:
            print(f"[-] Error executing query: {e}")

    def do_enum_users(self, line):
        self.sql_query("EXEC sp_helpuser")
        self.print_replies()
        self.sql.printRows()

    def do_enum_db(self, line):
        try:
            self.sql_query("select name, is_trustworthy_on from sys.databases")
            self.print_replies()
            self.sql.printRows()
        except:
            pass

    def do_enum_owner(self, line):
        try:
            self.sql_query("SELECT name [Database], suser_sname(owner_sid) [Owner] FROM sys.databases")
            self.print_replies()
            self.sql.printRows()
        except:
            pass

    def do_enum_impersonate(self, line):
        old_db = self.sql.currentDB
        try:
            self.sql_query("select name from sys.databases")
            result = []
            for row in self.sql.rows:
                result_rows = self.sql_query("use " + row['name'] + "; SELECT 'USER' as 'execute as', DB_NAME() "
                                                                    "AS 'database',pe.permission_name,"
                                                                    "pe.state_desc, pr.name AS 'grantee', "
                                                                    "pr2.name AS 'grantor' "
                                                                    "FROM sys.database_permissions pe "
                                                                    "JOIN sys.database_principals pr ON "
                                                                    "  pe.grantee_principal_id = pr.principal_Id "
                                                                    "JOIN sys.database_principals pr2 ON "
                                                                    "  pe.grantor_principal_id = pr2.principal_Id "
                                                                    "WHERE pe.type = 'IM'")
                if result_rows:
                    result.extend(result_rows)
            result_rows = self.sql_query("SELECT 'LOGIN' as 'execute as', '' AS 'database',pe.permission_name,"
                                            "pe.state_desc,pr.name AS 'grantee', pr2.name AS 'grantor' "
                                            "FROM sys.server_permissions pe JOIN sys.server_principals pr "
                                            "  ON pe.grantee_principal_id = pr.principal_Id "
                                            "JOIN sys.server_principals pr2 "
                                            "  ON pe.grantor_principal_id = pr2.principal_Id "
                                            "WHERE pe.type = 'IM'")
            result.extend(result_rows)
            self.print_replies()
            self.sql.rows = result
            self.sql.printRows()
        except:
            pass
        finally:
            self.sql_query("use " + old_db)

    def do_enum_logins(self, line):
        try:
            self.sql_query("select r.name,r.type_desc,r.is_disabled, sl.sysadmin, sl.securityadmin, "
                            "sl.serveradmin, sl.setupadmin, sl.processadmin, sl.diskadmin, sl.dbcreator, "
                            "sl.bulkadmin from  master.sys.server_principals r left join master.sys.syslogins sl "
                            "on sl.sid = r.sid where r.type in ('S','E','X','U','G')")
            self.print_replies()
            self.sql.printRows()
        except:
            pass

    def default(self, line):
        try:
            self.sql_query(line)
            self.print_replies()
            self.sql.printRows()
        except:
            pass

    def emptyline(self):
        pass

    def do_exit(self, line):
        if self.shell is not None:
            self.shell.close()
        return True
