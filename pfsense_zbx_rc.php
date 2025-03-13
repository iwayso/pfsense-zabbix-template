// Get IPSEC configuration with caching
function pfz_get_ipsec_config($phase = 'phase1') {
    $cache_key = "ipsec_config_{$phase}";
    $cache = pfz_get_cache($cache_key, CACHE_DURATION_STATIC);
    
    if ($cache !== null) {
        return $cache;
    }
    
    include_once_track('ipsec.inc');
    global $config;
    
    init_config_arr(array('ipsec', $phase));
    $config_data = &$config['ipsec'][$phase];
    
    pfz_set_cache($cache_key, $config_data);
    return $config_data;
}

// Helper function to determine if a value is static or dynamic
function pfz_is_static_ipsec_value($valuekey) {
    $static_values = array(
        'iketype', 'mode', 'protocol', 'interface', 'remote-gateway', 
        'encryption', 'lifetime', 'disabled', 'authentication_method',
        'descr', 'nat', 'localid', 'remoteid', 'mobike', 'rekey_enable',
        'dpd_delay', 'dpd_maxfail', 'closeaction', 'reauth_enable',
        'tunnel_local', 'tunnel_remote', 'pfsgroup', 'p1mode'  // Ajout de "p1mode"
    );
    
    return in_array($valuekey, $static_values);
}<?php
/*** 
pfsense_zbx.php - pfSense Zabbix Interface
Version 0.24.9 - 2025-03-12
Original written by Riccardo Bicelli <r.bicelli@gmail.com>
Optimized version with improved IPSEC caching
This program is licensed under Apache 2.0 License
*/

//Some Useful defines
define('SCRIPT_VERSION', '0.24.9');

define('SPEEDTEST_INTERVAL', 8); //Speedtest Interval (in hours)
define('CRON_TIME_LIMIT', 300); // Time limit in seconds of speedtest and sysinfo 
define('DEFAULT_TIME_LIMIT', 30); // Time limit in seconds otherwise

// Cache durations (in seconds)
define('CACHE_DURATION_SHORT', 60); // 1 minute
define('CACHE_DURATION_MEDIUM', 300); // 5 minutes
define('CACHE_DURATION_LONG', 3600); // 1 hour
define('CACHE_DURATION_STATIC', 86400); // 24 hours - for values that rarely change
define('CACHE_DURATION_REALTIME', 5); // 5 seconds - for critical status values

// Services critiques pour lesquels le cache est désactivé ou très court
$CRITICAL_SERVICES = array('openvpn', 'ipsec', 'ppp');

// Cache directory
define('CACHE_DIR', '/tmp/pfz_cache');

// Create cache directory if it doesn't exist
if (!is_dir(CACHE_DIR)) {
    mkdir(CACHE_DIR, 0755, true);
}

// Load required files only when needed
$included_files = array();

function include_once_track($filename) {
    global $included_files;
    if (!isset($included_files[$filename])) {
        include_once($filename);
        $included_files[$filename] = true;
    }
}

// Required for basic operations
include_once_track('globals.inc');
include_once_track('functions.inc');
include_once_track('config.inc');
include_once_track('util.inc');

//Backporting php 8 functions
if (!function_exists('str_contains')) {
    function str_contains($haystack, $needle) {
        return strstr($haystack, $needle) !== false;
    }
}

// Cache management functions
function pfz_get_cache($key, $duration = CACHE_DURATION_MEDIUM, $force_refresh = false) {
    // Si force_refresh est actif, on ignore complètement le cache
    if ($force_refresh) {
        return null;
    }
    
    $cache_file = CACHE_DIR . '/' . md5($key) . '.cache';
    
    if (file_exists($cache_file) && (time() - filemtime($cache_file) < $duration)) {
        return unserialize(file_get_contents($cache_file));
    }
    
    return null;
}

function pfz_set_cache($key, $data) {
    $cache_file = CACHE_DIR . '/' . md5($key) . '.cache';
    file_put_contents($cache_file, serialize($data));
}

// Nouvelles fonctions de cache groupé 
function pfz_get_cache_group($group, $key, $duration = CACHE_DURATION_MEDIUM, $force_refresh = false) {
    // Si force_refresh est actif, on ignore complètement le cache
    if ($force_refresh) {
        return null;
    }
    
    $cache_file = CACHE_DIR . '/group_' . md5($group) . '.cache';
    
    if (file_exists($cache_file) && (time() - filemtime($cache_file) < $duration)) {
        $data = unserialize(file_get_contents($cache_file));
        return isset($data[$key]) ? $data[$key] : null;
    }
    
    return null;
}

// Fonction qui détermine si un service est critique et nécessite un rafraîchissement fréquent
function pfz_is_critical_service($service_name) {
    global $CRITICAL_SERVICES;
    
    foreach ($CRITICAL_SERVICES as $critical) {
        if (strpos($service_name, $critical) !== false) {
            return true;
        }
    }
    
    return false;
}

function pfz_set_cache_group($group, $key, $value) {
    $cache_file = CACHE_DIR . '/group_' . md5($group) . '.cache';
    
    if (file_exists($cache_file)) {
        $data = unserialize(file_get_contents($cache_file));
    } else {
        $data = array();
    }
    
    $data[$key] = $value;
    file_put_contents($cache_file, serialize($data));
}

function pfz_get_cache_group_all($group, $duration = CACHE_DURATION_MEDIUM) {
    $cache_file = CACHE_DIR . '/group_' . md5($group) . '.cache';
    
    if (file_exists($cache_file) && (time() - filemtime($cache_file) < $duration)) {
        return unserialize(file_get_contents($cache_file));
    }
    
    return array();
}

function pfz_set_cache_group_all($group, $data) {
    $cache_file = CACHE_DIR . '/group_' . md5($group) . '.cache';
    file_put_contents($cache_file, serialize($data));
}

// Get cached IPsec Phase 1 values with grouped cache
function pfz_get_ipsec_ph1_values($ikeid) {
    $group = "ipsec_ph1_values";
    $all_values = pfz_get_cache_group_all($group, CACHE_DURATION_STATIC);
    
    if (isset($all_values[$ikeid])) {
        return $all_values[$ikeid];
    }
    
    $a_phase1 = pfz_get_ipsec_config('phase1');
    
    // Valeurs par défaut
    $values = array(
        'disabled' => "0",
        'mode' => "0",
        'p1mode' => "0",
        'iketype' => "0",
        'protocol' => "0"
    );
    
    foreach ($a_phase1 as $data) {
        if ($data['ikeid'] == $ikeid) {
            // Copier toutes les valeurs statiques
            foreach ($data as $key => $val) {
                if ($key == 'disabled') {
                    $values[$key] = "1";
                } else {
                    $values[$key] = pfz_valuemap("ipsec." . $key, $val, $val);
                }
            }
            break;
        }
    }
    
    // Mettre à jour le cache groupé
    $all_values[$ikeid] = $values;
    pfz_set_cache_group_all($group, $all_values);
    
    return $values;
}

// Get cached IPsec Phase 2 values with grouped cache
function pfz_get_ipsec_ph2_values($uniqid) {
    $group = "ipsec_ph2_values";
    $all_values = pfz_get_cache_group_all($group, CACHE_DURATION_STATIC);
    
    if (isset($all_values[$uniqid])) {
        return $all_values[$uniqid];
    }
    
    $a_phase2 = pfz_get_ipsec_config('phase2');
    
    // Valeurs par défaut
    $values = array(
        'disabled' => "0",
        'mode' => "1",      // tunnel mode par défaut
        'protocol' => "1"   // esp par défaut
    );
    
    foreach ($a_phase2 as $data) {
        if ($data['uniqid'] == $uniqid) {
            // Copier toutes les valeurs statiques
            foreach ($data as $key => $val) {
                if ($key == 'disabled') {
                    $values[$key] = "1";
                } else {
                    $values[$key] = pfz_valuemap("ipsec_ph2." . $key, $val, $val);
                }
            }
            break;
        }
    }
    
    // Mettre à jour le cache groupé
    $all_values[$uniqid] = $values;
    pfz_set_cache_group_all($group, $all_values);
    
    return $values;
}

//Testing function, for template creating purpose
function pfz_test() {
    $line = "-------------------\n";
    
    include_once_track('openvpn.inc');
    $ovpn_servers = pfz_openvpn_get_all_servers();
    echo "OPENVPN Servers:\n";
    print_r($ovpn_servers);
    echo $line;

    $ovpn_clients = openvpn_get_active_clients();
    echo "OPENVPN Clients:\n";
    print_r($ovpn_clients);
    echo $line;

    include_once_track('interfaces.inc');
    $ifdescrs = get_configured_interface_with_descr(true);
    $ifaces = array();
    foreach ($ifdescrs as $ifdescr => $ifname) {     
        $ifinfo = get_interface_info($ifdescr);
        $ifaces[$ifname] = $ifinfo;
    }
    echo "Network Interfaces:\n";        
    print_r($ifaces);
    print_r(get_interface_arr());
    print_r(get_configured_interface_list());
    echo $line;

    include_once_track('service-utils.inc');
    $services = get_services();
    echo "Services: \n";
    print_r($services);
    echo $line;
    
    echo "IPsec: \n";
    
    include_once_track('ipsec.inc');
    global $config;
    init_config_arr(array('ipsec', 'phase1'));
    init_config_arr(array('ipsec', 'phase2'));
    $a_phase2 = &$config['ipsec']['phase2'];
    $status = ipsec_list_sa();
    echo "IPsec Status: \n";
    print_r($status);        
    
    $a_phase1 = &$config['ipsec']['phase1'];
    $a_phase2 = &$config['ipsec']['phase2'];

    echo "IPsec Config Phase 1: \n";
    print_r($a_phase1);
    
    echo "IPsec Config Phase 2: \n";
    print_r($a_phase2);
    
    echo $line;
    
    //Packages
    echo "Packages: \n";
    include_once_track('pkg-utils.inc');
    $installed_packages = get_pkg_info('all', false, true);
    print_r($installed_packages);
}

// Interface Discovery
// Improved performance with caching
function pfz_interface_discovery($is_wan = false, $is_cron = false) {
    $cache_key = "interface_discovery_" . ($is_wan ? "wan" : "all");
    $cache = pfz_get_cache($cache_key);
    
    if ($cache !== null) {
        if ($is_cron) return $cache['if_ret'];
        echo $cache['json_string'];
        return;
    }
    
    include_once_track('interfaces.inc');
    $ifdescrs = get_configured_interface_with_descr(true);
    $ifaces = get_interface_arr();
    $ifcs = array();
    $if_ret = array();
 
    $json_data = array('data' => array());
                   
    foreach ($ifdescrs as $ifname => $ifdescr) {
        $ifinfo = get_interface_info($ifname);
        $ifinfo["description"] = $ifdescr;
        $ifcs[$ifname] = $ifinfo;          
    }    

    foreach ($ifaces as $hwif) {
        $ifdescr = $hwif;
        $has_gw = false;
        $is_vpn = false;
        $has_public_ip = false;
        
        foreach ($ifcs as $ifc => $ifinfo) {
            if ($ifinfo["hwif"] == $hwif) {
                $ifdescr = $ifinfo["description"];
                if (array_key_exists("gateway", $ifinfo)) $has_gw = true;
                //  Issue #81
                if (filter_var($ifinfo["ipaddr"], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) 
                    $has_public_ip = true;
                if (strpos($ifinfo["if"], "ovpn") !== false) $is_vpn = true;
                break;
            }
        }
        
        if (($is_wan == false) || (($is_wan == true) && (($has_gw == true) || ($has_public_ip == true)) && ($is_vpn == false))) { 
            $if_ret[] = $hwif;
            $json_data['data'][] = array(
                '{#IFNAME}' => $hwif,
                '{#IFDESCR}' => $ifdescr
            );
        }
    }
    
    $json_string = json_encode($json_data);
    
    $cache_data = array(
        'if_ret' => $if_ret,
        'json_string' => $json_string
    );
    pfz_set_cache($cache_key, $cache_data);
    
    if ($is_cron) return $if_ret;
    echo $json_string;
}

//Interface Speedtest
function pfz_interface_speedtest_value($ifname, $value) {    
    $tvalue = explode(".", $value);    
    
    if (count($tvalue) > 1) {
        $value = $tvalue[0];
        $subvalue = $tvalue[1];
    }        
    
    //If the interface has a gateway is considered WAN, so let's do the speedtest
    $filename = "/tmp/speedtest-$ifname";
    
    if (file_exists($filename)) {
        $speedtest_data = json_decode(file_get_contents($filename), true) ?? [];
        
        if (array_key_exists($value, $speedtest_data)) {
            if (empty($subvalue)) 
                echo $speedtest_data[$value];
            else
                echo $speedtest_data[$value][$subvalue];
        }    
    }
}

// This is supposed to run via cron job
function pfz_speedtest_cron() {
    include_once_track('services.inc');
    include_once_track('interfaces.inc');
    $ifdescrs = get_configured_interface_with_descr(true);
    $pf_interface_name = '';
                           
    $ifcs = pfz_interface_discovery(true, true);    
    
    foreach ($ifcs as $ifname) {
        foreach ($ifdescrs as $ifn => $ifd) {
            $ifinfo = get_interface_info($ifn);
            if ($ifinfo['hwif'] == $ifname) {
                $pf_interface_name = $ifn;
                break;
            }
        }    
        pfz_speedtest_exec($ifname, $ifinfo['ipaddr']);
    }
}

//installs a cron job for speedtests
function pfz_speedtest_cron_install($enable = true) {
    include_once_track('services.inc');
    //Install Cron Job
    $command = "/usr/local/bin/php " . __FILE__ . " speedtest_cron";
    install_cron_job($command, $enable, $minute = "*/15", "*", "*", "*", "*", "root", true);
}        

// Fixed issue #127
function pfz_speedtest_exec($ifname, $ipaddr) {
    $filename = "/tmp/speedtest-$ifname";
    $filetemp = "$filename.tmp";
    $filerun = "/tmp/speedtest-run"; 
    
    // Issue #82 - Sleep random delay to avoid problems with multiple pfSense on same Internet line
    sleep(rand(1, 90));
    
    if ((time() - filemtime($filename) > SPEEDTEST_INTERVAL * 3600) || (file_exists($filename) == false)) {
        // file is older than SPEEDTEST_INTERVAL
        if ((time() - filemtime($filerun) > 180)) @unlink($filerun);

        if (file_exists($filerun) == false) {                          
            touch($filerun);
            $st_command = "/usr/local/bin/speedtest --secure --source $ipaddr --json > $filetemp";
            exec($st_command);
            rename($filetemp, $filename);
            @unlink($filerun);
        }
    }    
    
    return true;
}

// OpenVPN Server Discovery
function pfz_openvpn_get_all_servers() {
    $cache_key = "openvpn_all_servers";
    $cache = pfz_get_cache($cache_key);
    
    if ($cache !== null) {
        return $cache;
    }
    
    include_once_track('openvpn.inc');
    $servers = openvpn_get_active_servers();
    $sk_servers = openvpn_get_active_servers("p2p");
    $servers = array_merge($servers, $sk_servers);
    
    pfz_set_cache($cache_key, $servers);
    return $servers;
}

function pfz_openvpn_serverdiscovery() {
    $servers = pfz_openvpn_get_all_servers();
    
    $json_data = array('data' => array());

    foreach ($servers as $server) {
        $name = trim(preg_replace('/\w{3}(\d)?\:\d{4,5}/i', '', $server['name']));
        $json_data['data'][] = array(
            '{#SERVER}' => $server['vpnid'],
            '{#NAME}' => $name
        );
    }

    echo json_encode($json_data);
}

// Get OpenVPN Server Value with improved reactivity
function pfz_openvpn_servervalue($server_id, $valuekey) {
    // Pour le statut, utiliser une durée de cache ultra-courte
    $force_refresh = ($valuekey == "status");
    $cache_duration = ($valuekey == "status") ? CACHE_DURATION_REALTIME : CACHE_DURATION_MEDIUM;
    
    $cache_key = "openvpn_server_{$server_id}_{$valuekey}";
    $cache = pfz_get_cache($cache_key, $cache_duration, $force_refresh);
    
    if ($cache !== null) {
        echo $cache;
        return;
    }
    
    $servers = pfz_openvpn_get_all_servers();     
    $value = "";
    
    foreach ($servers as $server) {
        if ($server['vpnid'] == $server_id) {
            $value = $server[$valuekey];
            if ($valuekey == "status") {
                if (($server['mode'] == "server_user") || ($server['mode'] == "server_tls_user") || ($server['mode'] == "server_tls")) {
                    if ($value == "") $value = "server_user_listening";                    
                } else if ($server['mode'] == "p2p_tls") {
                    // For p2p_tls, ensure we have one client, and return up if it's the case
                    if ($value == "")
                        $value = (is_array($server["conns"]) && count($server["conns"]) > 0) ? "up" : "down";
                }                  
            }
            break;
        }
    }
     
    switch ($valuekey) {     
        case "conns":
            //Client Connections: is an array so it is sufficient to count elements                    
            if (is_array($value))
                $value = count($value);
            else
                $value = "0";
            break;     
               
        case "status":
            $value = pfz_valuemap("openvpn.server.status", $value);
            break;

        case "mode":
            $value = pfz_valuemap("openvpn.server.mode", $value);
            break;
    }
    
    pfz_set_cache($cache_key, $value);
    echo $value;
}

//OpenVPN Server/User-Auth Discovery
function pfz_openvpn_server_userdiscovery() {
    $servers = pfz_openvpn_get_all_servers();

    $json_data = array('data' => array());

    foreach ($servers as $server) {
        if (($server['mode'] == 'server_user') || ($server['mode'] == 'server_tls_user') || ($server['mode'] == 'server_tls')) {
            if (is_array($server['conns'])) {               
                $name = trim(preg_replace('/\w{3}(\d)?\:\d{4,5}/i', '', $server['name']));
                    
                foreach ($server['conns'] as $conn) {
                    $common_name = pfz_replacespecialchars($conn['common_name']);
                                   
                    $json_data['data'][] = array(
                        '{#SERVERID}' => $server['vpnid'],
                        '{#SERVERNAME}' => $name,
                        '{#UNIQUEID}' => $server['vpnid'] . '+' . $common_name,
                        '{#USERID}' => $conn['common_name']
                    );
                }
            }
        }
    }

    echo json_encode($json_data);
}

// Get OpenVPN User Connected Value
function pfz_openvpn_server_uservalue($unique_id, $valuekey, $default = "") {
    $unique_id = pfz_replacespecialchars($unique_id, true);
    $atpos = strpos($unique_id, '+');
    $server_id = substr($unique_id, 0, $atpos);
    $user_id = substr($unique_id, $atpos + 1);
     
    $servers = pfz_openvpn_get_all_servers();
    foreach ($servers as $server) {
        if ($server['vpnid'] == $server_id) {
            foreach ($server['conns'] as $conn) {               
                if ($conn['common_name'] == $user_id) {
                    $value = $conn[$valuekey];
                    break;
                }
            }               
        }
    }
    if (empty($value)) $value = $default;
    echo $value;
}

// OpenVPN Client Discovery
function pfz_openvpn_clientdiscovery() {
    include_once_track('openvpn.inc');
    $cache_key = "openvpn_clients";
    $cache = pfz_get_cache($cache_key);
    
    if ($cache !== null) {
        echo $cache;
        return;
    }
    
    $clients = openvpn_get_active_clients();

    $json_data = array('data' => array());

    foreach ($clients as $client) {
        $name = trim(preg_replace('/\w{3}(\d)?\:\d{4,5}/i', '', $client['name']));
        $json_data['data'][] = array(
            '{#CLIENT}' => $client['vpnid'],
            '{#NAME}' => $name
        );
    }

    $json_string = json_encode($json_data);
    pfz_set_cache($cache_key, $json_string);
    
    echo $json_string;
}

function pfz_replacespecialchars($inputstr, $reverse = false) {
    $specialchars = ",',\",`,*,?,[,],{,},~,$,!,&,;,(,),<,>,|,#,@,0x0a";
    $specialchars = explode(",", $specialchars);     
    $resultstr = $inputstr;
     
    for ($n = 0; $n < count($specialchars); $n++) {
        if ($reverse == false)
            $resultstr = str_replace($specialchars[$n], '%%' . $n . '%', $resultstr);
        else
            $resultstr = str_replace('%%' . $n . '%', $specialchars[$n], $resultstr);
    }     
     
    return $resultstr;
}

function pfz_openvpn_clientvalue($client_id, $valuekey, $default = "none") {
    include_once_track('openvpn.inc');
    $clients = openvpn_get_active_clients();     
    
    $value = "";
    foreach ($clients as $client) {
        if ($client['vpnid'] == $client_id) {
            $value = $client[$valuekey];
            break;
        }
    }

    switch ($valuekey) {        
        case "status":
            $value = pfz_valuemap("openvpn.client.status", $value);
            break;
    }

    if ($value == "") $value = $default;
    echo $value;
}

// Services Discovery
// 2020-03-27: Added space replace with __ for issue #12
function pfz_services_discovery() {
    include_once_track('service-utils.inc');
    $cache_key = "services_discovery";
    $cache = pfz_get_cache($cache_key);
    
    if ($cache !== null) {
        echo $cache;
        return;
    }
    
    $services = get_services();

    $json_data = array('data' => array());

    foreach ($services as $service) {
        if (!empty($service['name'])) {
            $id = "";               
            //id for OpenVPN               
            if (!empty($service['id'])) $id = "." . $service["id"];
            //zone for Captive Portal
            if (!empty($service['zone'])) $id = "." . $service["zone"];
                              
            $json_data['data'][] = array(
                '{#SERVICE}' => str_replace(" ", "__", $service['name']) . $id,
                '{#DESCRIPTION}' => $service['description']
            );
        }
    }
    
    $json_string = json_encode($json_data);
    pfz_set_cache($cache_key, $json_string);
    
    echo $json_string;
}

// Get service value
// 2020-03-27: Added space replace in service name for issue #12
// 2020-09-28: Corrected Space Replace
function pfz_service_value($name, $value) {
    include_once_track('service-utils.inc');
    
    // Pour les valeurs de statut des services critiques, utiliser un cache ultra-court ou pas de cache
    $is_status_check = ($value == "status");
    $is_critical = pfz_is_critical_service($name);
    $force_refresh = $is_status_check && $is_critical;
    $cache_duration = ($is_status_check && $is_critical) ? CACHE_DURATION_REALTIME : CACHE_DURATION_MEDIUM;
    
    $cache_key = "service_value_{$name}_{$value}";
    $cache = pfz_get_cache($cache_key, $cache_duration, $force_refresh);
    
    if ($cache !== null) {
        echo $cache;
        return;
    }
    
    $services = get_services();     
    $name = str_replace("__", " ", $name);
           
    //List of service which are stopped on CARP Slave.
    //For now this is the best way i found for filtering out the triggers
    //Waiting for a way in Zabbix to use Global Regexp in triggers with items discovery
    $stopped_on_carp_slave = array("haproxy", "radvd", "openvpn.", "openvpn", "avahi");
    
    foreach ($services as $service) {
        $namecfr = $service["name"];
        $carpcfr = $service["name"];          

        //OpenVPN          
        if (!empty($service['id'])) {                           
            $namecfr = $service['name'] . "." . $service["id"];
            $carpcfr = $service['name'] . ".";          
        }

        //Captive Portal
        if (!empty($service['zone'])) {                           
            $namecfr = $service['name'] . "." . $service["zone"];
            $carpcfr = $service['name'] . ".";          
        }          

        if ($namecfr == $name) {
            switch ($value) {
                case "status":
                    $status = get_service_status($service);
                    if ($status == "") $status = 0;
                    pfz_set_cache($cache_key, $status);
                    echo $status;
                    return;

                case "name":
                    pfz_set_cache($cache_key, $namecfr);
                    echo $namecfr;
                    return;

                case "enabled":
                    $enabled = is_service_enabled($service['name']) ? 1 : 0;
                    pfz_set_cache($cache_key, $enabled);
                    echo $enabled;
                    return;

                case "run_on_carp_slave":
                    $run_on_slave = in_array($carpcfr, $stopped_on_carp_slave) ? 0 : 1;
                    pfz_set_cache($cache_key, $run_on_slave);
                    echo $run_on_slave;
                    return;
                    
                default:               
                    $result = $service[$value] ?? 0;
                    pfz_set_cache($cache_key, $result);
                    echo $result;
                    return;
            }
        }                                              
    }

    pfz_set_cache($cache_key, 0);
    echo 0;
}

//Gateway Discovery
function pfz_gw_rawstatus() {
    $cache_key = "gw_rawstatus";
    $cache = pfz_get_cache($cache_key, CACHE_DURATION_SHORT);
    
    if ($cache !== null) {
        echo $cache;
        return;
    }
    
    // Return a Raw Gateway Status, useful for action Scripts (e.g. Update Cloudflare DNS config)
    $gws = return_gateways_status(true);
    $gw_string = "";
    
    foreach ($gws as $gw) {
        $gw_string .= ($gw['name'] . '.' . $gw['status'] . ",");
    }
    
    $gw_string = rtrim($gw_string, ",");
    pfz_set_cache($cache_key, $gw_string);
    
    echo $gw_string;
}

function pfz_gw_discovery() {
    $cache_key = "gw_discovery";
    $cache = pfz_get_cache($cache_key, CACHE_DURATION_SHORT);
    
    if ($cache !== null) {
        echo $cache;
        return;
    }
    
    $gws = return_gateways_status(true);

    $json_data = array('data' => array());
    
    foreach ($gws as $gw) {          
        $json_data['data'][] = array('{#GATEWAY}' => $gw['name']);
    }     
    
    $json_string = json_encode($json_data);
    pfz_set_cache($cache_key, $json_string);
    
    echo $json_string;
}

function pfz_gw_value($gw, $valuekey) {
    // Pour les statuts, utiliser un cache ultra-court
    $cache_duration = ($valuekey == "status") ? CACHE_DURATION_REALTIME : CACHE_DURATION_SHORT;
    
    $cache_key = "gw_value_{$gw}_{$valuekey}";
    $cache = pfz_get_cache($cache_key, $cache_duration);
    
    if ($cache !== null) {
        echo $cache;
        return;
    }
    
    $gws = return_gateways_status(true);
    
    $value = "";
    if (array_key_exists($gw, $gws)) {
        $value = $gws[$gw][$valuekey];
        if ($valuekey == "status") { 
            //Issue #70: Gateway Forced Down
            if ($gws[$gw]["substatus"] != "none") 
                $value = $gws[$gw]["substatus"];
            
            $value = pfz_valuemap("gateway.status", $value);
        }     
    }
    
    pfz_set_cache($cache_key, $value);
    echo $value;
}

// IPSEC Discovery
function pfz_ipsec_discovery_ph1() {
    $cache_key = "ipsec_discovery_ph1";
    $cache = pfz_get_cache($cache_key);
    
    if ($cache !== null) {
        echo $cache;
        return;
    }
    
    $a_phase1 = pfz_get_ipsec_config('phase1');
    
    $json_data = array('data' => array());
    
    foreach ($a_phase1 as $data) {
        $json_data['data'][] = array(
            '{#IKEID}' => $data['ikeid'],
            '{#NAME}' => $data['descr']
        );
    }    

    $json_string = json_encode($json_data);
    pfz_set_cache($cache_key, $json_string);
    
    echo $json_string;
}

// Get cached static configuration values for IPSEC Phase 1
function pfz_get_ipsec_ph1_static_value($ikeid, $valuekey) {
    $cache_key = "ipsec_ph1_static_{$ikeid}_{$valuekey}";
    $cache = pfz_get_cache($cache_key, CACHE_DURATION_STATIC);
    
    if ($cache !== null) {
        return $cache;
    }
    
    $a_phase1 = pfz_get_ipsec_config('phase1');
    
    // Valeurs par défaut selon le type
    if ($valuekey == 'disabled') {
        $value = "0";  // Par défaut un tunnel n'est pas désactivé
    } else if ($valuekey == 'mode' || $valuekey == 'p1mode') {
        $value = "0";  // Par défaut, main mode (0)
    } else if ($valuekey == 'iketype') {
        $value = "0";  // Par défaut, auto (0)
    } else if ($valuekey == 'protocol') {
        $value = "0";  // Par défaut, both (0)
    } else {
        $value = "";
    }
    
    foreach ($a_phase1 as $data) {
        if ($data['ikeid'] == $ikeid) {
            if (array_key_exists($valuekey, $data)) {
                if ($valuekey == 'disabled')
                    $value = "1";
                else
                    $value = pfz_valuemap("ipsec." . $valuekey, $data[$valuekey], $data[$valuekey]);
                break;
            }
        }
    }
    
    pfz_set_cache($cache_key, $value);
    return $value;
}

function pfz_ipsec_ph1($ikeid, $valuekey) {    
    // Pour les valeurs dynamiques (comme le statut), garder un cache séparé avec une durée courte
    if ($valuekey == 'status') {
        $value = pfz_ipsec_status($ikeid);
        echo $value;
        return;
    }
    
    // Pour toutes les autres valeurs (statiques), utiliser le cache groupé
    $values = pfz_get_ipsec_ph1_values($ikeid);
    
    // Cas spécial pour "mode"
    if ($valuekey == 'mode' && empty($values['mode']) && isset($values['p1mode'])) {
        echo $values['p1mode'];
        return;
    }
    
    echo isset($values[$valuekey]) ? $values[$valuekey] : "";
}
    
    pfz_set_cache($cache_key, $value);
    echo $value;
}

function pfz_ipsec_discovery_ph2() {
    $cache_key = "ipsec_discovery_ph2";
    $cache = pfz_get_cache($cache_key);
    
    if ($cache !== null) {
        echo $cache;
        return;
    }
    
    $a_phase2 = pfz_get_ipsec_config('phase2');
    
    $json_data = array('data' => array());
    
    foreach ($a_phase2 as $data) {
        $json_data['data'][] = array(
            '{#IKEID}' => $data['ikeid'],
            '{#NAME}' => $data['descr'],
            '{#UNIQID}' => $data['uniqid'],
            '{#REQID}' => $data['reqid'],
            '{#EXTID}' => $data['ikeid'] . '.' . $data['reqid']
        );
    }    

    $json_string = json_encode($json_data);
    pfz_set_cache($cache_key, $json_string);
    
    echo $json_string;
}

// Get cached static configuration values for IPSEC Phase 2
function pfz_get_ipsec_ph2_static_value($uniqid, $valuekey) {
    $cache_key = "ipsec_ph2_static_{$uniqid}_{$valuekey}";
    $cache = pfz_get_cache($cache_key, CACHE_DURATION_STATIC);
    
    if ($cache !== null) {
        return $cache;
    }
    
    $a_phase2 = pfz_get_ipsec_config('phase2');
    
    // Valeurs par défaut selon le type
    if ($valuekey == 'disabled') {
        $value = "0";  // Par défaut une phase 2 n'est pas désactivée
    } else if ($valuekey == 'mode') {
        $value = "1";  // Par défaut, tunnel mode (1)
    } else if ($valuekey == 'protocol') {
        $value = "1";  // Par défaut, esp (1)
    } else {
        $value = "";
    }
    
    foreach ($a_phase2 as $data) {
        if ($data['uniqid'] == $uniqid) {
            if (array_key_exists($valuekey, $data)) {
                if ($valuekey == 'disabled')
                    $value = "1";
                else
                    $value = pfz_valuemap("ipsec_ph2." . $valuekey, $data[$valuekey], $data[$valuekey]);
                break;
            }
        }
    }
    
    pfz_set_cache($cache_key, $value);
    return $value;
}

function pfz_ipsec_ph2($uniqid, $valuekey) {
    $valuecfr = explode(".", $valuekey);
    
    // Pour les valeurs dynamiques (comme le statut), accès direct sans cache
    if ($valuecfr[0] == 'status') {
        $idarr = explode(".", $uniqid);
        $statuskey = "state";
        if (isset($valuecfr[1])) $statuskey = $valuecfr[1];
        
        $value = pfz_ipsec_status($idarr[0], $idarr[1], $statuskey);
        echo $value;
        return;
    }
    
    // Pour toutes les autres valeurs (statiques), utiliser le cache groupé
    $values = pfz_get_ipsec_ph2_values($uniqid);
    
    echo isset($values[$valuekey]) ? $values[$valuekey] : "";
}
    
    pfz_set_cache($cache_key, $value);
    echo $value;
}

function pfz_ipsec_status($ikeid, $reqid = -1, $valuekey = 'state') {
    $cache_key = "ipsec_status_{$ikeid}_{$reqid}_{$valuekey}";
    // Utiliser un cache ultra-court pour les statuts
    $cache = pfz_get_cache($cache_key, CACHE_DURATION_REALTIME);
    
    if ($cache !== null) {
        return $cache;
    }
    
    include_once_track('ipsec.inc');
    
    global $config;
    $a_phase1 = pfz_get_ipsec_config('phase1');
    
    $conmap = array();
    foreach ($a_phase1 as $ph1ent) {
        if (function_exists('get_ipsecifnum')) {
            if (get_ipsecifnum($ph1ent['ikeid'], 0)) {
                $cname = "con" . get_ipsecifnum($ph1ent['ikeid'], 0);
            } else {
                $cname = "con{$ph1ent['ikeid']}00000";
            }
        } else{
            $cname = ipsec_conid($ph1ent);
        }
        
        $conmap[$cname] = $ph1ent['ikeid'];
    }

    $status = ipsec_list_sa();
    $ipsecconnected = array();
    
    $carp_status = pfz_carp_status(false);
    
    //Phase-Status match borrowed from status_ipsec.php    
    if (is_array($status)) {        
        foreach ($status as $l_ikeid => $ikesa) {
            
            if (isset($ikesa['con-id'])) {
                $con_id = substr($ikesa['con-id'], 3);
            } else {
                $con_id = filter_var($l_ikeid, FILTER_SANITIZE_NUMBER_INT);
            }
            $con_name = "con" . $con_id;
            if ($ikesa['version'] == 1) {
                $ph1idx = $conmap[$con_name];
                $ipsecconnected[$ph1idx] = $ph1idx;
            } else {
                if (!ipsec_ikeid_used($con_id)) {
                    // probably a v2 with split connection then
                    $ph1idx = $conmap[$con_name];
                    $ipsecconnected[$ph1idx] = $ph1idx;
                } else {
                    $ipsecconnected[$con_id] = $ph1idx = $con_id;
                }
            }
            if ($ph1idx == $ikeid){
                if ($reqid != -1) {
                    // Asking for Phase2 Status Value
                    foreach ($ikesa['child-sas'] as $childsas) {
                        if ($childsas['reqid'] == $reqid) {
                            if (strtolower($childsas['state']) == 'rekeyed') {
                                //if state is rekeyed go on
                                $tmp_value = $childsas[$valuekey];
                            } else {
                                $tmp_value = $childsas[$valuekey];
                                break;
                            }
                        }                        
                    }
                } else {
                    $tmp_value = $ikesa[$valuekey];
                }
                                
                break;
            }            
        }    
    }
    
    switch($valuekey) {
        case 'state':
            $value = pfz_valuemap('ipsec.state', strtolower($tmp_value));
            if ($carp_status != 0) $value = $value + (10 * ($carp_status-1));                        
            break;
        default:
            $value = $tmp_value;
            break;
    }
    
    pfz_set_cache($cache_key, $value);
    return $value;
}

// Temperature sensors Discovery - optimized to run sysctl only once
function pfz_temperature_sensors_discovery() {
    $cache_key = "temperature_sensors_discovery";
    $cache = pfz_get_cache($cache_key);
    
    if ($cache !== null) {
        echo $cache;
        return;
    }
    
    $json_data = array('data' => array());
    $sensors = array();
    exec("sysctl -a | grep temperature | cut -d ':' -f 1", $sensors, $code);
    
    if ($code == 0) {
        foreach ($sensors as $sensor) {
            $json_data['data'][] = array('{#SENSORID}' => $sensor);
        }
    }

    $json_string = json_encode($json_data);
    pfz_set_cache($cache_key, $json_string);
    
    echo $json_string;
}

// Temperature sensor get value with caching
function pfz_get_temperature($sensorid) {
    $cache_key = "temperature_{$sensorid}";
    $cache = pfz_get_cache($cache_key, CACHE_DURATION_SHORT);
    
    if ($cache !== null) {
        echo $cache;
        return;
    }
    
    exec("sysctl '$sensorid' | cut -d ':' -f 2", $value, $code);
    
    if ($code == 0 && count($value) == 1) {
        $result = trim($value[0]);
        pfz_set_cache($cache_key, $result);
        echo $result;
    } else {
        echo "";
    }
}

function pfz_carp_status($echo = true) {
    //Detect CARP Status
    $cache_key = "carp_status";
    $cache = pfz_get_cache($cache_key, CACHE_DURATION_SHORT);
    
    if ($cache !== null) {
        if ($echo) echo $cache;
        return $cache;
    }
    
    global $config;
    $status_return = 0;
    $status = get_carp_status();
    $carp_detected_problems = get_single_sysctl("net.inet.carp.demotion");

    //CARP is disabled
    $ret = 0;
     
    if ($status != 0) { //CARP is enabled
        if ($carp_detected_problems != 0) {                              
            //There's some Major Problems with CARP
            $ret = 4;
            if ($echo) echo $ret;   
            pfz_set_cache($cache_key, $ret);
            return $ret;
        }
                    
        $status_changed = false;
        $prev_status = "";
        foreach ($config['virtualip']['vip'] as $carp) {
            if ($carp['mode'] != "carp") {
                continue;
            }
            $if_status = get_carp_interface_status("_vip{$carp['uniqid']}");

            if (($prev_status != $if_status) && (!empty($if_status))) { //Some glitches with GUI
                if ($prev_status != "") $status_changed = true;
                $prev_status = $if_status;
            }
        }          
        
        if ($status_changed) {
            //CARP Status is inconsistent across interfaces
            $ret = 3;
        } else {
            if ($prev_status == "MASTER")
                $ret = 1;                    
            else
                $ret = 2;
        }      
    }
    
    pfz_set_cache($cache_key, $ret);
    if ($echo) echo $ret;   
    return $ret;
}

// DHCP Checks (copy of status_dhcp_leases.php, waiting for pfsense 2.5)
function pfz_remove_duplicate($array, $field) {
    foreach ($array as $sub) {
        $cmp[] = $sub[$field];
    }
    $unique = array_unique(array_reverse($cmp, true));
    foreach ($unique as $k => $rien) {
        $new[] = $array[$k];
    }
    return $new;
}

// Get DHCP Arrays (optimized to avoid repeated processing)
function pfz_dhcp_get($valuekey) {
    $cache_key = "dhcp_get_{$valuekey}";
    $cache = pfz_get_cache($cache_key);
    
    if ($cache !== null) {
        return $cache;
    }
    
    include_once_track("config.inc");
    global $g;
    
    $leasesfile = "{$g['dhcpd_chroot_path']}/var/db/dhcpd.leases";

    $awk = "/usr/bin/awk";
    /* this pattern sticks comments into a single array item */
    $cleanpattern = "'{ gsub(\"#.*\", \"\");} { gsub(\";\", \"\"); print;}'";
    /* We then split the leases file by } */
    $splitpattern = "'BEGIN { RS=\"}\";} {for (i=1; i<=NF; i++) printf \"%s \", \$i; printf \"}\\n\";}'";

    /* stuff the leases file in a proper format into a array by line */
    @exec("/bin/cat {$leasesfile} 2>/dev/null| {$awk} {$cleanpattern} | {$awk} {$splitpattern}", $leases_content);
    
    // Get arp cache once to avoid multiple calls
    @exec("/usr/sbin/arp -an", $rawdata);
    $arpdata_ip = array();
    foreach ($rawdata as $line) {
        if (preg_match("/^\S+\s+\((\S+)\)\s+at\s+/", $line, $matches)) {
            $arpdata_ip[] = $matches[1];
        }
    }

    $leases = array();
    $pools = array();
    
    $i = 0;
    $l = 0;
    $p = 0;

    // Define here to avoid warnings
    $active_string = "active";
    $expired_string = "expired";
    $reserved_string = "reserved";
    $online_string = "online";
    $offline_string = "offline";
    $dynamic_string = "dynamic";

    foreach ($leases_content as $lease) {
        /* split the line by space */
        $data = explode(" ", $lease);
        /* walk the fields */
        $f = 0;
        $fcount = count($data);
        /* with less than 20 fields there is nothing useful */
        if ($fcount < 20) {
            $i++;
            continue;
        }
        while ($f < $fcount) {
            switch ($data[$f]) {
                case "failover":
                    $pools[$p]['name'] = trim($data[$f+2], '"');
                    $pools[$p]['name'] = "{$pools[$p]['name']} (" . convert_friendly_interface_to_friendly_descr(substr($pools[$p]['name'], 5)) . ")";
                    $pools[$p]['mystate'] = $data[$f+7];
                    $pools[$p]['peerstate'] = $data[$f+14];
                    $pools[$p]['mydate'] = $data[$f+10];
                    $pools[$p]['mydate'] .= " " . $data[$f+11];
                    $pools[$p]['peerdate'] = $data[$f+17];
                    $pools[$p]['peerdate'] .= " " . $data[$f+18];
                    $p++;
                    $i++;
                    continue 3;
                case "lease":
                    $leases[$l]['ip'] = $data[$f+1];
                    $leases[$l]['type'] = $dynamic_string;
                    $f = $f+2;
                    break;
                case "starts":
                    $leases[$l]['start'] = $data[$f+2];
                    $leases[$l]['start'] .= " " . $data[$f+3];
                    $f = $f+3;
                    break;
                case "ends":
                    if ($data[$f+1] == "never") {
                        // Quote from dhcpd.leases(5) man page:
                        // If a lease will never expire, date is never instead of an actual date.
                        $leases[$l]['end'] = "Never";
                        $f = $f+1;
                    } else {
                        $leases[$l]['end'] = $data[$f+2];
                        $leases[$l]['end'] .= " " . $data[$f+3];
                        $f = $f+3;
                    }
                    break;
                case "tstp":
                    $f = $f+3;
                    break;
                case "tsfp":
                    $f = $f+3;
                    break;
                case "atsfp":
                    $f = $f+3;
                    break;
                case "cltt":
                    $f = $f+3;
                    break;
                case "binding":
                    switch ($data[$f+2]) {
                        case "active":
                            $leases[$l]['act'] = $active_string;
                            break;
                        case "free":
                            $leases[$l]['act'] = $expired_string;
                            $leases[$l]['online'] = $offline_string;
                            break;
                        case "backup":
                            $leases[$l]['act'] = $reserved_string;
                            $leases[$l]['online'] = $offline_string;
                            break;
                    }
                    $f = $f+1;
                    break;
                case "next":
                    /* skip the next binding statement */
                    $f = $f+3;
                    break;
                case "rewind":
                    /* skip the rewind binding statement */
                    $f = $f+3;
                    break;
                case "hardware":
                    $leases[$l]['mac'] = $data[$f+2];
                    /* check if it's online and the lease is active */
                    if (in_array($leases[$l]['ip'], $arpdata_ip)) {
                        $leases[$l]['online'] = $online_string;
                    } else {
                        $leases[$l]['online'] = $offline_string;
                    }
                    $f = $f+2;
                    break;
                case "client-hostname":
                    if ($data[$f+1] <> "") {
                        $leases[$l]['hostname'] = preg_replace('/"/', '', $data[$f+1]);
                    } else {
                        $hostname = gethostbyaddr($leases[$l]['ip']);
                        if ($hostname <> "") {
                            $leases[$l]['hostname'] = $hostname;
                        }
                    }
                    $f = $f+1;
                    break;
                case "uid":
                    $f = $f+1;
                    break;
            }
            $f++;
        }
        $l++;
        $i++;
    }
    
    /* remove duplicate items by mac address */
    if (count($leases) > 0) {
        $leases = pfz_remove_duplicate($leases, "ip");
    }

    if (count($pools) > 0) {
        $pools = pfz_remove_duplicate($pools, "name");
        asort($pools);
    }

    $result = null;
    switch ($valuekey) {
        case "pools":
            $result = $pools;
            break;
        case "failover":
            $result = $failover ?? array();
            break;
        case "leases":
        default:
            $result = $leases;        
    }
    
    pfz_set_cache($cache_key, $result);
    return $result;
}

function pfz_dhcpfailover_discovery() {
    $cache_key = "dhcpfailover_discovery";
    $cache = pfz_get_cache($cache_key);
    
    if ($cache !== null) {
        echo $cache;
        return;
    }
    
    //System functions regarding DHCP Leases will be available in the upcoming release of pfSense, so let's wait
    include_once_track("system.inc");
    $leases = system_get_dhcpleases();
    
    $json_data = array('data' => array());
    
    if (count($leases['failover']) > 0) {
        foreach ($leases['failover'] as $data) {
            $json_data['data'][] = array('{#FAILOVER_GROUP}' => str_replace(" ", "__", $data['name']));          
        }
    }

    $json_string = json_encode($json_data);
    pfz_set_cache($cache_key, $json_string);
    
    echo $json_string;
}

function pfz_dhcp_check_failover() {
    $cache_key = "dhcp_check_failover";
    $cache = pfz_get_cache($cache_key, CACHE_DURATION_SHORT);
    
    if ($cache !== null) {
        return $cache;
    }
    
    // Check DHCP Failover Status
    // Returns number of failover pools which state is not normal or
    // different than peer state
    $failover = pfz_dhcp_get("failover");
    $ret = 0;
    
    foreach ($failover as $f) {
        if (($f["mystate"] != "normal") || ($f["mystate"] != $f["peerstate"])) {
            $ret++;
        }
    }        
    
    pfz_set_cache($cache_key, $ret);
    return $ret;    
}

function pfz_dhcp($section, $valuekey = "") {
    switch ($section) {
        case "failover":
            echo pfz_dhcp_check_failover();
            break;
        default:        
    }
}

//Packages - optimized to check package updates
function pfz_packages_uptodate() {
    $cache_key = "packages_uptodate";
    $cache = pfz_get_cache($cache_key, CACHE_DURATION_LONG);
    
    if ($cache !== null) {
        return $cache;
    }
    
    include_once_track("pkg-utils.inc");
    $installed_packages = get_pkg_info('all', false, true);
        
    $ret = 0;
    foreach ($installed_packages as $package) {
        if ($package['version'] != $package['installed_version']) {
            $ret++;
        }
    }
    
    pfz_set_cache($cache_key, $ret);
    return $ret;
}

function pfz_syscheck_cron_install($enable = true) {
    include_once_track("services.inc");
    //Install Cron Job
    $command = "/usr/local/bin/php " . __FILE__ . " syscheck_cron";
    install_cron_job($command, $enable, $minute = "0", "*/8", "*", "*", "*", "root", true);

    // FIX previous, wrong-coded install command
    $command = "/usr/local/bin/php " . __FILE__ . " systemcheck_cron";
    install_cron_job($command, false, $minute = "0", "9,21", "*", "*", "*", "root", true);
}    

// System information takes a long time to get on slower systems. 
// So it is saved via a cronjob.
function pfz_syscheck_cron() {    
    $filename = "/tmp/sysversion.json";    
    $upToDate = pfz_packages_uptodate();
    $sysVersion = get_system_pkg_version();
    $sysVersion["packages_update"] = $upToDate;
    $sysVersionJson = json_encode($sysVersion);
    
    if (file_exists($filename)) {
        if ((time() - filemtime($filename) > CRON_TIME_LIMIT)) {
            @unlink($filename);
        }
    }
    
    if (file_exists($filename) == false) {      
        touch($filename);
        file_put_contents($filename, $sysVersionJson);
    }    
    
    return true;
} 

//System Information
function pfz_get_system_value($section) {
    $filename = "/tmp/sysversion.json";    
    if (file_exists($filename)) {
        $sysVersion = json_decode(file_get_contents($filename), true);
    } else {
        // Install the cron script
        pfz_syscheck_cron_install();
        if ($section == "new_version_available") {
            echo "0";
        } else {
            echo "";
        }
        return;
    }
    
    switch ($section) {
        case "script_version":
            echo SCRIPT_VERSION;
            break;
        case "version":
            echo($sysVersion['version']);
            break;
        case "installed_version":
            echo($sysVersion['installed_version']);
            break;
        case "new_version_available":
            if ($sysVersion['version'] == $sysVersion['installed_version'])
                echo "0";
            else
                echo "1";
            break;
        case "packages_update":
            echo $sysVersion["packages_update"];
            break;
    }
}

//S.M.A.R.T Status
// Taken from /usr/local/www/widgets/widgets/smart_status.widget.php
function pfz_get_smart_status() {
    $cache_key = "smart_status";
    $cache = pfz_get_cache($cache_key, CACHE_DURATION_MEDIUM);
    
    if ($cache !== null) {
        echo $cache;
        return;
    }

    $devs = get_smart_drive_list();
    $status = 0;
    
    foreach ($devs as $dev) { ## for each found drive do                
        $smartdrive_is_displayed = true;
        // Instead of calling diskinfo and smartctl separately for each drive, 
        // we could optimize by collecting all drive info at once, but for now we'll keep this logic
        $dev_state = trim(exec("smartctl -H /dev/$dev | awk -F: '/^SMART overall-health self-assessment test result/ {print $2;exit}
/^SMART Health Status/ {print $2;exit}'"));
        
        switch ($dev_state) {
            case "PASSED":
            case "OK":
                //OK
                $status = 0;                                
                break;
            case "":
                //Unknown
                $status = 2;
                pfz_set_cache($cache_key, $status);
                echo $status;
                return;
            default:
                //Error
                $status = 1;
                pfz_set_cache($cache_key, $status);
                echo $status;
                return;
        }
    }
    
    pfz_set_cache($cache_key, $status);
    echo $status;
}

function pfz_get_revoked_cert_refs() {
    $cache_key = "revoked_cert_refs";
    $cache = pfz_get_cache($cache_key);
    
    if ($cache !== null) {
        return $cache;
    }
    
    global $config;    
    $revoked_cert_refs = array();
    
    if (isset($config["crl"])) {
        foreach ($config["crl"] as $crl) {
            if (isset($crl["cert"])) {
                foreach ($crl["cert"] as $revoked_cert) {
                    $revoked_cert_refs[] = $revoked_cert["refid"];
                }
            }
        }
    }
    
    pfz_set_cache($cache_key, $revoked_cert_refs);
    return $revoked_cert_refs;
}

// Certificate discovery
function pfz_cert_discovery() {
    $cache_key = "cert_discovery";
    $cache = pfz_get_cache($cache_key);
    
    if ($cache !== null) {
        echo $cache;
        return;
    }
    
    global $config;
    // Contains a list of refs that were revoked and should not be considered
    $revoked_cert_refs = pfz_get_revoked_cert_refs();
    
    $json_data = array('data' => array());
    
    foreach (array("cert", "ca") as $cert_type) {
        if (isset($config[$cert_type])) {
            foreach ($config[$cert_type] as $i => $cert) {
                if (!in_array($cert['refid'], $revoked_cert_refs)) {
                    $json_data['data'][] = array(
                        '{#CERT_INDEX}' => $cert_type == "cert" ? $i : $i + 0x10000,
                        '{#CERT_REFID}' => $cert['refid'],
                        '{#CERT_NAME}' => $cert['descr'],
                        '{#CERT_TYPE}' => strtoupper($cert_type)
                    );
                }
            }
        }
    }
    
    $json_string = json_encode($json_data);
    pfz_set_cache($cache_key, $json_string);
    
    echo $json_string;
}

function pfz_get_cert_info($index) {
    // Use a cache file to speed up multiple requests for certificate things. 
    $cacheFile = "/root/.ssl/certinfo_{$index}.json";
    if (file_exists($cacheFile) && (time() - filemtime($cacheFile) < 300)) {
        return json_decode(file_get_contents($cacheFile), true);        
    }
    
    global $config;    
    if ($index >= 0x10000) {
        $index -= 0x10000;
        $certType = "ca";
    } else {
        $certType = "cert";
    }
    
    if (!isset($config[$certType][$index]["crt"])) {
        return array();
    }
    
    $certinfo = openssl_x509_parse(base64_decode($config[$certType][$index]["crt"]));    
    
    # Don't allow other users access to private keys. 
    if (file_exists($cacheFile)) {
        unlink($cacheFile);
    }
    
    if (!is_dir('/root/.ssl')) {
        mkdir('/root/.ssl');
    }
    
    touch($cacheFile);
    chmod($cacheFile, 0600); 
    
    if (!file_put_contents($cacheFile, json_encode($certinfo))) {
        unlink($cacheFile);
    }    
    
    return $certinfo;    
}

function pfz_get_cert_pkey_info($index) {
    $details = array();
    
    $cacheFile = "/root/.ssl/certinfo_pk_{$index}.json";
    if (file_exists($cacheFile) && (time() - filemtime($cacheFile) < 300)) {
        return json_decode(file_get_contents($cacheFile), true);        
    }
    
    global $config;    
    if ($index >= 0x10000) {
        $index -= 0x10000;
        $certType = "ca";
    } else {
        $certType = "cert";
    }
    
    if (!isset($config[$certType][$index]["crt"])) {
        return array();
    }
    
    $cert_key = $config[$certType][$index]["crt"];
    if ($cert_key != false) {
        $publicKey = openssl_pkey_get_public(base64_decode($cert_key));
        $details = openssl_pkey_get_details($publicKey);    
        
        # Don't allow other users access to private keys. 
        if (file_exists($cacheFile)) {
            unlink($cacheFile);
        }
        
        if (!is_dir('/root/.ssl')) {
            mkdir('/root/.ssl');
        }
        
        touch($cacheFile);
        chmod($cacheFile, 0600); 
        
        if (!file_put_contents($cacheFile, json_encode($details))) {
            unlink($cacheFile);
        }
    }    
    
    return $details;
}

function pfz_get_ref_cert_algo_len($index) {
    $pkInfo = pfz_get_cert_pkey_info($index);
    echo isset($pkInfo["bits"]) ? $pkInfo["bits"] : "";
}

# Get the number of bits of security in a cryptographic key. 
function pfz_get_ref_cert_algo_bits($index) {
    $pkInfo = pfz_get_cert_pkey_info($index);
    
    if (!isset($pkInfo["bits"]) || !isset($pkInfo["type"])) {
        echo "";
        return;
    }
    
    $keyLength = $pkInfo["bits"];
    $bits = 0;
    
    switch ($pkInfo["type"]) {
        case(OPENSSL_KEYTYPE_RSA): 
        case(OPENSSL_KEYTYPE_DSA): 
        case(OPENSSL_KEYTYPE_DH): 
            ## See articles on the General Number Field Sieve L-notation complexity.
            $bits = floor(1 / log(2) * pow(64/9, 1/3) * pow($keyLength * log(2), 1/3) * pow(log(2048 * log(2)), 2/3));
            break;
        case (OPENSSL_KEYTYPE_EC): 
            ## Divide by two, floor, via right-shift.
            $bits = $keyLength >> 1;
            break;
    }
    
    echo $bits;
}

function pfz_get_ref_cert_algo($index) {
    $pkInfo = pfz_get_cert_pkey_info($index);
    
    if (!isset($pkInfo["type"])) {
        echo "";
        return;
    }
    
    switch ($pkInfo["type"]) {
        case(OPENSSL_KEYTYPE_RSA): 
            echo "RSA";
            break;
        case(OPENSSL_KEYTYPE_DSA): 
            echo "DSA";
            break;
        case(OPENSSL_KEYTYPE_DH): 
            echo "DH";
            break;
        case(OPENSSL_KEYTYPE_EC): 
            echo "EC";
            break;
        default:
            echo "";
    }
}

function pfz_get_ref_cert_hash_bits($index) {
    // Get the number of bits of security in the hash algorithm.
    $certinfo = pfz_get_cert_info($index);
    
    if (!isset($certinfo["signatureTypeSN"])) {
        echo "0";
        return;
    }
    
    $sigType = $certinfo["signatureTypeSN"];
    $upperSigType = strtoupper($sigType);
    
    if (str_contains($upperSigType, "MD2")) {
        echo 63; 
        return;        
    }
    if (str_contains($upperSigType, "MD4")) {
        echo 2; 
        return;        
    }
    if (str_contains($upperSigType, "MD5")) {
        echo 18;
        return;
    }
    if (str_contains($upperSigType, "SHA1")) {
        echo 61;
        return;        
    }
    if (str_contains($upperSigType, "SHA224")) {
        echo 112;
        return;        
    }
    if (str_contains($upperSigType, "SHA3-224")) {
        echo 112;
        return;        
    }
    if (str_contains($upperSigType, "SHA256")) {
        echo 128;
        return;        
    }
    if (str_contains($upperSigType, "SHA3-256")) {
        echo 128;
        return;        
    }
    if (str_contains($upperSigType, "SHAKE128")) {
        echo 128;
        return;        
    }
    if (str_contains($upperSigType, "SHA384")) {
        echo 192;
        return;        
    }
    if (str_contains($upperSigType, "SHA3-384")) {
        echo 192;
        return;        
    }
    if (str_contains($upperSigType, "SHA512")) {
        echo 256;
        return;        
    }
    if (str_contains($upperSigType, "SHA3-512")) {
        echo 256;
        return;        
    }
    if (str_contains($upperSigType, "SHAKE256")) {
        echo 256;
        return;        
    }
    if (str_contains($upperSigType, "WHIRLPOOL")) {
        echo 256;
        return;        
    }
    if (str_contains($upperSigType, "SHA")) {
        # Assuming 'SHA1' (worst case scenario) for other 'sha' things.
        echo 61;
        return;        
    }
    echo 0;
}

function pfz_get_ref_cert_hash($index) {
    $certinfo = pfz_get_cert_info($index);
    echo isset($certinfo["signatureTypeSN"]) ? $certinfo["signatureTypeSN"] : "";
}

// Certificate validity for a specific certificate
function pfz_get_ref_cert_date($valuekey, $index) {
    $certinfo = pfz_get_cert_info($index);
    
    $value = "";
    switch ($valuekey) {
        case "validFrom":
            if (isset($certinfo['validFrom_time_t'])) {
                $value = $certinfo['validFrom_time_t'];
            }
            break;
        case "validTo":
            if (isset($certinfo['validTo_time_t'])) {
                $value = $certinfo['validTo_time_t'];
            }
            break;
    }
    
    echo $value;    
}

// Certificates validity date
function pfz_get_cert_date($valuekey) {
    $cache_key = "cert_date_{$valuekey}";
    $cache = pfz_get_cache($cache_key);
    
    if ($cache !== null) {
        echo $cache;
        return;
    }
    
    global $config;    
    // Contains a list of refs that were revoked and should not be considered
    $revoked_cert_refs = pfz_get_revoked_cert_refs();    
    $value = 0;
    
    foreach (array("cert", "ca") as $cert_type) {
        if (isset($config[$cert_type])) {
            switch ($valuekey) {
                case "validFrom.max":
                    foreach ($config[$cert_type] as $cert) {
                        if (!in_array($cert['refid'], $revoked_cert_refs)) {
                            $certinfo = openssl_x509_parse(base64_decode($cert["crt"]));
                            if ($value == 0 || $value < $certinfo['validFrom_time_t']) {
                                $value = $certinfo['validFrom_time_t'];
                            }
                        }
                    }
                    break;
                case "validTo.min":
                    foreach ($config[$cert_type] as $cert) {
                        if (!in_array($cert['refid'], $revoked_cert_refs)) {
                            $certinfo = openssl_x509_parse(base64_decode($cert["crt"]));
                            if ($value == 0 || $value > $certinfo['validTo_time_t']) {
                                $value = $certinfo['validTo_time_t'];
                            }
                        }
                    }
                    break;
            }
        }
    }
    
    pfz_set_cache($cache_key, $value);
    echo $value;
}

// File is present
function pfz_file_exists($filename) {
    echo file_exists($filename) ? "1" : "0";
}

// Value mappings
// Each value map is represented by an associative array
function pfz_valuemap($valuename, $value, $default = "0") {
    static $valuemaps = null;
    
    if ($valuemaps === null) {
        // Initialize all value maps at once to avoid repeating the same data
        $valuemaps = array(
            "openvpn.server.status" => array(
                "down" => "0",
                "up" => "1",
                "connected (success)" => "1",
                "none" => "2",
                "reconnecting; ping-restart" => "3",
                "waiting" => "4",
                "server_user_listening" => "5"
            ),
            "openvpn.client.status" => array(
                "up" => "1",
                "connected (success)" => "1",
                "down" => "0",
                "none" => "0",
                "reconnecting; ping-restart" => "2"
            ),
            "openvpn.server.mode" => array(
                "p2p_tls" => "1",
                "p2p_shared_key" => "2",
                "server_tls" => "3",
                "server_user" => "4",
                "server_tls_user" => "5"
            ),
            "gateway.status" => array(
                "online" => "0",
                "none" => "0",
                "loss" => "1",
                "highdelay" => "2",
                "highloss" => "3",
                "force_down" => "4",
                "down" => "5"
            ),
            "ipsec.iketype" => array(
                "auto" => 0,
                "ikev1" => 1,
                "ikev2" => 2
            ),
            "ipsec.mode" => array(
                "main" => 0,
                "aggressive" => 1
            ),
            "ipsec.protocol" => array(
                "both" => 0,
                "inet" => 1,
                "inet6" => 2
            ),
            "ipsec_ph2.mode" => array(
                "transport" => 0,
                "tunnel" => 1,
                "tunnel6" => 2
            ),
            "ipsec_ph2.protocol" => array(
                "esp" => 1,
                "ah" => 2
            ),
            "ipsec.state" => array(
                "established" => 1,
                "connecting" => 2,
                "installed" => 1,
                "rekeyed" => 2
            )
        );
    }

    if (isset($valuemaps[$valuename])) {
        $value = strtolower($value);
        if (isset($valuemaps[$valuename][$value])) {
            return $valuemaps[$valuename][$value];
        }
    }
    
    return $default;
}

//Argument parsers for Discovery
function pfz_discovery($section) {
    switch (strtolower($section)) { 
        case "certificates":
            pfz_cert_discovery();
            break;    
        case "gw":
            pfz_gw_discovery();
            break;
        case "wan":
            pfz_interface_discovery(true);
            break;
        case "openvpn_server":
            pfz_openvpn_serverdiscovery();
            break;
        case "openvpn_server_user":
            pfz_openvpn_server_userdiscovery();
            break;
        case "openvpn_client":
            pfz_openvpn_clientdiscovery();
            break;
        case "services":
            pfz_services_discovery();
            break;
        case "interfaces":
            pfz_interface_discovery();
            break;
        case "ipsec_ph1":
            pfz_ipsec_discovery_ph1();
            break;
        case "ipsec_ph2":
            pfz_ipsec_discovery_ph2();
            break;
        case "dhcpfailover":
            pfz_dhcpfailover_discovery();
            break;
        case "temperature_sensors":
            pfz_temperature_sensors_discovery();
            break;
    }         
}

function pfz_clean_old_cache($max_age = 86400) {
    if (!is_dir(CACHE_DIR)) return 0;
    
    $files = glob(CACHE_DIR . '/*.cache');
    $now = time();
    $count = 0;
    
    foreach ($files as $file) {
        if ($now - filemtime($file) > $max_age) {
            unlink($file);
            $count++;
        }
    }
    
    return $count;
}

//Main Code
$mainArgument = isset($argv[1]) ? strtolower($argv[1]) : '';

if (substr($mainArgument, -4, 4) == "cron") {
    // A longer time limit for cron tasks.
    set_time_limit(CRON_TIME_LIMIT);
    
    // Nettoyer les vieux caches lors des exécutions cron
    if (rand(1, 10) == 1) { // ~10% de chance d'exécution pour éviter de le faire à chaque fois
        pfz_clean_old_cache(86400 * 7); // Nettoyer les caches plus vieux que 7 jours
    }
} else {
    // Set a timeout to prevent a blocked call from stopping all future calls.
    set_time_limit(DEFAULT_TIME_LIMIT);
}

switch ($mainArgument) {     
    case "discovery":
        pfz_discovery($argv[2]);
        break;
    case "gw_value":
        pfz_gw_value($argv[2], $argv[3]);
        break;     
    case "gw_status":
        pfz_gw_rawstatus();
        break;
    case "if_speedtest_value":
        pfz_speedtest_cron_install();
        pfz_interface_speedtest_value($argv[2], $argv[3]);
        break;
    case "openvpn_servervalue":
        pfz_openvpn_servervalue($argv[2], $argv[3]);
        break;
    case "openvpn_server_uservalue":
        pfz_openvpn_server_uservalue($argv[2], $argv[3]);
        break;
    case "openvpn_server_uservalue_numeric":
        pfz_openvpn_server_uservalue($argv[2], $argv[3], "0");
        break;
    case "openvpn_clientvalue":
        pfz_openvpn_clientvalue($argv[2], $argv[3]);
        break;
    case "service_value":
        pfz_service_value($argv[2], $argv[3]);
        break;
    case "carp_status":
        pfz_carp_status();
        break;
    case "if_name":
        pfz_get_if_name($argv[2]);
        break;
    case "syscheck_cron":
        pfz_syscheck_cron_install();
        pfz_syscheck_cron();
        break;
    case "system":
        pfz_get_system_value($argv[2]);
        break;
    case "ipsec_ph1":
        pfz_ipsec_ph1($argv[2], $argv[3]);
        break;
    case "ipsec_ph2":
        pfz_ipsec_ph2($argv[2], $argv[3]);
        break;
    case "dhcp":
        pfz_dhcp($argv[2], $argv[3]);
        break;
    case "file_exists":
        pfz_file_exists($argv[2]);
        break;
    case "speedtest_cron":
        pfz_speedtest_cron_install();
        pfz_speedtest_cron();
        break;
    case "syscheck_cron":
        pfz_syscheck_cron_install();
        pfz_syscheck_cron();
        break;
    case "cron_cleanup":
        pfz_speedtest_cron_install(false);
        pfz_syscheck_cron_install(false);
        break;
    case "smart_status":
        pfz_get_smart_status();
        break;     
    case "cert_ref_date":
        pfz_get_ref_cert_date($argv[2], $argv[3]);
        break;      
    case "cert_date":
        pfz_get_cert_date($argv[2]);
        break;   
    case "cert_algo":
        pfz_get_ref_cert_algo($argv[2]);
        break;    
    case "cert_algo_bits":
        pfz_get_ref_cert_algo_len($argv[2]);
        break;    
    case "cert_algo_secbits":
        pfz_get_ref_cert_algo_bits($argv[2]);
        break;    
    case "cert_hash":
        pfz_get_ref_cert_hash($argv[2]);
        break;    
    case "cert_hash_secbits":
        pfz_get_ref_cert_hash_bits($argv[2]);
        break;              
    case "temperature":
        pfz_get_temperature($argv[2]);
        break;
    case "clear_cache":
        // Added a way to clear the cache
        if (is_dir(CACHE_DIR)) {
            $files = glob(CACHE_DIR . '/*.cache');
            foreach ($files as $file) {
                unlink($file);
            }
            echo "Cache cleared\n";
        }
        break;
    case "cache_stats":
        // Afficher des statistiques sur les fichiers cache
        if (is_dir(CACHE_DIR)) {
            $files = glob(CACHE_DIR . '/*.cache');
            $group_count = 0;
            $normal_count = 0;
            $total_size = 0;
            
            foreach ($files as $file) {
                $total_size += filesize($file);
                if (strpos(basename($file), 'group_') === 0) {
                    $group_count++;
                } else {
                    $normal_count++;
                }
            }
            
            echo "Cache Statistics:\n";
            echo "  Group cache files: " . $group_count . "\n";
            echo "  Normal cache files: " . $normal_count . "\n";
            echo "  Total cache files: " . count($files) . "\n";
            echo "  Total cache size: " . round($total_size / 1024, 2) . " KB\n";
            
            // Fichiers les plus volumineux
            usort($files, function($a, $b) {
                return filesize($b) - filesize($a);
            });
            
            echo "  Top 5 largest cache files:\n";
            for ($i = 0; $i < min(5, count($files)); $i++) {
                echo "    " . basename($files[$i]) . ": " . round(filesize($files[$i]) / 1024, 2) . " KB\n";
            }
        }
        break;
    default:
        pfz_test();
}
