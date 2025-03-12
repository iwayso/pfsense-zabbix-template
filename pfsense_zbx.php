<?php
/*** 
pfsense_zbx.php - pfSense Zabbix Interface
Version 0.24.8 - 2025-03-12 (optimisé)

Written by Riccardo Bicelli <r.bicelli@gmail.com>
This program is licensed under Apache 2.0 License
*/

// Définitions utiles
define('SCRIPT_VERSION', '0.24.8');
define('SPEEDTEST_INTERVAL', 8); // Intervalle de speedtest en heures
define('CRON_TIME_LIMIT', 300); // Limite de temps pour speedtest et sysinfo (secondes)
define('DEFAULT_TIME_LIMIT', 30); // Limite de temps par défaut (secondes)

require_once('globals.inc');
require_once('functions.inc');
require_once('config.inc');
require_once('util.inc');
require_once('interfaces.inc');
require_once('openvpn.inc');
require_once('service-utils.inc');
require_once('pkg-utils.inc');

// Backport pour PHP 8
if (!function_exists('str_contains')) {
    function str_contains($haystack, $needle) {
        return strstr($haystack, $needle) !== false;
    }
}

// Fonction de test pour la création de templates
function pfz_test() {
    $line = "-------------------\n";
    echo "OPENVPN Servers:\n"; print_r(pfz_openvpn_get_all_servers()); echo $line;
    echo "OPENVPN Clients:\n"; print_r(openvpn_get_active_clients()); echo $line;
    echo "Network Interfaces:\n"; print_r(pfz_interface_discovery(false, true)); echo $line;
    echo "Services:\n"; print_r(get_services()); echo $line;
    echo "IPsec:\n"; require_once("ipsec.inc"); global $config;
    init_config_arr(['ipsec', 'phase1']); init_config_arr(['ipsec', 'phase2']);
    echo "IPsec Status:\n"; print_r(ipsec_list_sa());
    echo "IPsec Config Phase 1:\n"; print_r($config['ipsec']['phase1']);
    echo "IPsec Config Phase 2:\n"; print_r($config['ipsec']['phase2']); echo $line;
    echo "Packages:\n"; print_r(get_pkg_info('all', false, true));
}

// Découverte des interfaces (optimisée)
function pfz_interface_discovery($is_wan = false, $is_cron = false) {
    static $cache = null;
    if ($cache === null) {
        $ifdescrs = get_configured_interface_with_descr(true);
        $ifaces = get_interface_arr();
        $ifcs = [];
        foreach ($ifdescrs as $ifname => $ifdescr) {
            $ifcs[$ifname] = get_interface_info($ifname);
            $ifcs[$ifname]['description'] = $ifdescr;
        }
        $cache = ['ifcs' => $ifcs, 'ifaces' => $ifaces];
    }

    $ifcs = $cache['ifcs'];
    $ifaces = $cache['ifaces'];
    $if_ret = [];
    $json_string = '{"data":[';

    foreach ($ifaces as $hwif) {
        $ifdescr = $hwif;
        $has_gw = false;
        $is_vpn = false;
        $has_public_ip = false;

        foreach ($ifcs as $ifc => $ifinfo) {
            if ($ifinfo['hwif'] === $hwif) {
                $ifdescr = $ifinfo['description'];
                $has_gw = isset($ifinfo['gateway']);
                $has_public_ip = filter_var($ifinfo['ipaddr'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
                $is_vpn = strpos($ifinfo['if'], 'ovpn') !== false;
                break;
            }
        }

        if (!$is_wan || ($is_wan && ($has_gw || $has_public_ip) && !$is_vpn)) {
            $if_ret[] = $hwif;
            $json_string .= sprintf('{"{#IFNAME}":"%s","{#IFDESCR}":"%s"},', $hwif, addslashes($ifdescr));
        }
    }

    $json_string = rtrim($json_string, ',') . ']}';
    return $is_cron ? $if_ret : print($json_string);
}

// Valeur du speedtest d'interface
function pfz_interface_speedtest_value($ifname, $value) {
    $tvalue = explode(".", $value);
    $value = $tvalue[0];
    $subvalue = $tvalue[1] ?? false;

    $filename = "/tmp/speedtest-$ifname";
    if (file_exists($filename)) {
        $speedtest_data = json_decode(file_get_contents($filename), true) ?? [];
        if (isset($speedtest_data[$value])) {
            echo $subvalue ? $speedtest_data[$value][$subvalue] : $speedtest_data[$value];
        }
    }
}

// Tâche cron pour speedtest
function pfz_speedtest_cron() {
    require_once("services.inc");
    $ifdescrs = get_configured_interface_with_descr(true);
    $ifcs = pfz_interface_discovery(true, true);

    foreach ($ifcs as $ifname) {
        foreach ($ifdescrs as $ifn => $ifd) {
            $ifinfo = get_interface_info($ifn);
            if ($ifinfo['hwif'] === $ifname) {
                pfz_speedtest_exec($ifname, $ifinfo['ipaddr']);
                break;
            }
        }
    }
}

// Installation du cron pour speedtest
function pfz_speedtest_cron_install($enable = true) {
    $command = "/usr/local/bin/php " . __FILE__ . " speedtest_cron";
    install_cron_job($command, $enable, "*/15", "*", "*", "*", "*", "root", true);
}

// Exécution du speedtest (optimisée)
function pfz_speedtest_exec($ifname, $ipaddr) {
    $filename = "/tmp/speedtest-$ifname";
    $filetemp = "$filename.tmp";
    $filerun = "/tmp/speedtest-run";
    $lockfile = "$filerun.lock";

    if (file_exists($filename) && (time() - filemtime($filename) <= SPEEDTEST_INTERVAL * 3600)) {
        return true;
    }

    if (file_exists($lockfile)) {
        return false;
    }

    touch($lockfile);
    sleep(rand(1, 90));

    if (!file_exists($filerun) || (time() - filemtime($filerun) > 180)) {
        @unlink($filerun);
        touch($filerun);
        $st_command = "/usr/local/bin/speedtest --secure --source $ipaddr --json > $filetemp";
        exec($st_command);
        rename($filetemp, $filename);
        @unlink($filerun);
    }

    @unlink($lockfile);
    return true;
}

// Découverte des serveurs OpenVPN (optimisée)
function pfz_openvpn_get_all_servers() {
    static $servers = null;
    if ($servers === null) {
        $servers = array_merge(openvpn_get_active_servers(), openvpn_get_active_servers('p2p'));
    }
    return $servers;
}

function pfz_openvpn_serverdiscovery() {
    $servers = pfz_openvpn_get_all_servers();
    $json_string = '{"data":[';

    foreach ($servers as $server) {
        $name = trim(preg_replace('/\w{3}(\d)?\:\d{4,5}/i', '', $server['name']));
        $json_string .= sprintf('{"{#SERVER}":"%s","{#NAME}":"%s"},', $server['vpnid'], addslashes($name));
    }

    $json_string = rtrim($json_string, ',') . ']}';
    echo $json_string;
}

// Valeur d'un serveur OpenVPN
function pfz_openvpn_servervalue($server_id, $valuekey) {
    $servers = pfz_openvpn_get_all_servers();
    $value = "";
    file_put_contents("/tmp/openvpn_debug.log", "Servers found: " . count($servers) . "\n", FILE_APPEND);
    foreach ($servers as $server) {
        if ($server['vpnid'] == $server_id) {
            $value = $server[$valuekey];
            file_put_contents("/tmp/openvpn_debug.log", "Server $server_id - Mode: {$server['mode']}, Status: '$value'\n", FILE_APPEND);
            if ($valuekey === "status") {
                $mode_match = in_array($server['mode'], ["server_user", "server_tls_user", "server_tls"]);
                file_put_contents("/tmp/openvpn_debug.log", "Mode match: " . ($mode_match ? "true" : "false") . "\n", FILE_APPEND);
                $status_empty = ($value === "");
                file_put_contents("/tmp/openvpn_debug.log", "Status empty: " . ($status_empty ? "true" : "false") marshal. "\n", FILE_APPEND);
                if ($mode_match && $status_empty) {
                    $value = "server_user_listening";
                    file_put_contents("/tmp/openvpn_debug.log", "Set to server_user_listening\n", FILE_APPEND);
                } elseif ($server['mode'] === "p2p_tls" && $value === "") {
                    $value = (is_array($server["conns"]) && count($server["conns"]) > 0) ? "up" : "down";
                }
            }
            file_put_contents("/tmp/openvpn_debug.log", "After conditions - Value: '$value'\n", FILE_APPEND);
            break;
        }
    }
    if ($valuekey === "status") {
        $mapped_value = pfz_valuemap("openvpn.server.status", $value);
        file_put_contents("/tmp/openvpn_debug.log", "Before mapping - Value: '$value', Mapped: '$mapped_value'\n", FILE_APPEND);
        $value = $mapped_value;
    } elseif ($valuekey === "conns") {
        $value = is_array($value) ? count($value) : "0";
    } elseif ($valuekey === "mode") {
        $value = pfz_valuemap("openvpn.server.mode", $value);
    }
    file_put_contents("/tmp/openvpn_debug.log", "Final value: '$value'\n", FILE_APPEND);
    echo $value ?: "2";
}

// Découverte des utilisateurs OpenVPN
function pfz_openvpn_server_userdiscovery() {
    $servers = pfz_openvpn_get_all_servers();
    $json_string = '{"data":[';

    foreach ($servers as $server) {
        if (in_array($server['mode'], ['server_user', 'server_tls_user', 'server_tls']) && is_array($server['conns'])) {
            $name = trim(preg_replace('/\w{3}(\d)?\:\d{4,5}/i', '', $server['name']));
            foreach ($server['conns'] as $conn) {
                $common_name = pfz_replacespecialchars($conn['common_name']);
                $json_string .= sprintf('{"{#SERVERID}":"%s","{#SERVERNAME}":"%s","{#UNIQUEID}":"%s+%s","{#USERID}":"%s"},',
                    $server['vpnid'], addslashes($name), $server['vpnid'], $common_name, $conn['common_name']);
            }
        }
    }

    $json_string = rtrim($json_string, ',') . ']}';
    echo $json_string;
}

// Valeur d'un utilisateur OpenVPN
function pfz_openvpn_server_uservalue($unique_id, $valuekey, $default = "") {
    $unique_id = pfz_replacespecialchars($unique_id, true);
    $atpos = strpos($unique_id, '+');
    $server_id = substr($unique_id, 0, $atpos);
    $user_id = substr($unique_id, $atpos + 1);

    $servers = pfz_openvpn_get_all_servers();
    foreach ($servers as $server) {
        if ($server['vpnid'] === $server_id) {
            foreach ($server['conns'] as $conn) {
                if ($conn['common_name'] === $user_id) {
                    $value = $conn[$valuekey];
                    echo $value ?: $default;
                    return;
                }
            }
        }
    }
    echo $default;
}

// Découverte des clients OpenVPN
function pfz_openvpn_clientdiscovery() {
    $clients = openvpn_get_active_clients();
    $json_string = '{"data":[';

    foreach ($clients as $client) {
        $name = trim(preg_replace('/\w{3}(\d)?\:\d{4,5}/i', '', $client['name']));
        $json_string .= sprintf('{"{#CLIENT}":"%s","{#NAME}":"%s"},', $client['vpnid'], addslashes($name));
    }

    $json_string = rtrim($json_string, ',') . ']}';
    echo $json_string;
}

// Remplacement des caractères spéciaux
function pfz_replacespecialchars($inputstr, $reverse = false) {
    $specialchars = explode(",", ",',\",`,*,?,[,],{,},~,$,!,&,;,(,),<,>,|,#,@,0x0a");
    $resultstr = $inputstr;

    foreach ($specialchars as $n => $char) {
        $resultstr = $reverse
            ? str_replace("%%$n%", $char, $resultstr)
            : str_replace($char, "%%$n%", $resultstr);
    }
    return $resultstr;
}

// Valeur d'un client OpenVPN
function pfz_openvpn_clientvalue($client_id, $valuekey, $default = "none") {
    $clients = openvpn_get_active_clients();
    foreach ($clients as $client) {
        if ($client['vpnid'] === $client_id) {
            $value = $client[$valuekey];
            if ($valuekey === "status") {
                $value = pfz_valuemap("openvpn.client.status", $value);
            }
            echo $value ?: $default;
            return;
        }
    }
    echo $default;
}

// Découverte des services
function pfz_services_discovery() {
    $services = get_services();
    $json_string = '{"data":[';

    foreach ($services as $service) {
        if (!empty($service['name'])) {
            $id = !empty($service['id']) ? "." . $service['id'] : (!empty($service['zone']) ? "." . $service['zone'] : "");
            $json_string .= sprintf('{"{#SERVICE}":"%s%s","{#DESCRIPTION}":"%s"},',
                str_replace(" ", "__", $service['name']), $id, addslashes($service['description']));
        }
    }

    $json_string = rtrim($json_string, ',') . ']}';
    echo $json_string;
}

// Valeur d'un service
function pfz_service_value($name, $value) {
    $services = get_services();
    $name = str_replace("__", " ", $name);
    $stopped_on_carp_slave = ["haproxy", "radvd", "openvpn.", "openvpn", "avahi"];

    foreach ($services as $service) {
        $namecfr = $service["name"] . (!empty($service['id']) ? "." . $service["id"] : (!empty($service['zone']) ? "." . $service["zone"] : ""));
        $carpcfr = $service['name'] . (strpos($namecfr, '.') !== false ? "." : "");

        if ($namecfr === $name) {
            switch ($value) {
                case "status": echo get_service_status($service) ?: 0; return;
                case "name": echo $namecfr; return;
                case "enabled": echo is_service_enabled($service['name']) ? 1 : 0; return;
                case "run_on_carp_slave": echo in_array($carpcfr, $stopped_on_carp_slave) ? 0 : 1; return;
                default: echo $service[$value]; return;
            }
        }
    }
    echo 0;
}

// Découverte des passerelles
function pfz_gw_rawstatus() {
    $gws = return_gateways_status(true);
    $gw_string = "";
    foreach ($gws as $gw) {
        $gw_string .= $gw['name'] . '.' . $gw['status'] . ",";
    }
    echo rtrim($gw_string, ",");
}

function pfz_gw_discovery() {
    $gws = return_gateways_status(true);
    $json_string = '{"data":[';
    foreach ($gws as $gw) {
        $json_string .= sprintf('{"{#GATEWAY}":"%s"},', $gw['name']);
    }
    $json_string = rtrim($json_string, ',') . ']}';
    echo $json_string;
}

function pfz_gw_value($gw, $valuekey) {
    $gws = return_gateways_status(true);
    if (isset($gws[$gw])) {
        $value = $gws[$gw][$valuekey];
        if ($valuekey === "status" && $gws[$gw]["substatus"] !== "none") {
            $value = $gws[$gw]["substatus"];
        }
        if ($valuekey === "status") {
            $value = pfz_valuemap("gateway.status", $value);
        }
        echo $value;
    }
}

// Découverte IPsec
function pfz_ipsec_discovery_ph1() {
    require_once("ipsec.inc");
    global $config;
    init_config_arr(['ipsec', 'phase1']);
    $a_phase1 = &$config['ipsec']['phase1'];

    $json_string = '{"data":[';
    foreach ($a_phase1 as $data) {
        $json_string .= sprintf('{"{#IKEID}":"%s","{#NAME}":"%s"},', $data['ikeid'], addslashes($data['descr']));
    }
    $json_string = rtrim($json_string, ',') . ']}';
    echo $json_string;
}

function pfz_ipsec_ph1($ikeid, $valuekey) {
    require_once("ipsec.inc");
    global $config;
    init_config_arr(['ipsec', 'phase1']);
    $a_phase1 = &$config['ipsec']['phase1'];

    $value = "";
    switch ($valuekey) {
        case 'status': $value = pfz_ipsec_status($ikeid); break;
        case 'disabled': $value = "0"; break;
        default:
            foreach ($a_phase1 as $data) {
                if ($data['ikeid'] == $ikeid && isset($data[$valuekey])) {
                    $value = $valuekey === 'disabled' ? "1" : pfz_valuemap("ipsec.$valuekey", $data[$valuekey], $data[$valuekey]);
                    break;
                }
            }
    }
    echo $value;
}

function pfz_ipsec_discovery_ph2() {
    require_once("ipsec.inc");
    global $config;
    init_config_arr(['ipsec', 'phase2']);
    $a_phase2 = &$config['ipsec']['phase2'];

    $json_string = '{"data":[';
    foreach ($a_phase2 as $data) {
        $json_string .= sprintf('{"{#IKEID}":"%s","{#NAME}":"%s","{#UNIQID}":"%s","{#REQID}":"%s","{#EXTID}":"%s.%s"},',
            $data['ikeid'], addslashes($data['descr']), $data['uniqid'], $data['reqid'], $data['ikeid'], $data['reqid']);
    }
    $json_string = rtrim($json_string, ',') . ']}';
    echo $json_string;
}

function pfz_ipsec_ph2($uniqid, $valuekey) {
    require_once("ipsec.inc");
    global $config;
    init_config_arr(['ipsec', 'phase2']);
    $a_phase2 = &$config['ipsec']['phase2'];

    $valuecfr = explode(".", $valuekey);
    $value = "";
    switch ($valuecfr[0]) {
        case 'status':
            $idarr = explode(".", $uniqid);
            $statuskey = $valuecfr[1] ?? 'state';
            $value = pfz_ipsec_status($idarr[0], $idarr[1], $statuskey);
            break;
        case 'disabled': $value = "0"; break;
    }

    foreach ($a_phase2 as $data) {
        if ($data['uniqid'] === $uniqid && isset($data[$valuekey])) {
            $value = $valuekey === 'disabled' ? "1" : pfz_valuemap("ipsec_ph2.$valuekey", $data[$valuekey], $data[$valuekey]);
            break;
        }
    }
    echo $value;
}

function pfz_ipsec_status($ikeid, $reqid = -1, $valuekey = 'state') {
    require_once("ipsec.inc");
    global $config;
    init_config_arr(['ipsec', 'phase1']);
    $a_phase1 = &$config['ipsec']['phase1'];
    $conmap = [];
    foreach ($a_phase1 as $ph1ent) {
        $cname = function_exists('get_ipsecifnum') && get_ipsecifnum($ph1ent['ikeid'], 0)
            ? "con" . get_ipsecifnum($ph1ent['ikeid'], 0)
            : ipsec_conid($ph1ent);
        $conmap[$cname] = $ph1ent['ikeid'];
    }

    $status = ipsec_list_sa();
    $carp_status = pfz_carp_status(false);
    $tmp_value = "";

    if (is_array($status)) {
        foreach ($status as $l_ikeid => $ikesa) {
            $con_id = isset($ikesa['con-id']) ? substr($ikesa['con-id'], 3) : filter_var($l_ikeid, FILTER_SANITIZE_NUMBER_INT);
            $con_name = "con" . $con_id;
            $ph1idx = $ikesa['version'] == 1 || !ipsec_ikeid_used($con_id) ? $conmap[$con_name] : $con_id;

            if ($ph1idx == $ikeid) {
                if ($reqid != -1) {
                    foreach ($ikesa['child-sas'] as $childsas) {
                        if ($childsas['reqid'] == $reqid) {
                            $tmp_value = strtolower($childsas['state']) === 'rekeyed' ? $tmp_value : $childsas[$valuekey];
                            break;
                        }
                    }
                } else {
                    $tmp_value = $ikesa[$valuekey];
                }
                break;
            }
        }
    }

    switch ($valuekey) {
        case 'state':
            $value = pfz_valuemap('ipsec.state', strtolower($tmp_value));
            if ($carp_status != 0) $value += 10 * ($carp_status - 1);
            break;
        default: $value = $tmp_value; break;
    }
    return $value;
}

// Découverte des capteurs de température
function pfz_temperature_sensors_discovery() {
    $json_string = '{"data":[';
    exec("sysctl -a | grep temperature | cut -d ':' -f 1", $sensors, $code);
    if ($code == 0) {
        foreach ($sensors as $sensor) {
            $json_string .= sprintf('{"{#SENSORID}":"%s"},', $sensor);
        }
    }
    $json_string = rtrim($json_string, ',') . ']}';
    echo $json_string;
}

function pfz_get_temperature($sensorid) {
    exec("sysctl '$sensorid' | cut -d ':' -f 2", $value, $code);
    echo ($code == 0 && count($value) == 1) ? trim($value[0]) : "";
}

// Statut CARP
function pfz_carp_status($echo = true) {
    global $config;
    $status = get_carp_status();
    $carp_detected_problems = get_single_sysctl("net.inet.carp.demotion");
    $ret = 0;

    if ($status != 0) {
        if ($carp_detected_problems != 0) {
            $ret = 4;
        } else {
            $prev_status = "";
            $status_changed = false;
            foreach ($config['virtualip']['vip'] as $carp) {
                if ($carp['mode'] !== "carp") continue;
                $if_status = get_carp_interface_status("_vip{$carp['uniqid']}");
                if (!empty($if_status) && $prev_status !== "" && $prev_status !== $if_status) {
                    $status_changed = true;
                }
                $prev_status = $if_status;
            }
            $ret = $status_changed ? 3 : ($prev_status === "MASTER" ? 1 : 2);
        }
    }

    if ($echo) echo $ret;
    return $ret;
}

// DHCP
function pfz_remove_duplicate($array, $field) {
    $cmp = array_column($array, $field);
    $unique = array_unique(array_reverse($cmp, true));
    return array_intersect_key($array, $unique);
}

function pfz_dhcp_get($valuekey) {
    require_once("config.inc");
    global $g;
    $leasesfile = "{$g['dhcpd_chroot_path']}/var/db/dhcpd.leases";

    @exec("/bin/cat {$leasesfile} 2>/dev/null| /usr/bin/awk '{gsub(\"#.*\",\"\");gsub(\";\",\"\");print}' | /usr/bin/awk 'BEGIN{RS=\"}\"}{for(i=1;i<=NF;i++)printf\"%s \",$i;printf\"}\\n\"}'", $leases_content);
    @exec("/usr/sbin/arp -an", $rawdata);
    $leases = [];
    $pools = [];
    $l = $p = 0;

    foreach ($leases_content as $lease) {
        $data = explode(" ", $lease);
        if (count($data) < 20) continue;
        $f = 0;
        while ($f < count($data)) {
            switch ($data[$f]) {
                case "failover":
                    $pools[$p] = [
                        'name' => trim($data[$f + 2], '"') . " (" . convert_friendly_interface_to_friendly_descr(substr(trim($data[$f + 2], '"'), 5)) . ")",
                        'mystate' => $data[$f + 7], 'peerstate' => $data[$f + 14],
                        'mydate' => $data[$f + 10] . " " . $data[$f + 11],
                        'peerdate' => $data[$f + 17] . " " . $data[$f + 18]
                    ];
                    $p++;
                    break 2;
                case "lease": $leases[$l]['ip'] = $data[$f + 1]; $f += 2; break;
                case "starts": $leases[$l]['start'] = $data[$f + 2] . " " . $data[$f + 3]; $f += 3; break;
                case "ends": $leases[$l]['end'] = $data[$f + 1] === "never" ? "Never" : $data[$f + 2] . " " . $data[$f + 3]; $f += ($data[$f + 1] === "never" ? 1 : 3); break;
                case "tstp": case "tsfp": case "atsfp": case "cltt": $f += 3; break;
                case "binding":
                    $leases[$l]['act'] = $data[$f + 2] === "active" ? "active" : ($data[$f + 2] === "free" ? "expired" : "reserved");
                    $leases[$l]['online'] = ($data[$f + 2] === "free" || $data[$f + 2] === "backup") ? "offline" : (in_array($leases[$l]['ip'], $arpdata_ip ?? []) ? "online" : "offline");
                    $f += 1;
                    break;
                case "hardware": $leases[$l]['mac'] = $data[$f + 2]; $f += 2; break;
                case "client-hostname":
                    $leases[$l]['hostname'] = $data[$f + 1] ? preg_replace('/"/', '', $data[$f + 1]) : (gethostbyaddr($leases[$l]['ip']) ?: "");
                    $f += 1;
                    break;
                case "uid": $f += 1; break;
            }
            $f++;
        }
        $l++;
    }

    $leases = $l > 0 ? pfz_remove_duplicate($leases, "ip") : $leases;
    $pools = $p > 0 ? pfz_remove_duplicate($pools, "name") : $pools;

    switch ($valuekey) {
        case "pools": return $pools;
        case "failover": return $pools;
        default: return $leases;
    }
}

function pfz_dhcpfailover_discovery() {
    $leases = pfz_dhcp_get("failover");
    $json_string = '{"data":[';
    foreach ($leases as $data) {
        $json_string .= sprintf('{"{#FAILOVER_GROUP}":"%s"},', str_replace(" ", "__", $data['name']));
    }
    $json_string = rtrim($json_string, ',') . ']}';
    echo $json_string;
}

function pfz_dhcp_check_failover() {
    $failover = pfz_dhcp_get("failover");
    $ret = 0;
    foreach ($failover as $f) {
        if ($f["mystate"] !== "normal" || $f["mystate"] !== $f["peerstate"]) {
            $ret++;
        }
    }
    return $ret;
}

function pfz_dhcp($section, $valuekey = "") {
    if ($section === "failover") echo pfz_dhcp_check_failover();
}

// Packages
function pfz_packages_uptodate() {
    $installed_packages = get_pkg_info('all', false, true);
    $ret = 0;
    foreach ($installed_packages as $package) {
        if ($package['version'] !== $package['installed_version']) {
            $ret++;
        }
    }
    return $ret;
}

// Gestion du cron pour syscheck (optimisée avec APCu si disponible)
function pfz_syscheck_cron_install($enable = true) {
    $command = "/usr/local/bin/php " . __FILE__ . " syscheck_cron";
    install_cron_job($command, $enable, "0", "*/8", "*", "*", "*", "root", true);
    install_cron_job("/usr/local/bin/php " . __FILE__ . " systemcheck_cron", false, "0", "9,21", "*", "*", "*", "root", true);
}

function pfz_syscheck_cron() {
    if (extension_loaded('apcu') && apcu_exists('sysversion')) {
        return true;
    }

    $filename = "/tmp/sysversion.json";
    $upToDate = pfz_packages_uptodate();
    $sysVersion = get_system_pkg_version();
    $sysVersion['packages_update'] = $upToDate;
    $sysVersionJson = json_encode($sysVersion);

    if (file_exists($filename) && (time() - filemtime($filename) <= CRON_TIME_LIMIT)) {
        return true;
    }

    file_put_contents($filename, $sysVersionJson, LOCK_EX);
    if (extension_loaded('apcu')) {
        apcu_store('sysversion', $sysVersion, CRON_TIME_LIMIT);
    }
    return true;
}

function pfz_get_system_value($section) {
    if (extension_loaded('apcu') && apcu_exists('sysversion')) {
        $sysVersion = apcu_fetch('sysversion');
    } else {
        $filename = "/tmp/sysversion.json";
        if (!file_exists($filename)) {
            pfz_syscheck_cron_install();
            return ($section === 'new_version_available') ? '0' : '';
        }
        $sysVersion = json_decode(file_get_contents($filename), true);
    }

    switch ($section) {
        case 'script_version': echo SCRIPT_VERSION; break;
        case 'version': echo $sysVersion['version']; break;
        case 'installed_version': echo $sysVersion['installed_version']; break;
        case 'new_version_available': echo ($sysVersion['version'] === $sysVersion['installed_version']) ? '0' : '1'; break;
        case 'packages_update': echo $sysVersion['packages_update']; break;
    }
}

// Statut S.M.A.R.T
function pfz_get_smart_status() {
    $devs = get_smart_drive_list();
    foreach ($devs as $dev) {
        $dev_state = trim(exec("smartctl -H /dev/$dev | awk -F: '/^SMART overall-health self-assessment test result/ {print $2;exit} /^SMART Health Status/ {print $2;exit}'"));
        switch ($dev_state) {
            case "PASSED": case "OK": $status = 0; break;
            case "": $status = 2; echo $status; return;
            default: $status = 1; echo $status; return;
        }
    }
    echo 0;
}

// Certificats
function pfz_get_revoked_cert_refs() {
    global $config;
    $revoked_cert_refs = [];
    foreach ($config["crl"] as $crl) {
        foreach ($crl["cert"] as $revoked_cert) {
            $revoked_cert_refs[] = $revoked_cert["refid"];
        }
    }
    return $revoked_cert_refs;
}

function pfz_cert_discovery() {
    global $config;
    $revoked_cert_refs = pfz_get_revoked_cert_refs();
    $dataObject = new stdClass();
    $dataObject->data = [];

    foreach (["cert", "ca"] as $cert_type) {
        foreach ($config[$cert_type] as $i => $cert) {
            if (!in_array($cert['refid'], $revoked_cert_refs)) {
                $certObject = new stdClass();
                $certObject->{'{#CERT_INDEX}'} = $cert_type === "cert" ? $i : $i + 0x10000;
                $certObject->{'{#CERT_REFID}'} = $cert['refid'];
                $certObject->{'{#CERT_NAME}'} = $cert['descr'];
                $certObject->{'{#CERT_TYPE}'} = strtoupper($cert_type);
                $dataObject->data[] = $certObject;
            }
        }
    }
    echo json_encode($dataObject);
}

function pfz_get_cert_info($index) {
    $cacheFile = "/root/.ssl/certinfo_{$index}.json";
    if (file_exists($cacheFile) && (time() - filemtime($cacheFile) < 300)) {
        return json_decode(file_get_contents($cacheFile), true);
    }

    global $config;
    $certType = $index >= 0x10000 ? "ca" : "cert";
    $index = $index >= 0x10000 ? $index - 0x10000 : $index;
    $certinfo = openssl_x509_parse(base64_decode($config[$certType][$index]["crt"]));

    if (!is_dir('/root/.ssl')) mkdir('/root/.ssl');
    file_put_contents($cacheFile, json_encode($certinfo));
    chmod($cacheFile, 0600);
    return $certinfo;
}

function pfz_get_cert_pkey_info($index) {
    $cacheFile = "/root/.ssl/certinfo_pk_{$index}.json";
    if (file_exists($cacheFile) && (time() - filemtime($cacheFile) < 300)) {
        return json_decode(file_get_contents($cacheFile), true);
    }

    global $config;
    $certType = $index >= 0x10000 ? "ca" : "cert";
    $index = $index >= 0x10000 ? $index - 0x10000 : $index;
    $cert_key = $config[$certType][$index]["crt"];
    $details = $cert_key ? openssl_pkey_get_details(openssl_pkey_get_public(base64_decode($cert_key))) : [];

    if (!is_dir('/root/.ssl')) mkdir('/root/.ssl');
    file_put_contents($cacheFile, json_encode($details));
    chmod($cacheFile, 0600);
    return $details;
}

function pfz_get_ref_cert_algo_len($index) {
    $pkInfo = pfz_get_cert_pkey_info($index);
    echo $pkInfo["bits"];
}

function pfz_get_ref_cert_algo_bits($index) {
    $pkInfo = pfz_get_cert_pkey_info($index);
    $keyLength = $pkInfo["bits"];
    switch ($pkInfo["type"]) {
        case OPENSSL_KEYTYPE_RSA: case OPENSSL_KEYTYPE_DSA: case OPENSSL_KEYTYPE_DH:
            $bits = floor(1 / log(2) * pow(64 / 9, 1 / 3) * pow($keyLength * log(2), 1 / 3) * pow(log(2048 * log(2)), 2 / 3));
            break;
        case OPENSSL_KEYTYPE_EC: $bits = $keyLength >> 1; break;
    }
    echo $bits;
}

function pfz_get_ref_cert_algo($index) {
    $pkInfo = pfz_get_cert_pkey_info($index);
    echo ["RSA", "DSA", "DH", "EC"][$pkInfo["type"]] ?? "";
}

function pfz_get_ref_cert_hash_bits($index) {
    $certinfo = pfz_get_cert_info($index);
    $sigType = strtoupper($certinfo["signatureTypeSN"]);
    $bits = [
        "MD2" => 63, "MD4" => 2, "MD5" => 18, "SHA1" => 61, "SHA224" => 112, "SHA3-224" => 112,
        "SHA256" => 128, "SHA3-256" => 128, "SHAKE128" => 128, "SHA384" => 192, "SHA3-384" => 192,
        "SHA512" => 256, "SHA3-512" => 256, "SHAKE256" => 256, "WHIRLPOOL" => 256
    ];
    foreach ($bits as $type => $val) {
        if (str_contains($sigType, $type)) {
            echo $val;
            return;
        }
    }
    echo str_contains($sigType, "SHA") ? 61 : 0;
}

function pfz_get_ref_cert_hash($index) {
    $certinfo = pfz_get_cert_info($index);
    echo $certinfo["signatureTypeSN"];
}

function pfz_get_ref_cert_date($valuekey, $index) {
    $certinfo = pfz_get_cert_info($index);
    echo $valuekey === "validFrom" ? $certinfo['validFrom_time_t'] : $certinfo['validTo_time_t'];
}

function pfz_get_cert_date($valuekey) {
    global $config;
    $revoked_cert_refs = pfz_get_revoked_cert_refs();
    $value = 0;

    foreach (["cert", "ca"] as $cert_type) {
        foreach ($config[$cert_type] as $cert) {
            if (!in_array($cert['refid'], $revoked_cert_refs)) {
                $certinfo = openssl_x509_parse(base64_decode($cert["crt"]));
                if ($valuekey === "validFrom.max") {
                    $value = ($value == 0 || $value < $certinfo['validFrom_time_t']) ? $certinfo['validFrom_time_t'] : $value;
                } elseif ($valuekey === "validTo.min") {
                    $value = ($value == 0 || $value > $certinfo['validTo_time_t']) ? $certinfo['validTo_time_t'] : $value;
                }
            }
        }
    }
    echo $value;
}

// Vérification de l'existence d'un fichier
function pfz_file_exists($filename) {
    echo file_exists($filename) ? "1" : "0";
}

// Mappage des valeurs
function pfz_valuemap($valuename, $value, $default = "0") {
    $valuemaps = [
        "openvpn.server.status" => ["down" => "0", "up" => "1", "connected (success)" => "1", "none" => "2", "reconnecting; ping-restart" => "3", "waiting" => "4", "server_user_listening" => "5"],
        "openvpn.client.status" => ["up" => "1", "connected (success)" => "1", "down" => "0", "none" => "0", "reconnecting; ping-restart" => "2"],
        "openvpn.server.mode" => ["p2p_tls" => "1", "p2p_shared_key" => "2", "server_tls" => "3", "server_user" => "4", "server_tls_user" => "5"],
        "gateway.status" => ["online" => "0", "none" => "0", "loss" => "1", "highdelay" => "2", "highloss" => "3", "force_down" => "4", "down" => "5"],
        "ipsec.iketype" => ["auto" => 0, "ikev1" => 1, "ikev2" => 2],
        "ipsec.mode" => ["main" => 0, "aggressive" => 1],
        "ipsec.protocol" => ["both" => 0, "inet" => 1, "inet6" => 2],
        "ipsec_ph2.mode" => ["transport" => 0, "tunnel" => 1, "tunnel6" => 2],
        "ipsec_ph2.protocol" => ["esp" => 1, "ah" => 2],
        "ipsec.state" => ["established" => 1, "connecting" => 2, "installed" => 1, "rekeyed" => 2]
    ];

    $value = strtolower($value);
    return isset($valuemaps[$valuename][$value]) ? $valuemaps[$valuename][$value] : $default;
}

// Découverte générique
function pfz_discovery($section) {
    $map = [
        "certificates" => 'pfz_cert_discovery', "gw" => 'pfz_gw_discovery', "wan" => fn() => pfz_interface_discovery(true),
        "openvpn_server" => 'pfz_openvpn_serverdiscovery', "openvpn_server_user" => 'pfz_openvpn_server_userdiscovery',
        "openvpn_client" => 'pfz_openvpn_clientdiscovery', "services" => 'pfz_services_discovery',
        "interfaces" => 'pfz_interface_discovery', "ipsec_ph1" => 'pfz_ipsec_discovery_ph1',
        "ipsec_ph2" => 'pfz_ipsec_discovery_ph2', "dhcpfailover" => 'pfz_dhcpfailover_discovery',
        "temperature_sensors" => 'pfz_temperature_sensors_discovery'
    ];
    call_user_func($map[strtolower($section)] ?? fn() => null);
}

// Code principal
$mainArgument = strtolower($argv[1] ?? "");
set_time_limit(str_ends_with($mainArgument, "cron") ? CRON_TIME_LIMIT : DEFAULT_TIME_LIMIT);

switch ($mainArgument) {
    case "discovery": pfz_discovery($argv[2]); break;
    case "gw_value": pfz_gw_value($argv[2], $argv[3]); break;
    case "gw_status": pfz_gw_rawstatus(); break;
    case "if_speedtest_value": pfz_speedtest_cron_install(); pfz_interface_speedtest_value($argv[2], $argv[3]); break;
    case "openvpn_servervalue": pfz_openvpn_servervalue($argv[2], $argv[3]); break;
    case "openvpn_server_uservalue": pfz_openvpn_server_uservalue($argv[2], $argv[3]); break;
    case "openvpn_server_uservalue_numeric": pfz_openvpn_server_uservalue($argv[2], $argv[3], "0"); break;
    case "openvpn_clientvalue": pfz_openvpn_clientvalue($argv[2], $argv[3]); break;
    case "service_value": pfz_service_value($argv[2], $argv[3]); break;
    case "carp_status": pfz_carp_status(); break;
    case "syscheck_cron": pfz_syscheck_cron_install(); pfz_syscheck_cron(); break;
    case "system": pfz_get_system_value($argv[2]); break;
    case "ipsec_ph1": pfz_ipsec_ph1($argv[2], $argv[3]); break;
    case "ipsec_ph2": pfz_ipsec_ph2($argv[2], $argv[3]); break;
    case "dhcp": pfz_dhcp($argv[2], $argv[3]); break;
    case "file_exists": pfz_file_exists($argv[2]); break;
    case "speedtest_cron": pfz_speedtest_cron_install(); pfz_speedtest_cron(); break;
    case "cron_cleanup": pfz_speedtest_cron_install(false); pfz_syscheck_cron_install(false); break;
    case "smart_status": pfz_get_smart_status(); break;
    case "cert_ref_date": pfz_get_ref_cert_date($argv[2], $argv[3]); break;
    case "cert_date": pfz_get_cert_date($argv[2]); break;
    case "cert_algo": pfz_get_ref_cert_algo($argv[2]); break;
    case "cert_algo_bits": pfz_get_ref_cert_algo_len($argv[2]); break;
    case "cert_algo_secbits": pfz_get_ref_cert_algo_bits($argv[2]); break;
    case "cert_hash": pfz_get_ref_cert_hash($argv[2]); break;
    case "cert_hash_secbits": pfz_get_ref_cert_hash_bits($argv[2]); break;
    case "temperature": pfz_get_temperature($argv[2]); break;
    default: pfz_test();
}
