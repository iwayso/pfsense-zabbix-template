*** pfsense_zbx.php	2025-08-09
--- pfsense_zbx.php	2025-08-09
***************
*** 1,40 ****
- Optimized version with improved IPSEC caching
- This program is licensed under Apache 2.0 License */
- 
- //Some Useful defines
- define('SCRIPT_VERSION', '0.24.9');
- define('SPEEDTEST_INTERVAL', 8); //Speedtest Interval (in hours)
- define('CRON_TIME_LIMIT', 300); // Time limit in seconds of speedtest and sysinfo
- define('DEFAULT_TIME_LIMIT', 30); // Time limit in seconds otherwise
- 
- // Cache durations (in seconds)
- define('CACHE_DURATION_SHORT', 60); // 1 minute
- define('CACHE_DURATION_MEDIUM', 300); // 5 minutes
- define('CACHE_DURATION_LONG', 3600); // 1 hour
- define('CACHE_DURATION_STATIC', 86400); // 24 hours - for values that rarely change
- 
- // Cache directory
- define('CACHE_DIR', '/tmp/pfz_cache');
- 
- // Create cache directory if it doesn't exist
- if (!is_dir(CACHE_DIR)) {
-     mkdir(CACHE_DIR, 0755, true);
- }
- 
- // Load required files only when needed
- $included_files = array();
- function include_once_track($filename) {
-     global $included_files;
-     if (!isset($included_files[$filename])) {
-         include_once($filename);
-         $included_files[$filename] = true;
-     }
- }
- 
- // Required for basic operations
- include_once_track('globals.inc');
- include_once_track('functions.inc');
- include_once_track('config.inc');
- include_once_track('util.inc');
- 
- //Backporting php 8 functions
- if (!function_exists('str_contains')) {
-     function str_contains($haystack, $needle) { return strstr($haystack, $needle) !== false; }
- }
- 
- // Cache management functions
- function pfz_get_cache($key, $duration = CACHE_DURATION_MEDIUM) {
-     $cache_file = CACHE_DIR . '/' . md5($key) . '.cache';
-     if (file_exists($cache_file) && (time() - filemtime($cache_file) < $duration)) {
-         return unserialize(file_get_contents($cache_file));
-     }
-     return null;
- }
- function pfz_set_cache($key, $data) {
-     $cache_file = CACHE_DIR . '/' . md5($key) . '.cache';
-     file_put_contents($cache_file, serialize($data));
- }
+ <?php
+ declare(strict_types=1);
+ /*
+  * Optimized version with improved IPSEC caching
+  * This program is licensed under Apache 2.0 License
+  */
+ 
+ // ===== Core defines
+ define('SCRIPT_VERSION', '0.25.0-apcu-locks');
+ define('SPEEDTEST_INTERVAL', 8);      // Speedtest Interval (in hours)
+ define('CRON_TIME_LIMIT', 300);       // Time limit in seconds of speedtest and sysinfo
+ define('DEFAULT_TIME_LIMIT', 30);     // Time limit in seconds otherwise
+ 
+ // Cache durations (in seconds)
+ define('CACHE_DURATION_SHORT', 60);       // 1 minute
+ define('CACHE_DURATION_MEDIUM', 300);     // 5 minutes
+ define('CACHE_DURATION_LONG', 3600);      // 1 hour
+ define('CACHE_DURATION_STATIC', 86400);   // 24 hours - for values that rarely change
+ 
+ // Cache directory
+ define('CACHE_DIR', '/tmp/pfz_cache');
+ if (!is_dir(CACHE_DIR)) { @mkdir(CACHE_DIR, 0755, true); }
+ 
+ // Namespace to auto-invalidate caches when script upgrades
+ define('CACHE_NS', 'pfz_' . SCRIPT_VERSION . '_');
+ 
+ // Load required files only when needed
+ $included_files = array();
+ function include_once_track($filename) {
+     global $included_files;
+     if (!isset($included_files[$filename])) {
+         include_once($filename);
+         $included_files[$filename] = true;
+     }
+ }
+ 
+ // Required for basic operations
+ include_once_track('globals.inc');
+ include_once_track('functions.inc');
+ include_once_track('config.inc');
+ include_once_track('util.inc');
+ 
+ // Backporting php 8 functions
+ if (!function_exists('str_contains')) {
+     function str_contains(string $haystack, string $needle): bool { return strstr($haystack, $needle) !== false; }
+ }
+ 
+ // ===== Generic lock helpers (anti-stampede)
+ function pfz_lock_path(string $key): string { return CACHE_DIR . '/' . md5('lock_' . $key) . '.lock'; }
+ function pfz_acquire_lock(string $key, int $timeout = 5) {
+     $lockFile = pfz_lock_path($key);
+     $fp = @fopen($lockFile, 'c');
+     if (!$fp) return null;
+     $start = time();
+     do {
+         if (@flock($fp, LOCK_EX | LOCK_NB)) return $fp;
+         usleep(100000); // 100ms
+     } while ((time() - $start) < $timeout);
+     fclose($fp);
+     return null;
+ }
+ function pfz_release_lock($fp): void { if (is_resource($fp)) { @flock($fp, LOCK_UN); @fclose($fp); } }
+ 
+ // ===== Cache management (APCu + file fallback, namespaced)
+ function pfz_cache_get(string $key, int $duration = CACHE_DURATION_MEDIUM) {
+     $k = CACHE_NS . $key;
+     if (function_exists('apcu_fetch')) { $ok = false; $val = @apcu_fetch($k, $ok); if ($ok) return $val; }
+     $cache_file = CACHE_DIR . '/' . md5($k) . '.cache';
+     if (is_file($cache_file) && (time() - filemtime($cache_file) < $duration)) {
+         $raw = @file_get_contents($cache_file);
+         if ($raw !== false) return @unserialize($raw);
+     }
+     return null;
+ }
+ function pfz_cache_set(string $key, $data): void {
+     $k = CACHE_NS . $key;
+     if (function_exists('apcu_store')) { @apcu_store($k, $data); }
+     $cache_file = CACHE_DIR . '/' . md5($k) . '.cache';
+     @file_put_contents($cache_file, serialize($data), LOCK_EX);
+ }
+ function pfz_cache_clear(string $prefix = ''): int {
+     $count = 0;
+     $nsPrefix = CACHE_NS . $prefix;
+     foreach (@glob(CACHE_DIR . '/*.cache') ?: [] as $file) {
+         if ($prefix === '' || str_starts_with(@file_get_contents($file, false, null, 0, 0) ? '' : basename($file), '')) { /* noop */ }
+         // we can't read the key from the file; rely on prefix match on filename by re-hashing
+         // So just clear everything in file cache when prefix empty or use APCu for prefix deletion
+     }
+     // Clear APCu keys by prefix if available
+     if (function_exists('apcu_cache_info') && function_exists('apcu_delete')) {
+         $info = @apcu_cache_info();
+         if (isset($info['cache_list'])) {
+             foreach ($info['cache_list'] as $entry) {
+                 if (!empty($entry['info']) && str_starts_with((string)$entry['info'], $nsPrefix)) {
+                     @apcu_delete($entry['info']);
+                     $count++;
+                 }
+             }
+         }
+     }
+     // Brutal cleanup for file cache when prefix empty
+     if ($prefix === '') {
+         foreach (@glob(CACHE_DIR . '/*.cache') ?: [] as $file) { if (@unlink($file)) $count++; }
+     }
+     return $count;
+ }
+ 
+ // Backward compatible wrappers
+ function pfz_get_cache($key, $duration = CACHE_DURATION_MEDIUM) { return pfz_cache_get((string)$key, (int)$duration); }
+ function pfz_set_cache($key, $data) { pfz_cache_set((string)$key, $data); }
***************
*** 128,174 ****
- // This is supposed to run via cron job
- function pfz_speedtest_cron() {
-     include_once_track('services.inc');
-     include_once_track('interfaces.inc');
-     $ifdescrs = get_configured_interface_with_descr(true);
-     $pf_interface_name = '';
-     $ifcs = pfz_interface_discovery(true, true);
-     foreach ($ifcs as $ifname) {
-         foreach ($ifdescrs as $ifn => $ifd) {
-             $ifinfo = get_interface_info($ifn);
-             if ($ifinfo['hwif'] == $ifname) { $pf_interface_name = $ifn; break; }
-         }
-         pfz_speedtest_exec($ifname, $ifinfo['ipaddr']);
-     }
- }
- 
- //installs a cron job for speedtests
- function pfz_speedtest_cron_install($enable = true) {
-     include_once_track('services.inc');
-     //Install Cron Job
-     $command = "/usr/local/bin/php " . __FILE__ . " speedtest_cron";
-     install_cron_job($command, $enable, $minute = "*/15", "*", "*", "*", "*", "root", true);
- }
- 
- // Fixed issue #127
- function pfz_speedtest_exec($ifname, $ipaddr) {
-     $filename = "/tmp/speedtest-$ifname";
-     $filetemp = "$filename.tmp";
-     $filerun = "/tmp/speedtest-run";
-     // Issue #82 - Sleep random delay to avoid problems with multiple pfSense on same Internet line
-     sleep(rand(1, 90));
-     if ((time() - filemtime($filename) > SPEEDTEST_INTERVAL * 3600) || (file_exists($filename) == false)) {
-         // file is older than SPEEDTEST_INTERVAL
-         if ((time() - filemtime($filerun) > 180)) @unlink($filerun);
-         if (file_exists($filerun) == false) {
-             touch($filerun);
-             $st_command = "/usr/local/bin/speedtest --secure --source $ipaddr --json > $filetemp";
-             exec($st_command);
-             rename($filetemp, $filename);
-             @unlink($filerun);
-         }
-     }
-     return true;
- }
+ // This is supposed to run via cron job
+ function pfz_speedtest_cron(): void {
+     include_once_track('services.inc');
+     include_once_track('interfaces.inc');
+     $ifdescrs = get_configured_interface_with_descr(true);
+     $ifcs = pfz_interface_discovery(true, true);
+     foreach ($ifcs as $ifname) {
+         $ifinfo = null;
+         foreach ($ifdescrs as $ifn => $ifd) {
+             $ii = get_interface_info($ifn);
+             if ($ii && isset($ii['hwif']) && $ii['hwif'] === $ifname) { $ifinfo = $ii; break; }
+         }
+         if ($ifinfo && !empty($ifinfo['ipaddr'])) { pfz_speedtest_exec($ifname, (string)$ifinfo['ipaddr']); }
+     }
+ }
+ 
+ // Installs a cron job for speedtests
+ function pfz_speedtest_cron_install(bool $enable = true): void {
+     include_once_track('services.inc');
+     $command = "/usr/local/bin/php " . __FILE__ . " speedtest_cron";
+     install_cron_job($command, $enable, $minute = "*/15", "*", "*", "*", "*", "root", true);
+ }
+ 
+ // Hardened speedtest exec
+ function pfz_speedtest_exec(string $ifname, string $ipaddr): bool {
+     $filename = "/tmp/speedtest-" . preg_replace('/[^A-Za-z0-9_.-]/', '_', $ifname);
+     $filetemp = "$filename.tmp";
+     $filerun = "/tmp/speedtest-run";
+ 
+     // Random delay to avoid simultaneous runs across devices sharing the same line
+     usleep(random_int(1000000, 90000000));
+ 
+     $needsRun = !is_file($filename) || (time() - @filemtime($filename) > SPEEDTEST_INTERVAL * 3600);
+     if (!$needsRun) return true;
+ 
+     // Anti-stampede global lock
+     $lock = pfz_acquire_lock('speedtest', 3);
+     if (!$lock) { return false; }
+     try {
+         if ((time() - @filemtime($filerun) > 180)) @unlink($filerun);
+         if (!is_file($filerun)) {
+             @touch($filerun);
+             $cmd = sprintf('/usr/local/bin/speedtest --secure --source %s --json', escapeshellarg($ipaddr));
+             $rc = 0; $out = [];
+             exec($cmd . ' > ' . escapeshellarg($filetemp) . ' 2>/dev/null', $out, $rc);
+             if ($rc === 0 && is_file($filetemp) && filesize($filetemp) > 0) {
+                 $json = @json_decode(@file_get_contents($filetemp), true);
+                 if (is_array($json)) { @rename($filetemp, $filename); }
+                 else { @unlink($filetemp); }
+             }
+             @unlink($filerun);
+         }
+     } finally { pfz_release_lock($lock); }
+     return true;
+ }
***************
*** 200,214 ****
- function pfz_openvpn_servervalue($server_id, $valuekey) {
+ function pfz_openvpn_servervalue($server_id, $valuekey) {
      $servers = pfz_openvpn_get_all_servers();
      foreach ($servers as $server) {
          if ($server['vpnid'] == $server_id) {
              $value = $server[$valuekey];
              if ($valuekey == "status") {
                  if (($server['mode'] == "server_user") || ($server['mode'] == "server_tls_user") || ($server['mode'] == "server_tls")) {
                      if ($value == "") $value = "server_user_listening";
                  } else if ($server['mode'] == "p2p_tls") {
                      // For p2p_tls, ensure we have one client, and return up if it's the case
                      if ($value == "") $value = (is_array($server["conns"]) && count($server["conns"]) > 0) ? "up" : "down";
                  }
              }
              break;
          }
      }
      switch ($valuekey) {
          case "conns": //Client Connections: is an array so it is sufficient to count elements
              if (is_array($value)) $value = count($value); else $value = "0";
              break;
          case "status": $value = pfz_valuemap("openvpn.server.status", $value); break;
          case "mode":   $value = pfz_valuemap("openvpn.server.mode", $value); break;
      }
      echo $value;
  }
--- 200,218 ----
+ function pfz_openvpn_servervalue($server_id, $valuekey) {
+     // harden inputs
+     $server_id = (string)preg_replace('/[^0-9]/', '', (string)$server_id);
+     $valuekey  = (string)$valuekey;
      $servers = pfz_openvpn_get_all_servers();
      foreach ($servers as $server) {
          if ($server['vpnid'] == $server_id) {
              $value = $server[$valuekey];
              if ($valuekey == "status") {
                  if (($server['mode'] == "server_user") || ($server['mode'] == "server_tls_user") || ($server['mode'] == "server_tls")) {
                      if ($value == "") $value = "server_user_listening";
                  } else if ($server['mode'] == "p2p_tls") {
                      // For p2p_tls, ensure we have one client, and return up if it's the case
                      if ($value == "") $value = (is_array($server["conns"]) && count($server["conns"]) > 0) ? "up" : "down";
                  }
              }
              break;
          }
      }
      switch ($valuekey) {
          case "conns": if (is_array($value)) $value = count($value); else $value = "0"; break;
          case "status": $value = pfz_valuemap("openvpn.server.status", $value); break;
          case "mode":   $value = pfz_valuemap("openvpn.server.mode", $value); break;
      }
      echo $value;
  }
***************
*** 310,334 ****
- function pfz_gw_rawstatus() {
+ function pfz_gw_rawstatus() {
      $cache_key = "gw_rawstatus";
      $cache = pfz_get_cache($cache_key, CACHE_DURATION_SHORT);
      if ($cache !== null) { echo $cache; return; }
      // Return a Raw Gateway Status, useful for action Scripts (e.g. Update Cloudflare DNS config)
      $gws = return_gateways_status(true);
      $gw_string = "";
      foreach ($gws as $gw) { $gw_string .= ($gw['name'] . '.' . $gw['status'] . ","); }
      $gw_string = rtrim($gw_string, ",");
      pfz_set_cache($cache_key, $gw_string);
      echo $gw_string;
  }
--- 314,338 ----
+ function pfz_gw_rawstatus() {
      $cache_key = "gw_rawstatus";
      $cache = pfz_get_cache($cache_key, CACHE_DURATION_SHORT);
      if ($cache !== null) { echo $cache; return; }
      // Return a Raw Gateway Status, useful for action Scripts (e.g. Update Cloudflare DNS config)
      $gws = return_gateways_status(true);
      $gw_string = "";
      foreach ($gws as $gw) {
+         $name = isset($gw['name']) ? $gw['name'] : '';
+         $status = isset($gw['status']) ? $gw['status'] : '';
+         if ($name === '') continue;
+         $gw_string .= ($name . '.' . $status . ",");
+     }
      $gw_string = rtrim($gw_string, ",");
      pfz_set_cache($cache_key, $gw_string);
      echo $gw_string;
  }
***************
*** 420,520 ****
- function pfz_ipsec_status($ikeid, $reqid = -1, $valuekey = 'state') {
+ function pfz_ipsec_status($ikeid, $reqid = -1, $valuekey = 'state') {
      $cache_key = "ipsec_status_{$ikeid}_{$reqid}_{$valuekey}";
      $cache = pfz_get_cache($cache_key, CACHE_DURATION_SHORT);
      if ($cache !== null) { return $cache; }
      include_once_track('ipsec.inc');
      global $config;
      $a_phase1 = pfz_get_ipsec_config('phase1');
      $conmap = array();
      foreach ($a_phase1 as $ph1ent) {
          if (function_exists('get_ipsecifnum')) {
              if (get_ipsecifnum($ph1ent['ikeid'], 0)) { $cname = "con" . get_ipsecifnum($ph1ent['ikeid'], 0); }
              else { $cname = "con{$ph1ent['ikeid']}00000"; }
          } else{ $cname = ipsec_conid($ph1ent); }
          $conmap[$cname] = $ph1ent['ikeid'];
      }
      $status = ipsec_list_sa();
      $ipsecconnected = array();
      $carp_status = pfz_carp_status(false);
      //Phase-Status match borrowed from status_ipsec.php
      if (is_array($status)) {
          foreach ($status as $l_ikeid => $ikesa) {
              if (isset($ikesa['con-id'])) { $con_id = substr($ikesa['con-id'], 3); }
              else { $con_id = filter_var($l_ikeid, FILTER_SANITIZE_NUMBER_INT); }
              $con_name = "con" . $con_id;
              $ikeid = isset($conmap[$con_name]) ? $conmap[$con_name] : $ikeid;
              if (isset($ikesa['child-sas']) && is_array($ikesa['child-sas'])) {
                  foreach ($ikesa['child-sas'] as $child) {
                      $reqidc = (isset($child['reqid'])) ? $child['reqid'] : '-1';
                      $ipsecconnected[$ikeid][$reqidc] = $child['state'];
                  }
              }
          }
      }
      if ($reqid == -1) {
          $ret = isset($ipsecconnected[$ikeid]) ? 'up' : 'down';
      } else {
          $ret = isset($ipsecconnected[$ikeid][$reqid]) ? $ipsecconnected[$ikeid][$reqid] : 'down';
      }
      if ($valuekey == 'state') {
          $ret = pfz_valuemap('ipsec.status', $ret);
      } elseif ($valuekey == 'carpstate') {
          $ret = $carp_status;
      }
      pfz_set_cache($cache_key, $ret);
      return $ret;
  }
--- 424,545 ----
+ function pfz_ipsec_status($ikeid, $reqid = -1, $valuekey = 'state') {
      $cache_key = "ipsec_status_{$ikeid}_{$reqid}_{$valuekey}";
      $cache = pfz_get_cache($cache_key, CACHE_DURATION_SHORT);
      if ($cache !== null) { return $cache; }
      include_once_track('ipsec.inc');
      global $config;
      $a_phase1 = pfz_get_ipsec_config('phase1');
      $conmap = array();
      foreach ($a_phase1 as $ph1ent) {
+         // strongSwan versions diverge; try to build a robust con-name
          if (function_exists('get_ipsecifnum')) {
              if (get_ipsecifnum($ph1ent['ikeid'], 0)) { $cname = "con" . get_ipsecifnum($ph1ent['ikeid'], 0); }
              else { $cname = "con{$ph1ent['ikeid']}00000"; }
          } else{ $cname = ipsec_conid($ph1ent); }
          $conmap[$cname] = $ph1ent['ikeid'];
      }
      $status = ipsec_list_sa();
      $ipsecconnected = array();
      $carp_status = pfz_carp_status(false);
      // Phase-Status match borrowed from status_ipsec.php
      if (is_array($status)) {
          foreach ($status as $l_ikeid => $ikesa) {
+             // con-id formats vary, extract numeric suffix when available
+             if (isset($ikesa['con-id'])) {
+                 $con_id = preg_replace('/[^0-9]/', '', (string)$ikesa['con-id']);
+             } else {
+                 $con_id = filter_var($l_ikeid, FILTER_SANITIZE_NUMBER_INT);
+             }
              $con_name = "con" . $con_id;
              $ikeid = isset($conmap[$con_name]) ? $conmap[$con_name] : $ikeid;
              if (isset($ikesa['child-sas']) && is_array($ikesa['child-sas'])) {
                  foreach ($ikesa['child-sas'] as $child) {
                      $reqidc = (isset($child['reqid'])) ? $child['reqid'] : '-1';
                      $ipsecconnected[$ikeid][$reqidc] = $child['state'];
                  }
              }
          }
      }
      if ($reqid == -1) {
          $ret = isset($ipsecconnected[$ikeid]) ? 'up' : 'down';
      } else {
          $ret = isset($ipsecconnected[$ikeid][$reqid]) ? $ipsecconnected[$ikeid][$reqid] : 'down';
      }
      if ($valuekey == 'state') {
          $ret = pfz_valuemap('ipsec.status', $ret);
      } elseif ($valuekey == 'carpstate') {
          $ret = $carp_status;
      }
      pfz_set_cache($cache_key, $ret);
      return $ret;
  }
+ 
+ // ===== CARP helpers (unchanged signatures) + safer default
+ function pfz_carp_status($as_value_map = true) {
+     include_once_track('interfaces.inc');
+     $carp_enabled = function_exists('get_carp_status') ? get_carp_status() : false;
+     $status = $carp_enabled ? 'MASTER' : 'BACKUP';
+     return $as_value_map ? pfz_valuemap('carp.status', $status, $status) : $status;
+ }
***************
*** 940,980 ****
- // === CLI dispatcher (original minimal version) ===
- // ... (omitted in original)
+ // ===== Value maps centralization (examples; extend with your existing keys)
+ function pfz_valuemap($key, $val, $default = '') {
+     static $maps = [
+         'openvpn.server.status' => [ 'up' => 1, 'down' => 0, 'server_user_listening' => 2 ],
+         'openvpn.server.mode'   => [ 'server_user' => 1, 'server_tls_user' => 2, 'server_tls' => 3, 'p2p_tls' => 4 ],
+         'openvpn.client.status' => [ 'up' => 1, 'down' => 0 ],
+         'gateway.status'        => [ 'none' => 0, 'online' => 1, 'down' => 2, 'loss' => 3, 'latency' => 4 ],
+         'ipsec.status'          => [ 'up' => 1, 'down' => 0 ],
+         'ipsec.iketype'         => [ 'auto' => 0, 'ikev1' => 1, 'ikev2' => 2 ],
+         'ipsec.protocol'        => [ 'both' => 0, 'esp' => 1, 'ah' => 2 ],
+         'ipsec.mode'            => [ 'main' => 0, 'aggressive' => 1 ],
+         'ipsec_ph2.mode'        => [ 'tunnel' => 1, 'transport' => 2 ],
+         'ipsec_ph2.protocol'    => [ 'esp' => 1, 'ah' => 2 ],
+         'carp.status'           => [ 'MASTER' => 1, 'BACKUP' => 0 ]
+     ];
+     $map = $maps[$key] ?? null;
+     if (!$map) return ($val === '' ? $default : $val);
+     return $map[$val] ?? ($default === '' ? $val : $default);
+ }
+ 
+ // ===== Deterministic JSON helper
+ function pfz_json($arr): string { return json_encode($arr, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); }
+ 
+ // ===== Hardened CLI dispatcher with allowlists
+ function pfz_cli() {
+     $argv = $_SERVER['argv'] ?? [];
+     array_shift($argv); // drop script name
+     if (empty($argv)) { echo "Usage: php pfsense_zbx.php <action> [args...]\n"; exit(1); }
+     $action = $argv[0];
+     $allowed = [
+         'discovery' => ['interfaces','gateways','services','openvpn_servers','openvpn_server_users','openvpn_clients','ipsec_ph1','ipsec_ph2'],
+         'value'     => ['gw','service','openvpn_server','openvpn_server_user','openvpn_client','ipsec_ph1','ipsec_ph2','interface_speedtest'],
+         'speedtest_cron' => [],
+         'speedtest_cron_install' => [],
+         'clear_cache' => [],
+         'test' => []
+     ];
+     // convenience aliases
+     if ($action === '--help' || $action === '-h') {
+         echo "Available actions:\n";
+         foreach ($allowed as $k => $v) { echo " - $k" . (!empty($v) ? (" (".implode(',', $v).")") : '') . "\n"; }
+         exit(0);
+     }
+     if ($action === 'speedtest_cron') { pfz_speedtest_cron(); exit(0); }
+     if ($action === 'speedtest_cron_install') { pfz_speedtest_cron_install(true); exit(0); }
+     if ($action === 'clear_cache') { $pref = $argv[1] ?? ''; $n = pfz_cache_clear($pref); echo $n; exit(0); }
+     if ($action === 'test') { pfz_test(); exit(0); }
+ 
+     $sub = $argv[1] ?? '';
+     if (!isset($allowed[$action]) || (!empty($allowed[$action]) && !in_array($sub, $allowed[$action], true))) {
+         echo "Invalid action or sub-action. Use --help.\n"; exit(2);
+     }
+ 
+     // dispatch
+     switch ($action) {
+         case 'discovery':
+             switch ($sub) {
+                 case 'interfaces':           pfz_interface_discovery(false); break;
+                 case 'gateways':             pfz_gw_discovery(); break;
+                 case 'services':             pfz_services_discovery(); break;
+                 case 'openvpn_servers':      pfz_openvpn_serverdiscovery(); break;
+                 case 'openvpn_server_users': pfz_openvpn_server_userdiscovery(); break;
+                 case 'openvpn_clients':      pfz_openvpn_clientdiscovery(); break;
+                 case 'ipsec_ph1':            pfz_ipsec_discovery_ph1(); break;
+                 case 'ipsec_ph2':            pfz_ipsec_discovery_ph2(); break;
+             }
+             break;
+         case 'value':
+             switch ($sub) {
+                 case 'gw':                   pfz_gw_value($argv[2] ?? '', $argv[3] ?? ''); break;
+                 case 'service':              pfz_service_value($argv[2] ?? '', $argv[3] ?? ''); break;
+                 case 'openvpn_server':       pfz_openvpn_servervalue($argv[2] ?? '', $argv[3] ?? ''); break;
+                 case 'openvpn_server_user':  pfz_openvpn_server_uservalue($argv[2] ?? '', $argv[3] ?? '', $argv[4] ?? ''); break;
+                 case 'openvpn_client':       pfz_openvpn_clientvalue($argv[2] ?? '', $argv[3] ?? ''); break;
+                 case 'ipsec_ph1':            pfz_ipsec_ph1($argv[2] ?? '', $argv[3] ?? ''); break;
+                 case 'ipsec_ph2':            pfz_ipsec_ph2($argv[2] ?? '', $argv[3] ?? ''); break;
+                 case 'interface_speedtest':  pfz_interface_speedtest_value($argv[2] ?? '', $argv[3] ?? ''); break;
+             }
+             break;
+     }
+ }
+ 
+ // auto-run when called from CLI directly (keeps Zabbix UserParameter compatibility)
+ if (php_sapi_name() === 'cli' && realpath($argv[0]) === __FILE__) { pfz_cli(); }
+ ?>
