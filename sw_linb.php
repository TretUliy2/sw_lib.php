<?php
/* Class for management differen kind of active equipment 
 * with SNMP Protocol
 * It is designated for software which handles 
 * network management functions.
 * */
class sw_lib {
    private static $session;
    
    public function __construct($ip, $password) {
        if ( !filter_var($ip, FILTER_VALIDATE_IP) ) {
            print "Invalid ip address $ip\n";
            return FALSE;
        }    
        $this->ip = $ip;
        $this->password = $password;
        
        $timeout = 50000000;
        $retries = 0;
        self::$session = new SNMP(SNMP::VERSION_2C, $this->ip, $this->password, $timeout, $retries) 
            or die(self::$session -> getError());
        
        self::$session->oid_output_format = SNMP_OID_OUTPUT_NUMERIC;
        self::$session->valueretrieval = SNMP_VALUE_PLAIN;
        self::$session->exceptions_enabled = SNMP::ERRNO_ANY;
        
    }

    public function ping() {
        $oid = ".1.3.6.1.2.1.1.1.0";
        $timeout = 100000;
        $retries = 0;
        $s = new SNMP(SNMP::VERSION_2C, $this->ip, $this->password, $timeout, $retries) 
            or die($s->getError());
        $s->exceptions_enabled = 0;
        $s->oid_output_format = SNMP_OID_OUTPUT_NUMERIC;
        $s->valueretrieval = SNMP_VALUE_PLAIN;
        if ( !$s->get( $oid ) ){
            $s->close();    
            return false;
        }
        $s->close();
        return true;
    }
    
    public function getPortSpeed($port) {
        if ( !isset($port) ) {
            print "You should specify port\n";
            die();
        }
        $oid = ".1.3.6.1.2.1.2.2.1.5.$port";
        $speed = self::$session->get($oid);
        if ($speed == 1410065408) {
            $speed = "10G";
        } else if  ($speed > 100000000) {
            $speed = ((int)$speed / 1000000000) . "G";
        } else {
            $speed = ((int)$speed / 1000000) . "M";
        }

        return $speed;
    }

    public function getPortsInfo() {
        $ports = $this->getPorts();
        $speed_oid = ".1.3.6.1.2.1.2.2.1.5";
        $admin_state_oid = ".1.3.6.1.2.1.2.2.1.7";
        $status_oid = ".1.3.6.1.2.1.2.2.1.8";
        $errors_oid = ".1.3.6.1.2.1.2.2.1.14";
        $vlan_oid = ".1.3.6.1.2.1.17.7.1.4.5.1.1";
        
        $oids = array();
        $port_info = array();
        
        //var_dump(self::$session);
        foreach ( $ports as $port ) {
            array_push($oids, "$speed_oid.$port");
            array_push($oids, "$admin_state_oid.$port");
            array_push($oids, "$status_oid.$port");
            array_push($oids, "$errors_oid.$port");
            array_push($oids, "$vlan_oid.$port");
        }
        //var_dump($oids);
        self::$session->max_oids = 70;
        $result = self::$session->get( $oids );
        self::$session->max_oids = NULL;
        //$result = array_values($result);
        foreach ($ports as $port ) {
            $port_info[$port]['speed'] = self::prettyfySpeed($result["$speed_oid.$port"]);
            $port_info[$port]['admin_state'] = $result["$admin_state_oid.$port"];
            $port_info[$port]['status'] = $result["$status_oid.$port"];
            $port_info[$port]['errors'] = $result["$errors_oid.$port"];
            $port_info[$port]['vlan'] = $result["$vlan_oid.$port"];
        }
        return $port_info;
    }
    
    private function prettyfySpeed($speed) {
        if ($speed == 1410065408) {
            $speed = "10G";
        } else if ($speed > 100000000) {
            $speed = ((int)$speed / 1000000000) . "G";
        } else {
            $speed = ((int)$speed / 1000000) . "M";
        }
        return $speed;
    }
    
    public function getPortStatus($port) {
        $oid = ".1.3.6.1.2.1.2.2.1.8.$port";
        $result = self::$session->get( $oid );
        return $result;
    }

    public function getPortAdminState($port) {
        $oid = ".1.3.6.1.2.1.2.2.1.7.$port";
        $result = self::$session->get( $oid );
        return $result;
    }

    public function getPortAlias($port) {
        $oid = ".1.3.6.1.2.1.31.1.1.1.18.$port";
        $result = self::$session->get( $oid );
        return $result;
    }

    public function getPortDescr($port) {
        $oid = ".1.3.6.1.2.1.2.2.1.2.$port";
        $result = self::$session->get( $oid );
        return $result;
    }

    public function getPortVlan($port) {
        $oid = ".1.3.6.1.2.1.17.7.1.4.5.1.1.$port";
        $result = self::$session->get( $oid );
        return $result;
    }
    
    public function getPortVlanDGS1210($port) {
        $oid = ".1.3.6.1.4.1.171.10.76.28.1.11.5.1.2.$port";
        $result = self::$session->get( $oid );
        return $result;
    }

    public function getPortInErrors($port) {
        $oid = ".1.3.6.1.2.1.2.2.1.14.$port";
        $result = self::$session->get( $oid );
        return $result;
    }
        
    public function getPortMac($port, $oid = ".1.3.6.1.2.1.17.7.1.2.2.1.2") {
        $result = self::$session->walk( $oid );
        $macTable = array();

        foreach ($result as $key => $value) {
            if ($port != $value) {
                continue;
            }
            $tmp = preg_split('/\./', substr($key, 28));
            $vlan = array_shift($tmp);
            $mac = implode(":", array_map("self::hexval", $tmp));
            $sw_port = $value;
            array_push($macTable, array("port" => $port, "vlan" => $vlan, "mac" => $mac));
        }
        return $macTable;
    }

    public function getPortMacCelan ($port, $oid = ".1.3.6.1.4.1.655.5.15.1.4.4.1.2") {
         // default oid for 0800i-EA
         self::$session->max_oids = NULL;    
         $result = self::$session->walk( $oid );
         self::$session->max_oids = 70; 
         $macTable = array();
         foreach ($result as $key => $value) {
             $item = unpack("H12mac/H8port/H*vlan", $value);    
             $item['port'] = hexdec($item['port']);
             
             if ( $item['port'] != $port ) { continue; }
             
             $item['mac'] = implode(":", str_split($item['mac'], 2));
             $item['vlan'] = hexdec($item['vlan']);
             
             array_push($macTable, $item);
         }
         return $macTable;
    }
    
    public function getPortType($port) {
        $oid = ".1.3.6.1.2.1.2.2.1.3.$port";
        $result = self::$session->get( $oid );
        return $result;
    }
    
    public function getPorts() {
        $oid = ".1.3.6.1.2.1.2.2.1.3";
        $result = self::$session->walk( $oid );
        $validTypes = array(117, 6, 94);
        
        $ifaces = array();
        foreach ( $result as $key => $value ) {
            $port = array_pop(preg_split("/\./", $key));
            if (in_array($value, $validTypes)) {
                array_push($ifaces, $port);
            }
        }
        return $ifaces;
    }
    
    public function getPortMac0800iEA($port) {
        $result = self::getPortMacCelan($port);
        return $result;
    }

    public function getPortMac2402FGiEA($port) {
        $oid = ".1.3.6.1.4.1.655.9.3.1.4.4.1.2";
        $result = $this->getPortMacCelan($port, $oid);
        return $result;
    }

    public function getPortMac2402GiEA($port) {
        $oid = ".1.3.6.1.4.1.655.9.12.1.4.4.1.2";
        $result = $this->getPortMacCelan($port, $oid);
        return $result;
    }

    private function hexval($i) {
        return sprintf("%02x", $i);
    }

    public function getCableDiagInfo($port) {
        $this->setCableDiag($port);
        sleep(1);    
        $pair = array();
        $result_pair = array();
        
        $status_code = array(
             '0' => "ok", 
             '1' => "open", 
             '2' => "short", 
             '3' => "open-short", 
             '4' => "crosstalk", 
             '5' => "unknown", 
             '6' => "count", 
             '7' => "no-cable", 
             '8' => "other"
        );
        
        for ( $i = 1, $k = 8; $i <= 4; $i++, $k++) {
            $pair[$i]["len_oid"] = ".1.3.6.1.4.1.171.12.58.1.1.1.$k.$port";
        }
        
        for ( $i = 1, $k = 4; $i <= 4; $i++, $k++) {
            $pair[$i]["status_oid"] = ".1.3.6.1.4.1.171.12.58.1.1.1.$k.$port";
        }
        
        
        $oids = array();
        
        foreach ( $pair as $oid ) {
            array_push($oids, $oid["len_oid"]);
            array_push($oids, $oid["status_oid"]);
        }
        
        $result = self::$session->get( $oids );
        for ($i = 1; $i <= 4; $i++) {
            if ($result[$pair[$i]["status_oid"]] == 8 ) { continue; }
            $result_pair[$i]["len"] = $result[$pair[$i]["len_oid"]];
            $result_pair[$i]["status"] = $status_code[$result[$pair[$i]["status_oid"]]];
        }
        
        return $result_pair;
    }
    
    public function getCableDiagInfoDGS1210($port) {
    	$this->setCableDiagDGS1210($port);
    	sleep(1);
    	$pair = array();
    	$result_pair = array();
    
    	$status_code = array(
    			'0' => "ok",
    			'1' => "open",
    			'2' => "short",
    			'3' => "open-short",
    			'4' => "crosstalk",
    			'5' => "unknown",
    			'6' => "count",
    			'7' => "no-cable",
    			'8' => "other"
    	);
    
    	for ( $i = 1, $k = 8; $i <= 4; $i++, $k++) {
    		$pair[$i]["len_oid"] = ".1.3.6.1.4.1.171.10.76.28.1.35.1.1.$k.$port";
    	}
    
    	for ( $i = 1, $k = 4; $i <= 4; $i++, $k++) {
    		$pair[$i]["status_oid"] = ".1.3.6.1.4.1.171.10.76.28.1.35.1.1.$k.$port";
    	}
    
    
    	$oids = array();
    
    	foreach ( $pair as $oid ) {
    		array_push($oids, $oid["len_oid"]);
    		array_push($oids, $oid["status_oid"]);
    	}
    
    	$result = self::$session->get( $oids );
    	for ($i = 1; $i <= 4; $i++) {
    		if ($result[$pair[$i]["status_oid"]] == 8 ) { continue; }
    		$result_pair[$i]["len"] = $result[$pair[$i]["len_oid"]];
    		$result_pair[$i]["status"] = $status_code[$result[$pair[$i]["status_oid"]]];
    	}
    
    	return $result_pair;
    }

    public function setPortAlias($port, $descr) {
        $oid = ".1.3.6.1.2.1.31.1.1.1.18.$port";
        $result = self::$session->set( $oid, 's', $descr);
        return $result;
    }
    
    public function setPortDescrIES1248($port, $descr) {
        $oid = ".1.3.6.1.4.1.890.1.5.13.6.8.1.1.1.$port";
        $result = self::$session->set( $oid, 's', $descr);
        return $result;
    }
    
    public function setPortDescrIES1212($port, $descr) {
        $oid = ".1.3.6.1.4.1.890.1.5.11.11.8.1.1.1.$port";
        $result = self::$session->set( $oid, 's', $descr);
        return $result;
    }
    
    
    public function setPortDescr0800iEA($port, $descr) {
        $oid = ".1.3.6.1.4.1.655.5.15.1.2.1.1.2.$port";
        $result = self::$session->set( $oid, 's', $descr);
        return $result;
    }
    
    
    public function setPortDescr2402FGiEA($port, $descr) {
        $oid = ".1.3.6.1.4.1.655.9.3.1.2.1.1.2.$port";
        $result = self::$session->set( $oid, 's', $descr);
        return $result;
    }
    
        
    public function setPortDescr2402GiEA($port, $descr) {
        $oid = ".1.3.6.1.4.1.655.9.12.1.2.1.1.2.$port";
        $result = self::$session->set( $oid, 's', $descr);
        return $result;
    }
    
    public function setPortDescrDGS1210($port, $descr) {
    	if ( $port < 25 ) {
			$oid = ".1.3.6.1.4.1.171.10.76.28.1.1.14.1.3.$port.1";    	
    	} else {
    		$oid = ".1.3.6.1.4.1.171.10.76.28.1.1.14.1.3.$port.2";
    	}
    	$result = self::$session->set( $oid, 's', $descr);
    	return $result;
    }
    public function setPortAdmin($port, $action) {
        $oid = ".1.3.6.1.2.1.2.2.1.7.$port"; 
        if ( strtolower($action) === "up" ) {
            $value = "1";
        } elseif ( strtolower($action) === "down" ) {
            $value = "2";
        } else {
            print "unknown action: $action should by \"up\" or \"down\"\n";
            return FALSE;
        }
        $result = self::$session->set( $oid, "i", $value );
        return TRUE;        
    }
    
    public function setCableDiag($port) {
        $oid = ".1.3.6.1.4.1.171.12.58.1.1.1.12.$port";
        $value = 1;
        $result = self::$session->set( $oid, "i", $value );
        return $result;
    }
    
    public function setCableDiagDGS1210($port) {
    	$oid = ".1.3.6.1.4.1.171.10.76.28.1.35.1.1.12.$port";
    	$value = 1;
    	$result = self::$session->set( $oid, "i", $value );
    	return $result;
    }
    
    public function setRebootDlink() {
        $oid = ".1.3.6.1.2.1.16.19.5.0";
        $value = 2;
        $result = self::$session->set( $oid, "i", $value );
        return $result;
    }
    
    public function setSaveConfigDGS1210() {
    	$oid = ".1.3.6.1.4.1.171.10.76.28.1.1.10.0";
    	$value = 3;
    	$result = self::$session->set( $oid, "i", $value );
    	return $result;
    }
    
    public function setSaveConfigDlinkDES3200() {
        # Models DES-3200 A1/B1
        $oid = ".1.3.6.1.4.1.171.12.1.2.6.0";    
        $value = 5;
        self::$session->exceptions_enabled = 0;
        $result = self::$session->set( $oid, "i", $value );
        self::$session->exceptions_enabled = SNMP::ERRNO_ANY;
        return $result;
    }
    
    public function setSaveConfigDlinkType1() {
        # Models DES-3526 DES-3550 DES-3552
        $oid = ".1.3.6.1.4.1.171.12.1.2.6.0";    
        $value = 3;
        self::$session->exceptions_enabled = 0;
        $result = self::$session->set( $oid, "i", $value );
        self::$session->exceptions_enabled = SNMP::ERRNO_ANY;
        return $result;
    }
    
    public function setSaveConfigDlinkType2() {
        # Models DES-3200C1
        # agentBscFileSystemSaveCfg
        $oid = ".1.3.6.1.4.1.171.12.1.2.18.4.0";
        $value = 4;
        self::$session->exceptions_enabled = 0;
        $result = self::$session->set( $oid, "i", $value );
        self::$session->exceptions_enabled = SNMP::ERRNO_ANY;
        return $result;
    }
    
    public function setSaveConfig_DGS() {
        # agentSaveCfg
        $oid = "1.3.6.1.4.1.171.12.1.2.6.0";
        $value = 5;
        self::$session->exceptions_enabled = 0;
        $result = self::$session->set( $oid, "i", $value );
        self::$session->exceptions_enabled = SNMP::ERRNO_ANY;
        return $result;
    }
    
    public function __destructor() {
        self::$session->close();
    }
    
    public function close() {
        self::$session->close();
    }

}
?>
