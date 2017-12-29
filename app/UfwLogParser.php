<?php
/**
 * An small class to parse the ufw.log in an assoc array.
 * What to do with it? Up to you. I'll load it in a database for further analysis
 *
 * Usage:
 * $p = new UfwLogParser();
 * $p->parse();
 * var_dump($p->getParsedData());
 *
 * @author Peter <peter@qves.de>
 */

namespace App {

    use Exception;

    class UfwLogParser
    {
        /**
         * Global variables
         */
        var $_srcFile = null;
        var $_srcContent = null;
        var $_parsedContent = null;
        var $_knownHosts = array();
        var $_knownServices = array();

        /**
         * Class constructor
         *
         * @param   mixed   $fileName   Can be a filename. If nothing provided asumme you use CLI option -f
         * @return  bool
         */
        public function __construct($fileName = true)
        {
            global $argc, $argv;

            // for time and date calculation this must be set once.
            date_default_timezone_set('Europe/Bratislava');

            if ($fileName === true) {
                if ($argc < 2 && in_array($argv[1], array('--file', '-file', '-f'))) {
                    print "Usage Error: No arguments provided. Try -f filename --file filename";

                    return false;
                }

                // set the file to be loaded
                $this->setFile($argv[2]);
            }

            // set filename
            $this->setFile($fileName);

            // read file content
            $this->_readContent();

            return true;
        }

        /**
         * Class destructor
         */
        public function __destruct()
        {
            $this->_knownServices = null;
            $this->_knownHosts = null;
            $this->_srcContent = null;
            $this->_srcFile = null;
            $this->_parsedContent = null;
        }

        /**
         * Debug Printout function
         * @param mixed $str
         * @return mixed
         */
        public static function debug($str)
        {
            return printf("<pre>%s</pre>", print_r($str, true));
        }

        /**
         * Read file content
         * @param bool  $asArray  Create an array yes or no
         */
        private function _readContent($asArray = true)
        {
            try {
                if ($this->_srcFile != null) {
                    if ($asArray) {
                        $this->_srcContent = explode("\n", file_get_contents($this->_srcFile));
                    } else {
                        $this->_srcContent = file_get_contents($this->_srcFile);
                    }
                }
            } catch (Exception $e) {
                printf("Error: File read failed.");
                UfwLogParser::debug($e->getMessage());
            }
        }

        /**
         * Set filename to parse
         * @param string $input
         */
        public function setFile($input)
        {
            try {
                if (is_readable($input) && is_file($input))
                    $this->_srcFile = $input;
            } catch (Exception $e) {
                printf("Error: Unable to read %s from filesystem.", $input);
                UfwLogParser::debug($e->getMessage());
            }
        }

        /**
         * Parse the global Array of Ufw crap
         *
         * @param   $item mixed Can be bool or int
         */
        public function parse($item = true)
        {
            $return = array();

            // do it once to get the file creation year
            $fmTime = filemtime($this->_srcFile);

            if ($item === true) {
                foreach ($this->_srcContent as $k => $v) {
                    /**
                     * 0.   full string
                     * 1.   month e.g. Jan, Feb
                     * 2.   day of month
                     * 3.   time (HH:MM:ii)
                     * 4.   hostname
                     * 5.   action like BLOCK // REJECT // DENY
                     * 6.   Input Interface e.g. ens
                     * 7.   Output Interface
                     * 8.   Mac Address of the Interface
                     * 9.   Source IP
                     * 10.  Destination IP
                     * 11.  Protocol TCP/UDP
                     * 12.  Source Port
                     * 13.  Destination Port
                     */
                    preg_match('/^([a-zA-z]{3}) ([0-9]{1,2}) ([0-9]{2}:[0-9]{2}:[0-9]{2}) ([a-z0-9]{3,}) .* \[(UFW.*)\] IN=([a-z0-9]{2,9}) OUT=([a-z0-9]{0,9}) MAC=([a-z0-9:]{4,}) SRC=([0-9.]{4,}) DST=([0-9.]{4,}).*PROTO=([A-Z]{3}) SPT=([0-9]{1,5}) DPT=([0-9]{1,5}) .*$/i', $v, $r);

                    $return[$k]['log_month'] = $this->_shortMonthToInt($r[1]);
                    $return[$k]['log_day'] = $r[2];
                    $return[$k]['log_year'] = date('Y', $fmTime);
                    //$return[$k]['time'] = $r[3];
                    $_tmp = explode(":", $r[3]);
                    $return[$k]['log_unixtime'] = mktime((int)$_tmp[0], (int)$_tmp[1], (int)$_tmp[2], $return[$k]['month'], $r[2], $return[$k]['year']);
                    $return[$k]['log_hour'] = $_tmp[0];
                    $return[$k]['log_minute'] = $_tmp[1];
                    $return[$k]['log_second'] = $_tmp[2];
                    $return[$k]['hostname'] = $r[4];
                    $return[$k]['action'] = $r[5];
                    $return[$k]['interface_in'] = $r[6];
                    $return[$k]['interface_out'] = $r[7];
                    $return[$k]['mac_address'] = $r[8];
                    $return[$k]['source_ip'] = $r[9];
                    $return[$k]['source_name'] = $this->_getHostByAddress($r[9]);
                    $return[$k]['destination_ip'] = $r[10];
                    $return[$k]['destination_name'] = $this->_getHostByAddress($r[10]);
                    $return[$k]['protocol'] = $r[11];
                    $return[$k]['source_port_id'] = $r[12];
                    $return[$k]['source_port_name'] = $this->_getServiceById($r[12], $r[11]);
                    $return[$k]['destination_port_id'] = $r[13];
                    $return[$k]['destination_port_name'] = $this->_getServiceById($r[13], $r[11]);
                    $return[$k]['hash'] = $this->_makeHash($r[0], 'sha', 'ufwLog');
                }

                unset($return[count($return) -1]);

            } elseif (is_int($item)) {
                preg_match('/^([a-zA-z]{3}) ([0-9]{1,2}) ([0-9]{2}:[0-9]{2}:[0-9]{2}) ([a-z0-9]{3,}) .* \[(UFW.*)\] IN=([a-z0-9]{2,9}) OUT=([a-z0-9]{0,9}) MAC=([a-z0-9:]{4,}) SRC=([0-9.]{4,}) DST=([0-9.]{4,}).*PROTO=([A-Z]{3}) SPT=([0-9]{1,5}) DPT=([0-9]{1,5}) .*$/i', $this->_srcContent[$item], $r);

                $return['log_month'] = $this->_shortMonthToInt($r[1]);
                $return['log_day'] = $r[2];
                $return['log_year'] = date('Y', $fmTime);
                //$return['time'] = $r[3];
                $_tmp = explode(":", $r[3]);
                $return['log_unixtime'] = mktime((int)$_tmp[0], (int)$_tmp[1], (int)$_tmp[2], $return['month'], $r[2], $return['year']);
                $return['log_hour'] = $_tmp[0];
                $return['log_minute'] = $_tmp[1];
                $return['log_second'] = $_tmp[2];
                $return['hostname'] = $r[4];
                $return['action'] = $r[5];
                $return['interface_in'] = $r[6];
                $return['interface_out'] = $r[7];
                $return['mac_address'] = $r[8];
                $return['source_ip'] = $r[9];
                $return['source_name'] = $this->_getHostByAddress($r[9]);
                $return['destination_ip'] = $r[10];
                $return['destination_name'] = $this->_getHostByAddress($r[10]);
                $return['protocol'] = $r[11];
                $return['source_port_id'] = $r[12];
                $return['source_port_name'] = $this->_getServiceById($r[12], $r[11]);
                $return['destination_port_id'] = $r[13];
                $return['destination_port_name'] = $this->_getServiceById($r[13], $r[11]);
                $return['hash'] = $this->_makeHash($r[0], 'sha', 'ufwLog');
            }

            $this->_parsedContent = $return;
        }

        /**
         * Get parsed content
         *
         * @return  array
         */
        public function getParsedData()
        {
            return $this->_parsedContent;
        }

        /**
         * Make an unique has on the data provided to build an unique identifier
         *
         * @param   mixed   $data
         * @param   string  $hashType   default is md5 but can be sha or bcrypt
         * @param   string  $salt       if it needs to be always the same define a name other randomly we generate one
         * @return  string
         */
        private function _makeHash($data, $hashType = 'md5', $salt = 'random')
        {
            // first create an whole string out of our data
            $str = null;
            if (is_array($data)) {
                foreach ($data as $k => $v) {
                    $str .= trim($v);
                }
            } else {
                $str = trim($data);
            }

            if ($salt == "random") {
                // create an salt
                $salt = password_hash(uniqid(rand(0, microtime())), PASSWORD_BCRYPT);
            }
            $salt = trim($salt);

            // now generate an hash
            switch (strtolower($hashType)) {
                case 'md5':
                    $str = md5($str.$salt);
                    break;
                case 'sha':
                    $str = sha1($str.$salt);
                    break;
                case 'bcrypt':
                    $str = crypt($str,$salt);
                    break;
                default:
                    $str = md5($str.$salt);
            }

            return $str;
        }

        /**
         * Get Hostname for an IP Address.
         * To reduce the load an array will be filled with known hosts
         *
         * @param   string $ip  IP Address
         * @return  string      Hostname
         */
        private function _getHostByAddress($ip)
        {
            if (!in_array($ip, $this->_knownHosts)) {
                $this->_knownHosts[$ip] = @gethostbyaddr($ip);
                if (filter_var($this->_knownHosts[$ip], FILTER_VALIDATE_IP))
                    $this->_knownHosts[$ip] = 'unknown';
            }

            return $this->_knownHosts[$ip];
        }

        /**
         * Get ServiceName (if registered)
         * To reduce the load an array will be filled with known hosts
         *
         * @param   int     Service Id
         * @param   string  Protocol
         * @return  string  ServiceName if available otherwise unknown
         */
        private function _getServiceById($s, $p)
        {
            if (!in_array($s, $this->_knownServices)) {
                $this->_knownServices[$s] = @getservbyport($s, strtolower($p));
                if (trim($this->_knownServices[$s]) == '')
                    $this->_knownServices[$s] = 'unknown';
            }

            return $this->_knownServices[$s];
        }

        /**
         * Translate Month shortCode in Int
         *
         * @param string $i
         * @return int
         */
        private function _shortMonthToInt($i)
        {
            $months = array(
                '1' => 'Jan',
                '2' => 'Feb',
                '3' => 'Mar',
                '4' => 'Apr',
                '5' => 'Mai',
                '6' => 'Jun',
                '7' => 'Jul',
                '8' => 'Aug',
                '9' => 'Sep',
                '10'=> 'Oct',
                '11'=> 'Nov',
                '12'=> 'Dec'
            );

            return array_flip($months)[$i];
        }
    }
}

/* FileName: UfwLogParser.php */