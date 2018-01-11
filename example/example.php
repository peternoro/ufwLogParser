<?php
namespace App;
require_once '../app/UfwLogParser.php';

try {
    $p = new UfwLogParser('/var/log/ufw.log');
    $data = $p->parse()->getParsedData();

    print_r($data);
}
catch(Exception $e){
    echo $e->getMessage();
}
