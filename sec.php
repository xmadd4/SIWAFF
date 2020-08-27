<?php
error_reporting(0);
@clearstatcache();
@ini_set('error_log',NULL);
@ini_set('log_errors',0);
@ini_set('max_execution_time',0);
@ini_set('output_buffering',0);
@ini_set('display_errors', 0);
date_default_timezone_set('Asia/Jakarta');

$security_secret_file="hwkr.txt";
$alert="<html>
	<head>
<title>Blocked To Acces</title>
<meta name='Author' content='Underfif'>
<link rel='icon' href='https://upload.wikimedia.org/wikipedia/commons/7/70/Forbidden_sign.png'>
<style>
*{
    margin-top:2px;
}
 
body{
    background-position: center;
    background-color:#000000;
    height:98%;
    width:99%;
    background-attachment: fixed;
    background-size:100% 117%;
    background-image:url();
    cursor: url(http://cur.cursors-4u.net/cursors/cur-11/cur1025.ani), url(http://cur.cursors-4u.net/cursors/cur-11/cur1025.png), progress !important;
}
.foter span{
    text-align: center;
    font-family: Orbitron;
    font-size: 300%;
    color: silver;
    text-shadow: 0 0 3px silver, 0px 0px 5px darkblue;
}
 
#sec:hover{
    color:#000000;
    text-shadow: 0 0 3px silver, 0px 0px 5px darkblue;
}
 
</style></head>
    
<img src='https://i.ibb.co/8rXd3Rf/image-png.png' height='350px' width='350px' style='display: block; margin: auto;'>
<center> 
    <p><font face='iceland' style='font-size:30px; text-shadow:#0063FF 0px 5px 5px;' color='red'>Sorry your ip has ben block, Because Malicious Code Detected</font></p> 
   </center> 
    <center> 
    <p><font face='iceland' style='font-size:30px; text-shadow:#0063FF 0px 5px 5px;' color='white'>My Friends</font></p> 
   </center>
   <center>
   <table width=820px>
<td align=center>
<span style='font: 15px Courier;size:15px;color:#9E9E9E;'>
<strong>
	</center>
 <marquee behavior='alternate' scrollamount='5' style='border:1px solid;' width='70%'><font color='white' face='courier'>4.D |<font color='red'> Underfif</font>Riozn.id | F3R1 | Omest | Benon | Mr.mf33 | ./B3G4L | Elshaint | Helix | Underfif | Mr Blackhat10 | Azeverghost | Zbunny | Mr.bar</center></font></marquee></div>
 <p/>
<
<
<
<font color='white' size='5'>&copy; 2020 4dsecurity</font></a>
>
>
>
<p />
</html>";
//--------------------------------------------//

function security_logger($ip) {
    $x=fopen("threat_log", "a");
    fwrite($x, $ip." ( ".$_SERVER['HTTP_USER_AGENT']." ".date("r")." ) "." => ".$_SERVER['REQUEST_URI']."\n");
    fclose($x);
}
function security_add_ip($ip, $time) {
    global $security_secret_file;
    $f=fopen($security_secret_file, "a");
    fwrite($f, $ip."^^^".$time."\n");
    fclose($f);
    security_logger($ip);
}

function security_del_ip($ip, $time) {
    global $security_secret_file;
    $file=file_get_contents($security_secret_file);
    $f=fopen($security_secret_file, "w");
    fwrite($f, str_replace($ip."^^^".$time."\n", "", $file));
    fclose($f);
}

$malicious="/alert\(|alert \(|<|>|\"|\||\'|information_schema|\/var|\/etc|\/home|file_get_contents|wget|script|union|wget|cmd|order|javascript|shell_exec|table_schema|user\(\)|user \(\)/";
$security_user_agent="/Mozilla|Chrome|Google|WhatsApp|Telegram/";

if(!empty($_GET)) {
    foreach($_GET as $security_get_request) {
        if(preg_match("$malicious", $security_get_request)) {
            echo $alert;
            if(!preg_match($_SERVER['REMOTE_ADDR'], file_get_contents($security_secret_file))) {
                security_add_ip($_SERVER['REMOTE_ADDR'], time());
            }
            exit;
        }
    }
}

if(!empty($_POST)) {
    foreach($_POST as $security_post_request) {
        if(preg_match("$malicious", $security_post_request)) {
            echo $alert;
            if(!preg_match($_SERVER['REMOTE_ADDR'], file_get_contents($security_secret_file))) {
                security_add_ip($_SERVER['REMOTE_ADDR'], time());
            }
            exit;
        }
    }
}

if(!empty($_FILES)) {
    foreach($_FILES as $security_files_request) {
        if(preg_match("$malicious", $security_files_request)) {
            echo $alert;
            if(!preg_match($_SERVER['REMOTE_ADDR'], file_get_contents($security_secret_file))) {
                security_add_ip($_SERVER['REMOTE_ADDR'], time());
            }
            exit;
        }
    }
}

if(preg_match("/".$_SERVER['REMOTE_ADDR']."/", file_get_contents($security_secret_file))) {
    $security_file=explode("\n", file_get_contents($security_secret_file));
    foreach($security_file as $security_ip_line) {

        if(empty($security_ip_line)) {
            continue;
        }

        $security_ip_scan=explode('^^^', $security_ip_line);
        if(time() > $security_ip_scan[1]+3153600000000 ) {
            if($security_ip_scan[0] == $_SERVER['REMOTE_ADDR']) {
                security_del_ip($security_ip_scan[0], $security_ip_scan[1]);
            } else {
                continue;
            }
        } else {
            echo $alert;
            exit;
        }
    }
}

if(!preg_match($security_user_agent, $_SERVER['HTTP_USER_AGENT'])) {
    security_add_ip($_SERVER['REMOTE_ADDR'], time());
    echo $alert;
    exit;
}