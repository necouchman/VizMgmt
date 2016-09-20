<?php
date_default_timezone_set('America/Denver');

function connectDB() {
	if(!($DB = pg_connect("host=localhost user=vizmgmt password=vizmgmt dbname=vizdb sslmode=disable")))
		return false;
	return $DB;
}

function closeDB($DB) {
	return pg_close($DB);
}

function connectLDAP($server,$user,$pass) {
	if($server == "")
		$server = "ldaps://localhost";
	$LDAP = ldap_connect($server);
	ldap_set_option($LDAP, LDAP_OPT_PROTOCOL_VERSION, 3);
	if($user != "" && $pass == "")
		return false;
	else if($user != "" && $pass != "") {
		if(!ldap_bind($LDAP,$user,$pass))
			return FALSE;
	} else {
		if(!ldap_bind($LDAP))
			return FALSE;
	}
	return $LDAP;
}

function authDevice($devInfo,$hashValue) {
	/* Input:
		$devInfo - array with device name, public key.
		$data - data passed by the device for hashing.
		$hashValue - value of hash computed by device.
	   Return:
		True if hash of devInfo matches database and hash
		of data+private key matches.
		False if mis-match.
	*/
	$DB = connectDB();
	$QUERY = "SELECT private_key FROM devices WHERE device_name='" . $devInfo['name'] . "' AND public_key='" . $devInfo['public_key'] . "';";
	$QUERY = pg_query($DB,$QUERY);
	$KEY = pg_fetch_all($QUERY);
	$HASH = hash_hmac("sha256",$devInfo['name'] . $devInfo['public_key'] . $KEY[0]['private_key'],$KEY[0]['private_key']);
	if($HASH == $hashValue)
		return true;
	return false;
}

require 'Slim/Slim.php';

\Slim\Slim::registerAutoloader();

$vmsAPI = new \Slim\Slim();

// Search for existing visitor records by first and last name.
$vmsAPI->get('/visitor/search/:cn', function($cn) use ($vmsAPI) {
	$LDAP = connectLDAP(NULL,NULL,NULL);
	$filter = '(&(objectClass=inetOrgPerson)(cn=*' . $cn . '*))';
	$attrs = array("dn","o","mail","cn");
	$search = ldap_search($LDAP, "dc=vizmgmt,dc=example,dc=com", $filter, $attrs);
	$results = ldap_get_entries($LDAP, $search);
	if($results['count'] == 0)
		die("No users found that match this criteria");
	$retArray = array();
	for($i = 0; $i < $results['count']; $i++) {
		if(isset($results[$i]['o']))
			$retArray[$i]['Org'] = $results[$i]['o'][0];
		if(isset($results[$i]['mail']))
			$retArray[$i]['Mail'] = $results[$i]['mail'][0];
		if(isset($results[$i]['dn']))
			$retArray[$i]['dn'] = $results[$i]['dn'];
		if(isset($results[$i]['cn']))
			$retArray[$i]['cn'] = $results[$i]['cn'][0];
	}
	$vmsAPI->response->header("Content-Type: application/json");
	echo json_encode($retArray);

});

// Get full info for visitor record based on LDAP DN.
$vmsAPI->get('/visitor/info/:dn', function($dn) use ($vmsAPI) {
	$LDAP = connectLDAP(NULL,NULL,NULL);
	$filter = '(objectClass=inetOrgPerson)';
	// $attrs = array("dn","givenName","sn","o","ou","mail","telephoneNumber","mobile","cn","l","postalCode","st","street","jpegPhoto");
	$entry = ldap_read($LDAP, $dn, $filter);
	$entry = ldap_first_entry($LDAP, $entry);
	$results = ldap_get_attributes($LDAP, $entry);
	$retArray = array();
	foreach($results as $attr => $value) {
		if($attr == "jpegPhoto")
			continue;
		if(!is_numeric($attr) && $attr != "count") {
			if(is_array($value))
				$retArray[$attr] = $value[0];
			else
				$retArray[$attr] = $value;
		}
	}
	$vmsAPI->response->header("Content-Type: application/json");
	echo json_encode($retArray);
});

// Get Picture for Visitor.
$vmsAPI->get('/visitor/picture/:dn', function($dn) use ($vmsAPI) {
	$LDAP = connectLDAP(NULL,NULL,NULL);
	$filter = '(objectClass=inetOrgPerson)';
	$entry = ldap_read($LDAP,$dn,$filter,array("jpegPhoto"));
	$entry = ldap_first_entry($LDAP, $entry);
	$results = ldap_get_attributes($LDAP, $entry);
	if(isset($results['jpegPhoto'])) {
		if(is_array($results['jpegPhoto']))
			$photo = imagecreatefromstring($results['jpegPhoto'][0]);
		else
			$photo = imagecreatefromstring($results['jpegPhoto']);
	} else {
		$photo = imagecreatetruecolor(150,200);
		imagestring($photo, 5, 0, 0, "NO PHOTO", 0xFFFFFF);
	}
	$vmsAPI->response->header('Content-Type', 'content-type: image/jpeg');
	imagejpeg($photo);
});

// Register a new visitor from data in form.
$vmsAPI->post('/visitor/register', function() use ($vmsAPI) {
	$body = $vmsAPI->request->getBody();
	if($_SERVER['CONTENT_TYPE'] == "application/json")
		$input = json_decode($body, TRUE);
	else if($_SERVER['CONTENT_TYPE'] == "application/x-www-form-urlencoded")
		parse_str($body, $input);
	else
		return;
	$newCN = $input['First'] . " " . $input['Last'];
	$lfilter = "(cn=" . $newCN . "*)";
	$LDAP = connectLDAP(NULL,NULL,NULL);
	$lsearch = ldap_search($LDAP,"dc=vizmgmt,dc=example,dc=com", $lfilter, array("dn"));
	$lresults = ldap_get_entries($LDAP, $lsearch);
	if($lresults['count'] != 0)
		$newCN .= " " . $lresults['count'];
	$LDAPDN="cn=VizMgmt,ou=system,dc=vizmgmt,dc=example,dc=com";
	$LDAPPWD='vizmgmt';
	$LDAP = connectLDAP(NULL,$LDAPDN,$LDAPPWD);
	$LDAPBASE = "ou=New Users,dc=vizmgmt,dc=example,dc=com";
	$ldapAttrs = array();
	$ldapAttrs['objectClass'][0] = "top";
	$ldapAttrs['objectClass'][1] = "inetOrgPerson";
	$ldapAttrs['objectClass'][2] = "extensibleObject";
	$ldapAttrs['cn'] = $newCN;
	foreach($input as $attr => $value) {
		switch($attr) {
			case "First":
				$ldapAttrs['givenName'] = $value;
				break;
			case "Last":
				$ldapAttrs['sn'] = $value;
				break;
			case "Department":
				$ldapAttrs['ou'] = $value;
				break;
			case "Company":
				$ldapAttrs['o'] = $value;
				break;
			case "Email":
				$ldapAttrs['mail'] = $value;
				break;
			case "Telephone":
				$ldapAttrs['telephoneNumber'] = $value;
				break;
			case "Mobile":
				$ldapAttrs['mobile'] = $value;
				break;
			case "Address":
				$ldapAttrs['street'] = $value;
				break;
			case "City":
				$ldapAttrs['l'] = $value;
				break;
			case "State":
				$ldapAttrs['st'] = $value;
				break;
			case "Zip":
				$ldapAttrs['postalCode'] = $value;
				break;
			case "Photo":
				$ldapAttrs['jpegPhoto'] = $value;
				break;
			case "Country":
				$ldapAttrs['c'] = $value;
				break;
		}
	}
	$ldapEntry = "cn=" . $ldapAttrs['cn'] . "," . $LDAPBASE;
	$retVal = ldap_add($LDAP, $ldapEntry, $ldapAttrs);
	$vmsAPI->response->header("Content-Type: application/json");
	echo json_encode(array("Added" => $retVal, "dn" => $ldapEntry));
});

$vmsAPI->post('/visitor/update', function() use ($vmsAPI) {
	$body = $vmsAPI->request->getBody();
	        if($_SERVER['CONTENT_TYPE'] == "application/json")
                $input = json_decode($body, TRUE);
        else if($_SERVER['CONTENT_TYPE'] == "application/x-www-form-urlencoded")
                parse_str($body, $input);
	if(!($input['dn']) || ($input['dn'] == "")) {
		error_log("No DN specified.");
		return;
	}
	$LDAPDN="cn=VizMgmt,ou=system,dc=vizmgmt,dc=example,dc=com";
	$LDAPPWD='vizmgmt';
	$LDAP = connectLDAP(NULL,$LDAPDN,$LDAPPWD);
	$ENTRYDN = $input['dn'];
	$RETVAL = 0;
	unset($input['dn']);
	if(isset($input['cn'])) {
		$OLDDN = ldap_explode_dn($ENTRYDN,0);
		$NEWCN = "cn=" . $input['cn'];
		$NEWDN = $NEWCN;
		for($i = 1; $i < $OLDDN['count']; $i++)
			$NEWDN .= "," . $OLDDN[$i];
		error_log("New DN: " . $NEWDN);
		$RETVAL = ldap_rename($LDAP,$ENTRYDN,$NEWCN,NULL,true);
		error_log("Rename Result: " . $RETVAL);
		if($RETVAL)
			$ENTRYDN = $NEWDN;
		unset($input['cn']);
	}
	$RETVAL = $RETVAL and ldap_modify($LDAP,$ENTRYDN,$input);
	$vmsAPI->response->header("Content-Type: application/json");
	echo json_encode(array("Updated" => $RETVAL, "dn" => $ENTRYDN));
});

// Search for host based on first and last name.
$vmsAPI->get('/host/search/:first/:last', function($first, $last) use ($vmsAPI) {
	$LDAP = connectLDAP("ldaps://localhost",NULL,NULL);
	$filter = '(&(objectClass=inetOrgPerson)(!(loginDisabled=true))(mail=*@example.com)(givenName=*' . $first . '*)(sn=*' . $last . '*))';
	$attrs = array("dn","mail","sn","givenName","cn","ou");
	$search = ldap_search($LDAP, "dc=example,dc=com", $filter, $attrs);
	$results = ldap_get_entries($LDAP, $search);
	$retArray = array();
	for($i = 0; $i < $results['count']; $i++) {
		$tempArray = array();
		foreach($results[$i] as $attr => $value) {
			if(!is_numeric($attr) && $attr != "count") {
				if(is_array($value)) {
					$tempArray[$attr] = $value[0];
				} else {
					$tempArray[$attr] = $value;
				}
			}
		}
		$retArray[] = $tempArray;
	}
	$vmsAPI->response->header("Content-Type: application/json");
	echo json_encode($retArray);
});

// Search for host based on cn
$vmsAPI->get('/host/search/:cn', function($cn) use ($vmsAPI) {
        $LDAP = connectLDAP("ldaps://localhost",NULL,NULL);
        $filter = '(&(objectClass=inetOrgPerson)(!(loginDisabled=true))(mail=*@example.com)(cn=*' . $cn . '*))';
        $attrs = array("dn","mail","sn","givenName","cn","ou");
        $search = ldap_search($LDAP, "dc=example,dc=com", $filter, $attrs);
        $results = ldap_get_entries($LDAP, $search);
        $retArray = array();
        for($i = 0; $i < $results['count']; $i++) {
		$tempArray = array();
                foreach($results[$i] as $attr => $value) {
                        if(!is_numeric($attr) && $attr != "count") {
                                if(is_array($value)) {
                                        $tempArray[$attr] = $value[0];
                                } else {
                                        $tempArray[$attr] = $value;
                                }
                        }
                }
		$retArray[] = $tempArray;
        }
        $vmsAPI->response->header("Content-Type: application/json");
        echo json_encode($retArray);
});

// Send e-mail to host notifying of visit.
$vmsAPI->get('/host/notify/:mail/:dn', function($mail,$dn) use ($vmsAPI) {
	$LDAP = connectLDAP(NULL,NULL,NULL);
	$filter = '(objectClass=*)';
	$attrs = array("givenName","sn","o");
	$entry = ldap_read($LDAP, $dn, $filter, $attrs);
	$entry = ldap_first_entry($LDAP, $entry);
	$results = ldap_get_attributes($LDAP, $entry);
	$retArray = array();
	foreach($results as $attr => $value) {
		if(!is_numeric($attr) && $attr != "count") {
			if(is_array($value))
				$retArray[$attr] = $value[0];
			else
				$retArray[$attr] = $value;
		}
	}
	$SUBJECT = "Visitor Has Arrived";
	$MSG = "The following visitor has arrived:\n";
	$MSG .= $retArray['sn'] . ", " . $retArray['givenName'] . "\n";
	$MSG .= "You may pick your visitor up at the Front Desk.\n";
	$HDRS = "From: Visitor.Management@example.com\r\n";
	$HDRS .= "Reply-To: Front.Desk@example.com\r\n";
	$RETVAL = mail($mail,$SUBJECT,$MSG,$HDRS);
	$vmsAPI->response->header("Content-Type: application/json");
	echo json_encode(array("Mail",$RETVAL));
});

// Create visitor check-in record.
$vmsAPI->post('/visitor/checkin', function() use ($vmsAPI) {
	$body = $vmsAPI->request->getBody();
        if($_SERVER['CONTENT_TYPE'] == "application/json")
                $input = json_decode($body, TRUE);
        else if($_SERVER['CONTENT_TYPE'] == "application/x-www-form-urlencoded")
                parse_str($body, $input);
	$QUERY = "INSERT INTO visits(dn,checkin,verified)";
	$QUERY .= "VALUES('" . $input['dn'] . "',NOW(),FALSE);";
	$DB = connectDB();
	$QUERY = pg_query($DB,$QUERY);
	$OID = pg_last_oid($QUERY);
	closeDB($DB);
	$vmsAPI->response->header("Content-Type: application/json");
	echo json_encode(array("oid" => $OID));
});

$vmsAPI->get('/visitor/verifypoll/:oid', function($oid) use ($vmsAPI) {
	$QUERY = "SELECT verified FROM visits WHERE oid=" . $oid . ";";
	$DB = connectDB();
	$QUERY = pg_query($DB,$QUERY);
	$RESULTS = pg_fetch_all($QUERY);
	closeDB($DB);
	if($RESULTS[0]["verified"] == "t")
		echo json_encode("true");
	else
		echo json_encode("false");
});

// Send message to Front Desk to verify the ID.
/*
$vmsAPI->get('/visitor/verifyid/:vid', function($vid) use ($vmsAPI) {
	$body = $vmsAPI->request->getBody();
        if($_SERVER['CONTENT_TYPE'] == "application/json")
                $input = json_decode($body, TRUE);
        else if($_SERVER['CONTENT_TYPE'] == "application/x-www-form-urlencoded")
                parse_str($body, $input);
	$QUERY = "UPDATE visits SET verified=TRUE WHERE oid=" . $input['oid'] . ";";
	$DB = connectDB();
	$UPDATE = pg_query($DB,$QUERY);
	closeDB($DB);
	$vmsAPI->response->header("Content-Type: application/json");
	echo json_encode(array("Verified" => pg_result_status($UPDATE)));
});
*/

// Print the visitor's badge.
$vmsAPI->get('/visitor/badge/:oid', function($oid) use ($vmsAPI) {
	$DB = connectDB();
	$QUERY = "SELECT dn,checkin FROM visits WHERE oid=" . $oid . ";";
	$QUERY = pg_query($DB,$QUERY);
	$QUERY = pg_fetch_all($QUERY);
	$LDAP = connectLDAP(NULL,NULL,NULL);
	$LFILTER = "(objectClass=inetOrgPerson)";
	$LATTRS = array("jpegPhoto","sn","givenName","o");
	$LENTRY = ldap_read($LDAP, $QUERY[0]['dn'], $LFILTER, $LATTRS);
	$LENTRY = ldap_first_entry($LDAP, $LENTRY);
	$LRES = ldap_get_attributes($LDAP, $LENTRY);
	error_log(print_r($LRES,true));
        if(isset($LRES['jpegPhoto'])) {
                if(is_array($LRES['jpegPhoto']))
                        $photo = imagecreatefromstring($LRES['jpegPhoto'][0]);
                else   
                        $photo = imagecreatefromstring($LRES['jpegPhoto']);
        } else {
                $photo = imagecreatetruecolor(150,200);
                imagestring($photo, 5, 0, 0, "NO PHOTO", 0xFFFFFF);
        }
	$font = "/usr/share/fonts/truetype/luxirr.ttf";
	$fontsize = 50;
	$ratio = imagesx($photo)/180;
	$badge_img = imagecreatetruecolor(600,350);
	imagefill($badge_img,0,0,0xFFFFFF);
	imagefilledrectangle($badge_img,0,0,4,imagesy($badge_img)-1,0x000000);
	imagefilledrectangle($badge_img,0,0,imagesx($badge_img),4,0x000000);
	imagefilledrectangle($badge_img,imagesx($badge_img)-4,0,imagesx($badge_img),imagesy($badge_img),0x000000);
	imagefilledrectangle($badge_img,0,imagesy($badge_img)-4,imagesx($badge_img),imagesy($badge_img),0x000000);
	imagefilledrectangle($badge_img,10,10,imagesx($badge_img)-10,66,0x0000FF);
	imagecopyresampled($badge_img,$photo,10,80,0,0,180,imagesy($photo)/$ratio,imagesx($photo),imagesy($photo));
	imagedestroy($photo);
	imagettftext($badge_img,50,0,150,62,0xFFFFFF,$font,"VISITOR");
	while(true) {
		$nameBox = imagettfbbox(50,0,$font,$LRES['sn'][0] . ", " . $LRES['givenName'][0]);
		if($fontsize > 3 && ($nameBox[2] + 200 + 20) > imagesx($badge_img)) {
			$fontsize -= 2;
		} else {
			break;
		}
	}
	imagettftext($badge_img,32,0,200,120,0x000000,$font,$LRES['sn'][0] . ", " . $LRES['givenName'][0]);
	if(isset($LRES['o']) && $LRES['o'][0] != "")
		imagettftext($badge_img,18,0,200,160,0x000000,$font,$LRES['o'][0]);
	else
		imagettftext($badge_img,18,0,200,160,0x000000,$font,"Self");
	imagettftext($badge_img,18,0,200,200,0x000000,$font,date("Y/m/d",strtotime($QUERY[0]['checkin'])));
	$logoImg = imagecreatefrompng("img/logo.png");
	$ratio = imagesx($logoImg)/200;
	imagecopyresampled($badge_img,$logoImg,imagesx($badge_img)-200-20,imagesy($badge_img)-(imagesy($logoImg)/$ratio)-20,0,0,200,imagesy($logoImg)/$ratio,imagesx($logoImg),imagesy($logoImg));
        $vmsAPI->response->header('Content-Type', 'content-type: image/jpeg');
        imagejpeg($badge_img);
	// $UPDATE = pg_update($DB,"visits",array("badged" => TRUE),array("oid" => $oid));
	closeDB($DB);
});

// Get a current visit based on first/last name for purposes of signing out.
$vmsAPI->get('/visitor/visit/:first/:last', function($first,$last) use ($vmsAPI) {
	$DB = connectDB();
	$QUERY = "SELECT oid,* FROM visits WHERE dn ILIKE('%" . $first . "%" . $last . "%') AND checkin < NOW() AND checkout IS NULL;";
	$QUERY = pg_query($DB,$QUERY);
	$RESULTS = pg_fetch_all($QUERY);
	closeDB($DB);
	$vmsAPI->response->header("Content-Type: application/json");
	echo json_encode($RESULTS);
});

// Get a current visit based on visitor id for purposes of signing out.
$vmsAPI->get('/visitor/visit/:vid', function($vid) use ($vmsAPI) {
	$DB = connectDB();
	$QUERY = "SELECT oid,* FROM visits WHERE oid=" . $vid . " OR vid=" . $vid . ";";
	$QUERY = pg_query($DB,$QUERY);
	$RESULTS = pg_fetch_all($QUERY);
	closeDB($DB);
	$vmsAPI->response->header("Content-Type: application/json");
	echo json_encode($RESULTS);
});

$vmsAPI->get('/visitor/checkout/:vid', function($vid) use ($vmsAPI) {
    $QUERY = "UPDATE visits SET checkout=NOW() WHERE vid=" . $vid . " AND checkout IS NULL;";
    $DB = connectDB();
    $QUERY = pg_result_status(pg_query($DB,$QUERY));
    closeDB($DB);
    $vmsAPI->response->header("Content-Type: application/json");
    echo json_encode(array("Checkout" => $QUERY));
});

$vmsAPI->get('/visitor/checkout/oid/:oid', function($oid) use($vmsAPI) {
    $QUERY = "UPDATE visits SET checkout=NOW() WHERE oid=" . $oid . " AND checkout IS NULL;";
    $DB = connectDB();
    $QUERY = pg_result_status(pg_query($DB,$QUERY));
    closeDB($DB);
    $vmsAPI->response->header("Content-Type: application/json");
    echo json_encode(array("Checkout" => $QUERY));
});

// Update visit record with checkout info.
$vmsAPI->post('/visitor/checkout', function() use ($vmsAPI) {
	$body = $vmsAPI->request->getBody();
	if($_SERVER['CONTENT_TYPE'] == "application/json")
                $input = json_decode($body, TRUE);
        else if($_SERVER['CONTENT_TYPE'] == "application/x-www-form-urlencoded")
                parse_str($body, $input);
	$QUERY = "UPDATE visits SET checkout=NOW() WHERE oid=" . $input['oid'] . ";";
	$DB = connectDB();
	$UPDATE = pg_result_status(pg_query($DB,$QUERY));
	closeDB($DB);
	$vmsAPI->response->header("Content-Type: application/json");
	echo json_encode(array("Checkout" => $UPDATE));
});

$vmsAPI->run();

?>
