<?php
try {
    /*Get DB connection*/
    require_once "../src/DBController.php";

    /*Get information from the post request*/
    $myusername = $_POST['username'];
    $mypassword = $_POST['password'];

    //convert password to 80 byte hash using ripemd256 before comparing
    $hashpassword = hash('ripemd256', $mypassword);

    if($myusername==null)
    {throw new Exception("input did not exist");}


    $myusername = strtolower($myusername); //makes username noncase-sensitive
    global $acctype;


    //query for count
    $query = "SELECT COUNT(*) as count FROM User WHERE Email='$myusername' AND (Password='$mypassword' OR Password='$hashpassword')";
    $count = $db->querySingle($query);

    //query for the row(s)
    $query = "SELECT * FROM User WHERE Email='$myusername' AND (Password='$mypassword' OR Password='$hashpassword')";
    $results = $db->query($query);

    if ($results !== false) //query failed check
    {
        if (($userinfo = $results->fetchArray()) !== (null || false)) //checks if rows exist
        {
            // users or user found
            $error = false;

            $acctype = $userinfo[2];
        } else {
            // user was not found
            $error = true;

        }
    } else {
        //query failed
        $error = true;

    }
    
    //Input validation to confirm usdername is a valid email address in the format of username@domian.com
    if (!filter_var($my_username, FILTER_VALIDATE_EMAIL)) {
        header("Location: ../public/index.php?login=fail&reason=invalidemail");
        exit();
    }

    //Input validation to confirm that password is between length of 8 to 16 and consists of characters a-z, A-Z, and 0-9 with at least one capital and number
    if (strlen($mypassword) < 8 || strlen($mypassword) > 16) {
        header("Location: ..//public/index.php?login=fail&reason=invalidpassword");
        exit();
    }//between 8 and 16 char

    if (!preg_match('/[A-Z]/', $mypassword)) {
        header("Location: ..//public/index.php?login=fail&reason=invalidpassword");
        exit();
    } //AT least on capital

    if (!preg_match('/[0-9]', $mypassword)) {
        header("Location: ..//public/index.php?login=fail&reason=invalidpassword");
        exit();
    } //At least 1 number

    if (!preg_match('/^[a-zA-Z0-9]+$/', $mypassword)) {
        header("Location: ..//public/index.php?login=fail&reason=invalidpassword");
        exit();
    } //Only alphanumneric char





    //determine if an account that met the credentials was found
    if ($count >= 1 && !$error) {
        //login success

        if (isset($_SESSION)) {
            //a session already existed
            session_destroy();
            session_start();
            $_SESSION['email'] = $myusername;
            $_SESSION['acctype'] = $acctype;
        } else {
            //a session did not exist
            session_start();
            $_SESSION['email'] = $myusername;
            $_SESSION['acctype'] = $acctype;
        }
        //redirect
        header("Location: ../public/dashboard.php");
    } else {
        //login fail
        header("Location: ../public/index.php?login=fail");
    }
//note: since the database is not changed, it is not backed up
}
catch(Exception $e)
{
    //prepare page for content
    include_once "ErrorHeader.php";

    //Display error information
    echo 'Caught exception: ',  $e->getMessage(), "<br>";
    var_dump($e->getTraceAsString());
    echo 'in '.'http://'. $_SERVER['SERVER_NAME'] . $_SERVER['REQUEST_URI']."<br>";

    $allVars = get_defined_vars();
    debug_zval_dump($allVars);
}




