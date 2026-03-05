<?php
try {
    /*Get DB connection*/
    require_once "../src/DBController.php";

    /*Get information from the post request*/
    $myusername = $_POST['username'];
    $mypassword = $_POST['password'];

    if($myusername==null || $mypassword==null) {
    {throw new Exception("input did not exist");}

     //Input validation to confirm usdername is a valid email address in the format of username@domian.com
     if (!filter_var($myusername, FILTER_VALIDATE_EMAIL)) {
        header("Location: ../public/index.php?login=fail&reason=invalidemail");
        exit();
    }

    //Input validation to confirm that password is between length of 8 to 16 and consists of characters a-z, A-Z, and 0-9 with at least one capital and number
    if (strlen($mypassword) < 8 || strlen($mypassword) > 16) {
        header("Location: ../public/index.php?login=fail&reason=invalidpassword");
        exit();
    }//between 8 and 16 char

    if (!preg_match('/[A-Z]/', $mypassword)) {
        header("Location: ../public/index.php?login=fail&reason=invalidpassword");
        exit();
    } //AT least on capital

    if (!preg_match('/[0-9]', $mypassword)) {
        header("Location: ../public/index.php?login=fail&reason=invalidpassword");
        exit();
    } //At least 1 number

    if (!preg_match('/^[a-zA-Z0-9]+$/', $mypassword)) {
        header("Location: ../public/index.php?login=fail&reason=invalidpassword");
        exit();
    } //Only alphanumneric char

    //convert password to 80 byte hash using ripemd256 before comparing
    $hashpassword = hash('ripemd256', $mypassword);

    $myusername = strtolower($myusername); //makes username noncase-sensitive
    global $acctype;

    if (session_status() !== PHP_SESSION_ACTIVE) {
        session_start();
    }

    //SQLi Mitigation
    $stmt = $db->prepare("SELECT * FROM User WHERE lower(Email) = :email AND (Password = :password OR Password = :hashpassword) LIMIT 1");
    if (!$stmt){ 
        throw new Exception("Database query failed."); //Prepare failed
    }
    $stmt->bindValue(':email', $myusername, SQLITE3_TEXT);
    $stmt->bindValue(':password', $mypassword, SQLITE3_TEXT);
    $stmt->bindValue(':hashpassword', $hashpassword, SQLITE3_TEXT);
    $result = $stmt->execute();
    if (!$result) {
        throw new Exception("Database execution failed.");
    }

    $userinfo = $result->fetchArray(SQLITE3_NUM);

    //Login Success?
    if ($userinfo !== false && $userinfo !== null) {
        // login success
        session_regenerate_id(true);

        $_SESSION['email'] = $myusername;
        $_SESSION['acctype'] = $userinfo[2];

        header("Location: ../public/dashboard.php");
        exit();
    } else {
        //login fail
        header("Location: ../public/index.php?login=fail");
        exit();
    }

}
catch(Exception $e)
{
    error_log("Login error: " . $e->getMessage()); //does not expose stack trace/vars to user

    header("Location: ../public/index.php?login=error");
    exit();
}




